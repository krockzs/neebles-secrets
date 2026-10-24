//! F26-L: durable, idempotent *intent* journal for module vault requests.
//!
//! Stores only module, request ID and state; never passwords or secret values.
//! The journal is owned exclusively by the isolated VaultController worker.
//! No `vault.request` endpoint is advertised through Boss in this increment.
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const DIRECTORY: &str = ".request-journal";
const MAX_RECORDS: usize = 4096;
const MAX_BYTES: u64 = 1024;
const MAX_PENDING_MODULES: usize = 32;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State { Pending, Succeeded }

fn current_uid() -> u32 { unsafe { libc::geteuid() } }
fn valid_module(module: &str) -> bool {
    let bytes = module.as_bytes();
    (2..=64).contains(&bytes.len()) && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c==b'-')
        && module!="general" && !module.ends_with('-') && !module.contains("--")
}
pub(super) fn valid_request_id(id: &str) -> bool {
    (16..=72).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c==b'-')
        && id.as_bytes()[0].is_ascii_alphanumeric() && !id.ends_with('-')
}
fn private_dir(path:&Path) -> Result<(),String> {
    let meta=fs::symlink_metadata(path).map_err(|_|"request_journal_unavailable")?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid()!=current_uid()
        || meta.permissions().mode() & 0o077 != 0 {
        return Err("request_journal_insecure_directory".into());
    }
    Ok(())
}
fn private_record(path:&Path) -> Result<(),String> {
    let meta=fs::symlink_metadata(path).map_err(|_|"request_journal_unavailable")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.uid()!=current_uid()
        || meta.nlink()!=1 || meta.permissions().mode() & 0o077 != 0
        || meta.len()==0 || meta.len()>MAX_BYTES {
        return Err("request_journal_insecure_record".into());
    }
    Ok(())
}

pub struct Journal { folder: PathBuf }
impl Journal {
    pub fn open(vault_dir:&Path) -> Result<Self,String> {
        private_dir(vault_dir)?;
        let folder=vault_dir.join(DIRECTORY);
        if !folder.exists() {
            // `create_dir` refuses collisions; always verify after creation.
            match fs::create_dir(&folder) {
                Ok(()) => fs::set_permissions(&folder,fs::Permissions::from_mode(0o700))
                    .map_err(|_|"request_journal_permissions")?,
                Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists => {},
                Err(_) => return Err("request_journal_create_failed".into()),
            }
        }
        private_dir(&folder)?;
        File::open(vault_dir).and_then(|file|file.sync_all())
            .map_err(|_|"request_journal_parent_sync_failed")?;
        let journal=Self{folder};
        // An interrupted atomic write can leave only a private .tmp-UUID file.
        // The previous committed record (if any) remains authoritative.
        // Recovery happens on worker startup/open, before accepting requests.
        journal.recover_stale_temporaries()?;
        Ok(journal)
    }
    // Only the exact names produced by persist() are eligible for recovery.
    // Unexpected names and unsafe file metadata remain fatal, not silently removed.
    fn expected_temporary_name(name:&str)->bool {
        let Some(id)=name.strip_prefix(".tmp-") else {return false;};
        let b=id.as_bytes();
        if b.len()!=36 || b[14]!=b'4' || !matches!(b[19],b'8'|b'9'|b'a'|b'b') {
            return false;
        }
        b.iter().enumerate().all(|(i,c)| {
            if matches!(i,8|13|18|23){*c==b'-'}
            else {c.is_ascii_digit() || (b'a'..=b'f').contains(c)}
        })
    }
    fn recover_stale_temporaries(&self)->Result<(),String>{
        private_dir(&self.folder)?;
        let mut cleaned=false;
        for ent in fs::read_dir(&self.folder).map_err(|_|"request_journal_list_failed")? {
            let ent=ent.map_err(|_|"request_journal_list_failed")?;
            let name=ent.file_name().into_string().map_err(|_|"request_journal_invalid_name")?;
            if !name.starts_with(".tmp-"){continue;}
            if !Self::expected_temporary_name(&name){return Err("request_journal_invalid_temporary".into());}
            let path=ent.path();
            let md=fs::symlink_metadata(&path).map_err(|_|"request_journal_temporary_inspect_failed")?;
            // A crash may occur before the first byte is written: zero length is valid here.
            if !md.is_file() || md.file_type().is_symlink() || md.uid()!=current_uid()
                || md.nlink()!=1 || md.permissions().mode() & 0o777 != 0o600
                || md.len()>MAX_BYTES {
                return Err("request_journal_insecure_temporary".into());
            }
            let fd=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&path)
                .map_err(|_|"request_journal_temporary_open_failed")?;
            let opened=fd.metadata().map_err(|_|"request_journal_temporary_inspect_failed")?;
            if opened.dev()!=md.dev() || opened.ino()!=md.ino()
                || !opened.is_file() || opened.uid()!=current_uid()
                || opened.nlink()!=1 || opened.permissions().mode() & 0o777 != 0o600 {
                return Err("request_journal_temporary_changed".into());
            }
            // No committed request is removed; the temporary is uncommitted by definition.
            fs::remove_file(&path).map_err(|_|"request_journal_temporary_cleanup_failed")?;
            cleaned=true;
        }
        if cleaned {
            File::open(&self.folder).and_then(|f|f.sync_all())
                .map_err(|_|"request_journal_recovery_sync_failed")?;
        }
        Ok(())
    }
    fn path(&self,module:&str,id:&str)->Result<PathBuf,String> {
        if !valid_module(module) || !valid_request_id(id) { return Err("invalid_request_identity".into()); }
        Ok(self.folder.join(format!("request-{module}-{id}.json")))
    }
    fn inspect(&self, path:&Path, module:&str, id:&str)->Result<Option<State>,String> {
        match fs::symlink_metadata(path) {
            Ok(_) => private_record(path)?,
            Err(e) if e.kind()==std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("request_journal_read_failed".into()),
        }
        // O_NOFOLLOW blocks a symlink swap between metadata validation and open.
        let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)
            .map_err(|_|"request_journal_read_failed")?;
        let opened=file.metadata().map_err(|_|"request_journal_read_failed")?;
        if !opened.is_file() || opened.uid()!=current_uid() || opened.nlink()!=1
            || opened.permissions().mode() & 0o077 != 0 || opened.len()>MAX_BYTES {
            return Err("request_journal_insecure_record".into());
        }
        let mut raw=Vec::new();
        file.take(MAX_BYTES+1).read_to_end(&mut raw).map_err(|_|"request_journal_read_failed")?;
        if raw.len() as u64>MAX_BYTES {return Err("request_journal_record_too_large".into());}
        let data:Value=serde_json::from_slice(&raw).map_err(|_|"request_journal_corrupt")?;
        let fields=data.as_object().ok_or("request_journal_corrupt")?;
        if fields.len()!=4 || data.get("schema").and_then(Value::as_u64)!=Some(1)
            || data.get("module").and_then(Value::as_str)!=Some(module)
            || data.get("request_id").and_then(Value::as_str)!=Some(id) {
            return Err("request_journal_identity_mismatch".into());
        }
        match data.get("state").and_then(Value::as_str) {
            Some("pending")=>Ok(Some(State::Pending)),
            Some("succeeded")=>Ok(Some(State::Succeeded)),
            _=>Err("request_journal_invalid_state".into()),
        }
    }
    fn entries(&self)->Result<Vec<(String,String,State)>,String> {
        private_dir(&self.folder)?;
        let mut out=Vec::new();
        for ent in fs::read_dir(&self.folder).map_err(|_|"request_journal_list_failed")? {
            let ent=ent.map_err(|_|"request_journal_list_failed")?;
            let file=ent.file_name().into_string().map_err(|_|"request_journal_invalid_name")?;
            if file.starts_with(".tmp-") {return Err("request_journal_incomplete_transaction".into());}
            // Non-journal names under a private directory indicate corruption.
            if !file.starts_with("request-") || !file.ends_with(".json") {
                return Err("request_journal_invalid_name".into());
            }
            let name=file.strip_prefix("request-").and_then(|v|v.strip_suffix(".json"))
                .ok_or("request_journal_invalid_name")?;
            // Never slice a UTF-8 filename at an arbitrary byte boundary.
            if !name.is_ascii() {return Err("request_journal_invalid_name".into());}
            // IDs are UUID-like; search split candidates and verify exact path.
            let mut matched=None;
            for i in 2..name.len() {
                if name.as_bytes()[i]!=b'-' {continue;}
                let module=&name[..i]; let id=&name[i+1..];
                if valid_module(module) && valid_request_id(id)
                   && self.path(module,id)?.file_name()==Some(ent.file_name().as_os_str()) {
                    // File names containing dashes are ambiguous: prefer persisted identities.
                    let state=self.inspect(&ent.path(),module,id);
                    if let Ok(Some(state))=state { matched=Some((module.to_owned(),id.to_owned(),state)); break; }
                }
            }
            let record=matched.ok_or("request_journal_invalid_record")?;
            out.push(record);
            if out.len()>MAX_RECORDS {return Err("request_journal_capacity_exceeded".into());}
        }
        Ok(out)
    }
    fn persist(&self,module:&str,id:&str,state:State)->Result<(),String>{
        private_dir(&self.folder)?;
        let target=self.path(module,id)?;
        let value=json!({"schema":1,"module":module,"request_id":id,
            "state": if state==State::Pending {"pending"} else {"succeeded"}});
        let body=serde_json::to_vec(&value).map_err(|_|"request_journal_serialization")?;
        if body.len() as u64>MAX_BYTES{return Err("request_journal_record_too_large".into());}
        let nonce=crate::uuid_v4().map_err(|_|"request_journal_nonce")?;
        let temp=self.folder.join(format!(".tmp-{nonce}"));
        let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)
            .map_err(|_|"request_journal_temporary_failed")?;
        let outcome=(|| ->Result<(),String>{
            file.write_all(&body).map_err(|_|"request_journal_write_failed")?;
            file.sync_all().map_err(|_|"request_journal_sync_failed")?;
            match fs::symlink_metadata(&target) {
                Ok(_) => private_record(&target)?,
                Err(e) if e.kind()==std::io::ErrorKind::NotFound => {},
                Err(_) => return Err("request_journal_target_inspect_failed".into()),
            }
            fs::rename(&temp,&target).map_err(|_|"request_journal_commit_failed")?;
            File::open(&self.folder).and_then(|f|f.sync_all())
                .map_err(|_|"request_journal_directory_sync_failed")?;
            Ok(())
        })();
        if outcome.is_err(){let _=fs::remove_file(&temp);}
        outcome
    }
    pub fn claim(&self,module:&str,id:&str)->Result<State,String>{
        let file=self.path(module,id)?;
        // Validate the entire journal before returning even a duplicate ID.
        let entries=self.entries()?;
        if let Some(state)=self.inspect(&file,module,id)?{return Ok(state);}
        if entries.len()>=MAX_RECORDS {return Err("request_journal_capacity_exceeded".into());}
        let pending=entries.iter().filter(|(_,_,s)|*s==State::Pending)
            .map(|(m,_,_)|m.clone()).collect::<BTreeSet<_>>();
        if pending.len()>=MAX_PENDING_MODULES && !pending.contains(module){
            return Err("too_many_pending_vaults".into());
        }
        self.persist(module,id,State::Pending)?;
        Ok(State::Pending)
    }
    pub fn complete_module(&self,module:&str)->Result<(),String>{
        if !valid_module(module){return Err("invalid_module_id".into());}
        for (entry,id,state) in self.entries()? {
            if entry==module && state==State::Pending {
                self.persist(&entry,&id,State::Succeeded)?;
            }
        }
        Ok(())
    }
    pub fn pending_modules(&self)->Result<BTreeSet<String>,String>{
        Ok(self.entries()?.into_iter().filter(|(_,_,state)|*state==State::Pending)
            .map(|(module,_,_)|module).collect())
    }
    pub fn status(&self,module:&str,id:&str)->Result<Option<State>,String>{
        self.inspect(&self.path(module,id)?,module,id)
    }
}

#[cfg(test)] mod tests {
    use super::*;
    fn fixture()->(PathBuf,Journal){
        let path=std::env::temp_dir().join(format!(".neebles-f26l-{}",crate::uuid_v4().unwrap()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path,fs::Permissions::from_mode(0o700)).unwrap();
        let journal=Journal::open(&path).unwrap();
        (path,journal)
    }
    fn cleanup(root:PathBuf){fs::remove_dir_all(root).unwrap();}
    const A:&str="0123456789abcdef0123456789abcdef";
    #[test] fn request_survives_restart_and_duplicate_is_stable(){
        let (root,j)=fixture();
        assert_eq!(j.claim("neebles-connect",A).unwrap(),State::Pending);
        assert_eq!(j.claim("neebles-connect",A).unwrap(),State::Pending);
        let reread=Journal::open(&root).unwrap();
        assert_eq!(reread.pending_modules().unwrap(),BTreeSet::from(["neebles-connect".to_string()]));
        reread.complete_module("neebles-connect").unwrap();
        assert_eq!(j.claim("neebles-connect",A).unwrap(),State::Succeeded);
        assert!(j.pending_modules().unwrap().is_empty());
        cleanup(root);
    }
    #[test] fn separate_modules_and_request_ids_never_collide(){
        let (root,j)=fixture();
        let b="fedcba9876543210fedcba9876543210";
        assert_eq!(j.claim("neebles-connect",A).unwrap(),State::Pending);
        assert_eq!(j.claim("neebles-connect",b).unwrap(),State::Pending);
        assert_eq!(j.claim("neebles-db",A).unwrap(),State::Pending);
        j.complete_module("neebles-connect").unwrap();
        assert_eq!(j.claim("neebles-db",A).unwrap(),State::Pending);
        assert_eq!(j.claim("neebles-connect",b).unwrap(),State::Succeeded);
        cleanup(root);
    }
    #[test] fn no_secrets_or_master_in_journal_and_permissions_are_private(){
        let (root,j)=fixture();
        j.claim("neebles-connect",A).unwrap();
        let journal=root.join(DIRECTORY);
        assert_eq!(fs::metadata(&journal).unwrap().permissions().mode()&0o777,0o700);
        let entry=j.path("neebles-connect",A).unwrap();
        assert_eq!(fs::metadata(&entry).unwrap().permissions().mode()&0o777,0o600);
        let text=fs::read_to_string(entry).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap().as_object().unwrap().len(),4);
        assert!(!text.contains("password") && !text.contains("master_key"));
        cleanup(root);
    }
    #[test] fn malformed_identifiers_and_tampering_fail_closed(){
        let (root,j)=fixture();
        for module in ["../evil","general","db_x","neebles--db"]{
            assert!(j.claim(module,A).is_err());
        }
        for id in ["../something","short","FOOFOOFOOFOOFOOFOO", "bad/id______________"]{
            assert!(j.claim("neebles-connect",id).is_err());
        }
        j.claim("neebles-connect",A).unwrap();
        let record=j.path("neebles-connect",A).unwrap();
        fs::write(&record,"{broken-json").unwrap();
        assert!(j.claim("neebles-connect",A).is_err());
        assert!(j.pending_modules().is_err());
        cleanup(root);
    }
    #[test] fn symlinked_record_and_folder_are_rejected(){
        use std::os::unix::fs::symlink;
        let (root,j)=fixture();
        let target=root.join("other");
        fs::write(&target,b"not-a-journal").unwrap();
        symlink(&target,j.path("neebles-connect",A).unwrap()).unwrap();
        assert!(j.claim("neebles-connect",A).is_err());
        cleanup(root);
        let root=std::env::temp_dir().join(format!(".neebles-f26l-{}",crate::uuid_v4().unwrap()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();
        symlink(std::env::temp_dir(),root.join(DIRECTORY)).unwrap();
        assert!(Journal::open(&root).is_err());
        cleanup(root);
    }
    #[test] fn unrelated_files_or_stale_temp_are_not_silently_ignored(){
        let (root,j)=fixture();
        fs::write(root.join(DIRECTORY).join(".tmp-interrupted"),b"unexpected").unwrap();
        assert!(j.pending_modules().is_err());
        cleanup(root);
    }
    #[test] fn non_ascii_record_name_fails_without_panic(){
        let (root,j)=fixture();
        fs::write(root.join(DIRECTORY).join("request-neebles-á-0123456789abcdef.json"), b"{}") .unwrap();
        assert!(j.pending_modules().is_err());
        cleanup(root);
    }

    #[test] fn crashed_uncommitted_write_is_recovered_without_changing_committed_state(){
        let (root,j)=fixture();
        j.claim("neebles-connect",A).unwrap();
        let temp=root.join(DIRECTORY).join(format!(".tmp-{}",crate::uuid_v4().unwrap()));
        let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp).unwrap();
        file.write_all(b"partial").unwrap();
        file.sync_all().unwrap();
        drop(file);
        // A restarted worker must discard the orphan temp, retaining the prior pending record.
        let reopened=Journal::open(&root).unwrap();
        assert!(!temp.exists());
        assert_eq!(reopened.status("neebles-connect",A).unwrap(),Some(State::Pending));
        reopened.complete_module("neebles-connect").unwrap();
        assert_eq!(Journal::open(&root).unwrap().status("neebles-connect",A).unwrap(),Some(State::Succeeded));
        cleanup(root);
    }
    #[test] fn crash_before_first_write_does_not_block_clean_restart(){
        let (root,_)=fixture();
        let temp=root.join(DIRECTORY).join(format!(".tmp-{}",crate::uuid_v4().unwrap()));
        drop(OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp).unwrap());
        let j=Journal::open(&root).unwrap();
        assert!(!temp.exists());
        assert!(j.pending_modules().unwrap().is_empty());
        cleanup(root);
    }
    #[test] fn unsafe_or_unknown_temporary_is_never_removed(){
        use std::os::unix::fs::symlink;
        let (root,_)=fixture();
        let folder=root.join(DIRECTORY);
        let unexpected=folder.join(".tmp-not-a-uuid");
        fs::write(&unexpected,b"untrusted").unwrap();
        assert!(Journal::open(&root).is_err());
        assert!(unexpected.exists());
        fs::remove_file(&unexpected).unwrap();
        let outside=root.join("outside");
        fs::write(&outside,b"outside-data").unwrap();
        let link=folder.join(format!(".tmp-{}",crate::uuid_v4().unwrap()));
        symlink(&outside,&link).unwrap();
        assert!(Journal::open(&root).is_err());
        assert!(link.is_symlink());
        assert_eq!(fs::read(&outside).unwrap(),b"outside-data");
        cleanup(root);
    }
    #[test] fn oversized_stale_temporary_fails_closed(){
        let (root,_)=fixture();
        let temp=root.join(DIRECTORY).join(format!(".tmp-{}",crate::uuid_v4().unwrap()));
        let f=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp).unwrap();
        f.set_len(MAX_BYTES+1).unwrap();
        drop(f);
        assert!(Journal::open(&root).is_err());
        assert!(temp.exists());
        cleanup(root);
    }
}
