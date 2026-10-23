//! F11-D: journalled restoration of a set of ENCRYPTED vault files.
//! NOT connected to IPC/UI until disposable end-to-end QA is complete.
//! Caller must still provide KeePass authentication of every input.
//! No Master Key is stored in transaction records.
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const JOURNAL: &str = ".neebles-restore-transaction.json";
const MAX_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone)]
pub struct Incoming {
    pub target: String,
    pub staged_file: PathBuf,
}
#[derive(Clone)]
struct Record {
    target: String,
    backup: String,
    staged: String,
    old_exists: bool,
}

struct Journal {
    schema: u32,
    phase: String,
    records: Vec<Record>,
}
fn err(s: &'static str) -> String { s.into() }
fn uid() -> u32 {unsafe {libc::geteuid()}}
fn dir_check(dir: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(dir).map_err(|_|err("restore_directory_missing"))?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid()!=uid() || m.permissions().mode() & 0o077 != 0 {
        return Err(err("restore_directory_insecure"));
    }
    Ok(())
}
fn regular(dir: &Path, name: &str, min: u64) -> Result<File, String> {
    let path=dir.join(name);
    let meta=fs::symlink_metadata(&path).map_err(|_|err("restore_file_unavailable"))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.uid()!=uid()
        || meta.permissions().mode() & 0o077 != 0 || meta.len()<min || meta.len()>MAX_BYTES {
        return Err(err("restore_file_invalid"));
    }
    let mut opt=OpenOptions::new();
    opt.read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC);
    let file=opt.open(&path).map_err(|_|err("restore_file_open_failed"))?;
    let after=file.metadata().map_err(|_|err("restore_file_stat_failed"))?;
    if after.ino()!=meta.ino() || after.dev()!=meta.dev() {return Err(err("restore_file_race"));}
    Ok(file)
}
fn fsync_dir(dir: &Path) -> Result<(), String> {
    File::open(dir).and_then(|f|f.sync_all()).map_err(|_|err("restore_directory_sync_failed"))
}
fn nonce() -> Result<String, String> {
    let mut buf=[0u8;16];
    File::open("/dev/urandom").and_then(|mut f|f.read_exact(&mut buf))
        .map_err(|_|err("restore_random_failed"))?;
    Ok(buf.iter().map(|v|format!("{v:02x}")).collect())
}
fn write_journal(dir: &Path, value: &Journal, replace: bool) -> Result<(), String> {
    let data=serde_json::to_vec(&json!({"schema":value.schema,"phase":value.phase,
        "records":value.records.iter().map(|r|json!({"target":r.target,"backup":r.backup,
        "staged":r.staged,"old_exists":r.old_exists})).collect::<Vec<_>>()
    })).map_err(|_|err("restore_journal_encode_failed"))?;
    if data.len()>16384 {return Err(err("restore_journal_oversize"));}
    let name=if replace {format!(".neebles-restore-journal-{}.tmp",nonce()?)} else {JOURNAL.into()};
    let path=dir.join(&name);
    let mut f=OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(&path)
        .map_err(|_|err("restore_journal_open_failed"))?;
    let saved=(||{
        f.write_all(&data).map_err(|_|err("restore_journal_write_failed"))?;
        f.sync_all().map_err(|_|err("restore_journal_sync_failed"))?;
        if replace {
            fs::rename(&path,dir.join(JOURNAL)).map_err(|_|err("restore_journal_replace_failed"))?;
        }
        fsync_dir(dir)
    })();
    if saved.is_err() && replace {let _=fs::remove_file(&path);}
    saved
}
fn validate_record(r: &Record) -> Result<(), String> {
    if !crate::restore_sessions::valid_target(&r.target) {return Err(err("restore_journal_invalid_target"));}
    if !r.staged.starts_with(".neebles-restore-") || !r.staged.ends_with(".pending.kdbx")
        || !r.staged.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'.'||b==b'-') {
        return Err(err("restore_journal_invalid_stage"));
    }
    if !r.backup.starts_with(".neebles-restore-backup-") || !r.backup.ends_with(".kdbx")
        || !r.backup.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'.'||b==b'-') {
        return Err(err("restore_journal_invalid_backup"));
    }
    Ok(())
}
fn load_journal(dir: &Path) -> Result<Option<Journal>, String> {
    let path=dir.join(JOURNAL);
    if !path.exists() && fs::symlink_metadata(&path).is_err() {return Ok(None);}
    let mut f=regular(dir,JOURNAL,2)?;
    if f.metadata().map_err(|_|err("restore_journal_metadata_failed"))?.len()>16384 {
        return Err(err("restore_journal_oversize"));
    }
    let mut raw=Vec::new();
    f.read_to_end(&mut raw).map_err(|_|err("restore_journal_read_failed"))?;
    let v:Value=serde_json::from_slice(&raw).map_err(|_|err("restore_journal_parse_failed"))?;
    let arr=v.get("records").and_then(Value::as_array).ok_or_else(||err("restore_journal_invalid"))?;
    let mut entries=Vec::new();
    for item in arr {
        entries.push(Record {
            target:item.get("target").and_then(Value::as_str).ok_or_else(||err("restore_journal_invalid"))?.into(),
            backup:item.get("backup").and_then(Value::as_str).ok_or_else(||err("restore_journal_invalid"))?.into(),
            staged:item.get("staged").and_then(Value::as_str).ok_or_else(||err("restore_journal_invalid"))?.into(),
            old_exists:item.get("old_exists").and_then(Value::as_bool).ok_or_else(||err("restore_journal_invalid"))?,
        });
    }
    let value=Journal {
        schema:v.get("schema").and_then(Value::as_u64).ok_or_else(||err("restore_journal_invalid"))? as u32,
        phase:v.get("phase").and_then(Value::as_str).ok_or_else(||err("restore_journal_invalid"))?.into(),
        records:entries,
    };
    if value.schema!=1 || !["prepared","committed","rolled_back"].contains(&value.phase.as_str())
        || value.records.is_empty() || value.records.len()>64 {
        return Err(err("restore_journal_invalid"));
    }
    let mut names=std::collections::BTreeSet::new();
    let mut backups=std::collections::BTreeSet::new();
    for r in &value.records {
        validate_record(r)?;
        if !names.insert(r.target.clone()) || !backups.insert(r.backup.clone()) {
            return Err(err("restore_journal_duplicate"));
        }
    }
    Ok(Some(value))
}
fn remove_if_present(dir:&Path,name:&str) -> Result<(),String> {
    let path=dir.join(name);
    match fs::symlink_metadata(&path) {
        Ok(m) => {
            if !m.is_file() || m.file_type().is_symlink() || m.uid()!=uid(){return Err(err("restore_cleanup_unsafe_file"));}
            fs::remove_file(path).map_err(|_|err("restore_cleanup_failed"))
        },
        Err(e) if e.kind()==std::io::ErrorKind::NotFound => Ok(()),
        Err(_)=>Err(err("restore_cleanup_stat_failed")),
    }
}
/// Idempotent transaction recovery. Prepared => roll BACK every entry;
/// committed => finish cleanup without rolling back new vaults.
/// If recovery is uncertain, it returns an error and preserves the journal.
pub fn recover(dir: &Path) -> Result<bool, String> {
    dir_check(dir)?;
    let Some(j)=load_journal(dir)? else {return Ok(false)};
    if j.phase=="prepared" {
        // Preflight ALL backups before touching any live target.
        for r in &j.records {
            if r.old_exists {let _=regular(dir,&r.backup,128)?;}
        }
        for r in j.records.iter().rev() {
            if r.old_exists {
                // Preserve the original backup link until EVERY target has been
                // restored and the directory is synced. Re-running recovery after
                // an interruption is therefore safe.
                let recovery=dir.join(format!(".neebles-restore-recovery-{}.kdbx",nonce()?));
                fs::hard_link(dir.join(&r.backup),&recovery)
                    .map_err(|_|err("restore_recovery_link_failed"))?;
                if let Err(_) = fs::rename(&recovery,dir.join(&r.target)) {
                    let _=fs::remove_file(&recovery);
                    return Err(err("restore_recovery_replace_failed"));
                }
            } else {remove_if_present(dir,&r.target)?;}
        }
        fsync_dir(dir)?;
        // Journal rollback completion BEFORE deleting the backups, otherwise
        // a power loss mid-cleanup would leave an unrecoverable prepared journal.
        let finished=Journal{schema:1,phase:"rolled_back".into(),records:j.records.clone()};
        write_journal(dir,&finished,true)?;
    }
    // In committed/rolled_back phases backups may already be partially cleaned.
    for r in &j.records {
        remove_if_present(dir,&r.backup)?;
        remove_if_present(dir,&r.staged)?;
    }
    fsync_dir(dir)?;
    fs::remove_file(dir.join(JOURNAL)).map_err(|_|err("restore_journal_remove_failed"))?;
    fsync_dir(dir)?;
    Ok(true)
}
/// The supplied verifier MUST open every staged KDBX using the current Master Key.
/// Intentionally not exposed to IPC/UI until full KDBX integration QA is complete.
pub fn apply_checked<F>(dir: &Path, inputs: &[Incoming], verify: F) -> Result<(),String>
where F: FnMut(&Path)->Result<(), String> {
    run_checked(dir,inputs,verify,None)
}
fn run_checked<F>(dir: &Path, inputs: &[Incoming], mut verify:F, fail_after:Option<usize>)->Result<(),String>
where F: FnMut(&Path)->Result<(),String> {
    dir_check(dir)?;
    if load_journal(dir)?.is_some() {return Err(err("restore_recovery_required"));}
    if inputs.is_empty() || inputs.len()>64 {return Err(err("restore_invalid_selection"));}
    let key=nonce()?;
    let mut records=Vec::new();
    let mut names=std::collections::BTreeSet::new();
    for (i,x) in inputs.iter().enumerate() {
        if !crate::restore_sessions::valid_target(&x.target) || !names.insert(&x.target) {
            return Err(err("restore_duplicate_or_invalid_target"));
        }
        if x.staged_file.parent()!=Some(dir) {return Err(err("restore_stage_wrong_directory"));}
        let stage=x.staged_file.file_name().and_then(|s|s.to_str())
            .ok_or_else(||err("restore_invalid_stage_name"))?.to_string();
        let backup=format!(".neebles-restore-backup-{key}-{i}.kdbx");
        let existing=dir.join(&x.target);
        let old_exists=match fs::symlink_metadata(&existing){
            Ok(_)=>{let _=regular(dir,&x.target,128)?;true},
            Err(e) if e.kind()==std::io::ErrorKind::NotFound => false,
            Err(_)=>return Err(err("restore_target_unavailable")),
        };
        let mut f=regular(dir,&stage,128)?;
        let mut magic=[0u8;4];
        f.read_exact(&mut magic).map_err(|_|err("restore_stage_read_failed"))?;
        if magic!=[0x03,0xd9,0xa2,0x9a] {return Err(err("restore_not_kdbx"));}
        verify(&x.staged_file)?;
        f.sync_all().map_err(|_|err("restore_stage_sync_failed"))?;
        let r=Record{target:x.target.clone(),backup,staged:stage,old_exists};
        validate_record(&r)?;
        records.push(r);
    }
    // All checks precede the FIRST mutation of the live targets.
    let j=Journal{schema:1,phase:"prepared".into(),records};
    let mut created=Vec::new();
    for r in &j.records {
        if r.old_exists {
            if let Err(_)=fs::hard_link(dir.join(&r.target),dir.join(&r.backup)) {
                for b in &created {let _=fs::remove_file(dir.join(b));}
                return Err(err("restore_backup_link_failed"));
            }
            created.push(r.backup.clone());
        }
    }
    if let Err(e)=fsync_dir(dir).and_then(|_|write_journal(dir,&j,false)) {
        // Targets not yet changed. Do not discard backups if journal exists.
        if load_journal(dir)?.is_none() {
            for b in &created {let _=fs::remove_file(dir.join(b));}
            let _=fsync_dir(dir);
        }
        return Err(e);
    }
    let outcome=(||{
        for (i,r) in j.records.iter().enumerate() {
            if fail_after==Some(i) {return Err(err("restore_injected_failure"));}
            fs::rename(dir.join(&r.staged),dir.join(&r.target))
                .map_err(|_|err("restore_replace_failed"))?;
        }
        fsync_dir(dir)?;
        let complete=Journal{schema:1,phase:"committed".into(),records:j.records.clone()};
        write_journal(dir,&complete,true)?;
        Ok(())
    })();
    if outcome.is_err() {
        // A committed journal could have been created before a late fsync error.
        // Consult the journal instead of assuming rollback is safe.
        let _=recover(dir);
        return outcome;
    }
    recover(dir)?;
    Ok(())
}
#[cfg(test)] mod tests {
    use super::*;
    fn fixture(dir:&Path,name:&str, marker:u8){
        let mut bytes=vec![0u8;160];bytes[..4].copy_from_slice(&[3,217,162,154]);bytes[5]=marker;
        fs::write(dir.join(name),bytes).unwrap();
        fs::set_permissions(dir.join(name),fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn tmp()->PathBuf{
        let name=format!("neebles-f11d-{}-{}",std::process::id(),nonce().unwrap());
        let dir=std::env::temp_dir().join(name);fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir,fs::Permissions::from_mode(0o700)).unwrap();dir
    }
    fn check(_:&Path)->Result<(),String>{Ok(())} // Disposable TEST files only, not real KDBX
    #[test] fn two_vaults_replace_and_cleanup(){
        let dir=tmp();fixture(&dir,"vault-general.kdbx",1);fixture(&dir,"vault-neebles-connect.kdbx",2);
        fixture(&dir,".neebles-restore-a.pending.kdbx",7);
        fixture(&dir,".neebles-restore-b.pending.kdbx",8);
        let selected=[Incoming{target:"vault-general.kdbx".into(),staged_file:dir.join(".neebles-restore-a.pending.kdbx")},
            Incoming{target:"vault-neebles-connect.kdbx".into(),staged_file:dir.join(".neebles-restore-b.pending.kdbx")}];
        apply_checked(&dir,&selected,check).unwrap();
        assert_eq!(fs::read(dir.join("vault-general.kdbx")).unwrap()[5],7);
        assert_eq!(fs::read(dir.join("vault-neebles-connect.kdbx")).unwrap()[5],8);
        assert!(!dir.join(JOURNAL).exists());
        assert_eq!(fs::read_dir(&dir).unwrap().count(),2);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test] fn interrupted_multi_vault_rolls_back(){
        let dir=tmp();fixture(&dir,"vault-general.kdbx",1);fixture(&dir,"vault-neebles-connect.kdbx",2);
        fixture(&dir,".neebles-restore-c.pending.kdbx",7);fixture(&dir,".neebles-restore-d.pending.kdbx",8);
        let selected=[Incoming{target:"vault-general.kdbx".into(),staged_file:dir.join(".neebles-restore-c.pending.kdbx")},
            Incoming{target:"vault-neebles-connect.kdbx".into(),staged_file:dir.join(".neebles-restore-d.pending.kdbx")}];
        assert!(run_checked(&dir,&selected,check,Some(1)).is_err());
        assert_eq!(fs::read(dir.join("vault-general.kdbx")).unwrap()[5],1);
        assert_eq!(fs::read(dir.join("vault-neebles-connect.kdbx")).unwrap()[5],2);
        assert!(!dir.join(JOURNAL).exists());
        fs::remove_dir_all(dir).unwrap();
    }
    // Simulate a power loss AFTER installing the first new vault but BEFORE
    // recording transaction completion. Old ciphertext must be restored.
    #[test] fn recovery_after_restart_restores_original_ciphertext(){
        let dir=tmp();
        fixture(&dir,"vault-general.kdbx",11);
        fixture(&dir,".neebles-restore-crash.pending.kdbx",77);
        let record=Record{
            target:"vault-general.kdbx".into(),
            backup:".neebles-restore-backup-test-0.kdbx".into(),
            staged:".neebles-restore-crash.pending.kdbx".into(),
            old_exists:true,
        };
        fs::hard_link(dir.join(&record.target),dir.join(&record.backup)).unwrap();
        let journal=Journal{schema:1,phase:"prepared".into(),records:vec![record.clone()]};
        write_journal(&dir,&journal,false).unwrap();
        fs::rename(dir.join(&record.staged),dir.join(&record.target)).unwrap();
        assert_eq!(fs::read(dir.join(&record.target)).unwrap()[5],77);
        assert_eq!(recover(&dir).unwrap(),true);
        assert_eq!(fs::read(dir.join(&record.target)).unwrap()[5],11);
        assert_eq!(recover(&dir).unwrap(),false);
        assert_eq!(fs::read_dir(&dir).unwrap().count(),1);
        fs::remove_dir_all(dir).unwrap();
    }
    // A corrupt journal is NOT interpreted as permission to overwrite or
    // remove a vault. Leave evidence in place and fail closed.
    #[test] fn invalid_recovery_journal_preserves_live_vault(){
        let dir=tmp();
        fixture(&dir,"vault-general.kdbx",42);
        let path=dir.join(JOURNAL);
        fs::write(&path,b"{not valid json").unwrap();
        fs::set_permissions(&path,fs::Permissions::from_mode(0o600)).unwrap();
        assert!(recover(&dir).is_err());
        assert_eq!(fs::read(dir.join("vault-general.kdbx")).unwrap()[5],42);
        assert!(path.exists());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test] fn excludes_symlinks_and_unverified_staging(){
        let dir=tmp();fixture(&dir,"vault-general.kdbx",1);fixture(&dir,".neebles-restore-e.pending.kdbx",9);
        let selected=[Incoming{target:"vault-general.kdbx".into(),staged_file:dir.join(".neebles-restore-e.pending.kdbx")}];
        assert!(apply_checked(&dir,&selected,|_|Err("reject_key".into())).is_err());
        assert_eq!(fs::read(dir.join("vault-general.kdbx")).unwrap()[5],1);
        fs::remove_dir_all(dir).unwrap();
    }
}
