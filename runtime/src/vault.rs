//! F14: vault-general is exclusively user-owned. A module requests its own vault.
//! No implicit module-vault creation, no master password in module requests.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{compiler_fence, Ordering};
use std::thread;
use std::time::{Duration, Instant};

struct Master(Vec<u8>);
impl Master {
    fn as_bytes(&self)->&[u8] { &self.0 }
}
impl Drop for Master {
    fn drop(&mut self) {
        for byte in &mut self.0 { unsafe { std::ptr::write_volatile(byte,0); } }
        compiler_fence(Ordering::SeqCst);
    }
}

pub struct VaultController {
    directory: PathBuf,
    unlocked: Option<Master>,
    pending: BTreeSet<String>,
    backups: crate::backup_sessions::BackupSessions,
    restores: crate::restore_sessions::RestoreSessions,
    portable: crate::portable_exports::PortableExports,
}

fn current_uid() -> u32 { unsafe extern "C" { fn geteuid() -> u32; } unsafe { geteuid() } }
fn valid_module(module: &str) -> bool {
    module.len() <= 64 && module.len() >= 2 && module != "general" &&
    module.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') &&
    module.as_bytes()[0].is_ascii_lowercase() &&
    !module.ends_with('-') && !module.contains("--")
}
fn validate_private_dir(directory:&Path) -> Result<(),String> {
    let md=fs::symlink_metadata(directory).map_err(|e|format!("vault directory: {e}"))?;
    if !md.is_dir() || md.file_type().is_symlink() || md.uid()!=current_uid()
       || md.permissions().mode() & 0o077 != 0 {
        return Err("vault directory must be a real directory owned by user, mode 0700".into());
    }
    Ok(())
}
fn validate_vault(file: &Path) -> Result<bool,String> {
    let md=match fs::symlink_metadata(file) {
        Ok(md)=>md,
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(false),
        Err(_)=>return Err("cannot inspect vault".into()),
    };
    if !md.is_file() || md.file_type().is_symlink() || md.uid()!=current_uid()
       || md.permissions().mode() & 0o077 != 0 || md.len()<128 {
        return Err("insecure vault file permissions/type/size".into());
    }
    let mut header=[0u8;4];
    File::open(file).and_then(|mut f| f.read_exact(&mut header))
        .map_err(|_| "vault header not readable".to_string())?;
    if header!=[0x03,0xd9,0xa2,0x9a] {return Err("not a KDBX file".into());}
    Ok(true)
}
fn run_keepass(args: &[&OsStr],password:&[u8],repeat:bool) -> Result<(),String> {
    // No password in argv, environment, stdout, stderr, or log.
    let mut child=Command::new("/usr/bin/keepassxc-cli")
        .args(args).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().map_err(|_|"keepassxc-cli is unavailable in the selected world".to_string())?;
    let written=(|| ->Result<(),String>{
        let pipe=child.stdin.as_mut().ok_or("KeePass input pipe unavailable")?;
        pipe.write_all(password).map_err(|_|"KeePass password input failed")?;
        pipe.write_all(b"\n").map_err(|_|"KeePass password input failed")?;
        if repeat {
            pipe.write_all(password).map_err(|_|"KeePass confirmation input failed")?;
            pipe.write_all(b"\n").map_err(|_|"KeePass confirmation input failed")?;
        }
        Ok(())
    })();
    drop(child.stdin.take());
    if written.is_err() { let _=child.kill(); let _=child.wait(); return written; }
    let deadline=Instant::now()+Duration::from_secs(40);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return if status.success(){Ok(())}else{Err("KeePass rejected the password or operation".into())},
            Ok(None) if Instant::now()<deadline => thread::sleep(Duration::from_millis(25)),
            _ => {let _=child.kill(); let _=child.wait(); return Err("KeePass operation timed out or failed".into());}
        }
    }
}
fn db_create(path:&Path,password:&[u8]) -> Result<(),String> {
    let options:[&OsStr;3]=[OsStr::new("db-create"),OsStr::new("-p"),path.as_os_str()];
    run_keepass(&options,password,true)
}
fn db_verify(path:&Path,password:&[u8]) -> Result<(),String> {
    let options:[&OsStr;3]=[OsStr::new("db-info"),OsStr::new("-q"),path.as_os_str()];
    run_keepass(&options,password,false)
}
fn fresh_temp_file(dir:&Path, module:&str) -> Result<PathBuf,String> {
    let mut nonce=[0u8;16];
    File::open("/dev/urandom").and_then(|mut f|f.read_exact(&mut nonce))
        .map_err(|_|"kernel CSPRNG unavailable".to_string())?;
    let suffix=nonce.iter().map(|c|format!("{c:02x}")).collect::<String>();
    Ok(dir.join(format!(".vault-{module}-{suffix}.pending.kdbx")))
}
// F26-Q: the newly linked ciphertext must be durable *before* the request
// journal can transition to succeeded. Never replace an existing KDBX.
// This helper handles only filesystem publication: cryptographic verification
// is done by create_once() before calling it, and by ensure() on EEXIST.
fn publish_prepared_vault(dir:&Path,temp:&Path,target:&Path)->Result<bool,String>{
    use std::os::unix::fs::OpenOptionsExt;
    let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(temp)
        .map_err(|_|"vault_publish_source_unavailable")?;
    let source=file.metadata().map_err(|_|"vault_publish_source_inspect_failed")?;
    if !source.is_file() || source.uid()!=current_uid() || source.nlink()!=1
        || source.permissions().mode() & 0o777 != 0o600 {
        return Err("vault_publish_source_insecure".into());
    }
    // The KeePassXC output AND its mode are persisted before publishing its name.
    file.sync_all().map_err(|_|"vault_publish_file_sync_failed")?;
    match fs::hard_link(temp,target) {
        Ok(())=>{
            let published=fs::symlink_metadata(target)
                .map_err(|_|"vault_publish_identity_unavailable")?;
            if published.dev()!=source.dev() || published.ino()!=source.ino()
                || !published.is_file() || published.file_type().is_symlink() {
                return Err("vault_publish_identity_changed".into());
            }
            // Power-loss ordering: do not report successful publication to the
            // journal until the directory containing vault-{module}.kdbx is synced.
            File::open(dir).and_then(|f|f.sync_all())
                .map_err(|_|"vault_publish_directory_sync_failed")?;
            Ok(true)
        },
        Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists=>Ok(false),
        Err(_)=>Err("cannot publish new vault without replacement".into()),
    }
}
// F26-R: inventory interrupted KeePassXC creation files without guessing what
// they contain. Never remove or promote encrypted data without authenticated
// recovery; that is a separate operation requiring the correct Master Key.
fn inspect_orphaned_vault_temporaries(dir:&Path)->Result<BTreeSet<String>,String>{
    validate_private_dir(dir)?;
    let mut pending=BTreeSet::new();
    let mut count=0usize;
    for entry in fs::read_dir(dir).map_err(|_|"vault_recovery_scan_failed")? {
        let entry=entry.map_err(|_|"vault_recovery_scan_failed")?;
        let name=entry.file_name().into_string().map_err(|_|"vault_recovery_invalid_filename")?;
        if !name.starts_with(".vault-") || !name.ends_with(".pending.kdbx") {continue;}
        count+=1;
        if count>64 {return Err("vault_recovery_too_many_temporaries".into());}
        let body=name.strip_prefix(".vault-").and_then(|v|v.strip_suffix(".pending.kdbx"))
            .ok_or("vault_recovery_invalid_filename")?;
        let (module, nonce)=body.rsplit_once('-').ok_or("vault_recovery_invalid_filename")?;
        if !(module=="general" || valid_module(module)) || nonce.len()!=32
            || !nonce.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err("vault_recovery_invalid_filename".into());
        }
        let path=entry.path();
        let meta=fs::symlink_metadata(&path).map_err(|_|"vault_recovery_inspect_failed")?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.uid()!=current_uid()
            || meta.permissions().mode() & 0o777!=0o600 || !(1..=2).contains(&meta.nlink()) {
            return Err("vault_recovery_insecure_temporary".into());
        }
        // After a successful hard_link but before unlink, a valid temporary
        // has two names referring to the SAME inode. Never trust another link.
        if meta.nlink()==2 {
            let target=dir.join(format!("vault-{module}.kdbx"));
            let linked=fs::symlink_metadata(&target)
                .map_err(|_|"vault_recovery_unrecognized_hardlink")?;
            if !linked.is_file() || linked.file_type().is_symlink()
                || linked.dev()!=meta.dev() || linked.ino()!=meta.ino() {
                return Err("vault_recovery_unrecognized_hardlink".into());
            }
        }
        pending.insert(module.to_owned());
    }
    Ok(pending)
}
// F26-S: authenticated, journal-scoped reconciliation of an interrupted vault
// creation. No orphan is touched without the currently unlocked Master Key.
// The verification callback is private: production passes KeePassXC db-info,
// tests use fake bytes and deliberately do NOT exercise real cryptography.
fn reconcile_orphaned_module_with<F>(dir:&Path,module:&str,verify:F)->Result<bool,String>
where F:FnOnce(&Path)->Result<(),String>{
    if !valid_module(module) {return Err("invalid_module_id".into());}
    let pending=inspect_orphaned_vault_temporaries(dir)?;
    if !pending.contains(module){return Ok(false);}
    // No request journal intent, no automatic promotion or deletion. The
    // personal vault is intentionally outside the module recovery operation.
    let journal=crate::vault_request_journal::Journal::open(dir)?;
    if !journal.pending_modules()?.contains(module){
        return Err("vault_recovery_intent_missing".into());
    }
    let prefix=format!(".vault-{module}-");
    let mut candidates=Vec::new();
    for item in fs::read_dir(dir).map_err(|_|"vault_recovery_scan_failed")? {
        let item=item.map_err(|_|"vault_recovery_scan_failed")?;
        let name=item.file_name().into_string().map_err(|_|"vault_recovery_invalid_filename")?;
        if name.starts_with(&prefix) && name.ends_with(".pending.kdbx") {
            candidates.push(item.path());
        }
    }
    if candidates.len()!=1 {return Err("vault_recovery_ambiguous_candidates".into());}
    let temp=&candidates[0];
    let target=dir.join(format!("vault-{module}.kdbx"));
    // The first inventory verified the linked inode/ownership/modes. Re-check
    // before and after decryption to detect a candidate swap.
    let before=fs::symlink_metadata(temp).map_err(|_|"vault_recovery_source_missing")?;
    if !before.is_file() || before.file_type().is_symlink()
        || before.uid()!=current_uid() || before.permissions().mode() & 0o777!=0o600 {
        return Err("vault_recovery_source_changed".into());
    }
    if !validate_vault(temp)? {return Err("vault_recovery_not_kdbx".into());}
    // Production verifier is db_verify with the Master's bytes. A bad key or
    // malformed ciphertext stops here, preserving both files and journal.
    verify(temp)?;
    let after=fs::symlink_metadata(temp).map_err(|_|"vault_recovery_source_missing")?;
    if before.dev()!=after.dev() || before.ino()!=after.ino()
        || before.len()!=after.len() || before.nlink()!=after.nlink()
        || after.uid()!=current_uid() || after.permissions().mode() & 0o777!=0o600 {
        return Err("vault_recovery_source_changed".into());
    }
    match fs::symlink_metadata(&target) {
        Ok(meta)=>{
            // The only acceptable existing target is F26-Q's own hardlink,
            // made after cryptographic verification and before temp unlink.
            if before.nlink()!=2 || meta.dev()!=before.dev() || meta.ino()!=before.ino()
                || !meta.is_file() || meta.file_type().is_symlink() {
                return Err("vault_recovery_target_ambiguous".into());
            }
            if !validate_vault(&target)? {return Err("vault_recovery_target_invalid".into());}
            File::open(dir).and_then(|f|f.sync_all())
                .map_err(|_|"vault_recovery_directory_sync_failed")?;
        },
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{
            if before.nlink()!=1 {return Err("vault_recovery_links_ambiguous".into());}
            if !publish_prepared_vault(dir,temp,&target)? {
                return Err("vault_recovery_concurrent_target".into());
            }
        },
        Err(_)=>return Err("vault_recovery_target_inspect_failed".into()),
    }
    // Publication is durable before unlinking the matching encrypted temp.
    // An interrupted unlink is idempotently recoverable using the same inode.
    fs::remove_file(temp).map_err(|_|"vault_recovery_cleanup_failed")?;
    File::open(dir).and_then(|f|f.sync_all())
        .map_err(|_|"vault_recovery_cleanup_sync_failed")?;
    // Journal is completed only by fulfill_pending after ensure() has re-verified
    // the target and the request. Recovery itself cannot forge succeeded.
    Ok(true)
}
fn create_once(dir:&Path,module:&str,password:&[u8]) -> Result<bool,String> {
    let target=dir.join(format!("vault-{module}.kdbx"));
    if validate_vault(&target)? {return Ok(false);}
    // A crash may leave a valid encrypted temporary. Do not produce another
    // candidate until a later authenticated recovery has reconciled it.
    if inspect_orphaned_vault_temporaries(dir)?.contains(module){
        return Err("vault_recovery_required".into());
    }
    let temp=fresh_temp_file(dir,module)?;
    // create_new is a reservation against accidental collision; CLI creates its own file.
    let sentinel=OpenOptions::new().write(true).create_new(true).open(&temp)
        .map_err(|_|"cannot reserve vault temporary filename".to_string())?;
    drop(sentinel);
    fs::remove_file(&temp).map_err(|_|"cannot release vault temporary filename".to_string())?;
    let result=(||{
        db_create(&temp,password)?;
        fs::set_permissions(&temp,fs::Permissions::from_mode(0o600))
            .map_err(|_|"cannot protect new vault permissions".to_string())?;
        if !validate_vault(&temp)? { return Err("KeePass did not create a valid KDBX".to_string()); }
        db_verify(&temp,password)?;
        // Atomic create-if-absent and durable publication before journal success.
        match publish_prepared_vault(dir,&temp,&target)? {
            true=>Ok(true),
            false=>{
                if validate_vault(&target)? { Ok(false) } else { Err("existing vault is invalid".into()) }
            },
        }
    })();
    // The temporary name must also be durably removed to avoid stale encrypted
    // files after a successful operation. A cleanup failure cannot report success.
    let cleaned=fs::remove_file(&temp);
    if result.is_ok() {
        cleaned.map_err(|_|"vault_temporary_cleanup_failed")?;
        File::open(dir).and_then(|f|f.sync_all())
            .map_err(|_|"vault_temporary_cleanup_sync_failed")?;
    }
    result
}
// Contract destined for the authenticated Boss module IPC. Values are opaque strings.
// An uninitialized vault must never be reported as unlocked.
fn public_boss_variables(initialized: bool, locked: bool) -> Value {
    json!({
        "master_key": if initialized { "true" } else { "false" },
        "unblock": if initialized && !locked { "true" } else { "false" },
    })
}

impl VaultController {
    pub fn new()->Result<Self,String>{
        let home=std::env::var_os("HOME").ok_or("HOME is required")?;
        let base=match std::env::var_os("XDG_DATA_HOME") {
            Some(p) if !p.is_empty()=>PathBuf::from(p),
            _=>PathBuf::from(home).join(".local/share"),
        };
        if !base.is_absolute() {return Err("XDG data path must be absolute".into());}
        let folder=base.join("neebles-secrets/vaults");
        if !folder.exists(){
            fs::create_dir_all(&folder).map_err(|_|"could not create private vault directory".to_string())?;
            fs::set_permissions(&folder,fs::Permissions::from_mode(0o700))
                .map_err(|_|"could not protect vault directory".to_string())?;
        }
        validate_private_dir(&folder)?;
        // Recover an interrupted prepared transaction BEFORE accepting IPC or unlock.
        // This reads only encrypted files and the recovery journal; it never needs
        // the Master Key. Fail closed when rollback cannot be proven complete.
        crate::restore_transaction::recover(&folder)?;
        // Inspection only: never delete or promote orphan ciphertext at startup.
        inspect_orphaned_vault_temporaries(&folder)?;
        // Recover authenticated request intents without needing the Master Key.
        // Completed requests are not recreated after an ambiguous timeout.
        let pending=crate::vault_request_journal::Journal::open(&folder)?.pending_modules()?;
        Ok(Self {directory:folder,unlocked:None,pending,backups:Default::default(),restores:Default::default(),portable:Default::default()})
    }
    fn general(&self)->PathBuf{self.directory.join("vault-general.kdbx")}
    pub fn initialized(&self)->Result<bool,String>{validate_vault(&self.general())}
    pub fn status(&self)->Result<Value,String>{
        let initialized=self.initialized()?;
        let recovery_required=!inspect_orphaned_vault_temporaries(&self.directory)?.is_empty();
        // A daemon/socket can outlive module Uninstall. Requiring the canonical
        // installed manifest prevents orphan F17-style processes from passing
        // consumers' installation prerequisites.
        let manifest=std::path::Path::new("/opt/neebles/modules/neebles-secrets/manifest.json");
        let installed=match fs::symlink_metadata(manifest) {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
                fs::read(manifest).ok()
                    .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    .is_some_and(|item| {
                        item.get("schema").and_then(Value::as_u64)==Some(4)
                        && item.get("name").and_then(Value::as_str)==Some("neebles-secrets")
                        && item.get("version").and_then(Value::as_str)==Some(env!("CARGO_PKG_VERSION"))
                        && matches!(item.get("entrypoint").and_then(Value::as_str),
                            Some("runtime/neebles-secrets-ui" | "runtime/neebles-secrets"))
                    })
            },
            _ => false
        };
        Ok(json!({"locked":self.unlocked.is_none(),"initialized":initialized,"installed":installed,"vaults_ready":initialized&&self.unlocked.is_some(),"vault_recovery_required":recovery_required,"service":"neebles-secrets","protocol":1,
                  "boss_variables":public_boss_variables(initialized,self.unlocked.is_none())}))
    }
    pub fn setup(&mut self, password:&str)->Result<Value,String>{
        if self.initialized()? {return Err("already_initialized".into());}
        if !(8..=512).contains(&password.len()) || password.chars().any(|c| matches!(c, '\n' | '\r' | '\0')) {
            return Err("master_password_policy".into());
        }
        create_once(&self.directory,"general",password.as_bytes())?;
        self.unlocked=Some(Master(password.as_bytes().to_vec()));
        // F26-V: a failed pending-vault reconciliation must not leave an
        // unlocked controller after its caller was told setup failed.
        let provisioned=match self.fulfill_pending(){
            Ok(items)=>items,
            Err(error)=>{self.unlocked=None;return Err(error);}
        };
        Ok(json!({"initialized":true,"unlocked":true,"vault":"general","provisioned":provisioned}))
    }
    pub fn unlock(&mut self,password:&str)->Result<Value,String>{
        if !self.initialized()? {return Err("setup_required".into());}
        if password.len()>512 || password.is_empty() || password.chars().any(|c| matches!(c, '\n' | '\r' | '\0')) {
            return Err("invalid_password_input".into());
        }
        db_verify(&self.general(),password.as_bytes())?;
        self.unlocked=Some(Master(password.as_bytes().to_vec()));
        // F26-V: fail closed if cryptographic reconciliation, KDBX publication
        // or journal completion fails after the general KDBX was opened.
        let provisioned=match self.fulfill_pending(){
            Ok(items)=>items,
            Err(error)=>{self.unlocked=None;return Err(error);}
        };
        Ok(json!({"unlocked":true,"provisioned":provisioned}))
    }
    pub fn lock(&mut self)->Value{
        self.backups.clear();
        self.restores.clear();
        self.portable.clear();
        self.unlocked=None;
        json!({"locked":true})
    }
    // Pre-restore compatibility check: staging ONLY. No live vault is replaced.
    pub fn restore_start(&mut self,target:&str,size:u64,hash:&str)->Result<Value,String>{
        if self.unlocked.is_none(){return Err("vault_locked".into());}
        self.restores.start(&self.directory,target,size,hash)
    }
    pub fn restore_chunk(&mut self,token:&str,offset:u64,encoded:&str)->Result<Value,String>{
        if self.unlocked.is_none(){return Err("vault_locked".into());}
        self.restores.chunk(token,offset,encoded)
    }
    pub fn restore_validate(&mut self,token:&str)->Result<Value,String>{
        let master=self.unlocked.as_ref().ok_or("vault_locked")?;
        // The same master currently unlocked for Secrets must decrypt input.
        self.restores.validate(token,|path|db_verify(path,master.as_bytes()))
    }
    pub fn restore_queue(&mut self,token:&str)->Result<Value,String>{
        if self.unlocked.is_none(){return Err("vault_locked".into());}
        self.restores.queue(token)
    }
    pub fn restore_plan(&mut self)->Result<Value,String>{
        if self.unlocked.is_none(){return Err("vault_locked".into());}
        self.restores.plan()
    }
    pub fn restore_discard(&mut self)->Result<Value,String>{
        if self.unlocked.is_none(){return Err("vault_locked".into());}
        self.restores.clear();
        Ok(json!({"discarded":true}))
    }
    /// F11-E internal-only commit bridge, NOT wired to a live IPC operation.
    /// Each ciphertext is hashed again and opened with the active Master Key
    /// immediately before the transaction core receives it.
    pub fn restore_commit_prepared(&mut self)->Result<(),String>{
        let master=self.unlocked.as_ref().ok_or("vault_locked")?;
        let inputs=self.restores.prepared_inputs()?;
        let expected=self.restores.prepared_hashes()?;
        let result=crate::restore_transaction::apply_checked(&self.directory,&inputs,|path|{
            let expected_sha=expected.get(path).ok_or("restore_stage_not_in_plan")?;
            let mut file=File::open(path).map_err(|_|"restore_verify_file_unavailable")?;
            let mut h=Sha256::new();
            let mut buffer=[0u8;8192];
            loop {
                let n=file.read(&mut buffer).map_err(|_|"restore_verify_read_failed")?;
                if n==0{break;}
                h.update(&buffer[..n]);
            }
            let actual=h.finalize().iter().map(|b|format!("{b:02x}")).collect::<String>();
            if &actual!=expected_sha{return Err("restore_verify_hash_changed".into());}
            db_verify(path,master.as_bytes())
        });
        // On failure, restore_transaction has attempted recovery. A leftover
        // journal blocks the next daemon launch instead of risking silent mixing.
        self.restores.clear();
        if result.is_ok(){
            self.backups.clear();
            self.unlocked=None; // Require an explicit unlock and refreshed My clients.
        }
        result
    }
    pub fn restore_commit(&mut self,confirmation:&str)->Result<Value,String>{
        if self.unlocked.is_none(){return Err("vault_locked".into());}
        self.restores.consume_confirmation(confirmation)?;
        let total=self.restores.prepared_inputs()?.len();
        self.restore_commit_prepared()?;
        Ok(json!({"restored":total,"locked":true,"committed":true}))
    }
    pub fn restore_abort(&mut self,token:&str)->Result<Value,String>{
        self.restores.abort(token)
    }
    // Portable export is a NEW encrypted KDBX; it never reads, copies or
    // modifies any existing vault or uses the current Master Key.
    pub fn portable_begin(&mut self,key:&str)->Result<Value,String>{
        self.portable.begin(&self.directory,key)
    }
    pub fn portable_append(&mut self,token:&str,value:&str)->Result<Value,String>{
        self.portable.append(token,value)
    }
    pub fn portable_seal(&mut self,token:&str)->Result<Value,String>{
        self.portable.seal(token)
    }
    pub fn portable_read(&mut self,token:&str,offset:u64,count:usize)->Result<Value,String>{
        self.portable.read(token,offset,count)
    }
    pub fn portable_close(&mut self,token:&str)->Result<Value,String>{
        self.portable.close(token)
    }
    pub fn backup_catalog(&self)->Result<Value,String>{
        crate::backup_sessions::BackupSessions::catalog(&self.directory)
    }
    pub fn backup_open(&mut self,mode:&str,name:Option<&str>)->Result<Value,String>{
        self.backups.open(&self.directory,mode,name)
    }
    pub fn backup_read(&mut self,token:&str,index:usize,offset:u64,count:usize)->Result<Value,String>{
        self.backups.read(token,index,offset,count)
    }
    pub fn backup_close(&mut self,token:&str)->Result<Value,String>{
        self.backups.close(token)
    }
    pub fn exists(&self,module:&str)->Result<Value,String>{
        if !valid_module(module) {return Err("invalid_module_id".into());}
        let exists=validate_vault(&self.directory.join(format!("vault-{module}.kdbx")))?;
        Ok(json!({"module":module,"exists":exists,"locked":self.unlocked.is_none()}))
    }
    /// Boss future endpoint: durable request identity. Caller is authenticated by
    /// the outer provider + broker before invoking this worker method.
    /// It is intentionally NOT exported by the Boss commands contract yet.
    pub fn request_with_id(&mut self,module:&str,request_id:&str)->Result<Value,String>{
        if !valid_module(module){return Err("invalid_module_id".into());}
        let ledger=crate::vault_request_journal::Journal::open(&self.directory)?;
        let previous=ledger.status(module,request_id)?;
        if previous==Some(crate::vault_request_journal::State::Succeeded) {
            if !validate_vault(&self.directory.join(format!("vault-{module}.kdbx")))? {
                return Err("completed_vault_request_missing_vault".into());
            }
            // Never create again with an already-completed idempotency key.
            return Ok(json!({"module":module,"request_id":request_id,
                "exists":true,"pending":false,"replayed":true}));
        }
        if !self.pending.contains(module) && self.pending.len()>=32 {
            return Err("too_many_pending_vaults".into());
        }
        // Durable intent is committed before any KeePass operation.
        ledger.claim(module,request_id)?;
        self.pending.insert(module.to_string());
        if self.unlocked.is_some() {
            // An interrupted prior request may have left one encrypted temp.
            // Reconcile using the authenticated Master Key before ensure().
            if inspect_orphaned_vault_temporaries(&self.directory)?.contains(module) {
                let master=self.unlocked.as_ref().ok_or("vault_locked")?;
                reconcile_orphaned_module_with(&self.directory,module,
                    |path|db_verify(path,master.as_bytes()))?;
            }
            self.ensure(module)?;
            ledger.complete_module(module)?;
            self.pending.remove(module);
            return Ok(json!({"module":module,"request_id":request_id,
                "exists":true,"pending":false,"replayed":previous.is_some()}));
        }
        // When locked, even a valid KDBX header is not proof of decryption.
        let exists=validate_vault(&self.directory.join(format!("vault-{module}.kdbx")))?;
        Ok(json!({"module":module,"request_id":request_id,
            "exists":exists,"pending":true,"replayed":previous.is_some()}))
    }
    /// Read-only status of a durable request by the authenticated vault owner.
    /// An absent request is not an authorization to create one. If a completed
    /// request has lost its KDBX, never claim successful restoration.
    pub fn request_status_with_id(&self,module:&str,request_id:&str)->Result<Value,String>{
        if !valid_module(module){return Err("invalid_module_id".into());}
        let ledger=crate::vault_request_journal::Journal::open(&self.directory)?;
        let state=ledger.status(module,request_id)?;
        match state {
            None => Ok(json!({"module":module,"request_id":request_id,"state":"not_found"})),
            Some(crate::vault_request_journal::State::Pending) => Ok(json!({
                "module":module,"request_id":request_id,"state":"pending"})),
            Some(crate::vault_request_journal::State::Succeeded) => {
                if !validate_vault(&self.directory.join(format!("vault-{module}.kdbx")))? {
                    return Err("completed_vault_request_missing_vault".into());
                }
                Ok(json!({"module":module,"request_id":request_id,"state":"succeeded"}))
            }
        }
    }
    // A consumer requests a Vault, but only the Secrets service creates it.
    // A locked service keeps the request in memory until Qt unlocks it.
    // Requests do NOT create vaults during module installation or startup.
    pub fn request(&mut self,module:&str)->Result<Value,String>{
        if !valid_module(module) {return Err("invalid_module_id".into());}
        if validate_vault(&self.directory.join(format!("vault-{module}.kdbx")))? {
            self.pending.remove(module);
            return Ok(json!({"module":module,"exists":true,"pending":false}));
        }
        if self.pending.len() >= 32 && !self.pending.contains(module) {
            return Err("too_many_pending_vaults".into());
        }
        self.pending.insert(module.to_string());
        if self.unlocked.is_some() && self.initialized()? {
            self.ensure(module)?;
            crate::vault_request_journal::Journal::open(&self.directory)?.complete_module(module)?;
            self.pending.remove(module);
            return Ok(json!({"module":module,"exists":true,"pending":false}));
        }
        Ok(json!({"module":module,"exists":false,"pending":true}))
    }
    fn fulfill_pending(&mut self)->Result<Vec<String>,String>{
        let modules=self.pending.iter().cloned().collect::<Vec<_>>();
        let mut provisioned=Vec::new();
        for module in modules {
            // When an interrupted creation survives, authenticate and publish
            // its ciphertext instead of generating another KDBX for this ID.
            if inspect_orphaned_vault_temporaries(&self.directory)?.contains(&module) {
                let master=self.unlocked.as_ref().ok_or("vault_locked")?;
                reconcile_orphaned_module_with(&self.directory,&module,
                    |path|db_verify(path,master.as_bytes()))?;
            }
            self.ensure(&module)?;
            crate::vault_request_journal::Journal::open(&self.directory)?.complete_module(&module)?;
            self.pending.remove(&module);
            provisioned.push(module);
        }
        Ok(provisioned)
    }
    // vault-general belongs ONLY to the Secrets desktop. Do not route it
    // through valid_module(module); consumer modules must never address it.
    fn with_personal_vault<F>(&self,action:F)->Result<Value,String>
    where F:FnOnce(&Path,&[u8])->Result<Value,String>{
        let master=self.unlocked.as_ref().ok_or("vault_locked")?;
        if !self.initialized()? {return Err("setup_required".into());}
        let path=self.general();
        if !validate_vault(&path)? {return Err("personal_vault_missing".into());}
        action(&path,master.as_bytes())
    }
    pub fn general_list(&self)->Result<Value,String>{
        self.with_personal_vault(crate::vault_records::list)
    }
    pub fn general_get(&self,id:&str)->Result<Value,String>{
        self.with_personal_vault(|p,k|crate::vault_records::get(p,k,id))
    }
    pub fn general_put(&self,id:&str,value:&Value,update_only:bool)->Result<Value,String>{
        self.with_personal_vault(|p,k|crate::vault_records::put(p,k,id,value,update_only))
    }
    pub fn general_delete(&self,id:&str)->Result<Value,String>{
        self.with_personal_vault(|p,k|crate::vault_records::delete(p,k,id))
    }
    fn with_module_vault<F>(&self,module:&str,action:F)->Result<Value,String>
    where F:FnOnce(&Path,&[u8])->Result<Value,String>{
        if !valid_module(module){return Err("invalid_module_id".into());}
        let master=self.unlocked.as_ref().ok_or("vault_locked")?;
        if !self.initialized()?{return Err("setup_required".into());}
        let path=self.directory.join(format!("vault-{module}.kdbx"));
        if !validate_vault(&path)?{return Err("module_vault_missing".into());}
        action(&path,master.as_bytes())
    }
    pub fn secret_list(&self,module:&str)->Result<Value,String>{
        self.with_module_vault(module,crate::vault_records::list)
    }
    pub fn secret_get(&self,module:&str,id:&str)->Result<Value,String>{
        self.with_module_vault(module,|p,k|crate::vault_records::get(p,k,id))
    }
    pub fn secret_put(&self,module:&str,id:&str,value:&Value,update_only:bool)->Result<Value,String>{
        self.with_module_vault(module,|p,k|crate::vault_records::put(p,k,id,value,update_only))
    }
    pub fn secret_delete(&self,module:&str,id:&str)->Result<Value,String>{
        self.with_module_vault(module,|p,k|crate::vault_records::delete(p,k,id))
    }
    pub fn ensure(&mut self,module:&str)->Result<Value,String>{
        if !valid_module(module) {return Err("invalid_module_id".into());}
        let master=self.unlocked.as_ref().ok_or("vault_locked")?;
        if !self.initialized()? {return Err("setup_required".into());}
        let created=create_once(&self.directory,module,master.as_bytes())?;
        // Existing KDBX files must not merely have a correct header: verify
        // they are actually decryptable with the global master key.
        // Failure never erases or replaces the user's existing vault.
        if !created {
            let target=self.directory.join(format!("vault-{module}.kdbx"));
            db_verify(&target,master.as_bytes())?;
        }
        Ok(json!({"module":module,"created":created,"exists":true}))
    }
}

#[cfg(test)] mod tests {
    use super::*;
    // F26-V: These tests must run ONLY as individually selected, ignored
    // Rust tests inside the disposable keepass-full Bubblewrap world. They
    // exercise actual KeePassXC/KDBX, not the fake-byte recovery fixtures.
    // The Python harness mounts no host HOME, /opt, or Boss IPC socket.
    fn f26v_random_key()->String {
        let mut entropy=[0u8;32];
        File::open("/dev/urandom").unwrap().read_exact(&mut entropy).unwrap();
        entropy.iter().map(|x|format!("{x:02x}")).collect()
    }
    fn f26v_paths()->(PathBuf,PathBuf) {
        assert_eq!(std::env::var("NEEBLES_F26V_SANDBOX").unwrap(),"disposable-only");
        assert_eq!(std::env::var("XDG_DATA_HOME").unwrap(),"/qa-data");
        let world=PathBuf::from("/qa-data/neebles-secrets/vaults");
        // Refuse to run in an ordinary host test environment, even with
        // --ignored, unless the isolated scratch is mounted as expected.
        assert!(Path::new("/qa-data").is_dir());
        (PathBuf::from("/qa-data"),world)
    }
    #[test]
    #[ignore = "F26-V: requires disposable bwrap and genuine keepass-full"]
    fn f26v_real_controller_pending_restart_unlock_idempotency(){
        let (_scratch,dir)=f26v_paths();
        let password=f26v_random_key();
        let wrong=f26v_random_key();
        assert_ne!(password,wrong);
        let module="neebles-connect";
        let request_id="11111111111111111111111111111111";
        let target=dir.join("vault-neebles-connect.kdbx");
        let general=dir.join("vault-general.kdbx");
        let mut c=VaultController::new().unwrap();
        assert!(!c.initialized().unwrap());
        assert_eq!(c.request_with_id(module,request_id).unwrap()["pending"],true);
        assert_eq!(c.request_with_id(module,request_id).unwrap()["replayed"],true);
        assert!(!target.exists());
        drop(c);
        let mut c=VaultController::new().unwrap();
        assert_eq!(c.request_status_with_id(module,request_id).unwrap()["state"],"pending");
        c.setup(&password).unwrap();
        assert!(c.initialized().unwrap());
        assert!(validate_vault(&general).unwrap());
        assert!(validate_vault(&target).unwrap());
        assert_eq!(c.request_status_with_id(module,request_id).unwrap()["state"],"succeeded");
        db_verify(&general,password.as_bytes()).unwrap();
        db_verify(&target,password.as_bytes()).unwrap();
        assert!(db_verify(&target,wrong.as_bytes()).is_err());
        let ciphertext=fs::read(&target).unwrap();
        assert_eq!(c.request_with_id(module,request_id).unwrap()["replayed"],true);
        assert_eq!(fs::read(&target).unwrap(),ciphertext);
        c.lock();
        assert!(c.unlock(&wrong).is_err());
        assert!(c.unlocked.is_none());
        assert_eq!(fs::read(&target).unwrap(),ciphertext);
        c.unlock(&password).unwrap();
        assert_eq!(c.request_with_id(module,"22222222222222222222222222222222").unwrap()["pending"],false);
        assert_eq!(fs::read(&target).unwrap(),ciphertext);
        drop(c);
        let reloaded=VaultController::new().unwrap();
        assert_eq!(reloaded.request_status_with_id(module,request_id).unwrap()["state"],"succeeded");
        assert!(reloaded.unlocked.is_none());
    }
    #[test]
    #[ignore = "F26-V: requires disposable bwrap and genuine keepass-full"]
    fn f26v_real_controller_recovers_encrypted_orphan_after_restart(){
        let (_scratch,dir)=f26v_paths();
        let password=f26v_random_key();
        let module="neebles-db";
        let rid="33333333333333333333333333333333";
        let mut c=VaultController::new().unwrap();
        c.setup(&password).unwrap();
        c.lock();
        assert_eq!(c.request_with_id(module,rid).unwrap()["pending"],true);
        let temp=fresh_temp_file(&dir,module).unwrap();
        db_create(&temp,password.as_bytes()).unwrap();
        fs::set_permissions(&temp,fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_vault(&temp).unwrap());
        let ciphertext=fs::read(&temp).unwrap();
        drop(c);
        let mut c=VaultController::new().unwrap();
        assert_eq!(c.request_status_with_id(module,rid).unwrap()["state"],"pending");
        c.unlock(&password).unwrap();
        let published=dir.join("vault-neebles-db.kdbx");
        assert!(!temp.exists());
        assert_eq!(fs::read(&published).unwrap(),ciphertext);
        assert_eq!(c.request_status_with_id(module,rid).unwrap()["state"],"succeeded");
        assert_eq!(c.request_with_id(module,rid).unwrap()["replayed"],true);
        db_verify(&published,password.as_bytes()).unwrap();
    }
    #[test]
    #[ignore = "F26-V: requires disposable bwrap and genuine keepass-full"]
    fn f26v_real_wrong_orphan_key_preserved_and_controller_fail_closed(){
        let (_scratch,dir)=f26v_paths();
        let password=f26v_random_key();
        let other_password=f26v_random_key();
        assert_ne!(password,other_password);
        let module="neebles-db";
        let rid="44444444444444444444444444444444";
        let mut c=VaultController::new().unwrap();
        c.setup(&password).unwrap();
        c.lock();
        c.request_with_id(module,rid).unwrap();
        let temp=fresh_temp_file(&dir,module).unwrap();
        db_create(&temp,other_password.as_bytes()).unwrap();
        fs::set_permissions(&temp,fs::Permissions::from_mode(0o600)).unwrap();
        let ciphertext=fs::read(&temp).unwrap();
        drop(c);
        let mut c=VaultController::new().unwrap();
        assert!(c.unlock(&password).is_err());
        assert!(c.unlocked.is_none(),"failed reconcile must remain locked");
        assert_eq!(c.request_status_with_id(module,rid).unwrap()["state"],"pending");
        assert_eq!(fs::read(&temp).unwrap(),ciphertext);
        assert!(!dir.join("vault-neebles-db.kdbx").exists());
        assert!(db_verify(&temp,other_password.as_bytes()).is_ok());
    }
    // F26-Q tests are filesystem-only and use arbitrary bytes, NOT real KDBX.
    // They exercise atomic publication, never KeePassXC or a live vault.
    fn f26q_fixture()->PathBuf {
        let root=std::env::temp_dir().join(format!(".neebles-f26q-{}",crate::uuid_v4().unwrap()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
    fn f26q_temp(root:&Path,name:&str,body:&[u8])->PathBuf {
        use std::os::unix::fs::OpenOptionsExt;
        let path=root.join(name);
        let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(&path).unwrap();
        file.write_all(body).unwrap();
        path
    }
    #[test] fn f26q_publish_fsyncs_and_never_overwrites_a_prior_target(){
        let root=f26q_fixture();
        let first=f26q_temp(&root,"first.pending",b"fake-A-not-a-KDBX");
        let second=f26q_temp(&root,"second.pending",b"fake-B-not-a-KDBX");
        let target=root.join("vault-neebles-connect.kdbx");
        assert!(publish_prepared_vault(&root,&first,&target).unwrap());
        assert!(!publish_prepared_vault(&root,&second,&target).unwrap());
        assert_eq!(fs::read(&target).unwrap(),b"fake-A-not-a-KDBX");
        assert_eq!(fs::metadata(&first).unwrap().ino(),fs::metadata(&target).unwrap().ino());
        fs::remove_dir_all(root).unwrap();
    }
    #[test] fn f26q_concurrent_publishers_have_exactly_one_winner(){
        use std::sync::{Arc,Barrier};
        let root=f26q_fixture();
        let first=f26q_temp(&root,"first.pending",b"mock-one");
        let second=f26q_temp(&root,"second.pending",b"mock-two");
        let target=root.join("vault-neebles-connect.kdbx");
        let gate=Arc::new(Barrier::new(3));
        let mut jobs=Vec::new();
        for candidate in [first,second] {
            let root=root.clone(); let target=target.clone(); let gate=Arc::clone(&gate);
            jobs.push(thread::spawn(move || {
                gate.wait();
                publish_prepared_vault(&root,&candidate,&target).unwrap()
            }));
        }
        gate.wait();
        let winners=jobs.into_iter().map(|handle|handle.join().unwrap()).filter(|winner|*winner).count();
        assert_eq!(winners,1);
        let bytes=fs::read(&target).unwrap();
        assert!(bytes.as_slice()==b"mock-one" || bytes.as_slice()==b"mock-two");
        fs::remove_dir_all(root).unwrap();
    }
    #[test] fn f26q_refuses_to_publish_an_insecure_or_symlinked_source(){
        use std::os::unix::fs::symlink;
        let root=f26q_fixture();
        let target=root.join("vault-neebles-connect.kdbx");
        let insecure=f26q_temp(&root,"insecure.pending",b"mock");
        fs::set_permissions(&insecure,fs::Permissions::from_mode(0o644)).unwrap();
        assert!(publish_prepared_vault(&root,&insecure,&target).is_err());
        assert!(!target.exists());
        let link=root.join("linked.pending");
        symlink(&insecure,&link).unwrap();
        assert!(publish_prepared_vault(&root,&link,&target).is_err());
        assert!(!target.exists());
        fs::remove_dir_all(root).unwrap();
    }
    // All F26-R fixtures contain fake bytes and are never opened by KeePassXC.
    #[test] fn f26r_reports_orphans_without_reading_or_removing_them(){
        let root=f26q_fixture();
        let file=f26q_temp(&root,
            ".vault-neebles-connect-0123456789abcdef0123456789abcdef.pending.kdbx",b"fake encrypted bytes");
        let pending=inspect_orphaned_vault_temporaries(&root).unwrap();
        assert_eq!(pending,BTreeSet::from(["neebles-connect".to_owned()]));
        assert_eq!(fs::read(&file).unwrap(),b"fake encrypted bytes");
        // A second creation must fail before invoking keepassxc-cli.
        assert_eq!(create_once(&root,"neebles-connect",b"not-a-real-key").unwrap_err(),
                   "vault_recovery_required");
        assert_eq!(fs::read(&file).unwrap(),b"fake encrypted bytes");
        assert!(!root.join("vault-neebles-connect.kdbx").exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test] fn f26r_rejects_symlinks_wrong_modes_and_unknown_names(){
        use std::os::unix::fs::symlink;
        let root=f26q_fixture();
        let name=".vault-general-0123456789abcdef0123456789abcdef.pending.kdbx";
        let file=f26q_temp(&root,name,b"fake");
        fs::set_permissions(&file,fs::Permissions::from_mode(0o644)).unwrap();
        assert!(inspect_orphaned_vault_temporaries(&root).is_err());
        fs::set_permissions(&file,fs::Permissions::from_mode(0o600)).unwrap();
        assert!(inspect_orphaned_vault_temporaries(&root).unwrap().contains("general"));
        fs::remove_file(&file).unwrap();
        symlink("/does/not/exist",&file).unwrap();
        assert!(inspect_orphaned_vault_temporaries(&root).is_err());
        fs::remove_file(&file).unwrap();
        let bad=f26q_temp(&root,".vault-neebles-db-INVALID.pending.kdbx",b"fake");
        assert!(inspect_orphaned_vault_temporaries(&root).is_err());
        fs::remove_file(bad).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test] fn f26r_recognizes_only_own_published_hardlink(){
        let root=f26q_fixture();
        let name=".vault-neebles-db-fedcba9876543210fedcba9876543210.pending.kdbx";
        let file=f26q_temp(&root,name,b"fake pending bytes");
        let target=root.join("vault-neebles-db.kdbx");
        fs::hard_link(&file,&target).unwrap();
        assert!(inspect_orphaned_vault_temporaries(&root).unwrap().contains("neebles-db"));
        // The target must be the *same inode*. An unrelated second hard link
        // cannot make the temporary safe or eligible for deletion.
        fs::remove_file(&target).unwrap();
        fs::hard_link(&file,root.join("unrelated-link")).unwrap();
        assert!(inspect_orphaned_vault_temporaries(&root).is_err());
        assert_eq!(fs::read(&file).unwrap(),b"fake pending bytes");
        fs::remove_dir_all(root).unwrap();
    }
    fn f26s_fake_kdbx()->Vec<u8>{
        let mut raw=vec![0u8;160];
        raw[..4].copy_from_slice(&[0x03,0xd9,0xa2,0x9a]);
        raw
    }
    const F26S_ID:&str="0123456789abcdef0123456789abcdef";
    fn f26s_candidate(root:&Path,module:&str)->PathBuf {
        f26q_temp(root,&format!(".vault-{module}-{F26S_ID}.pending.kdbx"),&f26s_fake_kdbx())
    }
    fn f26s_intent(root:&Path,module:&str){
        crate::vault_request_journal::Journal::open(root).unwrap().claim(module,F26S_ID).unwrap();
    }
    #[test] fn f26s_reconciles_single_authenticated_pending_candidate(){
        let root=f26q_fixture();
        f26s_intent(&root,"neebles-connect");
        let temp=f26s_candidate(&root,"neebles-connect");
        let recovered=reconcile_orphaned_module_with(&root,"neebles-connect",|path|{
            assert_eq!(path,temp.as_path());
            assert_eq!(fs::read(path).unwrap(),f26s_fake_kdbx());
            Ok(())
        }).unwrap();
        assert!(recovered);
        let target=root.join("vault-neebles-connect.kdbx");
        assert!(!temp.exists());
        assert_eq!(fs::read(target).unwrap(),f26s_fake_kdbx());
        let journal=crate::vault_request_journal::Journal::open(&root).unwrap();
        assert_eq!(journal.status("neebles-connect",F26S_ID).unwrap(),
            Some(crate::vault_request_journal::State::Pending));
        journal.complete_module("neebles-connect").unwrap();
        assert_eq!(journal.status("neebles-connect",F26S_ID).unwrap(),
            Some(crate::vault_request_journal::State::Succeeded));
        fs::remove_dir_all(root).unwrap();
    }
    #[test] fn f26s_recovers_published_hardlink_after_interrupted_unlink(){
        let root=f26q_fixture();
        f26s_intent(&root,"neebles-db");
        let temp=f26s_candidate(&root,"neebles-db");
        let target=root.join("vault-neebles-db.kdbx");
        fs::hard_link(&temp,&target).unwrap();
        assert_eq!(fs::metadata(&temp).unwrap().ino(),fs::metadata(&target).unwrap().ino());
        assert!(reconcile_orphaned_module_with(&root,"neebles-db",|_|Ok(())).unwrap());
        assert!(!temp.exists());
        assert_eq!(fs::read(&target).unwrap(),f26s_fake_kdbx());
        fs::remove_dir_all(root).unwrap();
    }
    #[test] fn f26s_never_recovers_without_matching_pending_intent(){
        let root=f26q_fixture();
        let temp=f26s_candidate(&root,"neebles-connect");
        f26s_intent(&root,"neebles-db");
        assert_eq!(reconcile_orphaned_module_with(&root,"neebles-connect",|_|{
            panic!("must not verify orphan lacking its own durable request")
        }).unwrap_err(),"vault_recovery_intent_missing");
        assert!(temp.exists());
        assert!(!root.join("vault-neebles-connect.kdbx").exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test] fn f26s_bad_master_or_multiple_candidates_preserve_all_bytes(){
        let root=f26q_fixture();
        f26s_intent(&root,"neebles-connect");
        let temp=f26s_candidate(&root,"neebles-connect");
        assert_eq!(reconcile_orphaned_module_with(&root,"neebles-connect",|_|{
            Err("vault_recovery_master_key_rejected".to_owned())
        }).unwrap_err(),"vault_recovery_master_key_rejected");
        assert!(temp.exists());
        let other=f26q_temp(&root,
            ".vault-neebles-connect-fedcba9876543210fedcba9876543210.pending.kdbx",
            &f26s_fake_kdbx());
        assert_eq!(reconcile_orphaned_module_with(&root,"neebles-connect",|_|{
            panic!("two candidates must fail before verification")
        }).unwrap_err(),"vault_recovery_ambiguous_candidates");
        assert!(temp.exists() && other.exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test] fn f26s_unrelated_existing_target_blocks_recovery_without_unlink(){
        let root=f26q_fixture();
        f26s_intent(&root,"neebles-connect");
        let temp=f26s_candidate(&root,"neebles-connect");
        let target=f26q_temp(&root,"vault-neebles-connect.kdbx",&f26s_fake_kdbx());
        assert_eq!(reconcile_orphaned_module_with(&root,"neebles-connect",|_|Ok(())).unwrap_err(),
            "vault_recovery_target_ambiguous");
        assert!(temp.exists());
        assert_eq!(fs::read(target).unwrap(),f26s_fake_kdbx());
        fs::remove_dir_all(root).unwrap();
    }
    #[test] fn boss_states_are_strings_and_fail_closed() {
        let unconfigured = public_boss_variables(false, true);
        assert_eq!(unconfigured["master_key"], "false");
        assert_eq!(unconfigured["unblock"], "false");
        let inconsistent = public_boss_variables(false, false);
        assert_eq!(inconsistent["unblock"], "false");
        let locked = public_boss_variables(true, true);
        assert_eq!(locked["master_key"], "true");
        assert_eq!(locked["unblock"], "false");
        let unlocked = public_boss_variables(true, false);
        assert_eq!(unlocked["master_key"], "true");
        assert_eq!(unlocked["unblock"], "true");
        assert_eq!(unlocked.as_object().unwrap().len(), 2);
    }
    #[test] fn module_names_cannot_escape_namespace(){
        for name in ["../x","general","neebles/evil","neebles_connect", "","-evil","neebles-", "UPPER"]{assert!(!valid_module(name));}
        for name in ["neebles-connect","neebles-db","proxy"]{assert!(valid_module(name));}
    }
    #[test] fn durable_request_ids_wait_for_unlock_and_survive_process_restart(){
        let folder=std::env::temp_dir().join(format!(".neebles-f26l-vault-{}",crate::uuid_v4().unwrap()));
        std::fs::create_dir(&folder).unwrap();
        std::fs::set_permissions(&folder,std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut controller=VaultController { directory:folder.clone(),unlocked:None,
            pending:BTreeSet::new(),backups:Default::default(),restores:Default::default(),portable:Default::default() };
        let rid="deadbeefdeadbeefdeadbeefdeadbeef";
        let first=controller.request_with_id("neebles-connect",rid).unwrap();
        assert_eq!(first["exists"],false);
        assert_eq!(first["pending"],true);
        assert_eq!(first["replayed"],false);
        assert_eq!(controller.request_with_id("neebles-connect",rid).unwrap()["replayed"],true);
        let pending=crate::vault_request_journal::Journal::open(&folder).unwrap().pending_modules().unwrap();
        assert_eq!(pending,BTreeSet::from(["neebles-connect".to_owned()]));
        assert!(!folder.join("vault-neebles-connect.kdbx").exists());
        std::fs::remove_dir_all(folder).unwrap();
    }
    #[test] fn boss_worker_request_and_status_are_durable_without_unlock(){
        let root=std::env::temp_dir().join(format!(".neebles-f26n-{}",crate::uuid_v4().unwrap()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root,std::fs::Permissions::from_mode(0o700)).unwrap();
        let state=std::sync::Arc::new(std::sync::Mutex::new(VaultController {
            directory:root.clone(),unlocked:None,pending:BTreeSet::new(),
            backups:Default::default(),restores:Default::default(),portable:Default::default()
        }));
        let rid="deadbeefdeadbeefdeadbeefdeadbeef";
        let msg=json!({"op":"vault.request_id","module":"neebles-connect","request_id":rid});
        let first=crate::handle(&msg,Some("neebles-connect"),&state);
        assert_eq!(first["ok"],true);
        assert_eq!(first["data"]["pending"],true);
        assert_eq!(first["data"]["replayed"],false);
        let again=crate::handle(&msg,Some("neebles-connect"),&state);
        assert_eq!(again["data"]["replayed"],true);
        let status=json!({"op":"vault.request_status","module":"neebles-connect","request_id":rid});
        assert_eq!(crate::handle(&status,Some("neebles-connect"),&state)["data"]["state"],"pending");
        assert!(!root.join("vault-neebles-connect.kdbx").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test] fn boss_worker_rejects_cross_vault_forgery_and_untrusted_fields(){
        let root=std::env::temp_dir().join(format!(".neebles-f26n-{}",crate::uuid_v4().unwrap()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root,std::fs::Permissions::from_mode(0o700)).unwrap();
        let state=std::sync::Arc::new(std::sync::Mutex::new(VaultController {
            directory:root.clone(),unlocked:None,pending:BTreeSet::new(),
            backups:Default::default(),restores:Default::default(),portable:Default::default()
        }));
        let rid="deadbeefdeadbeefdeadbeefdeadbeef";
        for op in ["vault.request_id","vault.request_status"] {
            let msg=json!({"op":op,"module":"neebles-connect","request_id":rid});
            assert_eq!(crate::handle(&msg,Some("neebles-other"),&state)["ok"],false);
            assert_eq!(crate::handle(&msg,None,&state)["ok"],false);
            let mut extra=msg.clone(); extra["password"]=json!("MUST_NOT_LEAK");
            let refused=crate::handle(&extra,Some("neebles-connect"),&state);
            assert_eq!(refused["ok"],false);
            assert!(!refused.to_string().contains("MUST_NOT_LEAK"));
            let mut bad=msg; bad["request_id"]=json!("../wrong");
            assert_eq!(crate::handle(&bad,Some("neebles-connect"),&state)["ok"],false);
        }
        assert!(!root.join("vault-neebles-connect.kdbx").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test] fn worker_status_missing_request_never_creates_vault(){
        let root=std::env::temp_dir().join(format!(".neebles-f26n-{}",crate::uuid_v4().unwrap()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root,std::fs::Permissions::from_mode(0o700)).unwrap();
        let state=std::sync::Arc::new(std::sync::Mutex::new(VaultController {
            directory:root.clone(),unlocked:None,pending:BTreeSet::new(),
            backups:Default::default(),restores:Default::default(),portable:Default::default()
        }));
        let status=json!({"op":"vault.request_status","module":"neebles-connect",
            "request_id":"deadbeefdeadbeefdeadbeefdeadbeef"});
        let result=crate::handle(&status,Some("neebles-connect"),&state);
        assert_eq!(result["ok"],true);
        assert_eq!(result["data"]["state"],"not_found");
        assert!(!root.join("vault-neebles-connect.kdbx").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test] fn no_secret_is_implicitly_created(){
        assert!(!valid_module("general"));
    }
    #[test] fn request_is_pending_until_unlock_without_writing_files() {
        let directory=std::env::temp_dir().join(format!("neebles-f15-test-{}",std::process::id()));
        let mut controller=VaultController {
            directory:directory.clone(),unlocked:None,pending:BTreeSet::new(),backups:Default::default(),restores:Default::default(),portable:Default::default()
        };
        let first=controller.request("neebles-connect").unwrap();
        assert_eq!(first["exists"],false);
        assert_eq!(first["pending"],true);
        assert_eq!(controller.pending.len(),1);
        let repeated=controller.request("neebles-connect").unwrap();
        assert_eq!(repeated["pending"],true);
        assert_eq!(controller.pending.len(),1);
        assert!(!directory.join("vault-neebles-connect.kdbx").exists());
        assert!(controller.request("../escape").is_err());
    }
}


// F16 integration-style tests: exercise the framed UnixStream protocol,
// the real request dispatcher and namespace authorization end to end *within*
// one process. There is NO installed daemon, master-password prompt or KDBX IO.
// Broker executable provenance and installed 1.0.3 remain separate release QA.
#[cfg(test)]
mod f16_rpc_transport_qa {
    use super::*;
    use serde_json::{json, Value};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    fn fixture() -> (Arc<Mutex<VaultController>>, PathBuf) {
        // An uncreated, randomized path: tests never open a real Secrets vault.
        let directory=std::env::temp_dir().join(format!(
            ".neebles-secrets-f16-{}", crate::uuid_v4().expect("kernel CSPRNG")
        ));
        assert!(!directory.exists(), "F16 test path must not already exist");
        let controller=VaultController {
            directory:directory.clone(),
            unlocked:None,
            pending:BTreeSet::new(),
            backups:Default::default(),
            restores:Default::default(),
            portable:Default::default(),
        };
        (Arc::new(Mutex::new(controller)),directory)
    }

    fn rpc(
        state:&Arc<Mutex<VaultController>>,
        broker_peer:Option<&str>,
        request:Value,
    ) -> Value {
        let (mut client,worker)=UnixStream::pair().expect("disposable Unix socketpair");
        let state=Arc::clone(state);
        // The trusted peer string is passed out-of-band, NOT parsed from JSON.
        let peer=broker_peer.map(str::to_owned);
        let thread=std::thread::spawn(move || {
            crate::serve_authorized_one(worker,peer,state)
        });
        crate::rpc_write(&mut client,&request).expect("request framing");
        let response=crate::rpc_read(&mut client).expect("response framing");
        thread.join().expect("worker panic").expect("worker IO");
        response
    }

    fn denied(response:&Value,code:&str) {
        assert_eq!(response["ok"],false,"{response}");
        assert_eq!(response["error"],code,"{response}");
    }

    // F18: unlike F16's direct serve_authorized_one fixture, traverse the
    // exact SCM_RIGHTS handoff that the installed host broker uses.
    // All state is in memory; the fake master is never stored as a KDBX.
    fn f18_rpc_through_fd(
        state:&Arc<Mutex<VaultController>>,
        trusted_peer:Option<&str>,
        request:Value,
    ) -> Value {
        let (broker, isolated)=std::os::unix::net::UnixDatagram::pair().unwrap();
        let (mut caller, broker_end)=UnixStream::pair().unwrap();
        crate::ipc_bridge::send_connection(&broker,&broker_end,trusted_peer)
            .expect("forwarding a verified broker identity must work");
        drop(broker_end);
        let (worker, authenticated)=crate::ipc_bridge::recv_connection(&isolated)
            .expect("isolated worker receives inherited client FD");
        let state=Arc::clone(state);
        let handle=std::thread::spawn(move || {
            crate::serve_authorized_one(worker,authenticated,state)
        });
        crate::rpc_write(&mut caller,&request).unwrap();
        let answer=crate::rpc_read(&mut caller).unwrap();
        handle.join().unwrap().unwrap();
        answer
    }

    #[test]
    fn f18_private_fd_preserves_desktop_authority_and_blocks_json_spoofing() {
        let (state,path)=fixture();
        state.lock().unwrap().unlocked=Some(Master(b"f18-memory-only-sentinel".to_vec()));
        let forged=f18_rpc_through_fd(&state,None,json!({
            "op":"vault.lock","peer":"neebles-secrets","module":"neebles-secrets"
        }));
        denied(&forged,"vault_control_forbidden");
        assert!(state.lock().unwrap().unlocked.is_some(),"forged request cannot lock Secrets");
        let consumer=f18_rpc_through_fd(&state,Some("neebles-connect"),
            json!({"op":"vault.lock"}));
        denied(&consumer,"vault_control_forbidden");
        let desktop=f18_rpc_through_fd(&state,Some("neebles-secrets"),
            json!({"op":"vault.lock"}));
        assert_eq!(desktop["ok"],true,"{desktop}");
        assert_eq!(desktop["data"]["locked"],true);
        assert!(state.lock().unwrap().unlocked.is_none());
        assert!(!path.exists(),"F18 must never create a KDBX or data directory");
    }

    #[test]
    fn f18_private_fd_connect_stays_inside_its_vault_namespace() {
        let (state,path)=fixture();
        let good=f18_rpc_through_fd(&state,Some("neebles-connect"),
            json!({"op":"vault.request","module":"neebles-connect"}));
        assert_eq!(good["ok"],true,"{good}");
        assert_eq!(good["data"]["pending"],true);
        let bad=f18_rpc_through_fd(&state,Some("neebles-connect"),
            json!({"op":"vault.request","module":"neebles-db"}));
        denied(&bad,"vault_module_identity_mismatch");
        assert!(!path.exists());
    }

    #[test]
    fn f16_anonymous_json_cannot_impersonate_secrets_desktop() {
        let (state,path)=fixture();
        for op in ["vault.setup","vault.unlock","vault.lock"] {
            denied(&rpc(&state,None,json!({
                "op":op,"peer":"neebles-secrets", "module":"neebles-secrets",
                "password":"laboratory-not-a-real-key"
            })),"vault_control_forbidden");
        }
        denied(&rpc(&state,None,json!({"op":"general.list","peer":"neebles-secrets"})),"personal_vault_forbidden");
        denied(&rpc(&state,None,json!({"op":"backup.catalog"})),"backup_forbidden");
        denied(&rpc(&state,None,json!({"op":"restore.plan"})),"restore_forbidden");
        denied(&rpc(&state,None,json!({"op":"portable.begin","passphrase":"laboratory-password"})),"portable_export_forbidden");
        assert!(state.lock().unwrap().unlocked.is_none());
        assert!(!path.exists(),"denial must not create a KDBX or directory");
    }

    #[test]
    fn f16_connect_cannot_escape_its_namespace_or_control_master() {
        let (state,path)=fixture();
        let own=rpc(&state,Some("neebles-connect"),json!({"op":"vault.request","module":"neebles-connect"}));
        assert_eq!(own["ok"],true,"{own}");
        assert_eq!(own["data"]["pending"],true);
        let exists=rpc(&state,Some("neebles-connect"),json!({"op":"vault.exists","module":"neebles-connect"}));
        assert_eq!(exists["ok"],true,"{exists}");
        assert_eq!(exists["data"]["exists"],false);
        denied(&rpc(&state,Some("neebles-connect"),json!({"op":"vault.ensure","module":"neebles-db"})),"vault_module_identity_mismatch");
        denied(&rpc(&state,Some("neebles-connect"),json!({"op":"vault.request","module":"general"})),"vault_module_identity_mismatch");
        denied(&rpc(&state,Some("neebles-connect"),json!({"op":"secret.list","module":"neebles-db"})),"secret_module_identity_mismatch");
        denied(&rpc(&state,Some("neebles-connect"),json!({"op":"general.list"})),"personal_vault_forbidden");
        denied(&rpc(&state,Some("neebles-connect"),json!({"op":"vault.lock"})),"vault_control_forbidden");
        assert_eq!(state.lock().unwrap().pending.len(),1);
        assert!(!path.exists(),"vault request while locked must stay in memory");
    }

    #[test]
    fn f16_authorized_desktop_can_lock_but_consumer_cannot() {
        let (state,path)=fixture();
        {
            // A fake in-memory master proves whether lock actually mutated state.
            // It is NOT checked against any KDBX and is never persisted.
            state.lock().unwrap().unlocked=Some(Master(b"f16-disposable-test-only".to_vec()));
        }
        denied(&rpc(&state,Some("neebles-connect"),json!({"op":"vault.lock"})),"vault_control_forbidden");
        assert!(state.lock().unwrap().unlocked.is_some(),"denied lock must not change state");
        let locked=rpc(&state,Some("neebles-secrets"),json!({"op":"vault.lock"}));
        assert_eq!(locked["ok"],true,"{locked}");
        assert_eq!(locked["data"]["locked"],true);
        assert!(state.lock().unwrap().unlocked.is_none());
        denied(&rpc(&state,Some("neebles-secrets"),json!({"op":"vault.request","module":"neebles-connect"})),"vault_module_identity_mismatch");
        assert!(!path.exists());
    }

    #[test]
    fn f16_public_status_and_ephemeral_quick_generator_stay_available() {
        let (state,path)=fixture();
        let status=rpc(&state,None,json!({"op":"status"}));
        assert_eq!(status["ok"],true,"{status}");
        assert_eq!(status["data"]["initialized"],false);
        assert_eq!(status["data"]["locked"],true);
        let quick=rpc(&state,None,json!({"op":"quick.generate","kind":"password","length":20}));
        assert_eq!(quick["ok"],true,"quick generation failed");
        assert_eq!(quick["data"]["stored"],false);
        assert_eq!(quick["data"]["value"].as_str().unwrap().len(),20);
        assert!(!path.exists());
    }
}
