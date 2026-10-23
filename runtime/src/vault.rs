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
fn create_once(dir:&Path,module:&str,password:&[u8]) -> Result<bool,String> {
    let target=dir.join(format!("vault-{module}.kdbx"));
    if validate_vault(&target)? {return Ok(false);}
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
        // Atomic create-if-absent. link() MUST fail instead of replacing an existing vault.
        match fs::hard_link(&temp,&target) {
            Ok(())=>Ok(true),
            Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists => {
                if validate_vault(&target)? { Ok(false) } else { Err("existing vault is invalid".into()) }
            },
            Err(_)=>Err("cannot publish new vault without replacement".into())
        }
    })();
    let _=fs::remove_file(&temp);
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
        Ok(Self {directory:folder,unlocked:None,pending:BTreeSet::new(),backups:Default::default(),restores:Default::default(),portable:Default::default()})
    }
    fn general(&self)->PathBuf{self.directory.join("vault-general.kdbx")}
    pub fn initialized(&self)->Result<bool,String>{validate_vault(&self.general())}
    pub fn status(&self)->Result<Value,String>{
        let initialized=self.initialized()?;
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
                        && item.get("entrypoint").and_then(Value::as_str)==Some("runtime/neebles-secrets-ui")
                    })
            },
            _ => false
        };
        Ok(json!({"locked":self.unlocked.is_none(),"initialized":initialized,"installed":installed,"vaults_ready":initialized&&self.unlocked.is_some(),"service":"neebles-secrets","protocol":1,
                  "boss_variables":public_boss_variables(initialized,self.unlocked.is_none())}))
    }
    pub fn setup(&mut self, password:&str)->Result<Value,String>{
        if self.initialized()? {return Err("already_initialized".into());}
        if !(8..=512).contains(&password.len()) || password.chars().any(|c| matches!(c, '\n' | '\r' | '\0')) {
            return Err("master_password_policy".into());
        }
        create_once(&self.directory,"general",password.as_bytes())?;
        self.unlocked=Some(Master(password.as_bytes().to_vec()));
        let provisioned=self.fulfill_pending()?;
        Ok(json!({"initialized":true,"unlocked":true,"vault":"general","provisioned":provisioned}))
    }
    pub fn unlock(&mut self,password:&str)->Result<Value,String>{
        if !self.initialized()? {return Err("setup_required".into());}
        if password.len()>512 || password.is_empty() || password.chars().any(|c| matches!(c, '\n' | '\r' | '\0')) {
            return Err("invalid_password_input".into());
        }
        db_verify(&self.general(),password.as_bytes())?;
        self.unlocked=Some(Master(password.as_bytes().to_vec()));
        let provisioned=self.fulfill_pending()?;
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
            self.pending.remove(module);
            return Ok(json!({"module":module,"exists":true,"pending":false}));
        }
        Ok(json!({"module":module,"exists":false,"pending":true}))
    }
    fn fulfill_pending(&mut self)->Result<Vec<String>,String>{
        let modules=self.pending.iter().cloned().collect::<Vec<_>>();
        let mut provisioned=Vec::new();
        for module in modules {
            self.ensure(&module)?;
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
