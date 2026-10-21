//! F14: vault-general is exclusively user-owned. A module requests its own vault.
//! No implicit module-vault creation, no master password in module requests.
use serde_json::{json, Value};
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
        Ok(Self {directory:folder,unlocked:None,pending:BTreeSet::new()})
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
        self.unlocked=None;
        json!({"locked":true})
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
            directory:directory.clone(),unlocked:None,pending:BTreeSet::new()
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
