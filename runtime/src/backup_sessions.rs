//! NEEBLES Secrets encrypted KDBX snapshot IPC. Only called by the authorized
//! Secrets desktop via the service; never returns decrypted vault contents.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

const MAX_VAULTS: usize=64;
const MAX_EACH: u64=512*1024*1024;
const MAX_TOTAL: u64=1024*1024*1024;
const CHUNK: usize=6144;
const IDLE: Duration=Duration::from_secs(180);

struct VaultFile {
    name: String,
    file: File,
    length: u64,
    hash: String,
    next: u64,
}
struct Session {
    token: String,
    items: Vec<VaultFile>,
    last_used: Instant,
}
#[derive(Default)]
pub struct BackupSessions { current: Option<Session> }

fn allowed_file(name:&str)->bool {
    let Some(module)=name.strip_prefix("vault-").and_then(|x|x.strip_suffix(".kdbx")) else{return false};
    if module=="general" {return true;}
    (2..=64).contains(&module.len())
        && module.as_bytes()[0].is_ascii_lowercase()
        && module.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-')
        && !module.ends_with('-') && !module.contains("--")
}
fn file_names(directory:&Path)->Result<Vec<String>,String>{
    let dir=fs::symlink_metadata(directory).map_err(|_|"backup_directory_unavailable")?;
    if !dir.is_dir() || dir.file_type().is_symlink() || dir.uid()!=current_uid() || dir.permissions().mode()&0o077!=0 {
        return Err("backup_directory_unsafe".into());
    }
    let mut found=Vec::new();
    for entry in fs::read_dir(directory).map_err(|_|"backup_directory_unavailable")? {
        let entry=entry.map_err(|_|"backup_directory_unavailable")?;
        let Ok(name)=entry.file_name().into_string() else {continue};
        if allowed_file(&name) { found.push(name); }
    }
    found.sort();
    if found.len()>MAX_VAULTS {return Err("backup_too_many_vaults".into());}
    Ok(found)
}
fn current_uid()->u32{unsafe extern "C" {fn geteuid()->u32;} unsafe{geteuid()}}
fn open_vault(directory:&Path,name:String)->Result<VaultFile,String>{
    if !allowed_file(&name){return Err("backup_invalid_filename".into());}
    let path=directory.join(&name);
    let mut file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC)
        .open(&path).map_err(|_|"backup_source_unavailable")?;
    let metadata=file.metadata().map_err(|_|"backup_source_unavailable")?;
    if !metadata.is_file() || metadata.uid()!=current_uid()
        || metadata.permissions().mode()&0o077!=0 || !(128..=MAX_EACH).contains(&metadata.len()) {
        return Err("backup_source_invalid".into());
    }
    let mut header=[0u8;4];
    file.read_exact(&mut header).map_err(|_|"backup_source_invalid")?;
    if header!=[0x03,0xd9,0xa2,0x9a] {return Err("backup_source_not_kdbx".into());}
    file.seek(SeekFrom::Start(0)).map_err(|_|"backup_read_error")?;
    let mut hash=Sha256::new();
    let mut buf=[0u8;32768];
    let mut total=0u64;
    loop {
        let n=file.read(&mut buf).map_err(|_|"backup_read_error")?;
        if n==0 {break;}
        total=total.saturating_add(n as u64);
        if total>metadata.len() {return Err("backup_source_changed".into());}
        hash.update(&buf[..n]);
    }
    if total!=metadata.len(){return Err("backup_source_changed".into());}
    file.seek(SeekFrom::Start(0)).map_err(|_|"backup_read_error")?;
    let digest=hash.finalize();
    let hex=digest.iter().map(|b|format!("{b:02x}")).collect();
    Ok(VaultFile {name,file,length:total,hash:hex,next:0})
}
fn random_token()->Result<String,String>{
    let mut bytes=[0u8;16];
    File::open("/dev/urandom").and_then(|mut f|f.read_exact(&mut bytes))
        .map_err(|_|"backup_token_unavailable")?;
    Ok(bytes.iter().map(|b|format!("{b:02x}")).collect())
}
impl BackupSessions {
    pub fn clear(&mut self){self.current=None;}
    pub fn catalog(directory:&Path)->Result<Value,String>{
        Ok(json!({"names":file_names(directory)?}))
    }
    pub fn open(&mut self,directory:&Path,mode:&str,name:Option<&str>)->Result<Value,String>{
        if self.current.as_ref().is_some_and(|s|s.last_used.elapsed()>=IDLE){self.clear();}
        if self.current.is_some(){return Err("backup_session_busy".into());}
        let available=file_names(directory)?;
        let selected=match mode {
            "single"=>{
                let n=name.ok_or("backup_name_required")?;
                if !available.iter().any(|v|v==n){return Err("backup_name_not_found".into());}
                vec![n.to_owned()]
            },
            "full"=>available,
            _=>return Err("backup_invalid_mode".into()),
        };
        if selected.is_empty(){return Err("backup_no_vaults".into());}
        let mut total=0u64;
        let mut items=Vec::new();
        for name in selected {
            let item=open_vault(directory,name)?;
            total=total.checked_add(item.length).ok_or("backup_size_limit")?;
            if total>MAX_TOTAL{return Err("backup_size_limit".into());}
            items.push(item);
        }
        let desc=items.iter().map(|i|json!({"name":i.name,"size":i.length,"sha256":i.hash})).collect::<Vec<Value>>();
        let token=random_token()?;
        self.current=Some(Session{token:token.clone(),items,last_used:Instant::now()});
        Ok(json!({"token":token,"files":desc,"total":total,"format":1}))
    }
    pub fn read(&mut self,token:&str,index:usize,offset:u64,count:usize)->Result<Value,String>{
        let session=self.current.as_mut().ok_or("backup_session_missing")?;
        if session.last_used.elapsed()>=IDLE {
            self.clear();return Err("backup_session_expired".into());
        }
        if session.token!=token {return Err("backup_session_invalid".into());}
        if count==0 || count>CHUNK {return Err("backup_chunk_invalid".into());}
        let file=session.items.get_mut(index).ok_or("backup_index_invalid")?;
        if file.next!=offset || offset>=file.length || count as u64>file.length-offset {
            return Err("backup_offset_invalid".into());
        }
        let mut bytes=vec![0u8;count];
        file.file.read_exact(&mut bytes).map_err(|_|"backup_read_error")?;
        file.next=offset+count as u64;
        session.last_used=Instant::now();
        use base64::Engine as _;
        Ok(json!({"value":base64::engine::general_purpose::STANDARD.encode(bytes),"next":file.next}))
    }
    pub fn close(&mut self,token:&str)->Result<Value,String>{
        if self.current.as_ref().is_some_and(|s|s.token==token){
            self.clear();Ok(json!({"closed":true}))
        }else{Err("backup_session_invalid".into())}
    }
}
#[cfg(test)]mod tests{
    use super::*;
    #[test]fn accepts_only_named_vaults(){
        assert!(allowed_file("vault-general.kdbx"));
        assert!(allowed_file("vault-neebles-connect.kdbx"));
        for bad in ["vault-../evil.kdbx","vault-General.kdbx","vault-.kdbx","vault-evil--x.kdbx","vault-general.kdbx.old","other.kdbx"]{
            assert!(!allowed_file(bad));
        }
    }
    #[test]fn rejects_missing_session(){
        let mut sessions=BackupSessions::default();
        assert!(sessions.read("bogus",0,0,10).is_err());
        assert!(sessions.close("bogus").is_err());
    }
}
