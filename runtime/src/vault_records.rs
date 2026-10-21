//! NEEBLES Secrets 1.0.2: encrypted records in a module-owned KDBX.
//! No user/host/password values in argv, environment, disk sidecars or logs.
//! The only persisted index and values are KeePassXC *protected password* entries.
use serde_json::{json,Value};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self,File,OpenOptions};
use std::io::{Read,Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path,PathBuf};
use std::process::{Command,Stdio};
use std::thread;
use std::time::{Duration,Instant};

const MAX_VALUE:usize=8192;
const MAX_ENTRIES:usize=256;
const INDEX:&str="__neebles_secret_index_v1";

pub(crate) fn valid_id(value:&str)->bool {
    let bytes=value.as_bytes();
    (1..=64).contains(&bytes.len()) && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|c|c.is_ascii_lowercase()||c.is_ascii_digit()||*c==b'-')
        && !value.ends_with('-') && !value.contains("--")
}
fn record_key(id:&str)->String {format!("record-{id}")}
fn encode(value:&[u8])->String {
    const CHARS:&[u8;64]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s=String::with_capacity((value.len()*4+2)/3);
    for chunk in value.chunks(3) {
        let a=chunk[0]; let b=*chunk.get(1).unwrap_or(&0); let c=*chunk.get(2).unwrap_or(&0);
        s.push(CHARS[(a>>2)as usize]as char);
        s.push(CHARS[(((a&3)<<4)|(b>>4))as usize]as char);
        if chunk.len()>1{s.push(CHARS[(((b&15)<<2)|(c>>6))as usize]as char);}
        if chunk.len()>2{s.push(CHARS[(c&63)as usize]as char);}
    }
    s
}
fn decode(s:&str)->Result<Vec<u8>,String>{
    fn val(b:u8)->Option<u8>{match b {b'A'..=b'Z'=>Some(b-b'A'),b'a'..=b'z'=>Some(b-b'a'+26),b'0'..=b'9'=>Some(b-b'0'+52),b'-'=>Some(62),b'_'=>Some(63),_=>None}}
    if s.len()>MAX_VALUE*4 || s.len()%4==1 {return Err("invalid_encrypted_record_encoding".into());}
    let mut out=Vec::with_capacity(s.len()*3/4);
    let mut buf=0u32;let mut bits=0u32;
    for b in s.bytes(){let digit=val(b).ok_or("invalid_encrypted_record_encoding")?;
        buf=(buf<<6)|u32::from(digit);bits+=6;
        if bits>=8{bits-=8;out.push((buf>>bits) as u8); buf &= (1u32<<bits)-1;}
    }
    if bits>0 && buf!=0 {return Err("invalid_encrypted_record_encoding".into());}
    Ok(out)
}
// Status and output are never logged. stdout is private to the Secrets daemon.
// The first input line unlocks KDBX, the second supplies the protected entry password.
fn keepass(args:&[&OsStr], master:&[u8], secret:Option<&str>, read_output:bool)->Result<(bool,Vec<u8>),String>{
    if master.contains(&b'\n') || master.contains(&b'\r') {return Err("invalid_master_input".into());}
    let mut child=Command::new("/usr/bin/keepassxc-cli").args(args)
        .stdin(Stdio::piped()).stdout(if read_output{Stdio::piped()}else{Stdio::null()})
        .stderr(Stdio::null()).spawn().map_err(|_|"keepass_unavailable".to_string())?;
    let input=(||->Result<(),String>{
        let mut pipe=child.stdin.take().ok_or("keepass_pipe_unavailable")?;
        pipe.write_all(master).and_then(|_|pipe.write_all(b"\n"))
            .map_err(|_|"keepass_input_failed")?;
        if let Some(encoded)=secret {
            pipe.write_all(encoded.as_bytes()).and_then(|_|pipe.write_all(b"\n"))
                .map_err(|_|"keepass_input_failed")?;
        }
        Ok(())
    })();
    if input.is_err(){let _=child.kill();let _=child.wait();return Err("keepass_input_failed".into());}
    // Child output is at most 16KiB due to payload policy, but a malicious CLI
    // could block on pipe. Read it concurrently with the timeout guard.
    let reader=if read_output {
        let mut stdout=child.stdout.take().ok_or("keepass_output_unavailable")?;
        Some(thread::spawn(move||{
            let mut data=Vec::new();let mut buf=[0u8;1024];
            loop{let n=stdout.read(&mut buf).map_err(|_|"keepass_output_failed")?;
                if n==0{break;} if data.len()+n>16*1024 {return Err("keepass_output_too_large");}
                data.extend_from_slice(&buf[..n]);
            }
            Ok(data)
        }))
    }else{None};
    let deadline=Instant::now()+Duration::from_secs(40);
    let success=loop {match child.try_wait(){
        Ok(Some(status))=>break status.success(),
        Ok(None) if Instant::now()<deadline=>thread::sleep(Duration::from_millis(25)),
        _=>{let _=child.kill();let _=child.wait();return Err("keepass_timed_out".into());}
    }};
    let output=match reader{Some(handle)=>handle.join().map_err(|_|"keepass_reader_failed")?
        .map_err(|e|e.to_string())?,None=>Vec::new()};
    Ok((success,output))
}
fn show(path:&Path,master:&[u8],key:&str)->Result<Option<String>,String>{
    let args=[OsStr::new("show"),OsStr::new("-q"),OsStr::new("-s"),OsStr::new("-a"),OsStr::new("password"),path.as_os_str(),OsStr::new(key)];
    let (ok,output)=keepass(&args,master,None,true)?;
    if !ok {return Ok(None);}
    let s=std::str::from_utf8(&output).map_err(|_|"keepass_invalid_record_encoding")?;
    let value=s.trim_end_matches(|c| c == '\r' || c == '\n');
    Ok(Some(value.to_owned()))
}
fn add(path:&Path,master:&[u8],key:&str,encoded:&str)->Result<(),String>{
    let args=[OsStr::new("add"),OsStr::new("-q"),OsStr::new("-p"),path.as_os_str(),OsStr::new(key)];
    if keepass(&args,master,Some(encoded),false)?.0 {Ok(())}else{Err("keepass_add_failed".into())}
}
fn edit(path:&Path,master:&[u8],key:&str,encoded:&str)->Result<(),String>{
    let args=[OsStr::new("edit"),OsStr::new("-q"),OsStr::new("-p"),path.as_os_str(),OsStr::new(key)];
    if keepass(&args,master,Some(encoded),false)?.0 {Ok(())}else{Err("keepass_edit_failed".into())}
}
fn remove(path:&Path,master:&[u8],key:&str)->Result<(),String>{
    let args=[OsStr::new("rm"),OsStr::new("-q"),path.as_os_str(),OsStr::new(key)];
    if keepass(&args,master,None,false)?.0 {Ok(())}else{Err("keepass_remove_failed".into())}
}
fn load_index(path:&Path,master:&[u8])->Result<BTreeSet<String>,String>{
    let Some(s)=show(path,master,INDEX)? else{return Ok(BTreeSet::new())};
    let decoded=decode(&s)?;
    let ids:Vec<String>=serde_json::from_slice(&decoded).map_err(|_|"corrupt_vault_index")?;
    if ids.len()>MAX_ENTRIES || ids.iter().any(|id|!valid_id(id)) {return Err("corrupt_vault_index".into());}
    let index: BTreeSet<_>=ids.iter().cloned().collect();
    if ids.len()!=index.len(){return Err("corrupt_vault_index".into());}
    Ok(index)
}
fn store_index(path:&Path,master:&[u8],ids:&BTreeSet<String>)->Result<(),String>{
    let value=encode(&serde_json::to_vec(ids).map_err(|_|"serialize_vault_index")?);
    match show(path,master,INDEX)? {Some(_)=>edit(path,master,INDEX,&value),None=>add(path,master,INDEX,&value)}
}
fn transaction<T,F>(path:&Path,master:&[u8],action:F)->Result<T,String>
where F:FnOnce(&Path)->Result<T,String>{
    let folder=path.parent().ok_or("invalid_vault_directory")?;
    let mut random=[0u8;16];File::open("/dev/urandom").and_then(|mut f|f.read_exact(&mut random))
        .map_err(|_|"cannot_reserve_encrypted_transaction")?;
    let name=random.iter().map(|b|format!("{b:02x}")).collect::<String>();
    let temp:PathBuf=folder.join(format!(".secret-txn-{name}.kdbx"));
    let result=(||{
        let mut from=File::open(path).map_err(|_|"vault_unavailable")?;
        let mut to=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)
            .map_err(|_|"cannot_create_transaction")?;
        std::io::copy(&mut from,&mut to).map_err(|_|"cannot_copy_encrypted_vault")?;
        to.sync_all().map_err(|_|"cannot_sync_transaction")?;drop(to);
        let output=action(&temp)?;
        // Verify the complete encrypted database before atomic replacement.
        let args=[OsStr::new("db-info"),OsStr::new("-q"),temp.as_os_str()];
        if !keepass(&args,master,None,false)?.0{return Err("updated_vault_verification_failed".into());}
        File::open(&temp).and_then(|f|f.sync_all()).map_err(|_|"cannot_sync_updated_vault")?;
        fs::rename(&temp,path).map_err(|_|"cannot_commit_updated_vault")?;
        File::open(folder).and_then(|f|f.sync_all()).map_err(|_|"cannot_sync_vault_directory")?;
        Ok(output)
    })();
    let _=fs::remove_file(&temp);
    result
}
pub fn list(path:&Path,master:&[u8])->Result<Value,String>{
    let ids=load_index(path,master)?;
    Ok(json!({"ids":ids.into_iter().collect::<Vec<_>>()}))
}
pub fn get(path:&Path,master:&[u8],id:&str)->Result<Value,String>{
    if !valid_id(id){return Err("invalid_secret_id".into());}
    let index=load_index(path,master)?;
    if !index.contains(id){return Err("secret_not_found".into());}
    let encrypted=show(path,master,&record_key(id))?.ok_or("missing_indexed_secret")?;
    let raw=decode(&encrypted)?;
    let value:Value=serde_json::from_slice(&raw).map_err(|_|"corrupt_encrypted_secret")?;
    Ok(json!({"id":id,"value":value}))
}
pub fn put(path:&Path,master:&[u8],id:&str,value:&Value,update_only:bool)->Result<Value,String>{
    if !valid_id(id){return Err("invalid_secret_id".into());}
    let raw=serde_json::to_vec(value).map_err(|_|"invalid_secret_value")?;
    if raw.is_empty()||raw.len()>MAX_VALUE{return Err("secret_value_out_of_range".into());}
    let encoded=encode(&raw);
    transaction(path,master,|temp|{
        let mut index=load_index(temp,master)?;
        let exists=index.contains(id);
        if update_only&&!exists {return Err("secret_not_found".into());}
        if !exists && index.len()>=MAX_ENTRIES {return Err("vault_entry_limit".into());}
        if exists { edit(temp,master,&record_key(id),&encoded)?; }
        else {add(temp,master,&record_key(id),&encoded)?;index.insert(id.to_owned());store_index(temp,master,&index)?;}
        Ok(json!({"id":id,"created":!exists,"updated":exists}))
    })
}
pub fn delete(path:&Path,master:&[u8],id:&str)->Result<Value,String>{
    if !valid_id(id){return Err("invalid_secret_id".into());}
    transaction(path,master,|temp|{
        let mut index=load_index(temp,master)?;
        if !index.remove(id){return Err("secret_not_found".into());}
        remove(temp,master,&record_key(id))?;
        store_index(temp,master,&index)?;
        Ok(json!({"id":id,"deleted":true}))
    })
}
#[cfg(test)]mod tests{
    use super::*;
    #[test]fn ids_are_bounded(){assert!(valid_id("connection-1"));for bad in ["../etc","CAP","","_neebles_secret_index_v1","hello/world","a--b"]{assert!(!valid_id(bad));}}
    #[test]fn encoded_record_roundtrip(){for input in [b"abc".as_slice(),b"{}\n".as_slice(),b"\0\xff\x12".as_slice()]{assert_eq!(decode(&encode(input)).unwrap(),input);}}
    #[test]fn malformed_base64_rejected(){for s in ["a","AAAA!","__B","="]{assert!(decode(s).is_err());}}
}
