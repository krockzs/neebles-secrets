//! NEEBLES Secrets 1.0.2: encrypted records in a module-owned KDBX.
//! No user/host/password values in argv, environment, disk sidecars or logs.
//! The only persisted index and values are KeePassXC *protected password* entries.
use serde_json::{json,Value};
use std::collections::BTreeSet;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::{self,File,OpenOptions};
use std::io::{Read,Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::fd::AsRawFd;
use std::path::{Path,PathBuf};
use std::process::{Command,Stdio};
use std::thread;
use std::time::{Duration,Instant};

const MAX_VALUE:usize=8192;
// Logical values larger than the historical single-entry limit live as
// protected KDBX password entries. No unencrypted sidecars are created.
const MAX_RECORD_BYTES:usize=128*1024;
const RECORD_CHUNK_BYTES:usize=4096;
const MAX_RECORD_PARTS:usize=MAX_RECORD_BYTES/RECORD_CHUNK_BYTES;
const CHUNK_TAG:&str="__neebles_kdbx_value_chunks_v2";
// Legacy v1 retains its exact storage contract for backward compatibility.
const MAX_ENTRIES:usize=256;
const MAX_V2_ENTRIES:usize=16_384;
const IDS_PER_PAGE:usize=64;
const INDEX:&str="__neebles_secret_index_v1";
const INDEX_V2:&str="__neebles_secret_index_v2";
const INDEX_V2_PAGE_PREFIX:&str="__neebles_secret_index_v2_page_";

pub(crate) fn valid_id(value:&str)->bool {
    let bytes=value.as_bytes();
    (1..=64).contains(&bytes.len()) && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|c|c.is_ascii_lowercase()||c.is_ascii_digit()||*c==b'-')
        && !value.ends_with('-') && !value.contains("--")
}
fn record_key(id:&str)->String {format!("record-{id}")}
// Chunk entry names contain '~', which valid_id() forbids. Therefore they
// cannot collide with another user's logical record-{id} entry.
fn chunk_key(id:&str, part:usize)->String { format!("record-{id}~chunk~{part:04}") }

#[derive(Clone,Debug,PartialEq,Eq)]
struct ChunkHeader { bytes:usize, parts:usize, digest:String }

fn sha256_hex(data:&[u8])->String {
    let hash=Sha256::digest(data);
    hash.iter().map(|b|format!("{b:02x}")).collect::<String>()
}
fn new_chunk_header(data:&[u8])->ChunkHeader {
    ChunkHeader{bytes:data.len(),parts:data.len().div_ceil(RECORD_CHUNK_BYTES),digest:sha256_hex(data)}
}
fn header_json(header:&ChunkHeader)->Value {
    json!({"__neebles_kdbx_value_chunks_v2":2,"bytes":header.bytes,"parts":header.parts,"sha256":header.digest})
}
fn parse_chunk_header(value:&Value)->Result<Option<ChunkHeader>,String> {
    let Some(fields)=value.as_object() else {return Ok(None);};
    if !fields.contains_key(CHUNK_TAG) {return Ok(None);}
    if fields.len()!=4 || fields.get(CHUNK_TAG).and_then(Value::as_u64)!=Some(2) {
        return Err("corrupt_chunk_manifest".into());
    }
    let bytes=fields.get("bytes").and_then(Value::as_u64)
        .and_then(|n|usize::try_from(n).ok()).ok_or("corrupt_chunk_manifest")?;
    let parts=fields.get("parts").and_then(Value::as_u64)
        .and_then(|n|usize::try_from(n).ok()).ok_or("corrupt_chunk_manifest")?;
    let digest=fields.get("sha256").and_then(Value::as_str).ok_or("corrupt_chunk_manifest")?;
    if bytes<=MAX_VALUE || bytes>MAX_RECORD_BYTES || parts!=bytes.div_ceil(RECORD_CHUNK_BYTES)
        || parts==0 || parts>MAX_RECORD_PARTS || digest.len()!=64
        || !digest.bytes().all(|b|b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err("corrupt_chunk_manifest".into());
    }
    Ok(Some(ChunkHeader{bytes,parts,digest:digest.to_owned()}))
}
fn decode_value(path:&Path,master:&[u8],id:&str,primary:&str)->Result<Value,String>{
    let raw=decode(primary)?;
    let initial:Value=serde_json::from_slice(&raw).map_err(|_|"corrupt_encrypted_secret")?;
    let Some(header)=parse_chunk_header(&initial)? else {return Ok(initial);};
    let mut content=Vec::with_capacity(header.bytes);
    for i in 0..header.parts {
        let encoded=show(path,master,&chunk_key(id,i))?.ok_or("missing_secret_chunk")?;
        let part=decode(&encoded)?;
        let target=if i+1==header.parts {header.bytes-i*RECORD_CHUNK_BYTES} else {RECORD_CHUNK_BYTES};
        if part.len()!=target {return Err("corrupt_secret_chunk_length".into());}
        content.extend_from_slice(&part);
    }
    if content.len()!=header.bytes || sha256_hex(&content)!=header.digest {
        return Err("corrupt_secret_chunk_digest".into());
    }
    serde_json::from_slice(&content).map_err(|_|"corrupt_encrypted_secret".into())
}
fn write_value(path:&Path,master:&[u8],id:&str,raw:&[u8],old_parts:usize,exists:bool)->Result<(),String>{
    let key=record_key(id);
    let parts=if raw.len()<=MAX_VALUE {0} else {raw.len().div_ceil(RECORD_CHUNK_BYTES)};
    if parts>MAX_RECORD_PARTS {return Err("secret_value_out_of_range".into());}
    if parts>0 {
        // The index and primary marker are updated only after all encrypted
        // fragments are written to the transactional KDBX copy.
        for (i,fragment) in raw.chunks(RECORD_CHUNK_BYTES).enumerate() {
            let entry=chunk_key(id,i);
            let encoded=encode(fragment);
            if i<old_parts {edit(path,master,&entry,&encoded)?;}
            else {add(path,master,&entry,&encoded)?;}
        }
    }
    let primary=if parts==0 {encode(raw)}
        else {encode(&serde_json::to_vec(&header_json(&new_chunk_header(raw)))
            .map_err(|_|"invalid_secret_value")?)};
    if exists {edit(path,master,&key,&primary)?;}
    else {add(path,master,&key,&primary)?;}
    for i in parts..old_parts {remove(path,master,&chunk_key(id,i))?;}
    Ok(())
}
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
    // Output remains capped; reading an existing v1 index with 256 maximal
    // identifiers may exceed 16KiB even though individual secrets are small.
    // Do not let a malicious CLI block on a full pipe while we enforce timeout.
    let reader=if read_output {
        let mut stdout=child.stdout.take().ok_or("keepass_output_unavailable")?;
        Some(thread::spawn(move||{
            let mut data=Vec::new();let mut buf=[0u8;1024];
            loop{let n=stdout.read(&mut buf).map_err(|_|"keepass_output_failed")?;
                if n==0{break;} if data.len()+n>64*1024 {return Err("keepass_output_too_large");}
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
// Index v2 shards are ALSO KeePassXC protected password entries inside the
// original encrypted vault. No external index, plaintext cache, or sidecar.
// Both v1 and v2 are written on an encrypted transaction copy of the vault.
trait IndexStore {
    fn read(&self,key:&str)->Result<Option<String>,String>;
    fn write(&mut self,key:&str,value:&str)->Result<(),String>;
    fn delete(&mut self,key:&str)->Result<(),String>;
}
struct KdbxIndex<'a>{path:&'a Path,master:&'a[u8]}
impl IndexStore for KdbxIndex<'_> {
    fn read(&self,key:&str)->Result<Option<String>,String>{show(self.path,self.master,key)}
    fn write(&mut self,key:&str,value:&str)->Result<(),String>{
        if show(self.path,self.master,key)?.is_some(){edit(self.path,self.master,key,value)}
        else{add(self.path,self.master,key,value)}
    }
    fn delete(&mut self,key:&str)->Result<(),String>{remove(self.path,self.master,key)}
}
fn page_key(number:usize)->String{format!("{INDEX_V2_PAGE_PREFIX}{number:04}")}
fn decode_ids(encoded:&str,limit:usize,max_bytes:usize)->Result<Vec<String>,String>{
    let raw=decode(encoded)?;
    if raw.len()>max_bytes{return Err("corrupt_vault_index".into());}
    let ids:Vec<String>=serde_json::from_slice(&raw).map_err(|_|"corrupt_vault_index")?;
    if ids.len()>limit || ids.iter().any(|id|!valid_id(id)) {
        return Err("corrupt_vault_index".into());
    }
    Ok(ids)
}
fn v2_manifest(encoded:&str)->Result<(usize,usize),String>{
    let raw=decode(encoded)?;
    if raw.len()>512{return Err("corrupt_vault_index_v2".into());}
    let value:Value=serde_json::from_slice(&raw).map_err(|_|"corrupt_vault_index_v2")?;
    let obj=value.as_object().ok_or("corrupt_vault_index_v2")?;
    if obj.len()!=3 || value["format"]!=2 {return Err("corrupt_vault_index_v2".into());}
    let count=value["count"].as_u64().ok_or("corrupt_vault_index_v2")?;
    let pages=value["pages"].as_u64().ok_or("corrupt_vault_index_v2")?;
    let max_pages=MAX_V2_ENTRIES.div_ceil(IDS_PER_PAGE);
    if count>MAX_V2_ENTRIES as u64 || pages>max_pages as u64
        || pages != count.div_ceil(IDS_PER_PAGE as u64) {
        return Err("corrupt_vault_index_v2".into());
    }
    Ok((count as usize,pages as usize))
}
fn load_index_from(store:&impl IndexStore)->Result<BTreeSet<String>,String>{
    // The v2 marker is authoritative; a stale v1 index is deliberately retained
    // after one-way migration so installed 1.0.4 data is never deleted.
    if let Some(encoded)=store.read(INDEX_V2)? {
        let (count,pages)=v2_manifest(&encoded)?;
        let mut all=BTreeSet::new();
        let mut global_last=String::new();
        for number in 0..pages {
            let chunk=store.read(&page_key(number))?.ok_or("missing_vault_index_page")?;
            let ids=decode_ids(&chunk,IDS_PER_PAGE,MAX_VALUE)?;
            let expected_count=if number+1==pages {count-number*IDS_PER_PAGE} else {IDS_PER_PAGE};
            if ids.len()!=expected_count {return Err("corrupt_vault_index_page".into());}
            for id in &ids {
                if !global_last.is_empty() && global_last.as_str()>=id.as_str() {
                    return Err("corrupt_vault_index_page".into());
                }
                global_last=id.clone();
                if !all.insert(id.clone()){return Err("duplicate_vault_index_id".into());}
            }
        }
        if all.len()!=count {return Err("corrupt_vault_index_v2".into());}
        return Ok(all);
    }
    let Some(s)=store.read(INDEX)? else{return Ok(BTreeSet::new())};
    // v1 historically accepted up to 256 IDs of length 64, >8KiB raw.
    // Keep that encoding readable even though v2 pages have a smaller cap.
    let ids=decode_ids(&s,MAX_ENTRIES,24*1024)?;
    let index:BTreeSet<_>=ids.iter().cloned().collect();
    if ids.len()!=index.len(){return Err("corrupt_vault_index".into());}
    Ok(index)
}
fn store_index_into(store:&mut impl IndexStore,ids:&BTreeSet<String>)->Result<(),String>{
    if ids.len()>MAX_V2_ENTRIES {return Err("vault_entry_limit".into());}
    if ids.iter().any(|id|!valid_id(id)) {return Err("invalid_secret_id".into());}
    let serialized=serde_json::to_vec(ids).map_err(|_|"serialize_vault_index")?;
    let old_v2=store.read(INDEX_V2)?;
    // Preserve v1 byte format on old vaults until upgrading is necessary.
    if old_v2.is_none() && ids.len()<=MAX_ENTRIES && serialized.len()<=MAX_VALUE {
        return store.write(INDEX,&encode(&serialized));
    }
    let old_pages=old_v2.as_deref().map(v2_manifest).transpose()?.map_or(0,|(_,p)|p);
    let ordered=ids.iter().cloned().collect::<Vec<_>>();
    let pages=ordered.len().div_ceil(IDS_PER_PAGE);
    for (page,chunk) in ordered.chunks(IDS_PER_PAGE).enumerate() {
        let raw=serde_json::to_vec(chunk).map_err(|_|"serialize_vault_index")?;
        if raw.len()>MAX_VALUE {return Err("vault_index_page_too_large".into());}
        let key=page_key(page);
        let value=encode(&raw);
        if store.read(&key)?.as_deref()!=Some(value.as_str()) {store.write(&key,&value)?;}
    }
    // Only the fully prepared manifest makes v2 authoritative.
    let header=serde_json::to_vec(&json!({
        "format":2,"count":ordered.len(),"pages":pages
    })).map_err(|_|"serialize_vault_index")?;
    let marker=encode(&header);
    if old_v2.as_deref()!=Some(marker.as_str()) {store.write(INDEX_V2,&marker)?;}
    for page in pages..old_pages {store.delete(&page_key(page))?;}
    Ok(())
}
fn load_index(path:&Path,master:&[u8])->Result<BTreeSet<String>,String>{
    load_index_from(&KdbxIndex{path,master})
}
fn store_index(path:&Path,master:&[u8],ids:&BTreeSet<String>)->Result<(),String>{
    store_index_into(&mut KdbxIndex{path,master},ids)
}
pub(crate) fn transaction<T,F>(path:&Path,master:&[u8],action:F)->Result<T,String>
where F:FnOnce(&Path)->Result<T,String>{
    let folder=path.parent().ok_or("invalid_vault_directory")?;
    // Linux flock on the stable parent directory serializes all Secrets
    // writer transactions even when the KDBX inode changes by rename.
    // Never lock the KDBX inode: a rename would make that lock stale.
    let guard=File::open(folder).map_err(|_|"vault_directory_unavailable")?;
    let rc=unsafe { libc::flock(guard.as_raw_fd(),libc::LOCK_EX) };
    if rc!=0 {return Err("vault_transaction_lock_failed".into());}
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
    let value=decode_value(path,master,id,&encrypted)?;
    Ok(json!({"id":id,"value":value}))
}
// These inner operations are ONLY for paths held inside transaction().
// They must never be called on an installed KDBX outside that boundary.
pub(crate) fn put_in_transaction(path:&Path,master:&[u8],id:&str,value:&Value,update_only:bool)->Result<Value,String>{
    if !valid_id(id){return Err("invalid_secret_id".into());}
    let raw=serde_json::to_vec(value).map_err(|_|"invalid_secret_value")?;
    if raw.is_empty()||raw.len()>MAX_RECORD_BYTES {return Err("secret_value_out_of_range".into());}
    let mut index=load_index(path,master)?;
    let exists=index.contains(id);
    if update_only&&!exists {return Err("secret_not_found".into());}
    if !exists && index.len()>=MAX_V2_ENTRIES {return Err("vault_entry_limit".into());}
    let old_parts=if exists {
        let old=show(path,master,&record_key(id))?.ok_or("missing_indexed_secret")?;
        let metadata:Value=serde_json::from_slice(&decode(&old)?)
            .map_err(|_|"corrupt_encrypted_secret")?;
        parse_chunk_header(&metadata)?.map_or(0,|h|h.parts)
    } else {0};
    write_value(path,master,id,&raw,old_parts,exists)?;
    if !exists {index.insert(id.to_owned());store_index(path,master,&index)?;}
    Ok(json!({"id":id,"created":!exists,"updated":exists}))
}
pub(crate) fn delete_in_transaction(path:&Path,master:&[u8],id:&str)->Result<Value,String>{
    if !valid_id(id){return Err("invalid_secret_id".into());}
    let mut index=load_index(path,master)?;
    if !index.remove(id){return Err("secret_not_found".into());}
    let encoded=show(path,master,&record_key(id))?.ok_or("missing_indexed_secret")?;
    let old:Value=serde_json::from_slice(&decode(&encoded)?)
        .map_err(|_|"corrupt_encrypted_secret")?;
    let parts=parse_chunk_header(&old)?.map_or(0,|h|h.parts);
    remove(path,master,&record_key(id))?;
    for i in 0..parts {remove(path,master,&chunk_key(id,i))?;}
    store_index(path,master,&index)?;
    Ok(json!({"id":id,"deleted":true}))
}
pub fn put(path:&Path,master:&[u8],id:&str,value:&Value,update_only:bool)->Result<Value,String>{
    // All legacy one-record operations use the same vault-directory lock.
    transaction(path,master,|temp|put_in_transaction(temp,master,id,value,update_only))
}
pub fn delete(path:&Path,master:&[u8],id:&str)->Result<Value,String>{
    transaction(path,master,|temp|delete_in_transaction(temp,master,id))
}
#[cfg(test)]mod tests{
    use super::*;
    #[test]fn chunks_have_unforgeable_record_namespace(){
        for id in ["a","neebles-connect","long-record-42"] {
            assert!(valid_id(id));
            for i in [0,1,MAX_RECORD_PARTS-1] {
                assert!(!valid_id(&format!("{id}~chunk~{i:04}")));
                assert!(!chunk_key(id,i).eq(&record_key(id)));
            }
        }
    }
    #[test]fn chunk_manifest_is_strict_and_digest_is_detected(){
        let raw=serde_json::to_vec(&json!({"note":"X".repeat(20_000)})).unwrap();
        let info=new_chunk_header(&raw);
        assert_eq!(info.parts,raw.len().div_ceil(RECORD_CHUNK_BYTES));
        assert_eq!(parse_chunk_header(&header_json(&info)).unwrap(),Some(info.clone()));
        assert_eq!(parse_chunk_header(&json!({"normal":true})).unwrap(),None);
        for bad in [
            json!({"__neebles_kdbx_value_chunks_v2":2,"bytes":MAX_RECORD_BYTES+1,"parts":80,"sha256":info.digest}),
            json!({"__neebles_kdbx_value_chunks_v2":2,"bytes":raw.len(),"parts":1,"sha256":info.digest}),
            json!({"__neebles_kdbx_value_chunks_v2":2,"bytes":raw.len(),"parts":info.parts,"sha256":"a"}),
            json!({"__neebles_kdbx_value_chunks_v2":2,"bytes":raw.len(),"parts":info.parts,"sha256":info.digest,"leak":false}),
        ] {assert!(parse_chunk_header(&bad).is_err());}
        let mut tampered=raw.clone();tampered[10]^=1;
        assert_ne!(sha256_hex(&tampered),info.digest);
    }
    #[test]fn ids_are_bounded(){assert!(valid_id("connection-1"));for bad in ["../etc","CAP","","_neebles_secret_index_v1","hello/world","a--b"]{assert!(!valid_id(bad));}}
    #[test]fn encoded_record_roundtrip(){for input in [b"abc".as_slice(),b"{}\n".as_slice(),b"\0\xff\x12".as_slice()]{assert_eq!(decode(&encode(input)).unwrap(),input);}}
    #[test]fn malformed_base64_rejected(){for s in ["a","AAAA!","__B","="]{assert!(decode(s).is_err());}}
    // The index store is an abstraction over KeePassXC password entries.
    // These tests validate physical v2 paging decisions without Argon2 CLI cost.
    #[derive(Default)]
    struct MemoryIndex(std::collections::BTreeMap<String,String>);
    impl IndexStore for MemoryIndex {
        fn read(&self,key:&str)->Result<Option<String>,String>{Ok(self.0.get(key).cloned())}
        fn write(&mut self,key:&str,value:&str)->Result<(),String>{self.0.insert(key.to_owned(),value.to_owned());Ok(())}
        fn delete(&mut self,key:&str)->Result<(),String>{self.0.remove(key);Ok(())}
    }
    fn fixture_ids(count:usize)->BTreeSet<String>{
        (0..count).map(|n|format!("entry-{n:05}")).collect()
    }
    #[test]
    fn paged_index_migrates_legacy_without_erasing_v1() {
        let mut db=MemoryIndex::default();
        let original=fixture_ids(256);
        store_index_into(&mut db,&original).unwrap();
        let old=db.read(INDEX).unwrap().unwrap();
        assert!(db.read(INDEX_V2).unwrap().is_none());
        assert_eq!(load_index_from(&db).unwrap(),original);
        let enlarged=fixture_ids(1024);
        store_index_into(&mut db,&enlarged).unwrap();
        assert_eq!(db.read(INDEX).unwrap().unwrap(),old);
        assert_eq!(db.read(INDEX_V2).unwrap().is_some(),true);
        assert_eq!(load_index_from(&db).unwrap(),enlarged);
    }
    #[test]
    fn paged_index_handles_more_than_legacy_limit_and_prunes() {
        let mut db=MemoryIndex::default();
        for size in [257,1_024,2_048,31] {
            let ids=fixture_ids(size);
            store_index_into(&mut db,&ids).unwrap();
            assert_eq!(load_index_from(&db).unwrap(),ids);
            assert_eq!(v2_manifest(&db.read(INDEX_V2).unwrap().unwrap()).unwrap().1,
                size.div_ceil(IDS_PER_PAGE));
        }
        assert!(db.read(&page_key(30)).unwrap().is_none());
    }
    #[test]
    fn paged_index_fails_closed_on_missing_or_corrupt_pages() {
        let mut db=MemoryIndex::default();
        store_index_into(&mut db,&fixture_ids(321)).unwrap();
        let original=db.read(&page_key(2)).unwrap().unwrap();
        db.delete(&page_key(2)).unwrap();
        assert!(load_index_from(&db).is_err());
        db.write(&page_key(2),&original).unwrap();
        db.write(&page_key(2),&encode(b"[\"entry-00000\",\"entry-00000\"]")).unwrap();
        assert!(load_index_from(&db).is_err());
    }
    #[test]
    #[ignore = "requires a disposable Bubblewrap RootFS with genuine KeePassXC"]
    fn sprint_real_paged_index_kdbx_over_256() {
        assert_eq!(std::env::var("NEEBLES_F26V_SANDBOX").as_deref(),
            Ok("disposable-only"),"never run on host files");
        let home=PathBuf::from(std::env::var("HOME").expect("sandbox HOME"));
        assert_eq!(home,Path::new("/qa-data"),"strict scratch path");
        let path=home.join("scratch-v2-index.kdbx");
        assert!(!path.exists(),"refuse to overwrite even a sandbox fixture");
        let secret=b"disposable-index-v2-test-only";
        let options=[OsStr::new("db-create"),OsStr::new("-p"),path.as_os_str()];
        let (created,_)=keepass(&options,secret,Some("disposable-index-v2-test-only"),false).unwrap();
        assert!(created,"KeePassXC must create the scratch KDBX");
        let original=fixture_ids(256);
        store_index(&path,secret,&original).unwrap();
        assert_eq!(load_index(&path,secret).unwrap(),original);
        let expanded=fixture_ids(280);
        store_index(&path,secret,&expanded).unwrap();
        assert_eq!(load_index(&path,secret).unwrap(),expanded);
        let kdbx=fs::metadata(&path).unwrap();
        assert!(kdbx.is_file() && kdbx.len()>128);
        // No KDBX from a user profile is mounted into the test namespace.
        fs::remove_file(&path).unwrap();
    }
    #[test]
    fn legacy_v1_large_index_remains_readable_before_lazy_migration() {
        let mut db=MemoryIndex::default();
        let ids=(0..256).map(|n|format!("entry-{n:058}")).collect::<BTreeSet<_>>();
        let raw=serde_json::to_vec(&ids).unwrap();
        assert!(raw.len()>MAX_VALUE && raw.len()<24*1024);
        db.write(INDEX,&encode(&raw)).unwrap();
        assert_eq!(load_index_from(&db).unwrap(),ids);
        // Next write upgrades to the v2 marker but never discards legacy bytes.
        let old=db.read(INDEX).unwrap().unwrap();
        store_index_into(&mut db,&ids).unwrap();
        assert_eq!(db.read(INDEX).unwrap().unwrap(),old);
        assert!(db.read(INDEX_V2).unwrap().is_some());
    }
    #[test]
    fn paged_index_rejects_oversize_and_malformed_manifest() {
        let mut db=MemoryIndex::default();
        assert_eq!(store_index_into(&mut db,&fixture_ids(MAX_V2_ENTRIES+1)).unwrap_err(),"vault_entry_limit");
        assert!(db.0.is_empty());
        db.write(INDEX_V2,&encode(b"{\"format\":2,\"count\":100,\"pages\":0}")).unwrap();
        assert!(load_index_from(&db).is_err());
    }

}
