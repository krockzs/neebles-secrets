//! NEEBLES Secrets governed UI bridge (F16).
//! This is NOT the Keys daemon. Closing Qt only ends this governed UI session.
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

const MODULE: &str = "neebles-secrets";
const SOCKET: &str = "/run/neebles/modules.sock";
const MAX_FRAME: usize = 16 * 1024 * 1024;
static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn prctl(option: i32, a: usize, b: usize, c: usize, d: usize) -> i32;
    fn signal(signal: i32, handler: extern "C" fn(i32)) -> usize;
    fn kill(pid: i32, signal: i32) -> i32;
}
extern "C" fn on_signal(_: i32) { STOP.store(true, Ordering::Relaxed); }

fn write_frame<W: Write>(writer: &mut W, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME { return Err("IPC outgoing frame out of range".into()); }
    writer.write_all(&(bytes.len() as u32).to_be_bytes()).map_err(|e| e.to_string())?;
    writer.write_all(&bytes).map_err(|e| e.to_string())
}
fn read_frame<R: Read>(reader: &mut R) -> Result<Value, String> {
    let mut header=[0u8;4];
    reader.read_exact(&mut header).map_err(|e| format!("IPC header: {e}"))?;
    let n=u32::from_be_bytes(header) as usize;
    if n==0 || n>MAX_FRAME {return Err("IPC incoming frame out of range".into());}
    let mut bytes=vec![0u8;n];
    reader.read_exact(&mut bytes).map_err(|e|format!("IPC body: {e}"))?;
    let value:Value=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;
    if !value.is_object(){return Err("IPC expected object".into());}
    Ok(value)
}
fn check_identity(value:&Value,session:&str) -> Result<(),String> {
    if let Some(module)=value.get("module") {if module.as_str()!=Some(MODULE) {return Err("foreign module".into());}}
    if let Some(id)=value.get("session_id") {if id.as_str()!=Some(session){return Err("foreign session".into());}}
    Ok(())
}
fn require_message(value:&Value,session:&str,kind:&str) -> Result<(),String> {
    check_identity(value,session)?;
    if value.get("type").and_then(Value::as_str)!=Some(kind){return Err(format!("unexpected Boss response: expected {kind}"));}
    Ok(())
}
fn session_id()->Result<String,String>{
    let mut b=[0u8;16];
    File::open("/dev/urandom").and_then(|mut f|f.read_exact(&mut b)).map_err(|e|e.to_string())?;
    b[6]=(b[6]&0x0f)|0x40;b[8]=(b[8]&0x3f)|0x80;
    let mut s=String::with_capacity(36);
    for (i,v) in b.iter().enumerate(){if [4,6,8,10].contains(&i){s.push('-');}s.push_str(&format!("{v:02x}"));}
    Ok(s)
}
fn module_root()->Result<PathBuf,String>{
    let exe=std::env::current_exe().map_err(|e|e.to_string())?;
    let runtime=exe.parent().ok_or("runtime parent missing")?;
    let root=runtime.parent().ok_or("module parent missing")?;
    let m:Value=serde_json::from_slice(&fs::read(root.join("manifest.json")).map_err(|e|e.to_string())?)
        .map_err(|e|e.to_string())?;
    if m.get("name").and_then(Value::as_str)!=Some(MODULE)
        ||m.get("version").and_then(Value::as_str)!=Some("1.0.0")
        ||m.get("entrypoint").and_then(Value::as_str)!=Some("runtime/neebles-secrets-ui") {
        return Err("installed Secrets identity mismatch".into());
    }
    Ok(root.to_path_buf())
}
fn desktop_binary(root:&Path)->Result<PathBuf,String>{
    let p=root.join("bin/neebles-secrets-desktop");
    let m=fs::symlink_metadata(&p).map_err(|e|format!("Secrets Qt executable missing: {e}"))?;
    if !m.is_file()||m.file_type().is_symlink(){return Err("invalid Secrets Qt executable".into());}
    use std::os::unix::fs::PermissionsExt;
    if m.permissions().mode()&0o111==0{return Err("Qt binary not executable".into());}
    let mut magic=[0u8;4];
    File::open(&p).and_then(|mut f|f.read_exact(&mut magic)).map_err(|e|e.to_string())?;
    if &magic!=b"\x7fELF"{return Err("Qt binary is not ELF".into());}
    Ok(p)
}
fn spawn_qt(root:&Path)->Result<Child,String>{
    let mut cmd=Command::new(desktop_binary(root)?);
    cmd.current_dir(root).env_remove("NEEBLES_MODULES_SOCKET");
    #[cfg(target_os="linux")]
    unsafe {cmd.pre_exec(||{
        if prctl(1,15,0,0,0)!=0{return Err(std::io::Error::last_os_error());}
        Ok(())
    });}
    cmd.spawn().map_err(|e|format!("Secrets Qt launch: {e}"))
}
fn stop_child(child:&mut Child){
    if let Ok(Some(_))=child.try_wait(){return;}
    #[cfg(target_os="linux")]
    unsafe {let _=kill(child.id() as i32,15);}
    let deadline=Instant::now()+Duration::from_secs(3);
    while Instant::now()<deadline {
        if let Ok(Some(_))=child.try_wait(){return;}
        thread::sleep(Duration::from_millis(40));
    }
    let _=child.kill();let _=child.wait();
}
fn run()->Result<(),String>{
    let args:Vec<String>=std::env::args().skip(1).collect();
    if args.len()!=2||args[0]!="--intent"||args[1]!="open"{return Err("usage: neebles-secrets-ui --intent open".into());}
    if std::env::var("NEEBLES_MODULE").unwrap_or_else(|_|MODULE.into())!=MODULE{return Err("governor module mismatch".into());}
    let root=module_root()?;
    desktop_binary(&root)?;
    let session=session_id()?;
    let socket=std::env::var("NEEBLES_MODULES_SOCKET").unwrap_or_else(|_|SOCKET.into());
    if !socket.starts_with('/') {return Err("Boss IPC socket must be absolute".into());}
    let mut writer=UnixStream::connect(&socket).map_err(|e|format!("Boss module IPC unavailable: {e}"))?;
    writer.set_read_timeout(Some(Duration::from_secs(12))).map_err(|e|e.to_string())?;
    write_frame(&mut writer,&json!({"type":"register","protocol":1,"module":MODULE,"session_id":session,"endpoints":{"commands":[]}}))?;
    let registered=read_frame(&mut writer)?;
    if registered.get("type").and_then(Value::as_str)==Some("error") {
        let details=registered.get("error").and_then(|e|e.get("message"))
            .and_then(Value::as_str).unwrap_or("Boss rejected registration without reason");
        return Err(format!("Boss rejected Secrets IPC registration: {details}"));
    }
    require_message(&registered,&session,"registered")?;
    if registered.get("protocol").and_then(Value::as_u64)!=Some(1){return Err("Boss IPC protocol mismatch".into());}
    let topics=["module.lifecycle","settings.neebles-secrets"];
    write_frame(&mut writer,&json!({"type":"subscribe","module":MODULE,"session_id":session,"topics":topics}))?;
    let subscribed=read_frame(&mut writer)?;
    require_message(&subscribed,&session,"subscribed")?;
    let accepted=subscribed.get("topics").and_then(Value::as_array).ok_or("missing subscribed topics")?;
    if accepted.len()!=topics.len() || !topics.iter().all(|t|accepted.iter().any(|v|v.as_str()==Some(t))) {
        return Err("Boss rejected subscriptions".into());
    }
    writer.set_read_timeout(None).map_err(|e|e.to_string())?;
    let mut reader=writer.try_clone().map_err(|e|e.to_string())?;
    let (tx,rx)=mpsc::channel::<Result<Value,String>>();
    thread::spawn(move||loop{
        let message=read_frame(&mut reader);
        let failed=message.is_err();
        if tx.send(message).is_err()||failed{break;}
    });
    STOP.store(false,Ordering::Relaxed);
    #[cfg(target_os="linux")]
    unsafe {signal(15,on_signal);signal(2,on_signal);}
    let mut qt=spawn_qt(&root)?;
    let mut unregister=true;
    let mut failure:Option<String>=None;
    loop {
        if STOP.load(Ordering::Relaxed){break;}
        match qt.try_wait(){Ok(Some(_))=>break,Ok(None)=>{},Err(e)=>{failure=Some(format!("Qt status: {e}"));break;}}
        match rx.recv_timeout(Duration::from_millis(150)){
            Ok(Ok(msg))=>{
                if let Err(e)=check_identity(&msg,&session){failure=Some(e);break;}
                match msg.get("type").and_then(Value::as_str){
                    Some("ping")=>{if let Err(e)=write_frame(&mut writer,&json!({"type":"pong","module":MODULE,"session_id":session})){failure=Some(e);break;}},
                    Some("shutdown")=>{
                        if let Err(e)=write_frame(&mut writer,&json!({"type":"shutdown_ack","module":MODULE,"session_id":session})){failure=Some(e);}
                        unregister=false;break;
                    },
                    Some("event")|Some("notification_closed")=>{},
                    Some("error")=>{failure=Some(format!("Boss IPC error: {msg}"));break;},
                    _=>{failure=Some(format!("unexpected Boss IPC message: {msg}"));break;},
                }
            },
            Ok(Err(e))=>{failure=Some(e);break;},
            Err(RecvTimeoutError::Timeout)=>{},
            Err(RecvTimeoutError::Disconnected)=>{failure=Some("Boss IPC disconnected".into());break;},
        }
    }
    stop_child(&mut qt);
    if unregister {
        if let Err(e)=write_frame(&mut writer,&json!({"type":"unregister","module":MODULE,"session_id":session,"reason":"runtime_exit"})){
            if failure.is_none(){failure=Some(e);}
        }
    }
    if let Some(e)=failure {return Err(e);}
    Ok(())
}
fn main()->ExitCode{
    match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("NEEBLES Secrets UI: {e}");ExitCode::FAILURE}}
}
#[cfg(test)] mod tests{
    use super::*;
    #[test] fn frame_roundtrip(){let mut out=Vec::new();let v=json!({"type":"ping","module":MODULE});write_frame(&mut out,&v).unwrap();assert_eq!(read_frame(&mut out.as_slice()).unwrap(),v);}
    #[test] fn rejects_foreign_session(){assert!(check_identity(&json!({"module":"other"}),"ok").is_err());assert!(check_identity(&json!({"session_id":"bad"}),"ok").is_err());}
    #[test] fn uuid_shape(){let s=session_id().unwrap();assert_eq!(s.len(),36);assert_eq!(&s[14..15],"4");}
}
