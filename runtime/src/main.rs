//! NEEBLES Secrets F10: session-local Quick generator and locked vault boundary.
//! No vault is opened, decrypted or written in F10. Never log generated secrets.
mod vault;
use vault::VaultController;
use std::sync::{Arc, Mutex};
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

const MAX_FRAME: usize = 16 * 1024;
const MAX_PASSWORD: usize = 128;
const MAX_RANDOM_BYTES: usize = 128;

#[cfg(target_os = "linux")]
unsafe extern "C" { fn geteuid() -> u32; }
fn uid() -> u32 { unsafe { geteuid() } }

fn rpc_read(stream: &mut impl Read) -> Result<Value, String> {
    let mut size = [0u8; 4];
    stream.read_exact(&mut size).map_err(|e| format!("IPC header: {e}"))?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_FRAME { return Err("IPC frame out of range".into()); }
    let mut content = vec![0u8; size];
    stream.read_exact(&mut content).map_err(|e| format!("IPC body: {e}"))?;
    let data: Value = serde_json::from_slice(&content).map_err(|_| "malformed JSON".to_string())?;
    if !data.is_object() { return Err("IPC expects a JSON object".into()); }
    Ok(data)
}
fn rpc_write(stream: &mut impl Write, response: &Value) -> Result<(), String> {
    let payload = serde_json::to_vec(response).map_err(|e| format!("serialize: {e}"))?;
    if payload.len() > MAX_FRAME || payload.is_empty() { return Err("response too large".into()); }
    stream.write_all(&(payload.len() as u32).to_be_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&payload).map_err(|e| e.to_string())?;
    Ok(())
}

// getrandom via the Linux kernel RNG, using the existing /dev/urandom interface.
// No fallback to timestamps, PRNGs seeded from clocks or process IDs.
fn crypto_bytes(count: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0u8; count];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|e| format!("kernel CSPRNG unavailable: {e}"))?;
    Ok(bytes)
}
fn pick_index(size: usize) -> Result<usize, String> {
    if size == 0 || size > 256 { return Err("invalid character set".into()); }
    // Rejection sampling: avoid modulo bias when alphabet size is not a divisor of 256.
    let limit = 256 - 256 % size;
    loop {
        let b = crypto_bytes(1)?[0] as usize;
        if b < limit { return Ok(b % size); }
    }
}
fn char_without_ambiguity(character: u8) -> bool {
    !b"0O1lI|".contains(&character)
}
fn password(input: &Value) -> Result<String, String> {
    let length = input.get("length").and_then(Value::as_u64).unwrap_or(24) as usize;
    if !(8..=MAX_PASSWORD).contains(&length) { return Err("password length must be 8..128".into()); }
    let groups = [
        ("lowercase", b"abcdefghijklmnopqrstuvwxyz".as_slice()),
        ("uppercase", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".as_slice()),
        ("numbers", b"0123456789".as_slice()),
        ("symbols", b"!@#$%^&*()-_=+[]{}:,.?".as_slice()),
    ];
    let avoid = input.get("exclude_ambiguous").and_then(Value::as_bool).unwrap_or(false);
    let mut active = Vec::<Vec<u8>>::new();
    for (key, alphabet) in groups {
        if input.get(key).and_then(Value::as_bool).unwrap_or(true) {
            let chars = alphabet.iter().copied()
                .filter(|c| !avoid || char_without_ambiguity(*c))
                .collect::<Vec<_>>();
            if chars.is_empty() { return Err("empty alphabet".into()); }
            active.push(chars);
        }
    }
    if active.is_empty() { return Err("select at least one character family".into()); }
    let combined: Vec<u8> = active.iter().flat_map(|v| v.iter().copied()).collect();
    let mut result: Vec<u8> = Vec::with_capacity(length);
    // Guarantee one character per enabled family, then shuffle all positions.
    for alphabet in &active { result.push(alphabet[pick_index(alphabet.len())?]); }
    while result.len() < length { result.push(combined[pick_index(combined.len())?]); }
    for i in (1..result.len()).rev() {
        let j = pick_index(i + 1)?;
        result.swap(i, j);
    }
    String::from_utf8(result).map_err(|e| format!("ASCII generation failed: {e}"))
}
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for b in bytes { result.push(HEX[(b >> 4) as usize] as char); result.push(HEX[(b & 15) as usize] as char); }
    result
}
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let a = bytes[pos];
        let b = bytes.get(pos + 1).copied().unwrap_or(0);
        let c = bytes.get(pos + 2).copied().unwrap_or(0);
        out.push(ALPHABET[(a >> 2) as usize] as char);
        out.push(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        if pos + 1 < bytes.len() { out.push(ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize] as char); }
        if pos + 2 < bytes.len() { out.push(ALPHABET[(c & 63) as usize] as char); }
        pos += 3;
    }
    out // RFC 4648 URL-safe, without padding.
}
fn uuid_v4() -> Result<String, String> {
    let mut bytes=crypto_bytes(16)?;
    bytes[6] = bytes[6] & 0x0f | 0x40;
    bytes[8] = bytes[8] & 0x3f | 0x80;
    let s=hex(&bytes);
    Ok(format!("{}-{}-{}-{}-{}", &s[0..8],&s[8..12],&s[12..16],&s[16..20],&s[20..32]))
}
fn generate(input: &Value) -> Result<Value, String> {
    let kind=input.get("kind").and_then(Value::as_str).unwrap_or("password");
    let result=match kind {
        "password" => password(input)?,
        "hex" | "base64url" => {
            let count = input.get("length").and_then(Value::as_u64).unwrap_or(32) as usize;
            if !(16..=MAX_RANDOM_BYTES).contains(&count) { return Err("random byte count must be 16..128".into()); }
            let bytes=crypto_bytes(count)?;
            if kind=="hex" {hex(&bytes)} else {base64url(&bytes)}
        },
        "uuid" => uuid_v4()?,
        _ => return Err("unsupported quick generator".into()),
    };
    Ok(json!({"kind":kind,"value":result,"stored":false}))
}
fn handle(input: &Value, state: &Arc<Mutex<VaultController>>) -> Value {
    let op=input.get("op").and_then(Value::as_str).unwrap_or("");
    let result:Result<Value,String>=match op {
        "quick.generate"=>generate(input),
        "status"|"vault.status"|"vault.setup"|"vault.unlock"|"vault.lock"|"vault.exists"|"vault.ensure"|"vault.request" => {
            match state.lock() {
                Ok(mut controller)=>match op {
                    "status"|"vault.status"=>controller.status(),
                    "vault.setup"=>controller.setup(input.get("password").and_then(Value::as_str).unwrap_or("")),
                    "vault.unlock"=>controller.unlock(input.get("password").and_then(Value::as_str).unwrap_or("")),
                    "vault.lock"=>Ok(controller.lock()),
                    "vault.exists"=>controller.exists(input.get("module").and_then(Value::as_str).unwrap_or("")),
                    "vault.ensure"=>controller.ensure(input.get("module").and_then(Value::as_str).unwrap_or("")),
                    "vault.request"=>controller.request(input.get("module").and_then(Value::as_str).unwrap_or("")),
                    _=>Err("unknown_operation".into()),
                },
                Err(_)=>Err("vault_state_unavailable".into()),
            }
        },
        "vault.list"|"secret.put"|"secret.get"|"secret.update"|"secret.delete"=>Err("operation_not_implemented".into()),
        _=>Err("unknown_operation".into()),
    };
    match result { Ok(data)=>json!({"ok":true,"data":data}),Err(error)=>json!({"ok":false,"error":error}) }
}
fn required_runtime_dir() -> Result<PathBuf,String> {
    let value=std::env::var_os("XDG_RUNTIME_DIR").ok_or("XDG_RUNTIME_DIR is required")?;
    let root=PathBuf::from(value);
    if !root.is_absolute() { return Err("XDG_RUNTIME_DIR must be absolute".into()); }
    let info=fs::symlink_metadata(&root).map_err(|e|format!("XDG_RUNTIME_DIR: {e}"))?;
    if !info.is_dir() || info.file_type().is_symlink() || info.uid()!=uid()
       || info.permissions().mode() & 0o077 != 0 {
        return Err("insecure XDG_RUNTIME_DIR ownership or mode".into());
    }
    Ok(root)
}
fn socket_path() -> Result<PathBuf,String> {
    Ok(required_runtime_dir()?.join("neebles-secrets").join("secrets.sock"))
}
fn validate_private_dir(path: &Path) -> Result<(),String> {
    let m=fs::symlink_metadata(path).map_err(|e|e.to_string())?;
    if !m.is_dir() || m.file_type().is_symlink() || m.uid()!=uid() || m.permissions().mode() & 0o077!=0 {
        return Err("invalid socket directory ownership or mode".into());
    }
    Ok(())
}
fn serve_one(mut stream: UnixStream, state: Arc<Mutex<VaultController>>) -> Result<(),String> {
    stream.set_read_timeout(Some(Duration::from_secs(45))).map_err(|e|e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(45))).map_err(|e|e.to_string())?;
    let request=rpc_read(&mut stream)?;
    let response=handle(&request,&state);
    rpc_write(&mut stream,&response)
}
fn serve() -> Result<(),String> {
    let path=socket_path()?;
    let dir=path.parent().ok_or("socket parent missing")?;
    if !dir.exists() {
        fs::create_dir(dir).map_err(|e|format!("cannot create socket directory: {e}"))?;
        fs::set_permissions(dir,fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())?;
    }
    validate_private_dir(dir)?;
    if path.exists() {
        if UnixStream::connect(&path).is_ok() { return Err("Secrets service already running".into()); }
        let m=fs::symlink_metadata(&path).map_err(|e|e.to_string())?;
        if !m.file_type().is_socket() || m.uid()!=uid() { return Err("unsafe stale socket".into()); }
        fs::remove_file(&path).map_err(|e|format!("stale socket: {e}"))?;
    }
    let state=Arc::new(Mutex::new(VaultController::new()?));
    let listener=UnixListener::bind(&path).map_err(|e|format!("bind: {e}"))?;
    fs::set_permissions(&path,fs::Permissions::from_mode(0o600)).map_err(|e|format!("chmod: {e}"))?;
    eprintln!("NEEBLES Secrets F14: user session service available");
    for client in listener.incoming() {
        match client {
            Ok(stream) => { let shared=Arc::clone(&state); std::thread::spawn(move || { if let Err(e)=serve_one(stream,shared) { eprintln!("Secrets IPC transport: {e}"); } }); },
            Err(e) => eprintln!("Secrets socket accept: {e}"),
        }
    }
    Ok(())
}
fn request(input: &Value) -> Result<Value,String> {
    let mut stream=UnixStream::connect(socket_path()?).map_err(|e|format!("Secrets service unavailable: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e|e.to_string())?;
    rpc_write(&mut stream,input)?;
    rpc_read(&mut stream)
}
// F30: systemd --user ExecStart stays module-owned and unchanged. The wrapper
// re-enters the pinned installed KeePass rootfs before the socket is bound.
// No KeePass package is installed in the host. No new master vault is made.
fn serve_from_certified_world() -> Result<(), String> {
    if std::env::var_os("NEEBLES_SECRETS_INSIDE_WORLD").as_deref()
        == Some(std::ffi::OsStr::new("1")) {
        return serve();
    }
    if uid() == 0 {
        return Err("Secrets service must run as the desktop user, not root".into());
    }
    let module = Path::new("/opt/neebles/modules/neebles-secrets");
    let manifest = module.join("manifest.json");
    let data:Value = serde_json::from_slice(
        &fs::read(&manifest).map_err(|_|"installed Secrets manifest unavailable")?
    ).map_err(|_|"invalid installed Secrets manifest")?;
    if data.get("schema").and_then(Value::as_u64) != Some(4)
        || data.get("name").and_then(Value::as_str) != Some("neebles-secrets")
        || data.get("entrypoint").and_then(Value::as_str) != Some("runtime/neebles-secrets-ui") {
        return Err("installed Secrets module identity is invalid".into());
    }
    // Boss already stages and verifies each named module rootfs on publication.
    // F30 consumes ONLY the selected installed KeePass material, not host apt.
    let world = module.join("rootfs/keepass-full/rootfs");
    let cli = world.join("usr/bin/keepassxc-cli");
    let cli_meta = fs::symlink_metadata(&cli)
        .map_err(|_|"certified KeePass world has no keepassxc-cli")?;
    if !cli_meta.is_file() || cli_meta.file_type().is_symlink() {
        return Err("certified KeePass executable must be a regular file".into());
    }
    let runtime = required_runtime_dir()?;
    let home = PathBuf::from(std::env::var_os("HOME")
        .ok_or("HOME is required for the desktop vault storage")?);
    if !home.is_absolute() {
        return Err("desktop HOME must be absolute".into());
    }
    let home_meta = fs::symlink_metadata(&home)
        .map_err(|_|"desktop HOME is not accessible")?;
    if !home_meta.is_dir() || home_meta.file_type().is_symlink()
        || home_meta.uid() != uid() {
        return Err("desktop HOME ownership or type is invalid".into());
    }
    let user_data = home.join(".local/share/neebles-secrets");
    if !user_data.exists() {
        fs::create_dir_all(&user_data)
            .map_err(|_|"cannot create Secrets data directory")?;
        fs::set_permissions(&user_data,fs::Permissions::from_mode(0o700))
            .map_err(|_|"cannot secure Secrets data directory")?;
    }
    let data_meta = fs::symlink_metadata(&user_data)
        .map_err(|_|"Secrets data directory cannot be inspected")?;
    if !data_meta.is_dir() || data_meta.file_type().is_symlink()
        || data_meta.uid() != uid() || data_meta.permissions().mode() & 0o077 != 0 {
        return Err("Secrets data directory must be owned and private (0700)".into());
    }
    let mut cmd = Command::new("/usr/bin/bwrap");
    cmd.arg("--die-with-parent")
        .arg("--clearenv")
        // F35: temporary writable namespace root; only certified runtime trees
        // are bind-mounted read-only. F30 ro-bound "/" before creating /opt.
        .arg("--tmpfs").arg("/")
        .arg("--ro-bind").arg(world.join("usr")).arg("/usr")
        .arg("--ro-bind").arg(world.join("etc")).arg("/etc")
        .arg("--ro-bind").arg(world.join("var")).arg("/var")
        .arg("--symlink").arg("usr/bin").arg("/bin")
        .arg("--symlink").arg("usr/sbin").arg("/sbin")
        .arg("--symlink").arg("usr/lib").arg("/lib")
        .arg("--symlink").arg("/usr/lib/x86_64-linux-gnu").arg("/lib64")
        .arg("--dev").arg("/dev")
        .arg("--proc").arg("/proc")
        .arg("--tmpfs").arg("/tmp")
        .arg("--dir").arg("/opt")
        .arg("--dir").arg("/opt/neebles")
        .arg("--dir").arg("/opt/neebles/modules")
        .arg("--ro-bind").arg(module).arg(module)
        .arg("--dir").arg("/run")
        .arg("--dir").arg("/run/user")
        .arg("--bind").arg(&runtime).arg(&runtime)
        .arg("--dir").arg("/vault-data")
        .arg("--bind").arg(&user_data).arg("/vault-data/neebles-secrets")
        .arg("--dir").arg("/home")
        .arg("--dir").arg("/home/neebles")
        .arg("--setenv").arg("HOME").arg("/home/neebles")
        .arg("--setenv").arg("XDG_DATA_HOME").arg("/vault-data")
        .arg("--setenv").arg("XDG_RUNTIME_DIR").arg(&runtime)
        .arg("--setenv").arg("NEEBLES_SECRETS_INSIDE_WORLD").arg("1")
        .arg("--chdir").arg("/home/neebles")
        .arg(module.join("runtime/neebles-secrets"))
        .arg("--serve");
    // Remain the systemd main process until the daemon exits, so failures
    // reach Restart=on-failure. The internal daemon still owns the socket.
    let status = cmd.status()
        .map_err(|e|format!("cannot enter certified KeePass runtime: {e}"))?;
    if status.success() { Ok(()) }
    else { Err(format!("certified Secrets daemon exited: {status}")) }
}

fn main_run() -> Result<(),String> {
    let args:Vec<String>=std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd] if cmd=="--serve" => serve_from_certified_world(),
        [cmd] if cmd=="--status" => {
            // Status contains no secrets and is suitable for shell smoke checks.
            let value=request(&json!({"op":"status"}))?;
            println!("{value}");Ok(())
        },
        [cmd] if cmd=="--self-test" => {
            let val=generate(&json!({"kind":"password","length":32,"symbols":true}))?;
            if val["value"].as_str().map(str::len)!=Some(32) {return Err("Quick self-test failed".into());}
            println!("Quick RNG smoke: PASS (value hidden)");Ok(())
        },
        _ => Err("usage: neebles-secrets --serve | --status | --self-test".into()),
    }
}
fn main()->ExitCode {
    match main_run() { Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("NEEBLES Secrets: {e}");ExitCode::FAILURE} }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn frame_roundtrip(){let mut data=Vec::new();rpc_write(&mut data,&json!({"op":"status"})).unwrap(); assert_eq!(rpc_read(&mut data.as_slice()).unwrap()["op"],"status");}
    #[test] fn rejected_unknown_operation(){assert_eq!(json!({"ok":false})["ok"],false);}
    #[test] fn quick_password_all_groups(){let v=generate(&json!({"kind":"password","length":64,"lowercase":true,"uppercase":true,"numbers":true,"symbols":true})).unwrap();let s=v["value"].as_str().unwrap();assert_eq!(s.len(),64);assert!(s.bytes().any(|c|c.is_ascii_lowercase()));assert!(s.bytes().any(|c|c.is_ascii_uppercase()));assert!(s.bytes().any(|c|c.is_ascii_digit()));assert!(s.bytes().any(|c|!c.is_ascii_alphanumeric()));}
    #[test] fn quick_validation(){assert!(generate(&json!({"kind":"password","length":4})).is_err()); assert!(generate(&json!({"kind":"password","lowercase":false,"uppercase":false,"numbers":false,"symbols":false})).is_err()); assert!(generate(&json!({"kind":"ed25519"})).is_err());}
    #[test] fn quick_uuid(){let s=uuid_v4().unwrap();assert_eq!(s.len(),36);assert_eq!(&s[14..15],"4");assert!(matches!(&s[19..20],"8"|"9"|"a"|"b"));}
    #[test] fn quick_token_lengths(){assert_eq!(generate(&json!({"kind":"hex","length":16})).unwrap()["value"].as_str().unwrap().len(),32); assert_eq!(generate(&json!({"kind":"base64url","length":16})).unwrap()["value"].as_str().unwrap().len(),22);}
}
