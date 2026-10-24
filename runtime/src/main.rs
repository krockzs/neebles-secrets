//! NEEBLES Secrets 1.0.3: brokered IPC, personal KDBX and isolated crypto lab.
//! No vault is opened, decrypted or written in F10. Never log generated secrets.
mod vault;
// F26-L: durable journal for idempotent, scoped vault requests (not publicly advertised).
mod vault_request_journal;
mod vault_records;
mod backup_sessions;
mod restore_sessions;
#[allow(dead_code)]
mod restore_transaction;
mod ipc_bridge;
mod boss_publisher;
// F26-B: inert until the certified manifest/lifecycle migrates to the daemon entrypoint.
#[allow(dead_code)]
mod boss_health;
#[allow(dead_code)]
mod boss_runtime;
mod boss_scope;
// F26-J: identity-scoped FD handoff to the isolated KDBX worker.
mod boss_vault_bridge;
mod crypto_lab;
mod batch_generator;
mod portable_exports;
use vault::VaultController;
use std::sync::{Arc, Mutex};
use serde_json::{json, Value};
use std::fs::{self, File};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::Stdio;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

const MAX_FRAME: usize = 16 * 1024;
const MAX_PASSWORD: usize = 512;
const MAX_RANDOM_BYTES: usize = 512;

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
    if size == 0 || size > 4096 { return Err("invalid character set".into()); }
    // Uniform rejection sampling also supports password shuffles > 256 bytes.
    let span = 1u64 << 32;
    let limit = span - (span % size as u64);
    loop {
        let data=crypto_bytes(4)?;
        let value=u32::from_le_bytes([data[0],data[1],data[2],data[3]]) as u64;
        if value < limit { return Ok((value % size as u64) as usize); }
    }
}
fn char_without_ambiguity(character: u8) -> bool {
    !b"0O1lI|".contains(&character)
}
fn password(input: &Value) -> Result<String, String> {
    let length = input.get("length").and_then(Value::as_u64).unwrap_or(24) as usize;
    if !(8..=MAX_PASSWORD).contains(&length) { return Err("password length must be 8..512".into()); }
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
        "hex" | "base64url" | "base64" | "salt" | "pepper" | "key" => {
            let count = input.get("length").and_then(Value::as_u64).unwrap_or(32) as usize;
            if !(16..=MAX_RANDOM_BYTES).contains(&count) { return Err("random byte count must be 16..512".into()); }
            let bytes=crypto_bytes(count)?;
            match kind {
                "hex" | "salt" | "pepper" | "key" => hex(&bytes),
                "base64url" => base64url(&bytes),
                "base64" => base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes),
                _ => unreachable!(),
            }
        },
        "uuid" => uuid_v4()?,
        _ => return Err("unsupported quick generator".into()),
    };
    Ok(json!({"kind":kind,"value":result,"stored":false}))
}
// Secrets 1.0.2: never authorize secret retrieval by a client-supplied module
// string. Resolve the local peer's kernel identity and its installed executable.
// Only canonical, root-owned module binaries are accepted as secret clients.
// The system's same-UID user can still control their own files/processes;
// this is an installed-module provenance check, not a cross-UID sandbox.
#[repr(C)]
struct Ucred { pid:i32, uid:u32, gid:u32 }
unsafe extern "C" {
    fn getsockopt(fd:i32, level:i32, optname:i32, value:*mut std::ffi::c_void, len:*mut u32)->i32;
}
fn peer_module(stream:&UnixStream)->Result<String,String>{
    let mut cred=Ucred{pid:0,uid:0,gid:0};
    let mut len=std::mem::size_of::<Ucred>() as u32;
    // Linux SOL_SOCKET=1, SO_PEERCRED=17.
    let rc=unsafe{getsockopt(stream.as_raw_fd(),1,17,
        (&mut cred as *mut Ucred).cast(),&mut len)};
    if rc!=0 || len as usize!=std::mem::size_of::<Ucred>() || cred.pid<=0 || cred.uid!=uid(){
        return Err("unauthenticated_secret_peer".into());
    }
    let exe=fs::read_link(format!("/proc/{}/exe",cred.pid))
        .map_err(|_|"secret_peer_executable_unavailable")?;
    let root=Path::new("/opt/neebles/modules");
    let relative=exe.strip_prefix(root).map_err(|_|"secret_peer_outside_modules")?;
    let parts=relative.components().collect::<Vec<_>>();
    if parts.len()!=3 {return Err("invalid_secret_peer_executable".into());}
    let name=parts[0].as_os_str().to_str().ok_or("invalid_secret_peer_executable")?;
    let group=parts[1].as_os_str();
    let binary=parts[2].as_os_str().to_str().ok_or("invalid_secret_peer_executable")?;
    if name.is_empty() || name=="general" || name.len()>64
       || !name.as_bytes()[0].is_ascii_lowercase()
       || !name.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-')
       || name.ends_with('-')||name.contains("--"){
        return Err("invalid_secret_peer_module".into());
    }
    let is_runtime=group==OsStr::new("runtime") && binary==name;
    let is_desktop=group==OsStr::new("bin") && binary==format!("{name}-desktop");
    // The Secrets Qt desktop is a first-party self-client. Only that installed
    // ELF may address vault-general; Secrets' runtime must not gain UI authority.
    if name == "neebles-secrets" {
        if !is_desktop {return Err("invalid_secrets_personal_client".into());}
    } else if !is_runtime && !is_desktop {
        return Err("unexpected_secret_peer_binary".into());
    }
    let meta=fs::symlink_metadata(&exe).map_err(|_|"secret_peer_binary_unavailable")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.uid()!=0
       || meta.permissions().mode()&0o022!=0 || meta.permissions().mode()&0o111==0{
        return Err("untrusted_secret_peer_binary".into());
    }
    let manifest=root.join(name).join("manifest.json");
    let meta=fs::symlink_metadata(&manifest).map_err(|_|"secret_peer_module_not_installed")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.uid()!=0 || meta.permissions().mode()&0o022!=0 {
        return Err("untrusted_secret_peer_manifest".into());
    }
    let data:Value=serde_json::from_slice(&fs::read(&manifest).map_err(|_|"secret_peer_manifest_unavailable")?)
        .map_err(|_|"invalid_secret_peer_manifest")?;
    if data.get("schema").and_then(Value::as_u64)!=Some(4)
       || data.get("name").and_then(Value::as_str)!=Some(name) {
        return Err("invalid_secret_peer_module_identity".into());
    }
    Ok(name.to_owned())
}
fn authorized_personal_peer(peer: Option<&str>) -> bool {
    // This value is assigned exclusively by the external SO_PEERCRED broker;
    // incoming JSON cannot claim it. The broker verifies the root-owned Qt ELF.
    peer == Some("neebles-secrets")
}
// F15: operation-level authorization. The broker verifies executable provenance
// via SO_PEERCRED and carries peer identity over the private SCM_RIGHTS channel.
// A request's JSON "module" field is never an authentication credential.
fn authorize_vault_operation(
    op: &str,
    peer: Option<&str>,
    requested_module: Option<&str>,
) -> Result<(), &'static str> {
    match op {
        // Flags only; Boss publisher and diagnostics do not need module authority.
        "status" | "vault.status" => Ok(()),
        // Setup, unlocking and locking belong to the installed Secrets desktop.
        "vault.setup" | "vault.unlock" | "vault.lock" => {
            if authorized_personal_peer(peer) { Ok(()) }
            else { Err("vault_control_forbidden") }
        },
        // A consumer can query/create/request only ITS OWN namespaced KDBX.
        // Secrets' desktop is not a consumer and must not impersonate another module.
        "vault.exists" | "vault.ensure" | "vault.request" | "vault.request_id" | "vault.request_status" => {
            match (peer, requested_module) {
                (Some(caller), Some(target))
                    if caller == target && caller != "neebles-secrets" => Ok(()),
                _ => Err("vault_module_identity_mismatch"),
            }
        },
        _ => Err("unknown_operation"),
    }
}

// This classification is a defense-in-depth inventory used by regression
// checks. Per-operation authorization is enforced in handle(), not here.
fn is_sensitive_operation(op:&str)->bool {
    matches!(op,"vault.setup"|"vault.unlock"|"vault.lock"|"vault.exists"|"vault.ensure"|"vault.request"|"vault.request_id"|"vault.request_status"
        |"vault.list"|"secret.list"|"secret.put"|"secret.get"|"secret.update"|"secret.delete"
        |"general.list"|"general.get"|"general.put"|"general.update"|"general.delete"|"crypto.compute"|"batch.generate"
        |"backup.catalog"|"backup.open"|"backup.read"|"backup.close"
        |"portable.begin"|"portable.append"|"portable.seal"|"portable.read"|"portable.close"
        |"restore.start"|"restore.chunk"|"restore.validate"|"restore.abort"|"restore.queue"|"restore.plan"|"restore.discard"|"restore.commit")
}
fn handle(input: &Value, peer:Option<&str>, state: &Arc<Mutex<VaultController>>) -> Value {
    let op=input.get("op").and_then(Value::as_str).unwrap_or("");
    let result:Result<Value,String>=match op {
        "quick.generate"=>generate(input),
        "crypto.compute" => {
            if !authorized_personal_peer(peer) {Err("crypto_lab_forbidden".into())}
            else {crypto_lab::compute(input)}
        },
        "batch.generate" => {
            // Batch output is ephemeral and restricted to Secrets' own Qt UI.
            // Every response fits the existing 16 KiB IPC frame.
            if !authorized_personal_peer(peer) {Err("batch_generator_forbidden".into())}
            else {batch_generator::generate_batch(input)}
        },
        "status"|"vault.status"|"vault.setup"|"vault.unlock"|"vault.lock"|"vault.exists"|"vault.ensure"|"vault.request"|"vault.request_id"|"vault.request_status" => {
            // Fail closed BEFORE locking VaultController or running any mutation.
            // In particular an anonymous local socket caller cannot lock the UI,
            // select an initial Master Key or provision another module's vault.
            match authorize_vault_operation(op, peer, input.get("module").and_then(Value::as_str)) {
                Err(error) => Err(error.into()),
                Ok(()) => {
                    // F26-N: idempotent requests use a minimal worker envelope.
                    // Reject added password/peer/caller fields before acquiring the vault lock.
                    let versioned = matches!(op, "vault.request_id" | "vault.request_status");
                    let envelope_valid = !versioned || input.as_object().is_some_and(|fields| {
                        fields.len() == 3 && fields.contains_key("op")
                            && fields.get("module").and_then(Value::as_str).is_some()
                            && fields.get("request_id").and_then(Value::as_str).is_some()
                    });
                    if !envelope_valid {
                        Err("invalid_vault_request_envelope".into())
                    } else { match state.lock() {
                    Ok(mut controller)=>match op {
                        "status"|"vault.status"=>controller.status(),
                        "vault.setup"=>controller.setup(input.get("password").and_then(Value::as_str).unwrap_or("")),
                        "vault.unlock"=>controller.unlock(input.get("password").and_then(Value::as_str).unwrap_or("")),
                        "vault.lock"=>Ok(controller.lock()),
                        "vault.exists"=>controller.exists(input.get("module").and_then(Value::as_str).unwrap_or("")),
                        "vault.ensure"=>controller.ensure(input.get("module").and_then(Value::as_str).unwrap_or("")),
                        "vault.request"=>controller.request(input.get("module").and_then(Value::as_str).unwrap_or("")),
                        "vault.request_id"=>controller.request_with_id(
                            input.get("module").and_then(Value::as_str).unwrap_or(""),
                            input.get("request_id").and_then(Value::as_str).unwrap_or("")),
                        "vault.request_status"=>controller.request_status_with_id(
                            input.get("module").and_then(Value::as_str).unwrap_or(""),
                            input.get("request_id").and_then(Value::as_str).unwrap_or("")),
                        _=>Err("unknown_operation".into()),
                    },
                    Err(_)=>Err("vault_state_unavailable".into()),
                }}},
            }
        },
        "portable.begin"|"portable.append"|"portable.seal"|"portable.read"|"portable.close" => {
            if !authorized_personal_peer(peer){Err("portable_export_forbidden".into())}
            else {
                match state.lock(){
                    Ok(mut controller)=>match op {
                        "portable.begin"=>controller.portable_begin(input.get("passphrase").and_then(Value::as_str).unwrap_or("")),
                        "portable.append"=>controller.portable_append(input.get("token").and_then(Value::as_str).unwrap_or(""),input.get("value").and_then(Value::as_str).unwrap_or("")),
                        "portable.seal"=>controller.portable_seal(input.get("token").and_then(Value::as_str).unwrap_or("")),
                        "portable.read"=>{
                            let offset=input.get("offset").and_then(Value::as_u64).unwrap_or(u64::MAX);
                            let count=input.get("count").and_then(Value::as_u64).unwrap_or(u64::MAX);
                            if count>6144 || offset==u64::MAX{Err("portable_chunk_invalid".into())}
                            else {controller.portable_read(input.get("token").and_then(Value::as_str).unwrap_or(""),offset,count as usize)}
                        },
                        "portable.close"=>controller.portable_close(input.get("token").and_then(Value::as_str).unwrap_or("")),
                        _=>Err("unknown_operation".into()),
                    },
                    Err(_)=>Err("vault_state_unavailable".into()),
                }
            }
        },
        "backup.catalog"|"backup.open"|"backup.read"|"backup.close" => {
            // Only the root-owned installed Secrets desktop can stream encrypted
            // KDBX bytes. A consumer can never list or export another vault.
            if !authorized_personal_peer(peer) {Err("backup_forbidden".into())}
            else {
                match state.lock(){
                    Ok(mut controller)=>match op {
                        "backup.catalog"=>controller.backup_catalog(),
                        "backup.open"=>controller.backup_open(
                            input.get("mode").and_then(Value::as_str).unwrap_or(""),
                            input.get("name").and_then(Value::as_str)),
                        "backup.read"=>{
                            let token=input.get("token").and_then(Value::as_str).unwrap_or("");
                            let index=input.get("index").and_then(Value::as_u64).unwrap_or(u64::MAX);
                            let offset=input.get("offset").and_then(Value::as_u64).unwrap_or(u64::MAX);
                            let count=input.get("count").and_then(Value::as_u64).unwrap_or(u64::MAX);
                            if index>64 || count>6144 {Err("backup_chunk_invalid".into())}
                            else {controller.backup_read(token,index as usize,offset,count as usize)}
                        },
                        "backup.close"=>controller.backup_close(input.get("token").and_then(Value::as_str).unwrap_or("")),
                        _=>Err("unknown_operation".into()),
                    },
                    Err(_)=>Err("vault_state_unavailable".into()),
                }
            }
        },
        "restore.start"|"restore.chunk"|"restore.validate"|"restore.abort"|"restore.queue"|"restore.plan"|"restore.discard"|"restore.commit" => {
            if !authorized_personal_peer(peer){Err("restore_forbidden".into())}
            else {
                match state.lock(){
                    Ok(mut controller)=>match op {
                        "restore.start"=>controller.restore_start(
                            input.get("target").and_then(Value::as_str).unwrap_or(""),
                            input.get("size").and_then(Value::as_u64).unwrap_or(0),
                            input.get("sha256").and_then(Value::as_str).unwrap_or("")),
                        "restore.chunk"=>controller.restore_chunk(
                            input.get("token").and_then(Value::as_str).unwrap_or(""),
                            input.get("offset").and_then(Value::as_u64).unwrap_or(u64::MAX),
                            input.get("value").and_then(Value::as_str).unwrap_or("")),
                        "restore.validate"=>controller.restore_validate(input.get("token").and_then(Value::as_str).unwrap_or("")),
                        "restore.abort"=>controller.restore_abort(input.get("token").and_then(Value::as_str).unwrap_or("")),
                        "restore.queue"=>controller.restore_queue(input.get("token").and_then(Value::as_str).unwrap_or("")),
                        "restore.plan"=>controller.restore_plan(),
                        "restore.discard"=>controller.restore_discard(),
                        "restore.commit"=>controller.restore_commit(
                            input.get("confirmation").and_then(Value::as_str).unwrap_or("")),
                        _=>Err("unknown_operation".into())
                    },
                    Err(_)=>Err("vault_state_unavailable".into()),
                }
            }
        },
        // Personal Secrets uses a separate operation family. module=general is
        // never a consumer-controlled escape hatch into the general vault.
        "general.list"|"general.get"|"general.put"|"general.update"|"general.delete" => {
            if !authorized_personal_peer(peer) {
                Err("personal_vault_forbidden".into())
            } else {
                match state.lock() {
                    Ok(controller) => match op {
                        "general.list" => controller.general_list(),
                        "general.get" => controller.general_get(input.get("id").and_then(Value::as_str).unwrap_or("")),
                        "general.put"|"general.update" => {
                            let id=input.get("id").and_then(Value::as_str).unwrap_or("");
                            match input.get("value") {
                                Some(value) => controller.general_put(id,value,op=="general.update"),
                                None => Err("missing_secret_value".into()),
                            }
                        },
                        "general.delete" => controller.general_delete(input.get("id").and_then(Value::as_str).unwrap_or("")),
                        _ => Err("unknown_operation".into()),
                    },
                    Err(_) => Err("vault_state_unavailable".into()),
                }
            }
        },
        "vault.list"|"secret.list"|"secret.put"|"secret.get"|"secret.update"|"secret.delete" => {
            let module=input.get("module").and_then(Value::as_str).unwrap_or("");
            if peer != Some(module) {Err("secret_module_identity_mismatch".into())}
            else {
                match state.lock() {
                    Ok(controller)=>match op {
                        "vault.list"|"secret.list"=>controller.secret_list(module),
                        "secret.get"=>controller.secret_get(module,input.get("id").and_then(Value::as_str).unwrap_or("")),
                        "secret.put"|"secret.update"=>{
                            let id=input.get("id").and_then(Value::as_str).unwrap_or("");
                            match input.get("value") {
                                Some(value)=>controller.secret_put(module,id,value,op=="secret.update"),
                                None=>Err("missing_secret_value".into())
                            }
                        },
                        "secret.delete"=>controller.secret_delete(module,input.get("id").and_then(Value::as_str).unwrap_or("")),
                        _=>Err("unknown_operation".into()),
                    },
                    Err(_)=>Err("vault_state_unavailable".into()),
                }
            }
        },
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
fn serve_authorized_one(
    mut stream: UnixStream,
    peer: Option<String>,
    state: Arc<Mutex<VaultController>>,
) -> Result<(), String> {
    stream.set_read_timeout(Some(Duration::from_secs(45))).map_err(|e|e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(45))).map_err(|e|e.to_string())?;
    let request=rpc_read(&mut stream)?;
    // Identity always comes from the external broker's SO_PEERCRED verification,
    // carried over a private inherited datagram channel, never from JSON.
    let response=handle(&request,peer.as_deref(),&state);
    rpc_write(&mut stream,&response)
}
fn serve_in_isolated_world() -> Result<(), String> {
    // F04: stdin is the inherited anonymous control socket. The KeePass worker
    // no longer binds a filesystem socket or reads untrusted /proc/<PID>/exe.
    let control = unsafe { UnixDatagram::from_raw_fd(0) };
    let state=Arc::new(Mutex::new(VaultController::new()?));
    eprintln!("NEEBLES Secrets: isolated KeePass worker running");
    loop {
        let (client, peer)=ipc_bridge::recv_connection(&control)?;
        let shared=Arc::clone(&state);
        std::thread::spawn(move || {
            if let Err(error)=serve_authorized_one(client,peer,shared) {
                eprintln!("Secrets IPC transport: {error}");
            }
        });
    }
}
fn bind_broker_listener() -> Result<(UnixListener, PathBuf), String> {
    let path=socket_path()?;
    let dir=path.parent().ok_or("socket parent missing")?;
    if !dir.exists() {
        fs::create_dir(dir).map_err(|e|format!("cannot create socket directory: {e}"))?;
        fs::set_permissions(dir,fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())?;
    }
    validate_private_dir(dir)?;
    if path.exists() {
        if UnixStream::connect(&path).is_ok() {return Err("Secrets service already running".into());}
        let m=fs::symlink_metadata(&path).map_err(|e|e.to_string())?;
        if !m.file_type().is_socket() || m.uid()!=uid() {return Err("unsafe stale socket".into());}
        fs::remove_file(&path).map_err(|e|format!("stale socket: {e}"))?;
    }
    let listener=UnixListener::bind(&path).map_err(|e|format!("bind: {e}"))?;
    fs::set_permissions(&path,fs::Permissions::from_mode(0o600)).map_err(|e|format!("chmod: {e}"))?;
    listener.set_nonblocking(true).map_err(|e|e.to_string())?;
    Ok((listener,path))
}
fn broker_loop(
    listener: &UnixListener,
    child: &mut std::process::Child,
    control: &UnixDatagram,
) -> Result<std::process::ExitStatus,String> {
    control.set_write_timeout(Some(Duration::from_secs(3))).map_err(|e|e.to_string())?;
    loop {
        if let Some(status) = child.try_wait().map_err(|e|format!("isolated worker wait: {e}"))? {
            return Ok(status);
        }
        match listener.accept() {
            Ok((client,_)) => {
                // Host's user/mount namespaces can inspect both /proc/<pid>/exe
                // and root-owned installed manifests. Invalid peers carry None:
                // the isolated handle() denies every sensitive operation.
                let peer=peer_module(&client).ok();
                if let Err(error)=ipc_bridge::send_connection(control,&client,peer.as_deref()) {
                    eprintln!("Secrets private FD transport: {error}");
                }
            },
            Err(error) if error.kind()==std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(75));
            },
            Err(error) if error.kind()==std::io::ErrorKind::Interrupted => {},
            Err(error) => return Err(format!("Secrets broker accept: {error}")),
        }
    }
}
fn request(input: &Value) -> Result<Value,String> {
    let mut stream=UnixStream::connect(socket_path()?).map_err(|e|format!("Secrets service unavailable: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e|e.to_string())?;
    rpc_write(&mut stream,input)?;
    rpc_read(&mut stream)
}
// F04: systemd --user ExecStart stays unchanged. The host broker owns the
// public socket and the separate child re-enters the certified KeePass world.
// No KeePass package is installed in the host. No new master vault is made.
fn serve_from_certified_world() -> Result<(), String> {
    if std::env::var_os("NEEBLES_SECRETS_INSIDE_WORLD").as_deref()
        == Some(std::ffi::OsStr::new("1")) {
        return serve_in_isolated_world();
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
        || data.get("version").and_then(Value::as_str) != Some(env!("CARGO_PKG_VERSION"))
        || !matches!(data.get("entrypoint").and_then(Value::as_str),
            Some("runtime/neebles-secrets-ui" | "runtime/neebles-secrets")) {
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
    // Broker stays outside bwrap and owns the only public secrets.sock.
    // A private, anonymous SOCK_DGRAM pair passes approved client descriptors
    // directly to the isolated worker via SCM_RIGHTS. No RPC content crosses
    // broker userspace, no second filesystem socket and no Secrets data mount.
    let (listener, broker_socket_path)=bind_broker_listener()?;
    let (broker_control, isolated_control)=UnixDatagram::pair()
        .map_err(|e|format!("private FD channel: {e}"))?;
    let child_control:OwnedFd=isolated_control.into();
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
    // Bubblewrap keeps stdin connected to the isolated command (F03 passed).
    cmd.stdin(Stdio::from(child_control));
    // Remain the systemd main process until the daemon exits, so failures
    // reach Restart=on-failure. The internal daemon still owns the socket.
    // The systemd-owned outer process is the only Boss service publisher.
    // The inner KeePass worker stays in bwrap, with no Boss socket mounted.
    // The outer process reads only non-secret status flags through Secrets IPC.
    let publishing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let publisher_flag = std::sync::Arc::clone(&publishing);
    let publisher = std::thread::Builder::new()
        .name("secrets-boss-publisher".to_string())
        .spawn(move || boss_publisher::run(publisher_flag))
        .map_err(|e| format!("cannot create Boss publisher worker: {e}"))?;

    // F26-C: a second authenticated Boss socket for the SAME outer daemon PID.
    // This runtime activates only after a future certified manifest declares
    // `runtime/neebles-secrets` as entrypoint. The current UI-entrypoint
    // installation keeps its existing registration path unchanged.
    // The runtime receives only a cloned endpoint of the anonymous broker FD
    // channel. No public socket, caller-supplied peer, or KeePass data mount.
    let provider_control = broker_control.try_clone()
        .map_err(|e| format!("Secrets provider private FD channel: {e}"))?;
    let provider_flag = std::sync::Arc::clone(&publishing);
    let provider = std::thread::Builder::new()
        .name("secrets-boss-provider".to_string())
        .spawn(move || boss_runtime::run(provider_flag, provider_control))
        .map_err(|e| format!("cannot create Secrets provider worker: {e}"))?;

    let result = (|| {
        let mut child=cmd.spawn().map_err(|e|format!("cannot enter certified KeePass runtime: {e}"))?;
        let result=broker_loop(&listener,&mut child,&broker_control);
        if result.is_err() { let _=child.kill(); let _=child.wait(); }
        result
    })();
    publishing.store(false, std::sync::atomic::Ordering::Release);
    let _ = publisher.join();
    let _ = provider.join();
    // This path is created by the host broker, never the KeePass worker.
    drop(listener);
    let _ = fs::remove_file(&broker_socket_path);
    let status=result?;
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
    #[test] fn ipc_f15_master_key_and_lock_require_secrets_desktop() {
        for operation in ["vault.setup", "vault.unlock", "vault.lock"] {
            for identity in [None, Some("neebles-connect"), Some("neebles-db")] {
                assert_eq!(authorize_vault_operation(operation, identity, None), Err("vault_control_forbidden"));
            }
            assert_eq!(authorize_vault_operation(operation, Some("neebles-secrets"), None), Ok(()));
            assert!(is_sensitive_operation(operation));
        }
        // A forged JSON identity cannot create broker-assigned peer authority.
        let forged = json!({"op":"vault.unlock", "peer":"neebles-secrets", "module":"neebles-secrets"});
        assert_eq!(authorize_vault_operation(forged["op"].as_str().unwrap(), None,
            forged["module"].as_str()), Err("vault_control_forbidden"));
    }
    #[test] fn ipc_f15_consumer_cannot_request_other_modules_vaults() {
        for operation in ["vault.exists", "vault.ensure", "vault.request"] {
            assert_eq!(authorize_vault_operation(operation, Some("neebles-connect"), Some("neebles-connect")), Ok(()));
            assert_eq!(authorize_vault_operation(operation, Some("neebles-db"), Some("neebles-db")), Ok(()));
            for identity in [None, Some("neebles-secrets"), Some("neebles-db")] {
                assert_eq!(authorize_vault_operation(operation, identity, Some("neebles-connect")),
                    Err("vault_module_identity_mismatch"));
            }
            assert_eq!(authorize_vault_operation(operation, Some("neebles-connect"), None),
                Err("vault_module_identity_mismatch"));
            assert!(is_sensitive_operation(operation));
        }
    }
    #[test] fn ipc_f15_nonsecret_status_stays_available() {
        for operation in ["status", "vault.status"] {
            for identity in [None, Some("neebles-connect"), Some("neebles-secrets")] {
                assert_eq!(authorize_vault_operation(operation, identity, None), Ok(()));
            }
        }
        for operation in ["general.get", "secret.get", "restore.commit"] {
            assert!(is_sensitive_operation(operation));
        }
    }
    #[test] fn portable_export_requires_sensitive_peer(){assert!(is_sensitive_operation("portable.begin"));assert!(is_sensitive_operation("portable.read"));}
    #[test] fn restore_commit_requires_sensitive_peer(){assert!(is_sensitive_operation("restore.commit"));}
    #[test] fn sensitive_ops_are_separated(){assert!(is_sensitive_operation("crypto.compute"));assert!(is_sensitive_operation("batch.generate"));assert!(is_sensitive_operation("secret.get"));assert!(is_sensitive_operation("vault.list"));assert!(!is_sensitive_operation("quick.generate"));}
    #[test] fn rejected_unknown_operation(){assert_eq!(json!({"ok":false})["ok"],false);}
    #[test] fn quick_password_all_groups(){let v=generate(&json!({"kind":"password","length":64,"lowercase":true,"uppercase":true,"numbers":true,"symbols":true})).unwrap();let s=v["value"].as_str().unwrap();assert_eq!(s.len(),64);assert!(s.bytes().any(|c|c.is_ascii_lowercase()));assert!(s.bytes().any(|c|c.is_ascii_uppercase()));assert!(s.bytes().any(|c|c.is_ascii_digit()));assert!(s.bytes().any(|c|!c.is_ascii_alphanumeric()));}
    #[test] fn quick_validation(){assert!(generate(&json!({"kind":"password","length":4})).is_err()); assert!(generate(&json!({"kind":"password","lowercase":false,"uppercase":false,"numbers":false,"symbols":false})).is_err()); assert!(generate(&json!({"kind":"ed25519"})).is_err());}
    #[test] fn quick_expanded_generator() {
        assert_eq!(generate(&json!({"kind":"password","length":512})).unwrap()["value"].as_str().unwrap().len(),512);
        assert_eq!(generate(&json!({"kind":"base64","length":16})).unwrap()["value"].as_str().unwrap().len(),24);
        assert_eq!(generate(&json!({"kind":"salt","length":16})).unwrap()["value"].as_str().unwrap().len(),32);
    }
    #[test] fn quick_uuid(){let s=uuid_v4().unwrap();assert_eq!(s.len(),36);assert_eq!(&s[14..15],"4");assert!(matches!(&s[19..20],"8"|"9"|"a"|"b"));}
    #[test] fn personal_gate_is_separate_from_module_gate() {
        assert!(authorized_personal_peer(Some("neebles-secrets")));
        for who in [None,Some("general"),Some("neebles-connect"),Some("neebles-db")] {
            assert!(!authorized_personal_peer(who));
        }
        for op in ["general.list","general.get","general.put","general.update","general.delete"] {
            assert!(is_sensitive_operation(op));
        }
    }
    #[test] fn quick_token_lengths(){assert_eq!(generate(&json!({"kind":"hex","length":16})).unwrap()["value"].as_str().unwrap().len(),32); assert_eq!(generate(&json!({"kind":"base64url","length":16})).unwrap()["value"].as_str().unwrap().len(),22);}
}
#[cfg(test)]
mod restore_real_kdbx_tests;
