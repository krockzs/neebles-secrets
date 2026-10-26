//! NEEBLES Secrets 1.0.3 / F12-A: separately encrypted portable KDBX exporter.
//! Only the installed Secrets desktop is authorized by the IPC dispatcher.
//! The isolated worker holds exported data as KDBX ciphertext on disk; plaintext
//! enters KeePassXC via stdin, never argv, env, sidecars, journal or stdout.
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{compiler_fence, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const MAX_SESSIONS: usize = 2;
const MAX_ENTRIES: u32 = 250; // Bounded first stage. Future bulk KDBX needs profiling.
const MAX_VALUE: usize = 4096;
const MAX_ENCRYPTED_BYTES: u64 = 64 * 1024 * 1024;
const CHUNK: usize = 6144;
const TTL: Duration = Duration::from_secs(600);

fn valid_passphrase(value: &str) -> bool {
    (12..=512).contains(&value.len()) && !value.chars().any(|c| matches!(c, '\0' | '\n' | '\r'))
}
fn valid_secret(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VALUE
        && !value.chars().any(|c| matches!(c, '\0' | '\n' | '\r'))
}
fn rand_token() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| "portable_random_unavailable")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn validate_dir(dir: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(dir).map_err(|_| "portable_directory_unavailable")?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.permissions().mode() & 0o077 != 0
        || m.uid() != unsafe { libc::geteuid() }
    {
        return Err("portable_directory_insecure".into());
    }
    Ok(())
}
fn run_cli(args: &[&OsStr], secret_lines: &[&[u8]]) -> Result<(), String> {
    let mut child = Command::new("/usr/bin/keepassxc-cli")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "portable_keepass_unavailable".to_string())?;
    let written = (|| -> Result<(), String> {
        let pipe = child.stdin.as_mut().ok_or("portable_stdin_unavailable")?;
        for line in secret_lines {
            pipe.write_all(line).map_err(|_| "portable_stdin_failed")?;
            pipe.write_all(b"\n").map_err(|_| "portable_stdin_failed")?;
        }
        Ok(())
    })();
    drop(child.stdin.take());
    if written.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return written;
    }
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err("portable_keepass_rejected".into())
                }
            }
            Ok(None) if Instant::now() < until => thread::sleep(Duration::from_millis(25)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("portable_keepass_timeout".into());
            }
        }
    }
}
struct PrivatePassphrase(Vec<u8>);
impl Drop for PrivatePassphrase {
    fn drop(&mut self) {
        for b in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(b, 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}
struct Session {
    path: PathBuf,
    passphrase: PrivatePassphrase,
    created: Instant,
    entries: u32,
    sealed: bool,
    size: u64,
    hash: String,
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
#[derive(Default)]
pub struct PortableExports {
    sessions: BTreeMap<String, Session>,
}
impl PortableExports {
    pub fn clear(&mut self) {
        self.sessions.clear();
    }
    fn purge(&mut self) {
        self.sessions.retain(|_, s| s.created.elapsed() < TTL);
    }
    pub fn begin(&mut self, dir: &Path, passphrase: &str) -> Result<Value, String> {
        self.purge();
        validate_dir(dir)?;
        if !valid_passphrase(passphrase) {
            return Err("portable_invalid_passphrase".into());
        }
        if self.sessions.len() >= MAX_SESSIONS {
            return Err("portable_sessions_full".into());
        }
        let token = rand_token()?;
        let path = dir.join(format!(".neebles-portable-{token}.kdbx"));
        let reserved = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| "portable_temp_unavailable")?;
        drop(reserved);
        // CLI db-create expects a nonexistent target.
        fs::remove_file(&path).map_err(|_| "portable_temp_unavailable")?;
        let args = [OsStr::new("db-create"), OsStr::new("-p"), path.as_os_str()];
        let result = run_cli(&args, &[passphrase.as_bytes(), passphrase.as_bytes()]);
        if result.is_err() {
            let _ = fs::remove_file(&path);
            return result.map(|_| json!({}));
        }
        if fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).is_err() {
            let _ = fs::remove_file(&path);
            return Err("portable_permissions_failed".into());
        }
        let session = Session {
            path,
            passphrase: PrivatePassphrase(passphrase.as_bytes().to_vec()),
            created: Instant::now(),
            entries: 0,
            sealed: false,
            size: 0,
            hash: String::new(),
        };
        self.sessions.insert(token.clone(), session);
        Ok(json!({"token":token,"max_entries":MAX_ENTRIES,"max_value_bytes":MAX_VALUE}))
    }
    pub fn append(&mut self, token: &str, value: &str) -> Result<Value, String> {
        self.purge();
        if !valid_secret(value) {
            return Err("portable_invalid_value".into());
        }
        let session = self
            .sessions
            .get_mut(token)
            .ok_or("portable_session_missing")?;
        if session.sealed {
            return Err("portable_session_sealed".into());
        }
        if session.entries >= MAX_ENTRIES {
            return Err("portable_entries_limit".into());
        }
        let name = format!("Exportado {:06}", session.entries + 1);
        // One process per entry; no plaintext sidecar. Database and entry secrets
        // go ONLY through stdin, never command arguments or environment.
        let args = [
            OsStr::new("add"),
            OsStr::new("-p"),
            session.path.as_os_str(),
            OsStr::new(&name),
        ];
        run_cli(&args, &[&session.passphrase.0, value.as_bytes()])?;
        session.entries += 1;
        Ok(json!({"entries":session.entries}))
    }
    pub fn seal(&mut self, token: &str) -> Result<Value, String> {
        self.purge();
        let session = self
            .sessions
            .get_mut(token)
            .ok_or("portable_session_missing")?;
        if session.sealed {
            return Err("portable_session_sealed".into());
        }
        if session.entries == 0 {
            return Err("portable_empty_export".into());
        }
        let options = [
            OsStr::new("db-info"),
            OsStr::new("-q"),
            session.path.as_os_str(),
        ];
        run_cli(&options, &[&session.passphrase.0])?;
        let metadata = fs::symlink_metadata(&session.path).map_err(|_| "portable_kdbx_missing")?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() < 128
            || metadata.len() > MAX_ENCRYPTED_BYTES
        {
            return Err("portable_kdbx_invalid".into());
        }
        let mut f = File::open(&session.path).map_err(|_| "portable_kdbx_unreadable")?;
        let mut header = [0u8; 4];
        f.read_exact(&mut header)
            .map_err(|_| "portable_kdbx_unreadable")?;
        if header != [0x03, 0xd9, 0xa2, 0x9a] {
            return Err("portable_kdbx_invalid".into());
        }
        f.seek(SeekFrom::Start(0))
            .map_err(|_| "portable_kdbx_unreadable")?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let n = f
                .read(&mut buffer)
                .map_err(|_| "portable_kdbx_unreadable")?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        session.size = metadata.len();
        session.hash = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        session.sealed = true;
        Ok(
            json!({"size":session.size,"sha256":session.hash,"entries":session.entries,"chunk_limit":CHUNK}),
        )
    }
    pub fn read(&mut self, token: &str, offset: u64, count: usize) -> Result<Value, String> {
        self.purge();
        let s = self.sessions.get(token).ok_or("portable_session_missing")?;
        if !s.sealed
            || count == 0
            || count > CHUNK
            || offset >= s.size
            || offset + count as u64 > s.size
        {
            return Err("portable_chunk_invalid".into());
        }
        let mut file = File::open(&s.path).map_err(|_| "portable_read_failed")?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| "portable_read_failed")?;
        let mut buffer = vec![0u8; count];
        file.read_exact(&mut buffer)
            .map_err(|_| "portable_read_failed")?;
        Ok(json!({"offset":offset,"next":offset+count as u64,
            "value":base64::engine::general_purpose::STANDARD.encode(buffer)}))
    }
    pub fn close(&mut self, token: &str) -> Result<Value, String> {
        if self.sessions.remove(token).is_none() {
            return Err("portable_session_missing".into());
        }
        Ok(json!({"closed":true}))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_independent_export_key() {
        assert!(!valid_passphrase("12345"));
        assert!(!valid_passphrase("abcdefghijkl\n"));
        assert!(valid_passphrase("lab-independent-passphrase"));
    }
    #[test]
    fn prevents_multiline_values_and_unbounded_entries() {
        assert!(!valid_secret("one\ntwo"));
        assert!(!valid_secret(""));
        assert!(!valid_secret(&"a".repeat(MAX_VALUE + 1)));
        assert!(valid_secret("safe-laboratory-token"));
    }
    #[test]
    #[ignore = "F12-A requires keepassxc-cli in isolated keepass-full world; only disposable files"]
    fn real_portable_kdbx_export_and_chunks() {
        use std::os::unix::fs::PermissionsExt;
        let nonce = rand_token().expect("system CSPRNG");
        let dir =
            std::env::temp_dir().join(format!("neebles-f12-kdbx-{}-{nonce}", std::process::id()));
        fs::create_dir(&dir).expect("unique QA directory");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        // All generated entries and keys here are synthetic test fixtures.
        let mut export = PortableExports::default();
        let token = export
            .begin(&dir, "f12-independent-test-key")
            .unwrap()
            .get("token")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        assert_eq!(
            export.append(&token, "qa-secret-one").unwrap()["entries"],
            1
        );
        assert_eq!(
            export.append(&token, "qa-secret-two").unwrap()["entries"],
            2
        );
        let ready = export.seal(&token).unwrap();
        let bytes = ready["size"].as_u64().unwrap();
        assert!(bytes > 128);
        let first = export
            .read(&token, 0, (bytes.min(CHUNK as u64)) as usize)
            .unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(first["value"].as_str().unwrap())
            .unwrap();
        assert_eq!(&decoded[..4], &[0x03, 0xd9, 0xa2, 0x9a]);
        assert!(export.close(&token).is_ok());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_dir(&dir).unwrap();
    }
    #[test]
    fn no_unknown_export_session() {
        let mut sessions = PortableExports::default();
        assert!(sessions.append("absent", "safe").is_err());
        assert!(sessions.close("absent").is_err());
    }
}
