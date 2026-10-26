//! F11-C: bounded staging of encrypted KDBX for compatibility checks.
//! This code NEVER replaces a live vault. Every session is private to the
//! authorized Secrets desktop and must run inside the isolated Rust worker.
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_SIZE: u64 = 512 * 1024 * 1024;
const CHUNK: usize = 6144;
const TTL: Duration = Duration::from_secs(180);

pub fn valid_target(name: &str) -> bool {
    let Some(module) = name
        .strip_prefix("vault-")
        .and_then(|x| x.strip_suffix(".kdbx"))
    else {
        return false;
    };
    if module == "general" {
        return true;
    }
    (2..=64).contains(&module.len())
        && module.as_bytes()[0].is_ascii_lowercase()
        && module
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && !module.ends_with('-')
        && !module.contains("--")
}
fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn token() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| "restore_random_unavailable")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn owned_private_dir(path: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|_| "restore_directory_unavailable")?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != unsafe { libc::geteuid() }
        || m.permissions().mode() & 0o077 != 0
    {
        return Err("restore_directory_insecure".into());
    }
    Ok(())
}
struct Stage {
    token: String,
    target: String,
    path: PathBuf,
    file: File,
    expected: u64,
    expected_hash: String,
    received: u64,
    hasher: Sha256,
    valid: bool,
    last: Instant,
}
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
#[derive(Default)]
pub struct RestoreSessions {
    current: Option<Stage>,
    ready: Vec<Stage>,
    confirmation: Option<String>,
    confirmed_at: Option<Instant>,
}
impl RestoreSessions {
    pub fn clear(&mut self) {
        self.current = None;
        self.ready.clear();
        self.confirmation = None;
        self.confirmed_at = None;
    }
    pub fn start(
        &mut self,
        directory: &Path,
        target: &str,
        bytes: u64,
        checksum: &str,
    ) -> Result<Value, String> {
        if self
            .current
            .as_ref()
            .is_some_and(|s| s.last.elapsed() >= TTL)
        {
            self.clear();
        }
        if self.current.is_some() {
            return Err("restore_session_busy".into());
        }
        if self.ready.len() >= 64 {
            return Err("restore_selection_full".into());
        }
        if self.ready.iter().any(|s| s.target == target) {
            return Err("restore_duplicate_target".into());
        }
        owned_private_dir(directory)?;
        if !valid_target(target) {
            return Err("restore_invalid_target".into());
        }
        if !(128..=MAX_SIZE).contains(&bytes) {
            return Err("restore_invalid_size".into());
        }
        if !valid_hash(checksum) {
            return Err("restore_invalid_sha256".into());
        }
        let id = token()?;
        let path = directory.join(format!(".neebles-restore-{id}.pending.kdbx"));
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| "restore_cannot_stage")?;
        self.confirmation = None;
        self.confirmed_at = None;
        self.current = Some(Stage {
            token: id.clone(),
            target: target.into(),
            path,
            file,
            expected: bytes,
            expected_hash: checksum.into(),
            received: 0,
            hasher: Sha256::new(),
            valid: false,
            last: Instant::now(),
        });
        Ok(json!({"token":id,"target":target,"limit":CHUNK}))
    }
    fn active(&mut self, token: &str) -> Result<&mut Stage, String> {
        if self
            .current
            .as_ref()
            .is_some_and(|s| s.last.elapsed() >= TTL)
        {
            self.clear();
            return Err("restore_session_expired".into());
        }
        let stage = self.current.as_mut().ok_or("restore_session_missing")?;
        if stage.token != token {
            return Err("restore_session_invalid".into());
        }
        Ok(stage)
    }
    pub fn chunk(&mut self, token: &str, offset: u64, encoded: &str) -> Result<Value, String> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| "restore_chunk_bad_base64")?;
        if bytes.is_empty() || bytes.len() > CHUNK {
            return Err("restore_chunk_out_of_range".into());
        }
        let s = self.active(token)?;
        if s.valid {
            return Err("restore_stage_sealed".into());
        }
        if offset != s.received || (bytes.len() as u64) > s.expected - s.received {
            return Err("restore_chunk_offset_mismatch".into());
        }
        s.file
            .write_all(&bytes)
            .map_err(|_| "restore_stage_write_failed")?;
        s.hasher.update(&bytes);
        s.received += bytes.len() as u64;
        s.last = Instant::now();
        Ok(json!({"next":s.received}))
    }
    pub fn validate<F>(&mut self, token: &str, mut verify: F) -> Result<Value, String>
    where
        F: FnMut(&Path) -> Result<(), String>,
    {
        let s = self.active(token)?;
        if s.received != s.expected {
            return Err("restore_stage_incomplete".into());
        }
        let actual = s.hasher.clone().finalize();
        let hex = actual
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if hex != s.expected_hash {
            return Err("restore_hash_mismatch".into());
        }
        s.file.flush().map_err(|_| "restore_stage_sync_failed")?;
        s.file.sync_all().map_err(|_| "restore_stage_sync_failed")?;
        s.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| "restore_stage_read_failed")?;
        let mut magic = [0u8; 4];
        s.file
            .read_exact(&mut magic)
            .map_err(|_| "restore_stage_read_failed")?;
        if magic != [0x03, 0xd9, 0xa2, 0x9a] {
            return Err("restore_not_kdbx".into());
        }
        verify(&s.path)?;
        s.valid = true;
        s.last = Instant::now();
        Ok(json!({"compatible":true,"target":s.target,"encrypted_bytes":s.expected}))
    }
    // F11-E: keep validated ciphertext staged for a complete multi-vault transaction.
    // This transfers ownership of the open file without copying decrypted content.
    pub fn queue(&mut self, token: &str) -> Result<Value, String> {
        if self.ready.len() >= 64 {
            return Err("restore_selection_full".into());
        }
        let target = {
            let stage = self.active(token)?;
            if !stage.valid {
                return Err("restore_stage_unvalidated".into());
            }
            stage.target.clone()
        };
        if self.ready.iter().any(|r| r.target == target) {
            return Err("restore_duplicate_target".into());
        }
        let mut selected = self.current.take().ok_or("restore_session_missing")?;
        selected.last = Instant::now();
        let target = selected.target.clone();
        self.ready.push(selected);
        self.confirmation = None;
        self.confirmed_at = None;
        Ok(json!({"queued":true,"target":target,"count":self.ready.len()}))
    }
    // New short-lived, single-use confirmation issued only for a complete plan.
    // Never accept a JSON-supplied module identity or an unprepared selection.
    pub fn plan(&mut self) -> Result<Value, String> {
        if self.current.is_some() {
            return Err("restore_current_session_unfinished".into());
        }
        if self.ready.is_empty() {
            return Err("restore_no_prepared_vaults".into());
        }
        let confirmation = token()?;
        self.confirmation = Some(confirmation.clone());
        self.confirmed_at = Some(Instant::now());
        Ok(
            json!({"ready":self.ready.iter().map(|r|json!({"target":r.target,"size":r.expected})).collect::<Vec<_>>(),
            "count":self.ready.len(),"can_commit":true,"confirmation":confirmation}),
        )
    }
    pub fn consume_confirmation(&mut self, confirmation: &str) -> Result<(), String> {
        if confirmation.len() != 32 || !confirmation.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("restore_confirmation_invalid".into());
        }
        self.prepared_inputs()?;
        // Consume before ANY disk mutation. Replaying this authorization fails.
        if self.confirmation.as_deref() != Some(confirmation)
            || self
                .confirmed_at
                .as_ref()
                .is_none_or(|at| at.elapsed() > TTL)
        {
            return Err("restore_confirmation_invalid".into());
        }
        self.confirmation = None;
        self.confirmed_at = None;
        Ok(())
    }
    // Internal bridge only. The destructive IPC/UI operation is NOT enabled.
    pub fn prepared_inputs(&self) -> Result<Vec<crate::restore_transaction::Incoming>, String> {
        if self.current.is_some() {
            return Err("restore_current_session_unfinished".into());
        }
        if self.ready.is_empty() {
            return Err("restore_no_prepared_vaults".into());
        }
        for s in &self.ready {
            if !s.valid || s.received != s.expected {
                return Err("restore_stage_unvalidated".into());
            }
        }
        Ok(self
            .ready
            .iter()
            .map(|s| crate::restore_transaction::Incoming {
                target: s.target.clone(),
                staged_file: s.path.clone(),
            })
            .collect())
    }
    pub fn prepared_hashes(&self) -> Result<std::collections::BTreeMap<PathBuf, String>, String> {
        self.prepared_inputs()?;
        Ok(self
            .ready
            .iter()
            .map(|s| (s.path.clone(), s.expected_hash.clone()))
            .collect())
    }
    pub fn abort(&mut self, token: &str) -> Result<Value, String> {
        self.active(token)?;
        self.clear();
        Ok(json!({"staging_deleted":true}))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restricts_targets_and_sha() {
        for bad in [
            "../vault-general.kdbx",
            "vault-../../a.kdbx",
            "vault-General.kdbx",
            "vault-evil--id.kdbx",
            "vault-.kdbx",
            "vault-abc.kdbx.tmp",
        ] {
            assert!(!valid_target(bad));
        }
        assert!(valid_target("vault-general.kdbx"));
        assert!(valid_target("vault-neebles-connect.kdbx"));
        assert!(valid_hash(&"a".repeat(64)));
        assert!(!valid_hash(&"A".repeat(64)));
    }
    #[test]
    fn never_opens_untrusted_directory() {
        let mut ss = RestoreSessions::default();
        assert!(ss
            .start(
                Path::new("/does/not/exist"),
                "vault-general.kdbx",
                128,
                &"a".repeat(64)
            )
            .is_err());
        assert!(ss.chunk("none", 0, "eA==").is_err());
        assert!(ss.abort("none").is_err());
    }
    #[test]
    fn queues_multiple_validated_ciphertexts_and_cleans_on_discard() {
        let dir = std::env::temp_dir().join(format!(
            "neebles-f11e-{}-{}",
            std::process::id(),
            token().unwrap()
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let mut ss = RestoreSessions::default();
        let content = [0x03u8, 0xd9, 0xa2, 0x9a]
            .into_iter()
            .chain(std::iter::repeat_n(0u8, 124))
            .collect::<Vec<_>>();
        let sha = Sha256::digest(&content)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let data = base64::engine::general_purpose::STANDARD.encode(content);
        for target in ["vault-general.kdbx", "vault-neebles-connect.kdbx"] {
            let tok = ss.start(&dir, target, 128, &sha).unwrap()["token"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(ss.queue(&tok).is_err()); // Cannot queue without validation.
            ss.chunk(&tok, 0, &data).unwrap();
            ss.validate(&tok, |_| Ok(())).unwrap(); // Test-only validator; fake KDBX is disposable.
            ss.queue(&tok).unwrap();
            assert!(ss.start(&dir, target, 128, &sha).is_err()); // Duplicate destination.
        }
        assert_eq!(ss.plan().unwrap()["count"], 2);
        assert_eq!(ss.prepared_inputs().unwrap().len(), 2);
        assert_eq!(ss.prepared_hashes().unwrap().len(), 2);
        ss.clear();
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_dir(&dir).unwrap();
    }
    #[test]
    fn restore_requires_fresh_single_use_confirmation() {
        let dir = std::env::temp_dir().join(format!(
            "neebles-f11f-{}-{}",
            std::process::id(),
            token().unwrap()
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let mut ss = RestoreSessions::default();
        let bytes = [0x03u8, 0xd9, 0xa2, 0x9a]
            .into_iter()
            .chain(std::iter::repeat_n(0u8, 124))
            .collect::<Vec<_>>();
        let sha = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let id = ss.start(&dir, "vault-general.kdbx", 128, &sha).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(ss.plan().is_err());
        ss.chunk(
            &id,
            0,
            &base64::engine::general_purpose::STANDARD.encode(bytes),
        )
        .unwrap();
        ss.validate(&id, |_| Ok(())).unwrap();
        ss.queue(&id).unwrap();
        assert!(ss.consume_confirmation("0").is_err());
        let confirmation = ss.plan().unwrap()["confirmation"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(ss.consume_confirmation(&"0".repeat(32)).is_err());
        ss.consume_confirmation(&confirmation).unwrap();
        assert!(ss.consume_confirmation(&confirmation).is_err());
        let next = ss.plan().unwrap()["confirmation"]
            .as_str()
            .unwrap()
            .to_owned();
        ss.clear();
        assert!(ss.consume_confirmation(&next).is_err());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_dir(&dir).unwrap();
    }
    #[test]
    fn in_memory_stage_requires_valid_hash_and_erases_temporary() {
        let dir = std::env::temp_dir().join(format!("neebles-f11c-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let mut ss = RestoreSessions::default();
        let content = [0x03u8, 0xd9, 0xa2, 0x9a]
            .into_iter()
            .chain(std::iter::repeat_n(0u8, 124))
            .collect::<Vec<_>>();
        let good = Sha256::digest(&content)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let data = base64::engine::general_purpose::STANDARD.encode(content);
        let token = ss.start(&dir, "vault-general.kdbx", 128, &good).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(ss.chunk(&token, 1, &data).is_err());
        assert!(ss.chunk(&token, 0, &data).is_ok());
        assert!(ss.chunk(&token, 128, "eA==").is_err());
        let mut called = false;
        assert!(ss
            .validate(&token, |_| {
                called = true;
                Ok(())
            })
            .is_ok());
        assert!(called);
        assert!(ss.chunk(&token, 0, "eA==").is_err());
        ss.abort(&token).unwrap();
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_dir(&dir).unwrap();
    }
}
