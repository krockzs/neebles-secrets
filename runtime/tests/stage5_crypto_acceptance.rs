//! Acceptance test-only: genuine KeePassXC on throwaway KDBX in isolated bwrap.
//! Must never be run outside NEEBLES_STAGE5_SCRATCH=disposable-only.
#![allow(dead_code)]
#[path = "../src/backup_sessions.rs"]
mod backup_sessions;
#[path = "../src/portable_exports.rs"]
mod portable_exports;
#[path = "../src/restore_sessions.rs"]
mod restore_sessions;
#[path = "../src/restore_transaction.rs"]
mod restore_transaction;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MASTER: &str = "stage5-qa-disposable-master-key-2026";
const WRONG: &str = "stage5-qa-incorrect-master-key-2026";

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str) -> Self {
        assert_eq!(
            std::env::var("NEEBLES_STAGE5_SCRATCH").as_deref(),
            Ok("disposable-only"),
            "NEVER run on real KDBX"
        );
        let root = Path::new("/qa-data");
        assert!(root.is_dir() && !root.is_symlink());
        let mut nonce = [0u8; 16];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut nonce)
            .unwrap();
        let id = nonce.iter().map(|v| format!("{v:02x}")).collect::<String>();
        let path = root.join(format!("{label}-{id}"));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(fs::symlink_metadata(&path).unwrap().uid(), unsafe {
            libc::geteuid()
        });
        Self(path)
    }
    fn dir(&self) -> &Path {
        &self.0
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cli(arguments: &[&std::ffi::OsStr], lines: &[&str]) -> bool {
    let mut cmd = Command::new("/usr/bin/keepassxc-cli");
    cmd.args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd
        .spawn()
        .expect("keepassxc-cli unavailable in disposable RootFS");
    {
        let mut input = child.stdin.take().unwrap();
        for secret in lines {
            input.write_all(secret.as_bytes()).unwrap();
            input.write_all(b"\n").unwrap();
        }
    }
    child.wait().unwrap().success()
}
fn create_db(path: &Path, pass: &str) {
    use std::ffi::OsStr;
    assert!(!path.exists());
    assert!(cli(
        &[OsStr::new("db-create"), OsStr::new("-p"), path.as_os_str()],
        &[pass, pass]
    ));
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn verify_db(path: &Path, pass: &str) -> Result<(), String> {
    use std::ffi::OsStr;
    if cli(
        &[OsStr::new("db-info"), OsStr::new("-q"), path.as_os_str()],
        &[pass],
    ) {
        Ok(())
    } else {
        Err("key_or_kdbx_rejected".into())
    }
}
fn digest(bytes: &[u8]) -> String {
    let h = Sha256::digest(bytes);
    h.iter().map(|b| format!("{b:02x}")).collect()
}
fn write_private(path: &Path, bytes: &[u8]) {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

#[test]
#[ignore = "Run ONLY inside throwaway bwrap with real KeePassXC"]
fn stage5_acceptance_portable_independent_kdbx() {
    let f = Fixture::new("stage5-portable");
    let mut exporter = portable_exports::PortableExports::default();
    let key = "independent-export-password-stage5";
    assert_ne!(key, MASTER);
    let token = exporter.begin(f.dir(), key).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        exporter.append(&token, "disposable-qa-secret-one").unwrap()["entries"],
        1
    );
    assert_eq!(
        exporter.append(&token, "disposable-qa-secret-two").unwrap()["entries"],
        2
    );
    let sealed = exporter.seal(&token).unwrap();
    let total = sealed["size"].as_u64().unwrap() as usize;
    let mut bytes = Vec::with_capacity(total);
    while bytes.len() < total {
        let n = (total - bytes.len()).min(6144);
        let packet = exporter.read(&token, bytes.len() as u64, n).unwrap();
        assert_eq!(packet["next"].as_u64().unwrap(), (bytes.len() + n) as u64);
        bytes.extend(
            base64::engine::general_purpose::STANDARD
                .decode(packet["value"].as_str().unwrap())
                .unwrap(),
        );
    }
    assert_eq!(bytes.len(), total);
    assert_eq!(digest(&bytes), sealed["sha256"].as_str().unwrap());
    assert_eq!(&bytes[..4], &[3, 217, 162, 154]);
    let copy = f.dir().join("independent-portable-export.kdbx");
    write_private(&copy, &bytes);
    verify_db(&copy, key).unwrap();
    assert!(verify_db(&copy, MASTER).is_err());
    exporter.close(&token).unwrap();
    assert_eq!(
        fs::read_dir(f.dir()).unwrap().count(),
        1,
        "exporter temporary file left behind"
    );
    assert_eq!(
        fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
#[ignore = "Run ONLY inside throwaway bwrap with real KeePassXC"]
fn stage5_acceptance_backup_restore_encrypted_multi_vault() {
    let f = Fixture::new("stage5-backup-restore");
    let names = ["vault-general.kdbx", "vault-neebles-connect.kdbx"];
    let generated = f.dir().join("source");
    fs::create_dir(&generated).unwrap();
    fs::set_permissions(&generated, fs::Permissions::from_mode(0o700)).unwrap();
    let mut old = Vec::new();
    let mut replacements = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let live = f.dir().join(name);
        create_db(&live, MASTER);
        let old_bytes = fs::read(&live).unwrap();
        verify_db(&live, MASTER).unwrap();
        let next = generated.join(format!("new-{i}.kdbx"));
        create_db(&next, MASTER);
        let new_bytes = fs::read(&next).unwrap();
        assert_ne!(digest(&old_bytes), digest(&new_bytes));
        old.push(old_bytes);
        replacements.push(new_bytes);
    }
    let listing = backup_sessions::BackupSessions::catalog(f.dir()).unwrap();
    assert_eq!(listing["names"].as_array().unwrap().len(), 2);
    let mut backup = backup_sessions::BackupSessions::default();
    let session = backup.open(f.dir(), "full", None).unwrap();
    let token = session["token"].as_str().unwrap().to_string();
    assert_eq!(session["files"].as_array().unwrap().len(), 2);
    assert!(
        backup.open(f.dir(), "single", Some(names[0])).is_err(),
        "overlapping backup sessions"
    );
    for (i, name) in names.iter().enumerate() {
        assert_eq!(session["files"][i]["name"].as_str(), Some(*name));
        let n = session["files"][i]["size"].as_u64().unwrap() as usize;
        assert_eq!(n, old[i].len());
        assert_eq!(
            session["files"][i]["sha256"].as_str(),
            Some(digest(&old[i]).as_str())
        );
        let mut streamed = Vec::new();
        while streamed.len() < n {
            let step = (n - streamed.len()).min(6144);
            let packet = backup.read(&token, i, streamed.len() as u64, step).unwrap();
            streamed.extend(
                base64::engine::general_purpose::STANDARD
                    .decode(packet["value"].as_str().unwrap())
                    .unwrap(),
            );
        }
        assert_eq!(streamed, old[i]);
    }
    backup.close(&token).unwrap();
    assert!(backup.read(&token, 0, 0, 1).is_err());

    let mut restores = restore_sessions::RestoreSessions::default();
    for (i, name) in names.iter().enumerate() {
        let bytes = &replacements[i];
        let tok = restores
            .start(f.dir(), name, bytes.len() as u64, &digest(bytes))
            .unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let n = (bytes.len() - offset).min(6144);
            restores
                .chunk(
                    &tok,
                    offset as u64,
                    &base64::engine::general_purpose::STANDARD.encode(&bytes[offset..offset + n]),
                )
                .unwrap();
            offset += n;
        }
        restores
            .validate(&tok, |path| verify_db(path, MASTER))
            .unwrap();
        restores.queue(&tok).unwrap();
    }
    let confirm = restores.plan().unwrap()["confirmation"]
        .as_str()
        .unwrap()
        .to_string();
    restores.consume_confirmation(&confirm).unwrap();
    assert!(
        restores.consume_confirmation(&confirm).is_err(),
        "replayed restore confirmation"
    );
    let staged = restores.prepared_inputs().unwrap();
    assert_eq!(staged.len(), 2);
    for (i, name) in names.iter().enumerate() {
        assert_eq!(fs::read(f.dir().join(name)).unwrap(), old[i]);
    }
    restore_transaction::apply_checked(f.dir(), &staged, |path| verify_db(path, MASTER)).unwrap();
    restores.clear();
    for (i, name) in names.iter().enumerate() {
        assert_eq!(fs::read(f.dir().join(name)).unwrap(), replacements[i]);
        verify_db(&f.dir().join(name), MASTER).unwrap();
        assert_eq!(
            fs::metadata(f.dir().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert!(
        !fs::read_dir(f.dir())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e
                .file_name()
                .to_string_lossy()
                .starts_with(".neebles-restore")),
        "restore residue"
    );

    let invalid = generated.join("wrong-key.kdbx");
    create_db(&invalid, WRONG);
    let bad = fs::read(&invalid).unwrap();
    let before = names
        .iter()
        .map(|n| fs::read(f.dir().join(n)).unwrap())
        .collect::<Vec<_>>();
    let tok = restores
        .start(f.dir(), names[0], bad.len() as u64, &digest(&bad))
        .unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    for (offset, part) in bad.chunks(6144).enumerate() {
        restores
            .chunk(
                &tok,
                (offset * 6144) as u64,
                &base64::engine::general_purpose::STANDARD.encode(part),
            )
            .unwrap();
    }
    assert!(
        restores.validate(&tok, |p| verify_db(p, MASTER)).is_err(),
        "wrong-key KDBX validated"
    );
    restores.clear();
    for (i, name) in names.iter().enumerate() {
        assert_eq!(fs::read(f.dir().join(name)).unwrap(), before[i]);
    }
}
