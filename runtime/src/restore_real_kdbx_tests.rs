//! F11-H: authentic KeePassXC KDBX tests in disposable directories ONLY.
//! Explicitly ignored by default; run in the approved KeePassXC toolchain.
//! No installed /opt files, real vault directory, or system service touched.
#![cfg(test)]
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use crate::restore_transaction::{apply_checked, Incoming};

// Dummy constant for ephemeral test vaults. NEVER use as a production password.
const TEST_KEY: &[u8] = b"qa-f11h-disposable-vaults-2026";
const OTHER_KEY: &[u8] = b"qa-f11h-incompatible-vault-2026";

struct Lab { directory: PathBuf }
impl Lab {
    fn new() -> Self {
        let mut nonce=[0u8;16];
        File::open("/dev/urandom").unwrap().read_exact(&mut nonce).unwrap();
        let suffix=nonce.iter().map(|b|format!("{b:02x}")).collect::<String>();
        let directory=std::env::temp_dir().join(format!("neebles-f11h-kdbx-{}-{suffix}",std::process::id()));
        fs::create_dir(&directory).expect("unique isolated test directory");
        fs::set_permissions(&directory,fs::Permissions::from_mode(0o700)).unwrap();
        Self{directory}
    }
    fn file(&self, filename:&str)->PathBuf {self.directory.join(filename)}
}
impl Drop for Lab {
    fn drop(&mut self) {
        // This directory was created by this test with 128 bits of randomness.
        // Never delete a pre-existing directory or user-supplied location.
        let _=fs::remove_dir_all(&self.directory);
    }
}
fn cli_path()->PathBuf {
    std::env::var_os("NEEBLES_QA_KEEPASS_CLI")
        .map(PathBuf::from)
        .unwrap_or_else(||PathBuf::from("/usr/bin/keepassxc-cli"))
}
fn cli(args:&[&OsStr],password:&[u8],repeat:bool)->bool {
    let program=cli_path();
    assert!(program.is_file(),"KEEPASS_CLI_UNAVAILABLE: run this ignored test inside the approved keepass-full world, or set NEEBLES_QA_KEEPASS_CLI to an executable accessible with its libraries");
    let mut child=Command::new(program).args(args)
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("start disposable KeePassXC command");
    let mut payload=password.to_vec();payload.push(b'\n');
    if repeat {payload.extend_from_slice(password);payload.push(b'\n');}
    if child.stdin.take().unwrap().write_all(&payload).is_err() {
        let _=child.kill();let _=child.wait();return false;
    }
    let deadline=Instant::now()+Duration::from_secs(45);
    loop {
        match child.try_wait() {
            Ok(Some(status))=>return status.success(),
            Ok(None) if Instant::now()<deadline=>thread::sleep(Duration::from_millis(30)),
            _=>{let _=child.kill();let _=child.wait();return false;}
        }
    }
}
fn create(path:&Path,password:&[u8]) {
    let options=[OsStr::new("db-create"),OsStr::new("-p"),path.as_os_str()];
    assert!(cli(&options,password,true),"disposable KeePassXC db-create failed");
    fs::set_permissions(path,fs::Permissions::from_mode(0o600)).unwrap();
    assert!(path.is_file());
}
fn compatible(path:&Path,password:&[u8])->bool {
    let options=[OsStr::new("db-info"),OsStr::new("-q"),path.as_os_str()];
    cli(&options,password,false)
}
fn staged(lab:&Lab,name:&str,key:&[u8])->PathBuf {
    let file=lab.file(name);create(&file,key);file
}
#[test]
#[ignore="F11-H requires genuine keepassxc-cli; disposable isolated KDBX only"]
fn real_kdbx_two_vaults_commit_and_verify() {
    let lab=Lab::new();
    let old_general=lab.file("vault-general.kdbx");
    let old_connect=lab.file("vault-neebles-connect.kdbx");
    create(&old_general,TEST_KEY);create(&old_connect,TEST_KEY);
    let former_general=fs::read(&old_general).unwrap();
    let former_connect=fs::read(&old_connect).unwrap();
    let incoming_general=staged(&lab,".neebles-restore-f11h-general.pending.kdbx",TEST_KEY);
    let incoming_connect=staged(&lab,".neebles-restore-f11h-connect.pending.kdbx",TEST_KEY);
    let new_general=fs::read(&incoming_general).unwrap();
    let new_connect=fs::read(&incoming_connect).unwrap();
    let set=[Incoming{target:"vault-general.kdbx".into(),staged_file:incoming_general.clone()},
        Incoming{target:"vault-neebles-connect.kdbx".into(),staged_file:incoming_connect.clone()}];
    apply_checked(&lab.directory,&set,|path| {
        if compatible(path,TEST_KEY){Ok(())}else{Err("qa_kdbx_wrong_master".into())}
    }).expect("transactional real KDBX restore");
    assert_eq!(fs::read(&old_general).unwrap(),new_general);
    assert_eq!(fs::read(&old_connect).unwrap(),new_connect);
    assert_ne!(former_general,new_general);
    assert_ne!(former_connect,new_connect);
    assert!(compatible(&old_general,TEST_KEY));
    assert!(compatible(&old_connect,TEST_KEY));
    assert!(!incoming_general.exists());
    assert!(!incoming_connect.exists());
    assert_eq!(fs::read_dir(&lab.directory).unwrap().count(),2);
}
#[test]
#[ignore="F11-H requires genuine keepassxc-cli; disposable isolated KDBX only"]
fn real_kdbx_incompatible_master_never_replaces_original() {
    let lab=Lab::new();
    let original=lab.file("vault-general.kdbx");
    create(&original,TEST_KEY);
    let before=fs::read(&original).unwrap();
    let incoming=staged(&lab,".neebles-restore-f11h-rejected.pending.kdbx",OTHER_KEY);
    let selected=[Incoming{target:"vault-general.kdbx".into(),staged_file:incoming}];
    assert!(apply_checked(&lab.directory,&selected,|path| {
        if compatible(path,TEST_KEY){Ok(())}else{Err("qa_kdbx_wrong_master".into())}
    }).is_err());
    assert_eq!(fs::read(&original).unwrap(),before);
    assert!(compatible(&original,TEST_KEY));
    assert!(!lab.file(".neebles-restore-transaction.json").exists());
}
