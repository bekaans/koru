//! File-identity sources: real files in a temporary directory and `/proc` on Linux.
//!
//! The allowlist and Koru's self-exclusion rest on a file's identity (device and inode), not
//! its path name (KT-01). These tests check the identity against path tricks on a real file
//! system (only `tempfile` directories); the scenario tests use a fake source.

use std::fs;
use std::os::unix::fs::MetadataExt;

use koru_detect::{IdentitySource, KoruIdentity, SystemIdentitySource};

use crate::common::temporary;

#[test]
fn path_identity_gives_device_and_inode_following_links() {
    let d = temporary();
    let file = d.path.join("binary");
    fs::write(&file, b"content").unwrap();
    let hard = d.path.join("hard");
    fs::hard_link(&file, &hard).unwrap();
    let symbolic = d.path.join("symbolic");
    std::os::unix::fs::symlink(&file, &symbolic).unwrap();
    let same_content = d.path.join("same-content");
    fs::write(&same_content, b"content").unwrap();

    let k = SystemIdentitySource;
    let path = |p: &std::path::Path| k.path_id(p.to_str().unwrap());
    let m = fs::metadata(&file).unwrap();
    let id = path(&file).expect("an existing file's identity must be readable");
    assert_eq!((id.device, id.inode), (m.dev(), m.ino()));
    assert_eq!(path(&hard), Some(id), "a hard link is the same inode");
    assert_eq!(path(&symbolic), Some(id), "a symbolic link is followed");
    let another_id = path(&same_content).expect("second file");
    assert_ne!(another_id, id, "a separate file has a different identity even with the same content");
    assert_eq!(path(&d.path.join("missing")), None);
    assert_eq!(k.path_id(""), None);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_process_exe_identity_and_this_process() {
    let k = SystemIdentitySource;
    let own_exe = fs::read_link("/proc/self/exe").unwrap();
    let expected_id = k.path_id(own_exe.to_str().unwrap()).expect("the test binary's identity");
    assert_eq!(k.process_exe_id(std::process::id()), Some(expected_id));
    // No such process (far above pid_max): quietly ignored.
    assert_eq!(k.process_exe_id(u32::MAX), None);

    let b = KoruIdentity::this_process().expect("/proc/self is readable on Linux");
    assert_eq!(b.pid, std::process::id());
    assert_eq!(b.ppid, std::os::unix::process::parent_id());
    assert_eq!(b.exe, own_exe.to_str().unwrap());
    assert_eq!(b.file, expected_id);
    assert_eq!(b.command_line, std::env::args().collect::<Vec<String>>());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn no_process_identity_outside_linux() {
    // The dev machine has no /proc: an error or "absent" comes back, nothing is invented.
    assert!(KoruIdentity::this_process().is_err());
    assert_eq!(SystemIdentitySource.process_exe_id(std::process::id()), None);
}
