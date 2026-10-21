//! `IdentitySource::verify_process_exe`: verifies that a process's real exe (path and inode)
//! matches the expectation together (security review). The real source
//! (`SystemIdentitySource`) fails closed: `false` if `/proc` is unreadable, the path is not
//! UTF-8, or path or inode mismatches. For fake sources without path knowledge, the default
//! implementation checks the inode only.

use koru_detect::{FileIdentity, IdentitySource, SystemIdentitySource};

use crate::common::*;

#[test]
fn an_unreadable_process_is_not_verified() {
    // Far above pid_max: no such process; fail closed.
    let id = FileIdentity { device: 1, inode: 1 };
    assert!(!SystemIdentitySource.verify_process_exe(u32::MAX, "/usr/bin/x", id));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_own_process_verifies_by_path_and_inode() {
    use std::os::unix::fs::MetadataExt;

    let k = SystemIdentitySource;
    let exe = std::fs::read_link("/proc/self/exe").unwrap();
    let path = exe.to_str().unwrap();
    let m = std::fs::metadata(&exe).unwrap();
    let id = FileIdentity { device: m.dev(), inode: m.ino() };
    let pid = std::process::id();
    assert!(k.verify_process_exe(pid, path, id));
    assert!(!k.verify_process_exe(pid, "/tmp/another-path", id), "different path");
    assert!(!k.verify_process_exe(pid, path, FileIdentity { inode: id.inode + 1, ..id }), "different inode");
    assert!(!k.verify_process_exe(pid, path, FileIdentity { device: id.device + 1, ..id }), "different device");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn outside_linux_verification_is_unavailable_and_rejects() {
    // No /proc: fail closed; nothing is invented.
    let id = FileIdentity { device: 1, inode: 1 };
    assert!(!SystemIdentitySource.verify_process_exe(std::process::id(), "/usr/bin/x", id));
}

#[test]
fn the_default_impl_requires_only_the_inode_without_paths() {
    // A fake source without path knowledge (tests): true if the identity matches, else false.
    let source = identity_source();
    assert!(source.verify_process_exe(KORU_PID, KORU_EXE, KORU_FILE));
    assert!(!source.verify_process_exe(KORU_PID, KORU_EXE, OTHER_FILE));
    assert!(!source.verify_process_exe(1, KORU_EXE, KORU_FILE), "unknown process");
}
