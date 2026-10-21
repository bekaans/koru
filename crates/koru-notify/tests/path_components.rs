//! A below-threshold note from the security review: the INTERMEDIATE
//! components of `.env` and queue paths are checked too. Before, only the final component was
//! checked: an intermediate symlink could make `.env` read from an attacker-chosen place; a
//! parent directory writable by others let anyone swap the file.
//!
//! Rule: the path is opened component by component with `O_NOFOLLOW | O_DIRECTORY`; every
//! intermediate directory must belong to the user running Koru or to root and must not be
//! group/world-writable (with the sticky bit, like `/tmp`, it is accepted). Tests write only to temp dirs.

mod common;

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use common::*;
use koru_notify::{PersistentQueue, read_dotenv};

/// Creates the directory and missing parents explicitly with 0755 (modes must not depend on
/// `umask`; the Linux default umask 0002 produces group-writable dirs).
fn make_directory(dir: &Path) {
    let mut missing = Vec::new();
    let mut p = dir;
    while !p.exists() {
        missing.push(p);
        p = p.parent().unwrap();
    }
    for d in missing.iter().rev() {
        fs::create_dir(d).unwrap();
        fs::set_permissions(d, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn write_env(dir: &Path) -> PathBuf {
    make_directory(dir);
    let path = dir.join(".env");
    fs::write(&path, "KORU_NTFY_URL=https://ntfy.example.test/k\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn dotenv_is_rejected_when_a_parent_is_a_symlink() {
    let t = is_transient();
    let root = canonicalized(&t);
    write_env(&root.join("real"));
    symlink(root.join("real"), root.join("link")).unwrap();
    let e = read_dotenv(&root.join("link").join(".env")).expect_err("an intermediate symlink");
    assert!(e.to_string().contains("symlinks are not followed"), "{e}");
    // The same file reads fine through its real path.
    assert!(read_dotenv(&root.join("real").join(".env")).is_ok());
}

#[test]
fn a_deep_parent_symlink_is_also_rejected() {
    let t = is_transient();
    let root = canonicalized(&t);
    write_env(&root.join("a").join("b").join("c"));
    symlink(root.join("a").join("b"), root.join("a").join("bb")).unwrap();
    let e = read_dotenv(&root.join("a").join("bb").join("c").join(".env")).expect_err("a deep intermediate symlink");
    assert!(e.to_string().contains("symlinks are not followed"), "{e}");
}

#[test]
fn dotenv_is_rejected_when_a_parent_is_group_or_world_writable() {
    for mode in [0o777, 0o770, 0o707, 0o772] {
        let t = is_transient();
        let root = canonicalized(&t);
        let open_dir = root.join("open_dir");
        let env = write_env(&open_dir.join("child"));
        set_mode(&open_dir, mode);
        let e = read_dotenv(&env).expect_err("a writable parent dir");
        assert!(e.to_string().contains("writable"), "{mode:o}: {e}");
        // The containing dir itself follows the same rule.
        set_mode(&open_dir, 0o700);
        set_mode(&open_dir.join("child"), mode);
        let e = read_dotenv(&env).expect_err("a writable containing dir");
        assert!(e.to_string().contains("writable"), "{mode:o}: {e}");
        // A merely readable/traversable dir is fine.
        set_mode(&open_dir.join("child"), 0o755);
        set_mode(&open_dir, 0o755);
        assert!(read_dotenv(&env).is_ok(), "0755 must be accepted");
    }
}

#[test]
fn a_sticky_bit_shared_parent_is_accepted() {
    let t = is_transient();
    let root = canonicalized(&t);
    let shared_dir = root.join("shared");
    let env = write_env(&shared_dir.join("mine"));
    set_mode(&shared_dir, 0o1777);
    assert!(read_dotenv(&env).is_ok(), "a /tmp-like sticky dir must be accepted");
}

#[test]
fn a_relative_dotenv_path_resolves_and_is_checked_the_same() {
    let t = is_transient();
    let root = canonicalized(&t);
    write_env(&root.join("project"));
    symlink(root.join("project"), root.join("p")).unwrap();
    // The same error for an absolute path; a relative path cannot contain `..`.
    assert!(read_dotenv(&root.join("p").join(".env")).is_err());
    let e = read_dotenv(Path::new("../project/.env")).expect_err("a '..' component");
    assert!(e.to_string().contains(".."), "{e}");
}

#[test]
fn a_queue_with_a_writable_or_symlinked_parent_is_rejected() {
    let t = is_transient();
    let root = canonicalized(&t);
    // A writable parent.
    let open_dir = root.join("open_dir");
    make_directory(&open_dir);
    set_mode(&open_dir, 0o777);
    let e = PersistentQueue::open(&open_dir.join("queue"), "ntfy", 10).expect_err("a writable parent dir");
    assert!(e.to_string().contains("writable"), "{e}");
    assert!(!open_dir.join("queue").exists(), "no dir may be created on a rejected path");
    // An intermediate symlink.
    make_directory(&root.join("real"));
    set_mode(&root.join("real"), 0o700);
    symlink(root.join("real"), root.join("link")).unwrap();
    let e = PersistentQueue::open(&root.join("link").join("queue"), "ntfy", 10).expect_err("an intermediate symlink");
    assert!(e.to_string().contains("symlinks are not followed"), "{e}");
    // The normal path works (only the last dir is created; parents exist).
    make_directory(&root.join("clean"));
    assert!(PersistentQueue::open(&root.join("clean").join("queue"), "ntfy", 10).is_ok());
}
