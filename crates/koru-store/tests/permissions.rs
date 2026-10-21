//! File security (protected set; ADR-0006 "File security"):
//! the database is 0600, its directory 0700; symlinks, hard links, and special files are not
//! followed; a directory or file with the wrong owner or mode is rejected.

mod common;

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

use common::*;
use koru_store::{Store, StoreError, StoreSettings};

fn open(path: &Path) -> Result<Store, StoreError> {
    Store::open(StoreSettings::new(path))
}

#[test]
fn file_0600_and_directory_0700_created() {
    let t = temp();
    let dir = canonical(&t).join("child");
    let path = dir.join("event.db");
    let mut store_inst = open(&path).expect("the subdirectory must be created");
    store_inst.store_event(&event("file_opened", 0)).unwrap();
    assert_eq!(file_mode(&dir), 0o700);
    assert_eq!(file_mode(&path), 0o600);
}

#[test]
fn wal_and_shm_files_are_also_0600() {
    let t = temp();
    let path = store_path(&t);
    let mut store_inst = open(&path).unwrap();
    store_inst.store_event(&event("file_opened", 0)).unwrap();
    let mut seen = 0;
    for suffix in ["-wal", "-shm"] {
        let sidecar = path.with_file_name(format!("event.db{suffix}"));
        if sidecar.exists() {
            seen += 1;
            assert_eq!(file_mode(&sidecar), 0o600, "{} must be 0600", sidecar.display());
        }
    }
    assert!(seen >= 1, "at least one sidecar file is expected in WAL mode");
}

#[test]
fn missing_parent_dir_is_an_error_and_no_chain_is_created() {
    let t = temp();
    let path = canonical(&t).join("missing").join("child").join("event.db");
    assert!(open(&path).is_err());
    assert!(!canonical(&t).join("missing").exists());
}

#[test]
fn relative_and_dotted_paths_are_rejected() {
    assert!(matches!(open(Path::new("event.db")), Err(StoreError::UnsafePath { .. })));
    let t = temp();
    let path = canonical(&t).join("a").join("..").join("event.db");
    assert!(matches!(open(&path), Err(StoreError::UnsafePath { .. })));
}

#[test]
fn symlink_database_file_is_rejected() {
    let t = temp();
    let real = canonical(&t).join("real.db");
    fs::write(&real, b"").unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
    let path = store_path(&t);
    symlink(&real, &path).unwrap();
    assert!(matches!(open(&path), Err(StoreError::Symlink { .. })));
    assert_eq!(fs::metadata(&real).unwrap().len(), 0, "must not write to the link target");
}

#[test]
fn symlink_path_component_is_rejected() {
    let t = temp();
    let root = canonical(&t);
    fs::create_dir(root.join("real")).unwrap();
    fs::set_permissions(root.join("real"), fs::Permissions::from_mode(0o700)).unwrap();
    symlink(root.join("real"), root.join("connection")).unwrap();
    let path = root.join("connection").join("event.db");
    assert!(matches!(open(&path), Err(StoreError::Symlink { .. })));
    assert!(!root.join("real").join("event.db").exists());
}

#[test]
fn symlink_directory_is_rejected() {
    let t = temp();
    let root = canonical(&t);
    fs::create_dir(root.join("target")).unwrap();
    symlink(root.join("target"), root.join("child")).unwrap();
    assert!(matches!(open(&root.join("child").join("event.db")), Err(StoreError::Symlink { .. })));
}

#[test]
fn loose_directory_mode_is_rejected() {
    let t = temp();
    let root = canonical(&t);
    for mode in [0o755, 0o750, 0o701, 0o777] {
        let dir = root.join(format!("d{mode:o}"));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
        let err = open(&dir.join("event.db")).unwrap_err();
        assert!(matches!(err, StoreError::UnsafePath { .. }), "mode {mode:o}: {err:?}");
        assert!(!dir.join("event.db").exists(), "mode {mode:o}: no file must be created");
    }
}

#[test]
fn loose_file_mode_is_rejected() {
    let t = temp();
    let path = store_path(&t);
    drop(open(&path).unwrap());
    for mode in [0o644, 0o640, 0o602, 0o666] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        let err = open(&path).unwrap_err();
        assert!(matches!(err, StoreError::UnsafePath { .. }), "mode {mode:o}: {err:?}");
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    open(&path).expect("0600 must be accepted");
}

#[test]
fn hard_linked_file_is_rejected() {
    let t = temp();
    let path = store_path(&t);
    drop(open(&path).unwrap());
    fs::hard_link(&path, canonical(&t).join("other-name.db")).unwrap();
    let err = open(&path).unwrap_err();
    assert!(matches!(err, StoreError::UnsafePath { .. }), "{err:?}");
}

#[test]
fn special_file_and_directory_are_rejected() {
    let t = temp();
    let root = canonical(&t);
    let fifo = root.join("event.db");
    let status = Command::new("mkfifo").arg(&fifo).status().expect("mkfifo");
    assert!(status.success());
    let err = open(&fifo).unwrap_err();
    assert!(matches!(err, StoreError::UnsafePath { .. }), "must be rejected without blocking on the FIFO: {err:?}");
    let dir_named = root.join("dir.db");
    fs::create_dir(&dir_named).unwrap();
    assert!(matches!(open(&dir_named), Err(StoreError::UnsafePath { .. })));
}

#[test]
fn reopening_does_not_change_modes() {
    let t = temp();
    let path = store_path(&t);
    drop(open(&path).unwrap());
    drop(open(&path).unwrap());
    assert_eq!(file_mode(&path), 0o600);
    assert_eq!(file_mode(&canonical(&t)), 0o700);
}
