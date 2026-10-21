//! Rewrite safety on removal (a below-threshold note from the security review).
//!
//! Install checks an append target for a single link (`nlink == 1`), a regular file, and
//! ownership by the target user (KT-47). Removal runs the same check when it rewrites an
//! existing file (dropping appended lines or restoring from backup): a file that fails the
//! check is left untouched, the entry is reported, and it stays in the record.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use koru_decoy::{RemovalStatus, list_entries, uninstall};
use serde_json::json;

use crate::common::{Env, PREVIOUS_HISTORY, prepare_existing_home, temp_dir};

/// An environment where the user added a new line to the shell history after install.
fn installed_with_user_write() -> (Env, PathBuf) {
    let environment = Env::new();
    prepare_existing_home(environment.root());
    environment.install();
    let history = environment.root().join(".bash_history");
    OpenOptions::new().append(true).open(&history).unwrap().write_all(b"df -h\n").unwrap();
    (environment, history)
}

fn result<'a>(k: &'a koru_decoy::RemovalReport, path: &Path) -> &'a RemovalStatus {
    &k.results
        .iter()
        .find(|s| Path::new(&s.path) == path)
        .unwrap_or_else(|| panic!("{} missing from the report", path.display()))
        .state
}

fn in_record(environment: &Env, path: &Path) -> bool {
    list_entries(&environment.state()).unwrap().iter().any(|g| Path::new(&g.path) == path)
}

#[test]
fn append_removal_skips_hard_linked_file() {
    let (environment, history) = installed_with_user_write();
    let outside = temp_dir();
    let second_name = outside.path.join("second-name");
    fs::hard_link(&history, &second_name).unwrap();
    let content_before = fs::read(&history).unwrap();
    let inode_once = fs::metadata(&history).unwrap().ino();

    let k = uninstall(&environment.state()).unwrap();
    assert!(!k.completed(), "a hard-linked file must have been left: {:?}", k.results);
    assert!(
        matches!(result(&k, &history), RemovalStatus::Left { reason } if reason.contains("hard-linked")),
        "{:?}",
        result(&k, &history)
    );
    // The file was not rewritten: content, inode, and link count unchanged.
    assert_eq!(fs::read(&history).unwrap(), content_before);
    let m = fs::metadata(&history).unwrap();
    assert_eq!((m.ino(), m.nlink()), (inode_once, 2));
    assert_eq!(fs::read(&second_name).unwrap(), content_before);
    assert!(in_record(&environment, &history), "a left entry must stay in the record");

    // Once an administrator removes the second name, removal completes; the user's line is kept.
    fs::remove_file(&second_name).unwrap();
    let k = uninstall(&environment.state()).unwrap();
    assert!(k.completed(), "{:?}", k.results);
    assert_eq!(result(&k, &history), &RemovalStatus::AppendRemoved);
    assert_eq!(fs::read_to_string(&history).unwrap(), format!("{PREVIOUS_HISTORY}df -h\n"));
}

#[test]
fn append_removal_skips_differently_owned_file() {
    let (environment, history) = installed_with_user_write();
    let uid = fs::metadata(&history).unwrap().uid();
    // The record's owner is changed because a file's owner cannot change without root: the
    // file on disk no longer belongs to the (target) user in the record.
    let record_path = environment.state().join("record.json");
    let mut record: serde_json::Value = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
    let mut changed = 0;
    for g in record["entries"].as_array_mut().unwrap() {
        if g["path"] == json!(history.to_string_lossy()) {
            g["uid"] = json!(uid.wrapping_add(1));
            changed += 1;
        }
    }
    assert_eq!(changed, 1);
    fs::write(&record_path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    let content_before = fs::read(&history).unwrap();
    let inode_once = fs::metadata(&history).unwrap().ino();

    let k = uninstall(&environment.state()).unwrap();
    assert!(!k.completed());
    assert!(
        matches!(result(&k, &history), RemovalStatus::Left { reason } if reason.contains("owner")),
        "{:?}",
        result(&k, &history)
    );
    assert_eq!(fs::read(&history).unwrap(), content_before);
    assert_eq!(fs::metadata(&history).unwrap().ino(), inode_once);
    assert!(in_record(&environment, &history));
}

#[test]
fn backup_restore_skips_hard_linked_file() {
    // The user did not write the file (content as installed), but the file got a second name:
    // a restore from backup would write a new inode and the breadcrumb lines would stay under
    // the second name.
    let environment = Env::new();
    prepare_existing_home(environment.root());
    environment.install();
    let history = environment.root().join(".bash_history");
    let outside = temp_dir();
    let second_name = outside.path.join("second-name");
    fs::hard_link(&history, &second_name).unwrap();
    let content_before = fs::read(&history).unwrap();

    let k = uninstall(&environment.state()).unwrap();
    assert!(
        matches!(result(&k, &history), RemovalStatus::Left { reason } if reason.contains("hard-linked")),
        "{:?}",
        result(&k, &history)
    );
    assert_eq!(fs::read(&history).unwrap(), content_before);
    assert_eq!(fs::metadata(&history).unwrap().nlink(), 2);
    assert!(in_record(&environment, &history));

    fs::remove_file(&second_name).unwrap();
    let k = uninstall(&environment.state()).unwrap();
    assert!(k.completed(), "{:?}", k.results);
    assert_eq!(result(&k, &history), &RemovalStatus::Restored);
    assert_eq!(fs::read_to_string(&history).unwrap(), PREVIOUS_HISTORY);
}
