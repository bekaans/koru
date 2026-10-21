//! Clean rollback: the pre-install snapshot = the post-removal snapshot (path, kind, mode,
//! owner, content, mtime); appends to existing files come back from backup byte for byte; a
//! decoy changed after install is not deleted blindly.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use koru_decoy::{InstallError, RemovalStatus, install, list_entries, uninstall};

use crate::common::{
    Env, PREVIOUS_HISTORY, PREVIOUS_KNOWN_HOSTS, PREVIOUS_SSH_CONFIG, package, prepare_existing_home, snapshot,
    snapshot_diff,
};

fn state_is_empty(state: &Path) -> bool {
    !state.exists() || fs::read_dir(state).unwrap().next().is_none()
}

#[test]
fn empty_home_install_remove_snapshot_identical() {
    let environment = Env::new();
    let before = snapshot(environment.root());
    let report = environment.install();
    assert!(snapshot(environment.root()).len() > before.len() + report.entries.len() - 1, "install created no file");
    let k = uninstall(&environment.state()).unwrap();
    assert!(k.completed(), "removal did not complete: {:?}", k.results);
    assert_eq!(k.results.len(), report.entries.len());
    assert!(k.results.iter().all(|s| s.state == RemovalStatus::Removed), "{:?}", k.results);
    let diff = snapshot_diff(&before, &snapshot(environment.root()));
    assert!(diff.is_empty(), "the post-removal snapshot differs:\n{}", diff.join("\n"));
    assert!(matches!(list_entries(&environment.state()), Err(InstallError::NotInstalled)));
    assert!(state_is_empty(&environment.state()), "a record or backup remains in the state directory");
}

#[test]
fn existing_files_restored_from_backup_byte_for_byte() {
    let environment = Env::new();
    prepare_existing_home(environment.root());
    let before = snapshot(environment.root());
    environment.install();
    // After install, existing files start with the previous content, breadcrumbs appended.
    for (name, previous) in [
        (".bash_history", PREVIOUS_HISTORY),
        (".ssh/config", PREVIOUS_SSH_CONFIG),
        (".ssh/known_hosts", PREVIOUS_KNOWN_HOSTS),
    ] {
        let now = fs::read_to_string(environment.root().join(name)).unwrap();
        assert!(
            now.starts_with(previous) && now.len() > previous.len(),
            "{name}: the append is not in the expected form"
        );
    }
    // An append does not change an existing file's mode, owner, or times.
    let after = snapshot(environment.root());
    for name in ["./.bash_history", "./.ssh/config", "./.ssh/known_hosts"] {
        let (o, s) = (&before[Path::new(name)], &after[Path::new(name)]);
        assert_eq!((o.mode, o.uid, o.gid, o.mtime_ns), (s.mode, s.uid, s.gid, s.mtime_ns), "{name}");
    }
    let k = uninstall(&environment.state()).unwrap();
    assert!(k.completed(), "{:?}", k.results);
    let restored = k.results.iter().filter(|s| s.state == RemovalStatus::Restored).count();
    assert_eq!(restored, 3, "three files must be restored from backup: {:?}", k.results);
    let diff = snapshot_diff(&before, &snapshot(environment.root()));
    assert!(diff.is_empty(), "the post-removal snapshot differs:\n{}", diff.join("\n"));
    assert!(state_is_empty(&environment.state()));
}

#[test]
fn user_lines_added_after_install_preserved() {
    let environment = Env::new();
    prepare_existing_home(environment.root());
    environment.install();
    let history = environment.root().join(".bash_history");
    OpenOptions::new().append(true).open(&history).unwrap().write_all(b"df -h\nuptime\n").unwrap();
    let ssh_config = environment.root().join(".ssh/config");
    OpenOptions::new().append(true).open(&ssh_config).unwrap().write_all(b"\nHost new\n    User bob\n").unwrap();
    let k = uninstall(&environment.state()).unwrap();
    assert!(k.completed(), "{:?}", k.results);
    assert_eq!(fs::read_to_string(&history).unwrap(), format!("{PREVIOUS_HISTORY}df -h\nuptime\n"));
    assert_eq!(fs::read_to_string(&ssh_config).unwrap(), format!("{PREVIOUS_SSH_CONFIG}\nHost new\n    User bob\n"));
    assert_eq!(fs::read_to_string(environment.root().join(".ssh/known_hosts")).unwrap(), PREVIOUS_KNOWN_HOSTS);
    let removed = k.results.iter().filter(|s| s.state == RemovalStatus::AppendRemoved).count();
    assert_eq!(removed, 2, "{:?}", k.results);
}

#[test]
fn changed_decoy_not_deleted_reported_then_completable() {
    let environment = Env::new();
    prepare_existing_home(environment.root());
    let before = snapshot(environment.root());
    let report = environment.install();
    let aws = report.entries.iter().find(|g| g.class == "cloud_credentials").unwrap().path.clone();
    fs::write(&aws, "[default]\naws_access_key_id = the-users-own-value\n").unwrap();

    let k = uninstall(&environment.state()).unwrap();
    assert!(!k.completed());
    let aws_result = k.results.iter().find(|s| s.path == aws).unwrap();
    assert!(matches!(&aws_result.state, RemovalStatus::Left { reason } if !reason.is_empty()));
    assert_eq!(fs::read_to_string(&aws).unwrap(), "[default]\naws_access_key_id = the-users-own-value\n");
    let remaining = list_entries(&environment.state()).unwrap();
    assert_eq!(remaining.len(), 1, "only the left decoy must stay in the record");
    assert_eq!(remaining[0].path, aws);
    for g in report.entries.iter().filter(|g| g.path != aws && g.append.is_none()) {
        assert!(!Path::new(&g.path).exists(), "{} was not deleted", g.path);
    }

    // An administrator inspects and deletes the file; a second removal cleans the record and dirs.
    fs::remove_file(&aws).unwrap();
    let k = uninstall(&environment.state()).unwrap();
    assert!(k.completed(), "{:?}", k.results);
    assert_eq!(k.results.len(), 1);
    assert_eq!(k.results[0].state, RemovalStatus::AlreadyAbsent);
    let diff = snapshot_diff(&before, &snapshot(environment.root()));
    assert!(diff.is_empty(), "the snapshot differs after two-stage removal:\n{}", diff.join("\n"));
    assert!(matches!(list_entries(&environment.state()), Err(InstallError::NotInstalled)));
}

#[test]
fn second_install_rejected_and_changes_nothing() {
    let environment = Env::new();
    environment.install();
    let intermediate = snapshot(environment.root());
    let record = list_entries(&environment.state()).unwrap();
    let error = install(&package(), &environment.settings()).unwrap_err();
    assert!(matches!(error, InstallError::AlreadyInstalled), "{error}");
    assert!(snapshot_diff(&intermediate, &snapshot(environment.root())).is_empty());
    assert_eq!(list_entries(&environment.state()).unwrap(), record);
}

#[test]
fn removal_and_queries_error_without_install() {
    let environment = Env::new();
    assert!(matches!(uninstall(&environment.state()), Err(InstallError::NotInstalled)));
    assert!(matches!(list_entries(&environment.state()), Err(InstallError::NotInstalled)));
    assert!(matches!(koru_decoy::integrity(&environment.state()), Err(InstallError::NotInstalled)));
    assert!(!environment.state().exists(), "a query must not create the state directory");
}
