//! The integrity record (SHA-256, path, owner, mode, timestamps), change detection, and the
//! `DecoyCatalog` implementation.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use koru_decoy::{Catalog, DecoyKind, IntegrityReport, IntegrityStatus, RecordEntry, integrity, list_entries};
use koru_event::{DecoyCatalog, WatchedPathKind};
use sha2::{Digest, Sha256};

use crate::common::{Env, PREVIOUS_HISTORY, mtime_ns, prepare_existing_home, set_mode, temp_dir};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn status_of<'a>(report: &'a IntegrityReport, path: &str) -> &'a IntegrityStatus {
    &report.results.iter().find(|s| s.path == path).unwrap_or_else(|| panic!("missing from the report: {path}")).state
}

fn entry<'a>(entries: &'a [RecordEntry], class: &str) -> &'a RecordEntry {
    entries.iter().find(|g| g.class == class).unwrap_or_else(|| panic!("{class} is not installed"))
}

#[test]
fn record_is_consistent_with_real_files() {
    let environment = Env::new();
    let report = environment.install();
    let root_meta = fs::metadata(environment.root()).unwrap();
    assert_eq!(
        list_entries(&environment.state()).unwrap(),
        report.entries,
        "list_entries must equal the install report"
    );
    assert!(report.entries.len() >= 12);
    for g in &report.entries {
        let path = Path::new(&g.path);
        assert!(
            path.is_absolute() && path.starts_with(environment.root()),
            "{}: not an absolute path under the root",
            g.path
        );
        let m = fs::symlink_metadata(path).unwrap();
        assert!(m.file_type().is_file());
        let content = fs::read(path).unwrap();
        assert_eq!(g.sha256, hex(&Sha256::digest(&content)), "{}: SHA-256", g.path);
        assert_eq!(g.sha256.len(), 64);
        assert_eq!(g.size, content.len() as u64);
        assert_eq!(g.mode, m.permissions().mode() & 0o7777, "{}: mode", g.path);
        assert_eq!((g.uid, g.gid), (m.uid(), m.gid()), "{}: owner", g.path);
        assert_eq!(
            (g.uid, g.gid),
            (root_meta.uid(), root_meta.gid()),
            "{}: the owner must be the root's owner",
            g.path
        );
        assert_eq!(g.mtime.unix_nanos(), mtime_ns(&m), "{}: timestamp", g.path);
    }
}

#[test]
fn integrity_intact_right_after_install() {
    let environment = Env::new();
    let report = environment.install();
    let b = integrity(&environment.state()).unwrap();
    assert_eq!(b.results.len(), report.entries.len());
    assert!(b.intact(), "a change was reported right after install: {:?}", b.results);
    assert!(b.results.iter().all(|s| s.state == IntegrityStatus::Intact));
}

#[test]
fn content_mode_time_kind_changes_and_deletion_detected() {
    let environment = Env::new();
    let report = environment.install();
    let aws = entry(&report.entries, "cloud_credentials").path.clone();
    let key = entry(&report.entries, "ssh_key").path.clone();
    let dump = entry(&report.entries, "database_dump").path.clone();
    let not = entry(&report.entries, "ai_note").path.clone();
    let mcp = report.entries.iter().find(|g| g.path.ends_with("/.cursor/mcp.json")).unwrap().path.clone();

    // A content change (even at the same size).
    let mut content = fs::read(&aws).unwrap();
    let last = content.len() - 2;
    content[last] = if content[last] == b'A' { b'B' } else { b'A' };
    let timestamp = fs::metadata(&aws).unwrap().modified().unwrap();
    fs::write(&aws, &content).unwrap();
    fs::File::options().write(true).open(&aws).unwrap().set_modified(timestamp).unwrap();
    // A mode change.
    set_mode(Path::new(&key), 0o644);
    // Deletion.
    fs::remove_file(&dump).unwrap();
    // Replacement by a symlink.
    let outside = temp_dir();
    fs::write(outside.path.join("fake.md"), "x").unwrap();
    fs::remove_file(&not).unwrap();
    symlink(outside.path.join("fake.md"), &not).unwrap();
    // A timestamp-only change.
    fs::File::options().write(true).open(&mcp).unwrap().set_modified(std::time::SystemTime::now()).unwrap();

    let b = integrity(&environment.state()).unwrap();
    assert!(!b.intact());
    for path in [&aws, &key, &not, &mcp] {
        assert!(matches!(status_of(&b, path), IntegrityStatus::Changed { reasons } if !reasons.is_empty()), "{path}");
    }
    assert_eq!(status_of(&b, &dump), &IntegrityStatus::Missing);
    let changed = b.results.iter().filter(|s| s.state != IntegrityStatus::Intact).count();
    assert_eq!(changed, 5, "only the five changed decoys must be reported: {:?}", b.results);
}

#[test]
fn user_append_to_breadcrumb_file_is_intact_but_line_deletion_is_a_change() {
    let environment = Env::new();
    prepare_existing_home(environment.root());
    environment.install();
    let history = environment.root().join(".bash_history");
    let path = history.to_string_lossy().into_owned();
    // The shell appends new lines to the history: intact as long as the breadcrumb stays in place.
    OpenOptions::new().append(true).open(&history).unwrap().write_all(b"htop\n").unwrap();
    let b = integrity(&environment.state()).unwrap();
    assert_eq!(status_of(&b, &path), &IntegrityStatus::Intact, "a user append must not count as a change");
    // Deleting the appended lines is caught.
    fs::write(&history, format!("{PREVIOUS_HISTORY}htop\n")).unwrap();
    let b = integrity(&environment.state()).unwrap();
    assert!(matches!(status_of(&b, &path), IntegrityStatus::Changed { .. }));
}

#[test]
fn catalog_separates_decoys_and_breadcrumbs() {
    let environment = Env::new();
    let report = environment.install();
    let catalog = Catalog::read(&environment.state()).unwrap();
    let paths = catalog.watched_paths();
    assert_eq!(paths.len(), report.entries.len());
    for g in &report.entries {
        let found = catalog.find(&g.path).unwrap_or_else(|| panic!("missing from the catalog: {}", g.path));
        assert_eq!(found.path, g.path);
        assert_eq!(found.decoy_id, g.id);
        let expected = match g.kind {
            DecoyKind::Decoy => WatchedPathKind::Decoy,
            DecoyKind::Breadcrumb => WatchedPathKind::Breadcrumb,
        };
        assert_eq!(found.kind, expected, "{}", g.path);
    }
    let iz: BTreeSet<PathBuf> = paths
        .iter()
        .filter(|y| y.kind == WatchedPathKind::Breadcrumb)
        .map(|y| Path::new(&y.path).strip_prefix(environment.root()).unwrap().to_path_buf())
        .collect();
    let expected: BTreeSet<PathBuf> =
        [".bash_history", ".ssh/config", ".ssh/known_hosts"].iter().map(PathBuf::from).collect();
    assert_eq!(iz, expected);
    assert!(paths.iter().filter(|y| y.kind == WatchedPathKind::Decoy).count() >= 9);
    assert!(catalog.find("/nonexistent/path").is_none());
    assert!(catalog.find(&environment.root().to_string_lossy()).is_none());
    // The catalog can also be built from record entries.
    assert_eq!(Catalog::from_entries(&report.entries).watched_paths().len(), paths.len());
}

#[test]
fn state_dir_record_and_backups_owner_only_outside_root() {
    let environment = Env::new();
    prepare_existing_home(environment.root());
    let previous_files: BTreeSet<PathBuf> = crate::common::files(environment.root()).into_keys().collect();
    let report = environment.install();
    // The root holds only the previous files and the decoys: no backup or temp file remains.
    let decoys: BTreeSet<PathBuf> = report
        .entries
        .iter()
        .map(|g| Path::new(".").join(Path::new(&g.path).strip_prefix(environment.root()).unwrap()))
        .collect();
    let current: BTreeSet<PathBuf> = crate::common::files(environment.root()).into_keys().collect();
    let expected: BTreeSet<PathBuf> = previous_files.union(&decoys).cloned().collect();
    assert_eq!(current, expected, "an unexpected file at the root");
    // The state directory: directories 0700, files 0600; backups carry the previous content exactly.
    let state = environment.state();
    let mut backup_contents = Vec::new();
    let mut stack = vec![state.clone()];
    while let Some(d) = stack.pop() {
        let m = fs::symlink_metadata(&d).unwrap();
        assert!(m.is_dir(), "{}", d.display());
        assert_eq!(m.permissions().mode() & 0o7777, 0o700, "{}: dir mode", d.display());
        for g in fs::read_dir(&d).unwrap() {
            let path = g.unwrap().path();
            let m = fs::symlink_metadata(&path).unwrap();
            if m.is_dir() {
                stack.push(path);
            } else {
                assert!(m.is_file(), "{}: not a regular file", path.display());
                assert_eq!(m.permissions().mode() & 0o7777, 0o600, "{}: file mode", path.display());
                backup_contents.push(fs::read(&path).unwrap());
            }
        }
    }
    assert!(backup_contents.iter().any(|i| i == PREVIOUS_HISTORY.as_bytes()), "no .bash_history backup");
    assert!(backup_contents.iter().any(|i| i == crate::common::PREVIOUS_SSH_CONFIG.as_bytes()), "no ssh config backup");
    assert!(
        backup_contents.iter().any(|i| i == crate::common::PREVIOUS_KNOWN_HOSTS.as_bytes()),
        "no known_hosts backup"
    );
    // Appended files' records hold the previous-state summary and backup.
    let appended: Vec<&RecordEntry> = report.entries.iter().filter(|g| g.append.is_some()).collect();
    assert_eq!(appended.len(), 3);
    for g in appended {
        let previous =
            g.append.as_ref().unwrap().previous.as_ref().expect("the existing file's previous state must be recorded");
        assert_eq!(previous.sha256.len(), 64);
        assert!(
            !previous.backup.contains('/') && !previous.backup.contains(".."),
            "a backup name must be a plain name"
        );
    }
}
