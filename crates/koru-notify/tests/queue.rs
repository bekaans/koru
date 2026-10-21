//! The persistent queue (protected set; ADR-0007 "Persistent
//! queue"): durability, file security (0600/0700, symlinks), overflow, corrupt files, atomic writes.

mod common;

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;

use common::*;
use koru_event::Severity;
use koru_notify::{NotifyError, PersistentQueue};

fn dir(t: &tempfile::TempDir) -> PathBuf {
    canonicalized(t).join("queue")
}

fn open(t: &tempfile::TempDir, capacity: usize) -> PersistentQueue {
    PersistentQueue::open(&dir(t), "ntfy", capacity).expect("the queue must open")
}

#[test]
fn an_empty_queue_creates_a_0600_file_in_a_0700_dir() {
    let t = is_transient();
    let k = open(&t, 10);
    assert_eq!(k.length(), 0);
    assert_eq!(file_mode(&dir(&t)), 0o700);
    assert_eq!(file_mode(k.path()), 0o600);
    assert_eq!(k.path(), dir(&t).join("ntfy.queue"));
}

#[test]
fn records_survive_a_process_restart() {
    let t = is_transient();
    let b1 = notification(Severity::Critical, "Title 1", "Body 1\nline 2");
    let b2 = notification(Severity::Warning, "Title 2", "Body 2");
    {
        let mut k = open(&t, 10);
        assert!(!k.append(&b1, 1_000, 6_000).unwrap());
        assert!(!k.append(&b2, 2_000, 7_000).unwrap());
        assert_eq!(k.length(), 2);
    } // the "process" ends
    let k = open(&t, 10);
    assert_eq!(k.length(), 2);
    let r = k.records();
    assert_eq!(
        (r[0].title.as_str(), r[0].body.as_str(), r[0].severity.as_str()),
        ("Title 1", "Body 1\nline 2", "critical")
    );
    assert_eq!(r[0].event_id, b1.event_id.to_string());
    assert_eq!((r[0].attempts, r[0].next_ms, r[0].added_ms), (0, 6_000, 1_000));
    assert_eq!(r[1].severity, "warning");
    let back = r[0].notification().unwrap();
    assert_eq!(back, b1, "a record must convert back to the same notification");
    assert!(r[0].id < r[1].id);
}

#[test]
fn a_half_written_temp_file_does_not_corrupt_the_queue() {
    let t = is_transient();
    {
        let mut k = open(&t, 10);
        k.append(&plain_notification(), 1, 2).unwrap();
    }
    // A process that dies mid-write leaves a torn temp file.
    let leftover = dir(&t).join(".ntfy.queue.tmp");
    fs::write(&leftover, b"{\"half").unwrap();
    fs::set_permissions(&leftover, fs::Permissions::from_mode(0o600)).unwrap();
    let mut k = open(&t, 10);
    assert_eq!(k.length(), 1, "the real file must stay intact");
    assert_eq!(k.corrupt_count(), 0);
    k.append(&plain_notification(), 3, 4).unwrap();
    assert_eq!(open(&t, 10).length(), 2);
}

#[test]
fn the_oldest_due_record_is_next() {
    let t = is_transient();
    let mut k = open(&t, 10);
    let b1 = notification(Severity::Warning, "one", "g");
    let b2 = notification(Severity::Warning, "two", "g");
    let b3 = notification(Severity::Warning, "three", "g");
    k.append(&b1, 0, 5_000).unwrap();
    k.append(&b2, 0, 1_000).unwrap();
    k.append(&b3, 0, 1_000).unwrap();
    assert!(k.next(999).is_none());
    assert_eq!(k.next(1_000).unwrap().title, "two", "the oldest of those due");
    assert_eq!(k.next(5_000).unwrap().title, "one", "id order: oldest first");
}

#[test]
fn a_success_deletes_the_record_persistently() {
    let t = is_transient();
    let mut k = open(&t, 10);
    k.append(&plain_notification(), 0, 0).unwrap();
    let id = k.next(0).unwrap().id;
    k.succeeded(id).unwrap();
    assert_eq!(k.length(), 0);
    assert_eq!(open(&t, 10).length(), 0);
    assert!(k.succeeded(id).is_err(), "a missing record is an error");
}

#[test]
fn a_failure_increments_attempts_and_defers_persistently() {
    let t = is_transient();
    let mut k = open(&t, 10);
    k.append(&plain_notification(), 0, 100).unwrap();
    let id = k.next(100).unwrap().id;
    assert_eq!(k.failed(id, 9_000).unwrap(), 1);
    assert_eq!(k.failed(id, 19_000).unwrap(), 2);
    assert!(k.next(18_999).is_none());
    let reopened = open(&t, 10);
    let r = &reopened.records()[0];
    assert_eq!((r.attempts, r.next_ms), (2, 19_000));
}

#[test]
fn an_exhausted_record_drops_and_counts_persistently() {
    let t = is_transient();
    let mut k = open(&t, 10);
    k.append(&plain_notification(), 0, 0).unwrap();
    let id = k.next(0).unwrap().id;
    k.drop_expired_retries(id).unwrap();
    assert_eq!((k.length(), k.dropped_retries(), k.dropped_overflow()), (0, 1, 0));
    let reopened = open(&t, 10);
    assert_eq!((reopened.length(), reopened.dropped_retries()), (0, 1), "counters survive a reopen");
}

#[test]
fn an_overflowing_queue_drops_and_counts_the_oldest() {
    let t = is_transient();
    let mut k = open(&t, 3);
    for i in 0..3 {
        assert!(!k.append(&notification(Severity::Warning, &format!("b{i}"), "g"), i, i).unwrap());
    }
    assert!(k.append(&notification(Severity::Warning, "b3", "g"), 3, 3).unwrap(), "overflow must be reported");
    assert!(k.append(&notification(Severity::Warning, "b4", "g"), 4, 4).unwrap());
    assert_eq!(k.length(), 3);
    let headers: Vec<_> = k.records().iter().map(|r| r.title.clone()).collect();
    assert_eq!(headers, ["b2", "b3", "b4"], "the oldest drop");
    assert_eq!(k.dropped_overflow(), 2);
    let reopened = open(&t, 3);
    assert_eq!((reopened.length(), reopened.dropped_overflow()), (3, 2), "counters are persistent");
}

#[test]
fn a_shrunk_capacity_on_reopen_drops_excess_old_records() {
    let t = is_transient();
    {
        let mut k = open(&t, 10);
        for i in 0..5 {
            k.append(&notification(Severity::Warning, &format!("b{i}"), "g"), i, i).unwrap();
        }
    }
    let k = open(&t, 2);
    assert_eq!(k.length(), 2);
    assert_eq!(k.dropped_overflow(), 3);
    assert_eq!(k.records()[0].title, "b3");
}

#[test]
fn an_overlong_notification_is_bounded_in_the_queue() {
    let t = is_transient();
    let mut k = open(&t, 1_000);
    for i in 0..20 {
        k.append(&notification(Severity::Warning, &"B".repeat(100_000), &"g".repeat(5_000_000)), i, i).unwrap();
    }
    for r in k.records() {
        assert!(r.title.len() <= PersistentQueue::MAX_TITLE_BYTES);
        assert!(r.body.len() <= PersistentQueue::MAX_BODY_BYTES);
    }
    assert!(fs::metadata(k.path()).unwrap().len() < 200_000);
}

#[test]
fn a_corrupt_file_is_set_aside_counted_and_the_queue_starts_empty() {
    for content in [
        &b"this is not json"[..],
        &b"{\"version\":1,\"records\":[{\"id\":1}]}"[..],
        &b"{\"version\":99,\"dropped_overflow\":0,\"dropped_retries\":0,\"records\":[]}"[..],
        &b"{\"version\":1,\"dropped_overflow\":0,\"dropped_retries\":0,\"records\":[],\"extra_field\":1}"[..],
        &b""[..],
    ] {
        let t = is_transient();
        drop(open(&t, 10));
        let path = dir(&t).join("ntfy.queue");
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut k = open(&t, 10);
        assert_eq!(k.length(), 0, "{:?}", String::from_utf8_lossy(content));
        assert_eq!(k.corrupt_count(), 1);
        let corrupt = dir(&t).join("ntfy.queue.corrupt");
        assert!(corrupt.exists(), "the corrupt file is kept for inspection");
        assert_eq!(file_mode(&corrupt), 0o600);
        k.append(&plain_notification(), 0, 0).unwrap();
        assert_eq!(open(&t, 10).length(), 1, "the queue keeps working");
    }
}

#[test]
fn an_oversized_file_counts_as_corrupt_without_reading() {
    let t = is_transient();
    drop(open(&t, 10));
    let path = dir(&t).join("ntfy.queue");
    let file = fs::File::options().write(true).open(&path).unwrap();
    file.set_len(PersistentQueue::MAX_FILE_BYTES + 1).unwrap();
    let k = open(&t, 10);
    assert_eq!((k.length(), k.corrupt_count()), (0, 1));
}

#[test]
fn a_hand_edited_invalid_record_never_becomes_a_notification() {
    let t = is_transient();
    {
        let mut k = open(&t, 10);
        k.append(&plain_notification(), 0, 0).unwrap();
    }
    let path = dir(&t).join("ntfy.queue");
    let text = fs::read_to_string(&path).unwrap();
    let bad = text.replace("\"critical\"", "\"very_critical\"");
    assert_ne!(bad, text);
    fs::write(&path, bad).unwrap();
    let k = open(&t, 10);
    let result = k.records().first().map(|r| r.notification());
    assert!(matches!(result, None | Some(Err(NotifyError::Queue(_)))), "{result:?}");
    // An invalid event id (not UUIDv7).
    let bad = text.replace(&scan_plain_credentials(&text), "00000000-0000-4000-8000-000000000000");
    fs::write(&path, bad).unwrap();
    let k = open(&t, 10);
    let result = k.records().first().map(|r| r.notification());
    assert!(matches!(result, None | Some(Err(NotifyError::Queue(_)))), "{result:?}");
}

fn scan_plain_credentials(text: &str) -> String {
    let i = text.find("\"event_id\":\"").unwrap() + "\"event_id\":\"".len();
    text[i..i + 36].to_string()
}

#[test]
fn a_valid_name() {
    let t = is_transient();
    for bad in ["", "../x", "a/b", "A", "a b", "a.queue", "a\0b", "\u{015f}", ".secret"] {
        let error = PersistentQueue::open(&dir(&t), bad, 10).expect_err(bad);
        assert!(matches!(error, NotifyError::Queue(_) | NotifyError::Settings(_)));
    }
    assert!(PersistentQueue::open(&dir(&t), "telegram-2_a", 10).is_ok());
    assert!(PersistentQueue::open(&dir(&t), "x", 0).is_err(), "capacity 0 is rejected");
}

// --- file security ---

#[test]
fn relative_and_dotted_directories_are_rejected() {
    assert!(PersistentQueue::open(std::path::Path::new("queue"), "ntfy", 10).is_err());
    let t = is_transient();
    assert!(PersistentQueue::open(&canonicalized(&t).join("a").join("..").join("k"), "ntfy", 10).is_err());
}

#[test]
fn a_missing_parent_is_never_chained_into_existence() {
    let t = is_transient();
    assert!(PersistentQueue::open(&canonicalized(&t).join("missing").join("queue"), "ntfy", 10).is_err());
    assert!(!canonicalized(&t).join("missing").exists());
}

#[test]
fn a_symlinked_queue_file_is_rejected_and_never_written_through() {
    let t = is_transient();
    let root = canonicalized(&t);
    drop(open(&t, 10));
    let target = root.join("target.txt");
    fs::write(&target, b"hands-off").unwrap();
    let path = dir(&t).join("ntfy.queue");
    fs::remove_file(&path).unwrap();
    symlink(&target, &path).unwrap();
    let error = PersistentQueue::open(&dir(&t), "ntfy", 10).expect_err("a symlink must not be followed");
    assert!(matches!(error, NotifyError::Queue(_)));
    assert_eq!(fs::read(&target).unwrap(), b"hands-off");
}

#[test]
fn a_symlinked_temp_file_is_never_written_through() {
    let t = is_transient();
    let root = canonicalized(&t);
    let mut k = open(&t, 10);
    let target = root.join("target.txt");
    fs::write(&target, b"hands-off").unwrap();
    symlink(&target, dir(&t).join(".ntfy.queue.tmp")).unwrap();
    k.append(&plain_notification(), 0, 0).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"hands-off", "the tmp link must not make it write to the target");
    assert_eq!(open(&t, 10).length(), 1);
}

#[test]
fn a_symlinked_directory_or_component_is_rejected() {
    let t = is_transient();
    let root = canonicalized(&t);
    fs::create_dir(root.join("real")).unwrap();
    fs::set_permissions(root.join("real"), fs::Permissions::from_mode(0o700)).unwrap();
    symlink(root.join("real"), root.join("link")).unwrap();
    assert!(PersistentQueue::open(&root.join("link"), "ntfy", 10).is_err());
    assert!(PersistentQueue::open(&root.join("link").join("sub"), "ntfy", 10).is_err());
    assert!(!root.join("real").join("ntfy.queue").exists());
}

#[test]
fn a_wide_directory_mode_is_rejected() {
    let t = is_transient();
    let root = canonicalized(&t);
    for mode in [0o755, 0o750, 0o701, 0o777] {
        let d = root.join(format!("d{mode:o}"));
        fs::create_dir(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(mode)).unwrap();
        assert!(PersistentQueue::open(&d, "ntfy", 10).is_err(), "mode {mode:o}");
        assert!(!d.join("ntfy.queue").exists());
    }
}

#[test]
fn a_wide_file_mode_is_rejected() {
    let t = is_transient();
    let path = open(&t, 10).path().to_path_buf();
    for mode in [0o644, 0o640, 0o602, 0o666] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(PersistentQueue::open(&dir(&t), "ntfy", 10).is_err(), "mode {mode:o}");
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(PersistentQueue::open(&dir(&t), "ntfy", 10).is_ok());
}

#[test]
fn a_hard_linked_file_is_rejected() {
    let t = is_transient();
    let path = open(&t, 10).path().to_path_buf();
    fs::hard_link(&path, canonicalized(&t).join("other-name")).unwrap();
    assert!(PersistentQueue::open(&dir(&t), "ntfy", 10).is_err());
}

#[test]
fn a_special_file_is_rejected_without_hanging() {
    let t = is_transient();
    drop(open(&t, 10));
    let path = dir(&t).join("ntfy.queue");
    fs::remove_file(&path).unwrap();
    let state = std::process::Command::new("mkfifo").arg(&path).status().expect("mkfifo");
    assert!(state.success());
    assert!(PersistentQueue::open(&dir(&t), "ntfy", 10).is_err(), "a FIFO must be rejected without blocking");
}

#[test]
fn reopening_never_changes_modes() {
    let t = is_transient();
    drop(open(&t, 10));
    let k = open(&t, 10);
    assert_eq!(file_mode(k.path()), 0o600);
    assert_eq!(file_mode(&dir(&t)), 0o700);
    // Still 0600 after the write (the file that replaces the temp file).
    let mut k = k;
    k.append(&plain_notification(), 0, 0).unwrap();
    assert_eq!(file_mode(k.path()), 0o600);
    assert!(!dir(&t).join(".ntfy.queue.tmp").exists(), "no temp file may remain");
}

#[test]
fn two_channels_keep_separate_queue_files() {
    let t = is_transient();
    let mut a = PersistentQueue::open(&dir(&t), "ntfy", 10).unwrap();
    let b = PersistentQueue::open(&dir(&t), "telegram", 10).unwrap();
    a.append(&plain_notification(), 0, 0).unwrap();
    assert_eq!(b.length(), 0);
    assert_ne!(a.path(), b.path());
}
