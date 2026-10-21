//! A disk-persistent queue (ADR-0007 "Persistent queue").
//!
//! - The queue directory is 0700, the file 0600; both must belong to the user running Koru.
//!   The path is opened component by component with `O_NOFOLLOW`; symlinks are never followed.
//!   The file must be regular and single-linked.
//! - Every change is written to a temp file and `rename`d into place (`fsync` included);
//!   a `kill -9` never leaves the queue half-written.
//! - The file size is bounded; parsing is strict with `deny_unknown_fields`. A corrupt file is
//!   set aside as `<name>.queue.corrupt` and counted; the queue starts empty.
//! - When the queue fills, the oldest record drops and [`PersistentQueue::dropped_overflow`] grows.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use koru_event::{EventId, Notification, Severity};
use serde::{Deserialize, Serialize};

use crate::NotifyError;
use crate::safe_file::{self, ReadOutcome};

/// The file format version.
const VERSION: u32 = 1;

/// One queued record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueRecord {
    /// Increasing record number (the order).
    pub id: u64,
    /// `info`, `warning` or `critical`.
    pub severity: String,
    /// Title (raw; the channel sanitizes at send time).
    pub title: String,
    /// Body (raw; the channel sanitizes at send time).
    pub body: String,
    /// Event id (canonical UUIDv7).
    pub event_id: String,
    /// Failed attempts so far.
    pub attempts: u32,
    /// When the next attempt is due (unix ms).
    pub next_ms: u64,
    /// When it entered the queue (unix ms).
    pub added_ms: u64,
}

impl QueueRecord {
    /// Turns the record back into a notification; an invalid severity or event id (a hand-edited file)
    /// returns an error.
    pub fn notification(&self) -> Result<Notification, NotifyError> {
        let severity = match self.severity.as_str() {
            "info" => Severity::Info,
            "warning" => Severity::Warning,
            "critical" => Severity::Critical,
            _ => return Err(NotifyError::Queue("the queue record has an invalid severity".to_string())),
        };
        let event_id = EventId::try_from(self.event_id.clone())
            .map_err(|_| NotifyError::Queue("the queue record has an invalid event id".to_string()))?;
        Ok(Notification { severity, title: self.title.clone(), body: self.body.clone(), event_id })
    }
}

fn severity_text(o: Severity) -> &'static str {
    match o {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    }
}

/// The on-disk state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredState {
    version: u32,
    dropped_overflow: u64,
    dropped_retries: u64,
    records: Vec<QueueRecord>,
}

impl StoredState {
    fn empty() -> StoredState {
        StoredState { version: VERSION, ..StoredState::default() }
    }

    /// Version and record-number consistency.
    fn is_valid(&self) -> bool {
        self.version == VERSION && self.records.windows(2).all(|w| w[0].id < w[1].id)
    }
}

/// Truncates at a char boundary (no escaping; the channel sanitizes at send time).
fn truncate_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut last = max_bytes;
    while !text.is_char_boundary(last) {
        last -= 1;
    }
    text[..last].to_string()
}

/// Whether queue file content is valid: JSON, the schema (`deny_unknown_fields`) and record-
/// number consistency. [`PersistentQueue::open`] runs the same check; an invalid file is set
/// aside as `.corrupt`. The fuzz target (`fuzz/fuzz_targets/persistent_queue.rs`) uses this.
pub fn queue_content_valid(bytes: &[u8]) -> bool {
    bytes.len() as u64 <= PersistentQueue::MAX_FILE_BYTES
        && serde_json::from_slice::<StoredState>(bytes).is_ok_and(|d| d.is_valid())
}

/// The persistent queue.
#[derive(Debug)]
pub struct PersistentQueue {
    dir: OwnedFd,
    name: String,
    path: PathBuf,
    capacity: usize,
    state: StoredState,
    corrupt: u64,
}

impl PersistentQueue {
    /// The largest queue file size (bytes); a bigger file counts as corrupt.
    pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
    /// The largest title size at enqueue time (bytes).
    pub const MAX_TITLE_BYTES: usize = 200;
    /// The largest body size (bytes).
    pub const MAX_BODY_BYTES: usize = 4000;

    /// Opens `dir/<name>.queue` (creates it when missing). `dir` must be absolute; only a
    /// missing last component is created, 0700. `name` may hold only `[a-z0-9_-]`.
    pub fn open(dir: &Path, name: &str, capacity: usize) -> Result<PersistentQueue, NotifyError> {
        let name_valid = !name.is_empty()
            && name.len() <= 32
            && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if !name_valid {
            return Err(NotifyError::Queue(
                "a queue name may hold only lowercase letters, digits, '_' and '-'".to_string(),
            ));
        }
        if capacity == 0 {
            return Err(NotifyError::Settings("the queue capacity must be greater than zero".to_string()));
        }
        let dir_fd = safe_file::prepare_directory(dir)?;
        let file_name = format!("{name}.queue");
        let path = dir.join(&file_name);
        let mut corrupt = 0;
        let (mut state, write_message) = match safe_file::read_file(&dir_fd, &file_name, &path, Self::MAX_FILE_BYTES)? {
            ReadOutcome::NotFound => (StoredState::empty(), true),
            ReadOutcome::Content(b) => match serde_json::from_slice::<StoredState>(&b) {
                Ok(d) if d.is_valid() => (d, false),
                _ => {
                    safe_file::set_aside(&dir_fd, &file_name, &path)?;
                    corrupt = 1;
                    (StoredState::empty(), true)
                }
            },
            ReadOutcome::TooLarge => {
                safe_file::set_aside(&dir_fd, &file_name, &path)?;
                corrupt = 1;
                (StoredState::empty(), true)
            }
        };
        let mut write_message = write_message;
        if state.records.len() > capacity {
            let excess = state.records.len() - capacity;
            state.records.drain(..excess);
            state.dropped_overflow = state.dropped_overflow.saturating_add(excess as u64);
            write_message = true;
        }
        let mut k = PersistentQueue { dir: dir_fd, name: file_name, path, capacity, state, corrupt };
        if write_message {
            let d = k.state.clone();
            k.store(d)?;
        }
        Ok(k)
    }

    /// Writes the new state to disk; on success it replaces the in-memory state.
    fn store(&mut self, new: StoredState) -> Result<(), NotifyError> {
        let bytes = serde_json::to_vec(&new)
            .map_err(|_| NotifyError::Queue("the queue could not be serialized".to_string()))?;
        safe_file::write_atomically(&self.dir, &self.name, &self.path, &bytes)?;
        self.state = new;
        Ok(())
    }

    /// The queue file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends the notification (title and body bounded); at capacity the oldest record drops
    /// and it returns `true`. It does not return before the record is on disk.
    pub fn append(&mut self, notification: &Notification, now_ms: u64, next_ms: u64) -> Result<bool, NotifyError> {
        let mut new = self.state.clone();
        let id = new.records.last().map_or(1, |k| k.id.saturating_add(1));
        new.records.push(QueueRecord {
            id,
            severity: severity_text(notification.severity).to_string(),
            title: truncate_text(&notification.title, Self::MAX_TITLE_BYTES),
            body: truncate_text(&notification.body, Self::MAX_BODY_BYTES),
            event_id: notification.event_id.to_string(),
            attempts: 0,
            next_ms,
            added_ms: now_ms,
        });
        let mut dropped = false;
        while new.records.len() > self.capacity {
            new.records.remove(0);
            new.dropped_overflow = new.dropped_overflow.saturating_add(1);
            dropped = true;
        }
        self.store(new)?;
        Ok(dropped)
    }

    /// The oldest record that is due (`next_ms <= now_ms`).
    pub fn next(&self, now_ms: u64) -> Option<QueueRecord> {
        self.state.records.iter().find(|k| k.next_ms <= now_ms).cloned()
    }

    fn position(&self, id: u64) -> Result<usize, NotifyError> {
        self.state
            .records
            .iter()
            .position(|k| k.id == id)
            .ok_or_else(|| NotifyError::Queue("no such record in the queue".to_string()))
    }

    /// Deletes a delivered record.
    pub fn succeeded(&mut self, id: u64) -> Result<(), NotifyError> {
        let i = self.position(id)?;
        let mut new = self.state.clone();
        new.records.remove(i);
        self.store(new)
    }

    /// Marks an attempt failed: `attempts` grows, `next_ms` is set; returns the new count.
    pub fn failed(&mut self, id: u64, next_ms: u64) -> Result<u32, NotifyError> {
        let i = self.position(id)?;
        let mut new = self.state.clone();
        let k = &mut new.records[i];
        k.attempts = k.attempts.saturating_add(1);
        k.next_ms = next_ms;
        let attempts = k.attempts;
        self.store(new)?;
        Ok(attempts)
    }

    /// Drops a record past its attempt limit and grows [`PersistentQueue::dropped_retries`].
    pub fn drop_expired_retries(&mut self, id: u64) -> Result<(), NotifyError> {
        let i = self.position(id)?;
        let mut new = self.state.clone();
        new.records.remove(i);
        new.dropped_retries = new.dropped_retries.saturating_add(1);
        self.store(new)
    }

    /// The number of queued records.
    pub fn length(&self) -> usize {
        self.state.records.len()
    }

    /// The records (oldest first).
    pub fn records(&self) -> &[QueueRecord] {
        &self.state.records
    }

    /// Records dropped because the queue overflowed (persistent).
    pub fn dropped_overflow(&self) -> u64 {
        self.state.dropped_overflow
    }

    /// Records dropped past the attempt limit (persistent).
    pub fn dropped_retries(&self) -> u64 {
        self.state.dropped_retries
    }

    /// Files found corrupt and set aside (this open).
    pub fn corrupt_count(&self) -> u64 {
        self.corrupt
    }
}
