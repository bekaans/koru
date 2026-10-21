//! Store: SQLite WAL, ingest, query, counters.

use std::time::Duration;

use koru_event::{Event, EventId, EventStore, InterfaceError, RecordResult};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::key::event_key;
use crate::raw::{ParseOutcome, parse_line};
use crate::schema::{CONNECTION_SETTINGS, COUNTER_DEDUPLICATED, CREATE_SCHEMA, SCHEMA_VERSION};
use crate::{MAX_EVENT_BYTES, RejectReason, StoreError, StoreSettings, path};

/// The longest wait for a busy database.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The ingest outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    /// A new record.
    Stored,
    /// The same event was already stored; deduplicated and counted.
    Duplicate,
    /// Rejected and counted by reason.
    Rejected(RejectReason),
}

/// Event store.
#[derive(Debug)]
pub struct Store {
    pub(crate) settings: StoreSettings,
    pub(crate) connection: Connection,
}

pub(crate) fn sqlite(e: rusqlite::Error) -> StoreError {
    StoreError::Sqlite(e.to_string())
}

fn increment_rejected(tx: &Transaction<'_>, reason: RejectReason, count: u64) -> Result<(), StoreError> {
    let count = i64::try_from(count).unwrap_or(i64::MAX);
    tx.execute(
        "INSERT INTO rejected (reason, count) VALUES (?1, ?2)
         ON CONFLICT (reason) DO UPDATE SET count = count + ?2",
        params![reason.code(), count],
    )
    .map_err(sqlite)?;
    Ok(())
}

/// Validates an imported JSON line without writing it to the store: JSON form, size, source tag,
/// schema v1, cross-field rules, and the strict form of the `host` and `sensor.*` fields (KT-66).
/// Used by `store_json` and the fuzz target (`fuzz/fuzz_targets/jsonl_import.rs`).
pub fn validate_line(line: &str) -> Result<Event, RejectReason> {
    match parse_line(line) {
        ParseOutcome::Rejected(reason) => Err(reason),
        ParseOutcome::Event(event) => {
            if event.check_identity_fields().is_err() {
                return Err(RejectReason::Validation);
            }
            Ok(*event)
        }
    }
}

impl Store {
    /// Opens the store; when absent (and not `must_exist`) creates the 0600 file and 0700 directory.
    pub fn open(settings: StoreSettings) -> Result<Store, StoreError> {
        if settings.retention_days == 0 {
            return Err(StoreError::Settings("the retention period must be at least 1 day".to_string()));
        }
        if settings.max_records == 0 {
            return Err(StoreError::Settings("the record cap must be at least 1".to_string()));
        }
        path::prepare(&settings.path, settings.must_exist)?;
        let flags =
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&settings.path, flags).map_err(sqlite)?;
        connection.busy_timeout(BUSY_TIMEOUT).map_err(sqlite)?;
        let mut store = Store { settings, connection };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&mut self) -> Result<(), StoreError> {
        let version: i64 = self.connection.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(sqlite)?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::SchemaVersion { found: version, supported: SCHEMA_VERSION });
        }
        let mode: String = self.connection.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0)).map_err(sqlite)?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::Sqlite("WAL mode could not be enabled".to_string()));
        }
        self.connection.execute_batch(CONNECTION_SETTINGS).map_err(sqlite)?;
        if version == 0 {
            let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sqlite)?;
            let again_v: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(sqlite)?;
            if again_v == 0 {
                tx.execute_batch(CREATE_SCHEMA).map_err(sqlite)?;
            }
            tx.commit().map_err(sqlite)?;
        }
        Ok(())
    }

    /// Settings.
    pub fn settings(&self) -> &StoreSettings {
        &self.settings
    }

    /// Validates and stores a JSON line; when invalid, rejects it and counts it by reason.
    pub fn store_json(&mut self, line: &str) -> Result<IngestOutcome, StoreError> {
        match validate_line(line) {
            Err(reason) => self.record_rejection(reason),
            Ok(event) => self.append(&event),
        }
    }

    /// Stores the event after `Event::validate`.
    pub fn store_event(&mut self, event: &Event) -> Result<IngestOutcome, StoreError> {
        if event.validate().is_err() || event.check_identity_fields().is_err() {
            return self.record_rejection(RejectReason::Validation);
        }
        self.append(event)
    }

    fn record_rejection(&mut self, reason: RejectReason) -> Result<IngestOutcome, StoreError> {
        self.count_rejected(reason, 1)?;
        Ok(IngestOutcome::Rejected(reason))
    }

    fn append(&mut self, event: &Event) -> Result<IngestOutcome, StoreError> {
        let data = serde_json::to_string(event).map_err(|e| StoreError::Sqlite(e.to_string()))?;
        if data.len() > MAX_EVENT_BYTES {
            return self.record_rejection(RejectReason::SizeLimit);
        }
        let key = event_key(event);
        let id = event.event_id.to_string();
        let timestamp = event.timestamp.text();
        let source = source_code(event);
        let kind = event.event_type.to_string();
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sqlite)?;
        let has_key: bool = tx
            .query_row("SELECT EXISTS (SELECT 1 FROM events WHERE event_key = ?1)", params![key], |r| r.get(0))
            .map_err(sqlite)?;
        let outcome = if has_key {
            tx.execute(
                "INSERT INTO counters (name, value) VALUES (?1, 1)
                 ON CONFLICT (name) DO UPDATE SET value = value + 1",
                params![COUNTER_DEDUPLICATED],
            )
            .map_err(sqlite)?;
            IngestOutcome::Duplicate
        } else {
            let id_exists: bool = tx
                .query_row("SELECT EXISTS (SELECT 1 FROM events WHERE event_id = ?1)", params![id], |r| r.get(0))
                .map_err(sqlite)?;
            if id_exists {
                increment_rejected(&tx, RejectReason::IdConflict, 1)?;
                IngestOutcome::Rejected(RejectReason::IdConflict)
            } else {
                tx.execute(
                    "INSERT INTO events (event_id, event_key, timestamp, source_tag, event_type, data)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![id, key, timestamp, source, kind, data],
                )
                .map_err(sqlite)?;
                IngestOutcome::Stored
            }
        };
        tx.commit().map_err(sqlite)?;
        Ok(outcome)
    }

    /// The event by id.
    pub fn get_event(&self, id: &EventId) -> Result<Option<Event>, StoreError> {
        let data: Option<String> = self
            .connection
            .query_row("SELECT data FROM events WHERE event_id = ?1", params![id.to_string()], |r| r.get(0))
            .optional()
            .map_err(sqlite)?;
        match data {
            None => Ok(None),
            Some(v) => serde_json::from_str::<Event>(&v).map(Some).map_err(|e| StoreError::Sqlite(e.to_string())),
        }
    }

    /// The number of records in the store.
    pub fn record_count(&self) -> Result<u64, StoreError> {
        let n: i64 = self.connection.query_row("SELECT count(*) FROM events", [], |r| r.get(0)).map_err(sqlite)?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// The number of events deduplicated on ingest.
    pub fn deduplicated_count(&self) -> Result<u64, StoreError> {
        let n: Option<i64> = self
            .connection
            .query_row("SELECT value FROM counters WHERE name = ?1", params![COUNTER_DEDUPLICATED], |r| r.get(0))
            .optional()
            .map_err(sqlite)?;
        Ok(u64::try_from(n.unwrap_or(0)).unwrap_or(0))
    }

    /// The distribution of rejections by reason (in code order; only those greater than zero).
    pub fn rejected(&self) -> Result<Vec<(RejectReason, u64)>, StoreError> {
        let mut s = self
            .connection
            .prepare("SELECT reason, count FROM rejected WHERE count > 0 ORDER BY reason")
            .map_err(sqlite)?;
        let lines = s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).map_err(sqlite)?;
        let mut outcome = Vec::new();
        for line in lines {
            let (code, count) = line.map_err(sqlite)?;
            if let Some(reason) = RejectReason::from_code(&code) {
                outcome.push((reason, u64::try_from(count).unwrap_or(0)));
            }
        }
        Ok(outcome)
    }

    /// Total rejected.
    pub fn rejected_total(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .connection
            .query_row("SELECT coalesce(sum(count), 0) FROM rejected", [], |r| r.get(0))
            .map_err(sqlite)?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Counts events rejected outside the store (e.g. sensor translation) by reason.
    pub fn count_rejected(&mut self, reason: RejectReason, count: u64) -> Result<(), StoreError> {
        if count == 0 {
            return Ok(());
        }
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(sqlite)?;
        increment_rejected(&tx, reason, count)?;
        tx.commit().map_err(sqlite)
    }
}

fn source_code(event: &Event) -> &'static str {
    match event.source_tag {
        koru_event::SourceTag::Synthetic => "synthetic",
        koru_event::SourceTag::Legitimate => "legitimate",
        koru_event::SourceTag::Real => "real",
    }
}

fn interface_error(e: StoreError) -> InterfaceError {
    match &e {
        StoreError::Sqlite(m) if m.contains("database is locked") || m.contains("busy") || m.contains("full") => {
            InterfaceError::Transient(e.to_string())
        }
        _ => InterfaceError::Permanent(e.to_string()),
    }
}

impl EventStore for Store {
    fn store(&mut self, event: &Event) -> Result<RecordResult, InterfaceError> {
        match self.store_event(event).map_err(interface_error)? {
            IngestOutcome::Stored => Ok(RecordResult::Stored),
            IngestOutcome::Duplicate => Ok(RecordResult::Duplicate),
            IngestOutcome::Rejected(reason) => Err(InterfaceError::Permanent(format!("rejected: {}", reason.code()))),
        }
    }

    fn get(&self, id: &EventId) -> Result<Option<Event>, InterfaceError> {
        self.get_event(id).map_err(interface_error)
    }

    fn rejected_count(&self) -> u64 {
        self.rejected_total().unwrap_or(u64::MAX)
    }
}
