//! Store settings.

use std::path::PathBuf;

/// Default retention period (days). Storage limitation: GDPR Art. 5(1)(e), KVKK Art. 4.
pub const DEFAULT_RETENTION_DAYS: u32 = 90;
/// Default record cap (the oldest records are deleted on rotation).
pub const DEFAULT_MAX_RECORDS: u64 = 10_000_000;
/// The maximum size of a single event as JSON (bytes).
pub const MAX_EVENT_BYTES: usize = 1 << 20;

/// Store settings. The path has no default: the store sits in a user-chosen place that does not
/// reveal Koru (ADR-0006).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSettings {
    /// The absolute path of the database file.
    pub path: PathBuf,
    /// Retention period (days, at least 1).
    pub retention_days: u32,
    /// Record cap (at least 1).
    pub max_records: u64,
    /// When true, a missing store is an error instead of being created.
    pub must_exist: bool,
}

impl StoreSettings {
    /// Settings with the default retention period and record cap.
    pub fn new(path: impl Into<PathBuf>) -> StoreSettings {
        StoreSettings {
            path: path.into(),
            retention_days: DEFAULT_RETENTION_DAYS,
            max_records: DEFAULT_MAX_RECORDS,
            must_exist: false,
        }
    }

    /// Changes the retention period (days).
    pub fn retention_days(mut self, days: u32) -> StoreSettings {
        self.retention_days = days;
        self
    }

    /// Changes the record cap.
    pub fn max_records(mut self, count: u64) -> StoreSettings {
        self.max_records = count;
        self
    }

    /// Errors instead of creating the store when it is missing.
    pub fn must_exist(mut self) -> StoreSettings {
        self.must_exist = true;
        self
    }
}
