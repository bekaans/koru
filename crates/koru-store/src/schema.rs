//! The SQLite schema and its version (ADR-0006 "Store design"). All SQL is written as constant
//! text here and in `store.rs` and `retention.rs`; changing values are parameters only.

/// The supported schema version (`PRAGMA user_version`).
pub(crate) const SCHEMA_VERSION: i64 = 2;

/// Connection settings. WAL: concurrent read and write, crash-resistant; FULL sync: evidence data
/// must not be lost on power failure; secure_delete: deleted personal data must not linger in the
/// file (GDPR/KVKK); trusted_schema off: schema-defined functions are treated as untrusted.
pub(crate) const CONNECTION_SETTINGS: &str = "PRAGMA synchronous = FULL;
PRAGMA secure_delete = ON;
PRAGMA trusted_schema = OFF;
PRAGMA cell_size_check = ON;";

pub(crate) const CREATE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    event_key TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    source_tag TEXT NOT NULL CHECK (source_tag IN ('synthetic', 'legitimate', 'real')),
    event_type TEXT NOT NULL,
    data TEXT NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS events_time ON events (timestamp);
CREATE TABLE IF NOT EXISTS rejected (
    reason TEXT PRIMARY KEY,
    count INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL
) STRICT;
PRAGMA user_version = 2;";

pub(crate) const COUNTER_DEDUPLICATED: &str = "deduplicated";
