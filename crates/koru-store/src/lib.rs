#![forbid(unsafe_code)]
//! # koru-store
//!
//! The Koru event store (ADR-0006): SQLite WAL, schema
//! validation on entry, deduplication, JSONL and OCSF export, IP masking (privacy: GDPR/KVKK),
//! retention and rotation, data quality reporting.
//!
//! This layer depends only on koru-event; it does not know Pulsar, the other layers, or the
//! sensor. It communicates with the other layers through
//! [`koru_event::EventStore`]. All SQL queries are parameterized; SQL is never built by string
//! concatenation.

mod error;
mod export;
mod key;
mod mask;
mod ocsf;
mod path;
mod raw;
mod report;
mod retention;
mod schema;
mod settings;
mod store;

pub use error::{RejectReason, StoreError};
pub use export::{ExportError, ExportFormat, ExportOptions, ExportResult};
pub use key::event_key;
pub use mask::{mask_event, mask_ip_in_text};
pub use ocsf::{OCSF_VERSION, ocsf_event};
pub use report::{QualityReport, ThreatReport};
pub use retention::RotationResult;
pub use settings::{DEFAULT_MAX_RECORDS, DEFAULT_RETENTION_DAYS, MAX_EVENT_BYTES, StoreSettings};
pub use store::{IngestOutcome, Store, validate_line};
