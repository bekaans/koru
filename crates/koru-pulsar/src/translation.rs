//! Platform-independent translation types. The Pulsar-dependent translation function lives in the
//! `pulsar_translation` module (Linux only).

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use koru_event::{AncestorProcess, Event, Namespaces, SensorInfo, SourceTag, ValidationError};

/// The Koru bridge module's name in Pulsar (visible in `pulsar status`). THREAT events arriving
/// under this name are never re-processed (KT-30). Configurable names for self-concealment
/// are a possible future extension (KT-23).
pub const KORU_MODULE_NAME: &str = "koru-bridge";

/// Translation context: fields that come not from the event but from the install config and the runtime.
/// `source_tag` is never taken from event input (KT-19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslationContext {
    /// The install's source tag.
    pub source_tag: SourceTag,
    /// Host name.
    pub host: String,
    /// Whether the clock is NTP-synced (`timestamp_trusted`).
    pub timestamp_trusted: bool,
    /// Sensor info.
    pub sensor: SensorInfo,
}

/// Information absent from the Pulsar event header, taken from the process tracker in the embedded
/// module (ADR-0001 "Container info", KT-20).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessAttachment {
    /// The process's command line; for Exec events the event's own argv is used.
    pub command_line: Option<Vec<String>>,
    /// The process's namespaces.
    pub namespaces: Option<Namespaces>,
    /// Ancestors: from the nearest parent to the root.
    pub lineage: Vec<AncestorProcess>,
}

/// The outcome of a translation.
#[derive(Debug, Clone, PartialEq)]
pub enum Translation {
    /// The Koru event (validated).
    Event(Box<Event>),
    /// The event was deliberately not translated.
    Skipped(SkipReason),
}

/// Why a Pulsar event was not translated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// `header.threat` present: a THREAT copy derived by a module (Pulsar's rule engine or Koru).
    /// The original event is also on the bus. Processing a Koru-originated one would open a bus
    /// feedback loop (ADR-0001 consequence 4, KT-30).
    ThreatDuplicate {
        /// Whether the THREAT was produced by Koru's own module.
        koru_originated: bool,
    },
    /// A Pulsar event type with no counterpart in schema v1 (e.g. DnsQuery, Fork).
    UnsupportedKind {
        /// The Pulsar event type's name.
        kind: String,
    },
}

/// Translation error: the Pulsar event carries a value that does not fit the Koru schema.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TranslationError {
    /// The Pulsar field is invalid (e.g. a negative pid).
    #[error("invalid field {field} in the Pulsar event: {reason}")]
    InvalidField {
        /// The Pulsar field.
        field: &'static str,
        /// Reason.
        reason: String,
    },
    /// The produced Koru event failed validation.
    #[error("the translated event failed validation: {0}")]
    Validation(#[from] ValidationError),
}

/// A snapshot of the translation counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TranslationCountersSnapshot {
    /// Events translated successfully.
    pub translated: u64,
    /// Events rejected because a Pulsar field was invalid ([`TranslationError::InvalidField`]).
    pub rejected_invalid_field: u64,
    /// Events rejected because the translated event failed validation ([`TranslationError::Validation`]).
    pub rejected_validation: u64,
    /// Deliberately skipped THREAT copies (not a rejection; KT-30).
    pub skipped_threat_duplicate: u64,
    /// Deliberately skipped unsupported event types (not a rejection).
    pub skipped_unsupported_kind: u64,
}

impl TranslationCountersSnapshot {
    /// Total rejected (goes to the data-quality report).
    pub fn rejected_total(&self) -> u64 {
        self.rejected_invalid_field.saturating_add(self.rejected_validation)
    }
}

/// Counts translation outcomes. Shared between the Pulsar bridge module, the agent and the caller
/// (`Arc<TranslationCounters>`); the `koru` crate, where the composition is built, forwards the values
/// to the data store. This crate does not know koru-store.
#[derive(Debug, Default)]
pub struct TranslationCounters {
    translated: AtomicU64,
    invalid_field: AtomicU64,
    validation: AtomicU64,
    threat_duplicate: AtomicU64,
    unsupported_kind: AtomicU64,
    first_rejection: Mutex<Option<String>>,
}

impl TranslationCounters {
    /// A snapshot.
    pub fn snapshot(&self) -> TranslationCountersSnapshot {
        TranslationCountersSnapshot {
            translated: self.translated.load(Ordering::Relaxed),
            rejected_invalid_field: self.invalid_field.load(Ordering::Relaxed),
            rejected_validation: self.validation.load(Ordering::Relaxed),
            skipped_threat_duplicate: self.threat_duplicate.load(Ordering::Relaxed),
            skipped_unsupported_kind: self.unsupported_kind.load(Ordering::Relaxed),
        }
    }
}

impl TranslationCounters {
    /// The first rejection's message (for diagnostics; holds only field names and reasons Koru produced).
    pub fn first_rejection_sample(&self) -> Option<String> {
        self.first_rejection.lock().ok().and_then(|g| g.clone())
    }

    fn record_first_rejection(&self, error: &TranslationError) {
        if let Ok(mut g) = self.first_rejection.lock()
            && g.is_none()
        {
            *g = Some(error.to_string());
        }
    }
}

/// Counts a translation outcome and yields the translated event. A translation error is not dropped
/// silently: it is counted (a rejection); deliberately skipped events are counted separately.
pub fn count_translation(
    result: Result<Translation, TranslationError>,
    counters: &TranslationCounters,
) -> Option<Box<Event>> {
    match result {
        Ok(Translation::Event(event)) => {
            counters.translated.fetch_add(1, Ordering::Relaxed);
            Some(event)
        }
        Ok(Translation::Skipped(SkipReason::ThreatDuplicate { .. })) => {
            counters.threat_duplicate.fetch_add(1, Ordering::Relaxed);
            None
        }
        Ok(Translation::Skipped(SkipReason::UnsupportedKind { .. })) => {
            counters.unsupported_kind.fetch_add(1, Ordering::Relaxed);
            None
        }
        Err(error) => {
            match error {
                TranslationError::InvalidField { .. } => counters.invalid_field.fetch_add(1, Ordering::Relaxed),
                TranslationError::Validation(_) => counters.validation.fetch_add(1, Ordering::Relaxed),
            };
            counters.record_first_rejection(&error);
            None
        }
    }
}
