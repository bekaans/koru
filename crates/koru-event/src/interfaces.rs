//! Interfaces between layers.
//!
//! Layers do not know each other; they communicate only through these traits and [`crate::Event`].
//! Composition is wired up in the `koru` CLI. Each trait is narrow enough to test on its own with
//! a mock implementation. The roadmap traits ([`Router`], [`ResponseAction`],
//! [`IntentClassifier`]) are placeholders only; today only [`Record`] (shadow mode) is
//! implemented for [`ResponseAction`].

use crate::{Detection, Event, EventId, Response, ResponseKind, SensorInfo, Timestamp};

/// The shared error type of interface implementations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InterfaceError {
    /// A transient error; it can be retried (e.g. a network outage).
    #[error("transient error: {0}")]
    Transient(String),
    /// A permanent error; retrying does not change the outcome (e.g. broken configuration).
    #[error("permanent error: {0}")]
    Permanent(String),
}

/// Produces an event stream (e.g. koru-pulsar). `run` returns when the sensor stops and passes
/// each event to `receiver`.
pub trait Sensor {
    /// The sensor's name, version, and platform.
    fn info(&self) -> SensorInfo;

    /// Starts the event stream; returns when the sensor stops.
    fn run(&mut self, receiver: &mut dyn FnMut(Event)) -> Result<(), InterfaceError>;
}

/// Derives findings from events (koru-detect).
pub trait Detector {
    /// Detections matching the event; empty when nothing matches.
    fn inspect(&mut self, event: &Event) -> Vec<Detection>;
}

/// The kind of a watched path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchedPathKind {
    /// A decoy file.
    Decoy,
    /// A breadcrumb.
    Breadcrumb,
}

/// A path watched by the detection layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WatchedPath {
    /// Absolute path.
    pub path: String,
    /// The decoy's unique identity.
    pub decoy_id: String,
    /// Kind.
    pub kind: WatchedPathKind,
    /// Decoy class: the template's `class` field (e.g. `ssh_key`, `bash_history`). The detection
    /// layer selects rules and the ATT&CK mapping by this class.
    pub class: String,
}

/// Provides watched paths and decoy identities (koru-decoy). The detection layer works
/// through this type without knowing koru-decoy.
pub trait DecoyCatalog {
    /// All watched paths.
    fn watched_paths(&self) -> Vec<WatchedPath>;

    /// The definition if the path is watched.
    fn find(&self, path: &str) -> Option<WatchedPath>;
}

/// The result of storing a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordResult {
    /// A new record.
    Stored,
    /// The same event was already stored (deduplication).
    Duplicate,
}

/// Event store (koru-store).
pub trait EventStore {
    /// Validates and stores the event; an event that does not match the schema is rejected and counted.
    fn store(&mut self, event: &Event) -> Result<RecordResult, InterfaceError>;

    /// The event by identity.
    fn get(&self, id: &EventId) -> Result<Option<Event>, InterfaceError>;

    /// The number of rejected events (data quality report).
    fn rejected_count(&self) -> u64;
}

/// Notification severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Info.
    Info,
    /// Warning.
    Warning,
    /// Critical.
    Critical,
}

/// A notification. The texts never contain the raw form of untrusted fields (KT-15, KT-25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// Severity.
    pub severity: Severity,
    /// Short title.
    pub title: String,
    /// Body.
    pub body: String,
    /// The event the notification is based on.
    pub event_id: EventId,
}

/// Notification channel (koru-notify): ntfy, Telegram, SMTP.
pub trait NotificationChannel {
    /// The channel's name.
    fn name(&self) -> &str;

    /// Sends the notification.
    fn send(&mut self, notification: &Notification) -> Result<(), InterfaceError>;
}

/// A regular health signal sent out (koru-notify; Healthchecks.io).
pub trait Heartbeat {
    /// Sends one heartbeat.
    fn beat(&mut self) -> Result<(), InterfaceError>;
}

/// Routing result (isolated trap VM, on the roadmap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingResult {
    /// The attacker was routed to the decoy VM.
    Routed {
        /// The identity of the session in the decoy VM.
        session_id: String,
    },
    /// No routing was performed.
    NotRouted,
}

/// Roadmap: routes the attacker to an isolated trap VM. Not implemented yet.
pub trait Router {
    /// Routes according to the event.
    fn route(&mut self, event: &Event) -> Result<RoutingResult, InterfaceError>;
}

/// Roadmap: response action (monitor, freeze, isolate, terminate). Today only [`Record`].
pub trait ResponseAction {
    /// The kind of the action.
    fn kind(&self) -> ResponseKind;

    /// Applies the action and returns its record.
    fn apply(&mut self, event: &Event) -> Result<Response, InterfaceError>;
}

/// Shadow mode: applies no action, only records what would be done (a bridge to session termination on the roadmap).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Record;

impl ResponseAction for Record {
    fn kind(&self) -> ResponseKind {
        ResponseKind::Record
    }

    fn apply(&mut self, _event: &Event) -> Result<Response, InterfaceError> {
        Ok(Response {
            action: ResponseKind::Record,
            timestamp: Timestamp::now(),
            rationale: "shadow mode: no action applied, only recorded".to_string(),
        })
    }
}

/// Roadmap: derives an intent class from an event. Today only the rule-based implementation; no model.
pub trait IntentClassifier {
    /// The intent class; `None` when it cannot be derived.
    fn classify(&self, event: &Event) -> Option<String>;
}
