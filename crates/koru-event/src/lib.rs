#![forbid(unsafe_code)]
//! # koru-event
//!
//! The shared Koru event format and the interfaces between layers.
//!
//! - [`Event`]: schema v1 (`schemas/event.v1.json`); all layers communicate only through this
//!   type. An event with unknown, missing, or out-of-rule fields is rejected ([`Event::validate`]).
//! - [`Untrusted`]: the type of fields an attacker can control ([`UNTRUSTED_FIELDS`]).
//! - [`mask_ip_in_text`], [`mask_ip`]: IP masking (privacy; IPv4 /24, IPv6 /48). koru-store and
//!   koru-notify use the same function (ADR-0007 §8).
//! - Traits: [`Sensor`], [`Detector`], [`DecoyCatalog`], [`EventStore`], [`NotificationChannel`],
//!   [`Heartbeat`], and the roadmap placeholders [`Router`], [`ResponseAction`] ([`Record`]),
//!   [`IntentClassifier`].
//!
//! This crate depends on no Koru crate and not on Pulsar; its external dependencies are serde,
//! thiserror, uuid, and time (`dependency-rules.toml`).

mod event;
mod id;
mod identity_fields;
mod interfaces;
mod mask;
mod time;
mod untrusted;

pub use event::{
    Actor, ActorKind, AncestorProcess, Confidence, Container, Detection, Event, EventType, FileFlag, MitreTechnique,
    Namespaces, NetworkEndpoint, NetworkProtocol, Process, Response, ResponseKind, SCHEMA_VERSION, SchemaVersion,
    SensorInfo, SourceTag, Tags, Target, ThreatClass, UNTRUSTED_FIELDS, User, ValidationError,
};
pub use id::{EventId, IdError};
pub use identity_fields::is_valid_host;
pub use interfaces::{
    DecoyCatalog, Detector, EventStore, Heartbeat, IntentClassifier, InterfaceError, Notification, NotificationChannel,
    Record, RecordResult, ResponseAction, Router, RoutingResult, Sensor, Severity, WatchedPath, WatchedPathKind,
};
pub use mask::{mask_ip, mask_ip_in_text};
pub use time::{Timestamp, TimestampError};
pub use untrusted::Untrusted;
