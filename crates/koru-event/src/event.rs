//! Koru event schema v1: Rust types (JSON schema: `schemas/event.v1.json`).
//!
//! Rules:
//! - Every struct carries `deny_unknown_fields`; an event with unknown fields is rejected.
//! - All fields are required. Fields that may be empty are `Option` typed and written as `null` in
//!   JSON; they cannot be omitted (`required_null`).
//! - Field-level rules live in newtypes ([`SchemaVersion`], [`crate::EventId`],
//!   [`crate::Timestamp`], [`Confidence`], [`MitreTechnique`]); they are enforced during serde
//!   parsing.
//! - Cross-field rules (e.g. `target.path` required for file events) live in [`Event::validate`].
//!   Every event entering the store passes both.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Deserializer, Serialize};

use crate::{EventId, Timestamp, Untrusted};

/// Schema version. Every incompatible change is a new version and a new schema file.
pub const SCHEMA_VERSION: u32 = 1;

/// Fields an attacker can control: the paths of those marked `x-koru-untrusted: true` in the
/// JSON schema (array items are `*`). On the Rust side these fields are [`Untrusted`] typed.
pub const UNTRUSTED_FIELDS: &[&str] = &[
    "/process/exe",
    "/process/command_line",
    "/process/environment",
    "/process/lineage/*/exe",
    "/process/lineage/*/command_line",
    "/container/id",
    "/container/name",
    "/container/image",
    "/container/image_digest",
    "/target/path",
    "/target/new_path",
];

/// The field must be present in JSON; its value may be `null`. It turns off serde's default
/// behavior of treating a missing `Option` field as `None`.
fn required_null<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

/// A Koru event (schema v1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// Always [`SCHEMA_VERSION`].
    pub schema_version: SchemaVersion,
    /// UUIDv7.
    pub event_id: EventId,
    /// The event's kernel time (UTC, ns).
    pub timestamp: Timestamp,
    /// Whether the clock was NTP-synchronized at event time.
    pub timestamp_trusted: bool,
    /// Comes from the install configuration, not from the event input.
    pub source_tag: SourceTag,
    /// The sensor that produced the event.
    pub sensor: SensorInfo,
    /// Hostname (from the install configuration).
    pub host: String,
    /// The process that produced the event.
    pub process: Process,
    /// The process's container context (namespaces may exist outside containers too).
    pub container: Container,
    /// The event kind.
    pub event_type: EventType,
    /// The event target (file, process, network endpoint).
    pub target: Target,
    /// The actor kind estimate.
    pub actor: Actor,
    /// Detection (finding); `null` when there is none.
    #[serde(deserialize_with = "required_null")]
    pub detection: Option<Detection>,
    /// Label fields for AI training.
    pub tags: Tags,
    /// For session termination (roadmap); `null` today.
    #[serde(deserialize_with = "required_null")]
    pub session_id: Option<String>,
    /// The response record for session termination (roadmap); `null` today.
    #[serde(deserialize_with = "required_null")]
    pub response: Option<Response>,
}

/// The schema version field; only [`SCHEMA_VERSION`] is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct SchemaVersion(u32);

impl SchemaVersion {
    /// Schema v1.
    pub const V1: SchemaVersion = SchemaVersion(SCHEMA_VERSION);
}

impl Default for SchemaVersion {
    fn default() -> Self {
        SchemaVersion::V1
    }
}

impl TryFrom<u32> for SchemaVersion {
    type Error = String;

    fn try_from(s: u32) -> Result<SchemaVersion, String> {
        if s == SCHEMA_VERSION {
            Ok(SchemaVersion(s))
        } else {
            Err(format!("unsupported schema_version {s} (expected {SCHEMA_VERSION})"))
        }
    }
}

impl From<SchemaVersion> for u32 {
    fn from(s: SchemaVersion) -> u32 {
        s.0
    }
}

/// The event source. The three kinds never mix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceTag {
    /// Simulated attack (lab).
    Synthetic,
    /// Normal workload (lab).
    Legitimate,
    /// A real server (VPS).
    Real,
}

/// Sensor information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensorInfo {
    /// Sensor name (e.g. `pulsar`).
    pub name: String,
    /// Sensor version.
    pub version: String,
    /// Platform (e.g. `linux-aarch64`).
    pub platform: String,
}

/// The process that produced the event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Process {
    /// Process id (> 0).
    pub pid: u32,
    /// Parent process id (0 when unknown).
    pub ppid: u32,
    /// The process start (fork) time; `null` when unknown. Together with pid it identifies the process uniquely.
    #[serde(deserialize_with = "required_null")]
    pub start_time: Option<Timestamp>,
    /// The executable path.
    pub exe: Untrusted<String>,
    /// Command line (argv); empty when unknown.
    pub command_line: Untrusted<Vec<String>>,
    /// Environment variables. Not collected yet and empty; if collected, only allowlisted
    /// names and masked values are written (secret leakage, KT-25).
    pub environment: Untrusted<Vec<String>>,
    /// User and group.
    pub user: User,
    /// Ancestors: from the nearest parent toward the root.
    pub lineage: Vec<AncestorProcess>,
}

/// User and group ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// User id.
    pub uid: u32,
    /// Group id.
    pub gid: u32,
}

/// An ancestor process in the lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AncestorProcess {
    /// Process id (> 0).
    pub pid: u32,
    /// The executable path.
    pub exe: Untrusted<String>,
    /// Command line.
    pub command_line: Untrusted<Vec<String>>,
}

/// Container context (ADR-0001 "Container information").
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Container {
    /// Container id; `null` when the process is not in a recognized container.
    #[serde(deserialize_with = "required_null")]
    pub id: Option<Untrusted<String>>,
    /// Container name.
    #[serde(deserialize_with = "required_null")]
    pub name: Option<Untrusted<String>>,
    /// Image name.
    #[serde(deserialize_with = "required_null")]
    pub image: Option<Untrusted<String>>,
    /// Image digest (e.g. `sha256:...`).
    #[serde(deserialize_with = "required_null")]
    pub image_digest: Option<Untrusted<String>>,
    /// The process's namespaces; `null` when unknown. Even when the container is not recognized,
    /// namespaces differing from the host's are a "container suspected" signal.
    #[serde(deserialize_with = "required_null")]
    pub namespaces: Option<Namespaces>,
}

/// Namespace inode numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Namespaces {
    /// UTS namespace.
    pub uts: u32,
    /// IPC namespace.
    pub ipc: u32,
    /// Mount namespace.
    pub mnt: u32,
    /// PID namespace.
    pub pid: u32,
    /// Network namespace.
    pub net: u32,
    /// Time namespace.
    pub time: u32,
    /// cgroup namespace.
    pub cgroup: u32,
}

/// Event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// File opened (`target.path`, `target.flags`).
    FileOpened,
    /// File created.
    FileCreated,
    /// File deleted.
    FileDeleted,
    /// File renamed (`target.path` is the old name, `target.new_path` the new name).
    FileRenamed,
    /// Link created (`target.path` is the link, `target.new_path` the path it points to).
    FileLink,
    /// Directory created.
    DirectoryCreated,
    /// Directory deleted.
    DirectoryDeleted,
    /// A process executed a new binary (exec; `target.path`).
    ProcessExecuted,
    /// A process exited (`target.exit_code`).
    ProcessExited,
    /// Outbound network connection (`target.remote`).
    NetworkConnection,
    /// Inbound connection accepted (`target.remote`, `target.local`).
    NetworkAccept,
}

/// `open` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileFlag {
    /// Read-only.
    #[serde(rename = "O_RDONLY")]
    Rdonly,
    /// Write-only.
    #[serde(rename = "O_WRONLY")]
    Wronly,
    /// Read and write.
    #[serde(rename = "O_RDWR")]
    Rdwr,
    /// Create if absent.
    #[serde(rename = "O_CREAT")]
    Creat,
    /// Error if present.
    #[serde(rename = "O_EXCL")]
    Excl,
    /// Do not make it the controlling terminal.
    #[serde(rename = "O_NOCTTY")]
    Noctty,
    /// Truncate.
    #[serde(rename = "O_TRUNC")]
    Trunc,
    /// Append at the end.
    #[serde(rename = "O_APPEND")]
    Append,
    /// Non-blocking.
    #[serde(rename = "O_NONBLOCK")]
    Nonblock,
    /// Directory.
    #[serde(rename = "O_DIRECTORY")]
    Directory,
}

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProtocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// Network endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEndpoint {
    /// IPv4 or IPv6 address.
    pub ip: IpAddr,
    /// Port.
    pub port: u16,
}

/// The event target. Which fields are present depends on the event kind ([`Event::validate`]).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// File or directory path; in exec, the executed file; in link and rename, the source.
    #[serde(deserialize_with = "required_null")]
    pub path: Option<Untrusted<String>>,
    /// In rename, the new name; in link, the path pointed to.
    #[serde(deserialize_with = "required_null")]
    pub new_path: Option<Untrusted<String>>,
    /// File open flags.
    pub flags: Vec<FileFlag>,
    /// Whether the link is a hard link.
    #[serde(deserialize_with = "required_null")]
    pub hard_link: Option<bool>,
    /// Network protocol.
    #[serde(deserialize_with = "required_null")]
    pub protocol: Option<NetworkProtocol>,
    /// Local network endpoint.
    #[serde(deserialize_with = "required_null")]
    pub local: Option<NetworkEndpoint>,
    /// Remote network endpoint.
    #[serde(deserialize_with = "required_null")]
    pub remote: Option<NetworkEndpoint>,
    /// The process exit code.
    #[serde(deserialize_with = "required_null")]
    pub exit_code: Option<u32>,
}

/// Actor kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// Human.
    Human,
    /// AI agent.
    AiAgent,
    /// Unknown.
    Unknown,
}

/// The actor kind estimate: it is rule-based and recorded with its rationale.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    /// The estimate.
    pub kind: ActorKind,
    /// The rationales for the estimate; at least one is required unless the kind is `unknown`.
    pub rationale: Vec<String>,
    /// Confidence, between 0 and 1.
    pub confidence: Confidence,
}

impl Actor {
    /// An actor with no estimate.
    pub fn unknown() -> Actor {
        Actor { kind: ActorKind::Unknown, rationale: Vec::new(), confidence: Confidence::ZERO }
    }
}

/// A finite confidence value between 0 and 1 (inclusive).
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct Confidence(f64);

impl Confidence {
    /// 0.
    pub const ZERO: Confidence = Confidence(0.0);

    /// An out-of-range or non-finite value is rejected.
    pub fn new(value: f64) -> Result<Confidence, String> {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            Ok(Confidence(value))
        } else {
            Err(format!("confidence must be between 0 and 1: {value}"))
        }
    }

    /// The value.
    pub fn value(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for Confidence {
    type Error = String;

    fn try_from(value: f64) -> Result<Confidence, String> {
        Confidence::new(value)
    }
}

impl From<Confidence> for f64 {
    fn from(g: Confidence) -> f64 {
        g.0
    }
}

/// A MITRE ATT&CK technique id: `T1234` or `T1234.001`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MitreTechnique(String);

impl MitreTechnique {
    /// Creates it with a format check.
    pub fn new(id: &str) -> Result<MitreTechnique, String> {
        let b = id.as_bytes();
        let head = b.len() >= 5 && b[0] == b'T' && b[1..5].iter().all(u8::is_ascii_digit);
        let valid = match b.len() {
            5 => head,
            9 => head && b[5] == b'.' && b[6..9].iter().all(u8::is_ascii_digit),
            _ => false,
        };
        if valid {
            Ok(MitreTechnique(id.to_string()))
        } else {
            Err(format!(
                "ATT&CK technique id must be in T1234 or T1234.001 form: {:?}",
                id.chars().take(32).collect::<String>()
            ))
        }
    }

    /// The id text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for MitreTechnique {
    type Error = String;

    fn try_from(s: String) -> Result<MitreTechnique, String> {
        MitreTechnique::new(&s)
    }
}

impl From<MitreTechnique> for String {
    fn from(m: MitreTechnique) -> String {
        m.0
    }
}

/// Threat class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatClass {
    /// Access to a decoy file.
    DecoyAccess,
    /// Access to a breadcrumb.
    BreadcrumbAccess,
    /// Decoy access originating from an AI agent.
    SuspectedHijackedAgent,
    /// An event directed at Koru itself (configuration, store, decoy, or binary change, stopping).
    SelfProtection,
}

/// Detection (finding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detection {
    /// The rule id.
    pub rule: String,
    /// The triggered decoy's id; `null` for a non-decoy rule.
    #[serde(deserialize_with = "required_null")]
    pub decoy_id: Option<String>,
    /// Threat class.
    pub threat_class: ThreatClass,
    /// The ATT&CK techniques the rule maps to (at least one).
    pub attack: Vec<MitreTechnique>,
}

/// Label fields for AI training.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tags {
    /// Intent class; `null` when unknown.
    #[serde(deserialize_with = "required_null")]
    pub intent: Option<String>,
    /// Related ATT&CK techniques.
    pub mitre_techniques: Vec<MitreTechnique>,
    /// Whether verified by a human.
    pub verified: bool,
}

/// Response action kind (a bridge to session termination on the roadmap; today only `record`, shadow mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseKind {
    /// Record only (shadow mode).
    Record,
    /// Monitor.
    Monitor,
    /// Freeze.
    Freeze,
    /// Isolate from the network.
    Isolate,
    /// Terminate.
    Terminate,
}

/// The record of an applied response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Action.
    pub action: ResponseKind,
    /// The action time.
    pub timestamp: Timestamp,
    /// Rationale.
    pub rationale: String,
}

/// When cross-field rules are violated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// A text that cannot be empty is empty.
    #[error("{field} must not be empty")]
    Empty {
        /// Field path.
        field: &'static str,
    },
    /// The field value violates a rule.
    #[error("{field} invalid: {reason}")]
    Invalid {
        /// Field path.
        field: &'static str,
        /// Reason.
        reason: String,
    },
    /// A field required by the event kind is empty.
    #[error("{field} is required for {event_type} events")]
    MissingForKind {
        /// Event kind.
        event_type: EventType,
        /// Missing field.
        field: &'static str,
    },
}

fn non_empty(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() { Err(ValidationError::Empty { field }) } else { Ok(()) }
}

fn non_empty_path(
    event_type: EventType,
    field: &'static str,
    path: &Option<Untrusted<String>>,
) -> Result<(), ValidationError> {
    match path {
        Some(y) if !y.untrusted_value().is_empty() => Ok(()),
        _ => Err(ValidationError::MissingForKind { event_type, field }),
    }
}

fn present<T>(event_type: EventType, field: &'static str, value: &Option<T>) -> Result<(), ValidationError> {
    if value.is_some() { Ok(()) } else { Err(ValidationError::MissingForKind { event_type, field }) }
}

impl Event {
    /// Checks the cross-field rules. Serde parsing already enforces field-level rules; every event
    /// going to the store, export, or notification also passes through here.
    pub fn validate(&self) -> Result<(), ValidationError> {
        non_empty("host", &self.host)?;
        non_empty("sensor.name", &self.sensor.name)?;
        non_empty("sensor.version", &self.sensor.version)?;
        non_empty("sensor.platform", &self.sensor.platform)?;
        if self.process.pid == 0 {
            return Err(ValidationError::Invalid { field: "process.pid", reason: "must not be 0".to_string() });
        }
        if self.process.lineage.iter().any(|a| a.pid == 0) {
            return Err(ValidationError::Invalid { field: "process.lineage.pid", reason: "must not be 0".to_string() });
        }
        if self.actor.kind != ActorKind::Unknown && self.actor.rationale.is_empty() {
            return Err(ValidationError::Invalid {
                field: "actor.rationale",
                reason: "an actor kind estimate must have a rationale".to_string(),
            });
        }
        if self.actor.rationale.iter().any(|g| g.trim().is_empty()) {
            return Err(ValidationError::Empty { field: "actor.rationale" });
        }
        if let Some(t) = &self.detection {
            non_empty("detection.rule", &t.rule)?;
            if let Some(k) = &t.decoy_id {
                non_empty("detection.decoy_id", k)?;
            }
            if t.attack.is_empty() {
                return Err(ValidationError::Invalid {
                    field: "detection.attack",
                    reason: "every detection maps to at least one ATT&CK technique".to_string(),
                });
            }
        }
        if let Some(n) = &self.tags.intent {
            non_empty("tags.intent", n)?;
        }
        if let Some(o) = &self.session_id {
            non_empty("session_id", o)?;
        }
        if let Some(y) = &self.response {
            non_empty("response.rationale", &y.rationale)?;
        }
        self.target_matches_kind()
    }

    fn target_matches_kind(&self) -> Result<(), ValidationError> {
        let t = self.event_type;
        let h = &self.target;
        match t {
            EventType::FileOpened
            | EventType::FileCreated
            | EventType::FileDeleted
            | EventType::DirectoryCreated
            | EventType::DirectoryDeleted
            | EventType::ProcessExecuted => non_empty_path(t, "target.path", &h.path),
            EventType::FileRenamed => {
                non_empty_path(t, "target.path", &h.path)?;
                non_empty_path(t, "target.new_path", &h.new_path)
            }
            EventType::FileLink => {
                non_empty_path(t, "target.path", &h.path)?;
                non_empty_path(t, "target.new_path", &h.new_path)?;
                present(t, "target.hard_link", &h.hard_link)
            }
            EventType::ProcessExited => present(t, "target.exit_code", &h.exit_code),
            EventType::NetworkConnection => {
                present(t, "target.remote", &h.remote)?;
                present(t, "target.protocol", &h.protocol)
            }
            EventType::NetworkAccept => {
                present(t, "target.remote", &h.remote)?;
                present(t, "target.local", &h.local)
            }
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            EventType::FileOpened => "file_opened",
            EventType::FileCreated => "file_created",
            EventType::FileDeleted => "file_deleted",
            EventType::FileRenamed => "file_renamed",
            EventType::FileLink => "file_link",
            EventType::DirectoryCreated => "directory_created",
            EventType::DirectoryDeleted => "directory_deleted",
            EventType::ProcessExecuted => "process_executed",
            EventType::ProcessExited => "process_exited",
            EventType::NetworkConnection => "network_connection",
            EventType::NetworkAccept => "network_accept",
        };
        f.write_str(name)
    }
}
