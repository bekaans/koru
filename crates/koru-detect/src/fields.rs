//! The fields rules evaluate against: Sigma's standard field names and Koru-specific derived
//! fields with the `koru.` prefix.

/// Field names rules may use. A rule referencing a field outside this list is rejected (no
/// "junk" rule that could never match).
///
/// Standard Sigma fields:
/// - `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `ProcessId`, `ParentProcessId`
/// - `TargetFilename` (the target in file events; the new name in renames), `SourceFilename`
///   (the old name in renames, the shown path in links)
/// - `DestinationIp`, `DestinationPort`, `SourceIp`, `SourcePort` (network events)
///
/// Koru-specific derived fields:
/// - `koru.event_type`: the Koru event kind (`file_opened` ...)
/// - `koru.decoy_id`, `koru.decoy_class`, `koru.breadcrumb`: when the target path is a decoy
///   or a breadcrumb (`DecoyCatalog`)
/// - `koru.ai_agent_ancestor`, `koru.ai_agent`, `koru.ai_agent_kind`: when the process or one
///   of its ancestors matches an AI-agent signature
/// - `koru.modified`: whether the event changes the file system (open for writing, create,
///   delete, rename, link)
/// - `koru.read`: whether the open can read (`O_RDONLY` or `O_RDWR`); not a write-only open
///   (`O_WRONLY`, e.g. a shell appending to its history file), nor non-open events. Breadcrumb
///   rules use this (KT-58)
/// - `koru.protected_kind`: when the target is one of Koru's protected paths (`config`,
///   `secret`, `store`, `state`, `binary`, `service`)
/// - `koru.stop_attempt`: when the process tries to stop Koru (`service` or `process`)
/// - `koru.container`, `koru.container_suspected`: inside a container; with no id, a
///   namespace difference (KT-20, KT-45)
/// - `koru.self_event`: an event Koru itself produced (`stopped`)
pub const SUPPORTED_FIELDS: &[&str] = &[
    "Image",
    "CommandLine",
    "ParentImage",
    "ParentCommandLine",
    "ProcessId",
    "ParentProcessId",
    "TargetFilename",
    "SourceFilename",
    "DestinationIp",
    "DestinationPort",
    "SourceIp",
    "SourcePort",
    "koru.event_type",
    "koru.decoy_id",
    "koru.decoy_class",
    "koru.breadcrumb",
    "koru.ai_agent_ancestor",
    "koru.ai_agent",
    "koru.ai_agent_kind",
    "koru.modified",
    "koru.read",
    "koru.protected_kind",
    "koru.stop_attempt",
    "koru.container",
    "koru.container_suspected",
    "koru.self_event",
];

/// A field's value. Converted to text for comparison (`true`/`false`, a decimal number).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    /// Text.
    Text(String),
    /// A boolean value.
    Bool(bool),
    /// An integer.
    Number(i64),
}

/// One event's fields. A missing field means "absent" (`exists: false`, `null`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldSet {
    fields: std::collections::BTreeMap<String, FieldValue>,
}

impl FieldSet {
    /// An empty set.
    pub fn new() -> FieldSet {
        FieldSet::default()
    }

    /// Adds a text field.
    pub fn text(mut self, name: &str, value: &str) -> FieldSet {
        self.fields.insert(name.to_string(), FieldValue::Text(value.to_string()));
        self
    }

    /// Adds a boolean field.
    pub fn boolean(mut self, name: &str, value: bool) -> FieldSet {
        self.fields.insert(name.to_string(), FieldValue::Bool(value));
        self
    }

    /// Adds a number field.
    pub fn number(mut self, name: &str, value: i64) -> FieldSet {
        self.fields.insert(name.to_string(), FieldValue::Number(value));
        self
    }

    /// The field's value; `None` if absent.
    pub fn get(&self, name: &str) -> Option<&FieldValue> {
        self.fields.get(name)
    }
}
