//! Error and rejection reason types.

/// A store error (not a rejection; rejection is [`RejectReason`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// Invalid settings.
    #[error("invalid store setting: {0}")]
    Settings(String),
    /// There is a symlink in the path; it is not followed.
    #[error("{path}: symlink is not followed")]
    Symlink {
        /// Path.
        path: String,
    },
    /// The path is unsafe in owner, mode, kind, or link count.
    #[error("{path}: unsafe: {reason}")]
    UnsafePath {
        /// Path.
        path: String,
        /// Reason.
        reason: String,
    },
    /// `must_exist` was requested but the store is absent.
    #[error("{path}: no store")]
    NotFound {
        /// Path.
        path: String,
    },
    /// A filesystem error.
    #[error("{path}: {reason}")]
    Io {
        /// Path.
        path: String,
        /// Reason.
        reason: String,
    },
    /// An SQLite error.
    #[error("sqlite: {0}")]
    Sqlite(String),
    /// The database was written with a newer schema than this version.
    #[error("database schema version {found}, supported {supported}")]
    SchemaVersion {
        /// The version in the file.
        found: i64,
        /// The supported version.
        supported: i64,
    },
}

/// Why an event did not enter the store. Codes are permanent (visible in the data quality report
/// and in the database); attacker data never becomes a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RejectReason {
    /// Not JSON, or not an object.
    JsonFormat,
    /// The event is larger than [`crate::MAX_EVENT_BYTES`].
    SizeLimit,
    /// `source_tag` is absent, `null`, or empty.
    UntaggedRecord,
    /// `source_tag` is present but not synthetic, legitimate, or real.
    InvalidSourceTag,
    /// A field not in the schema.
    UnknownField,
    /// A required field is missing.
    MissingField,
    /// `schema_version` is not supported.
    SchemaVersion,
    /// Another schema violation (kind, format, range).
    SchemaViolation,
    /// `Event::validate` rejected a cross-field rule.
    Validation,
    /// The same `event_id` is already stored with different content.
    IdConflict,
    /// Sensor translation: an invalid Pulsar field.
    TranslationInvalidField,
    /// Sensor translation: the translated event failed validation.
    TranslationValidation,
}

const CODES: [(RejectReason, &str); 12] = [
    (RejectReason::JsonFormat, "json_format"),
    (RejectReason::SizeLimit, "size_limit"),
    (RejectReason::UntaggedRecord, "untagged"),
    (RejectReason::InvalidSourceTag, "invalid_source_tag"),
    (RejectReason::UnknownField, "unknown_field"),
    (RejectReason::MissingField, "missing_field"),
    (RejectReason::SchemaVersion, "schema_version"),
    (RejectReason::SchemaViolation, "schema_violation"),
    (RejectReason::Validation, "validation"),
    (RejectReason::IdConflict, "id_conflict"),
    (RejectReason::TranslationInvalidField, "translation_invalid_field"),
    (RejectReason::TranslationValidation, "translation_validation"),
];

const ALL: [RejectReason; 12] = [
    RejectReason::JsonFormat,
    RejectReason::SizeLimit,
    RejectReason::UntaggedRecord,
    RejectReason::InvalidSourceTag,
    RejectReason::UnknownField,
    RejectReason::MissingField,
    RejectReason::SchemaVersion,
    RejectReason::SchemaViolation,
    RejectReason::Validation,
    RejectReason::IdConflict,
    RejectReason::TranslationInvalidField,
    RejectReason::TranslationValidation,
];

impl RejectReason {
    /// The permanent code.
    pub fn code(&self) -> &'static str {
        CODES.iter().find(|(n, _)| n == self).map_or("", |(_, k)| k)
    }

    /// The reason from a code; an unknown code is `None`.
    pub fn from_code(code: &str) -> Option<RejectReason> {
        CODES.iter().find(|(_, k)| *k == code).map(|(n, _)| *n)
    }

    /// All reasons.
    pub fn all() -> &'static [RejectReason] {
        &ALL
    }
}
