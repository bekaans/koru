//! Event identity (UUIDv7).

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::{Uuid, Variant};

/// Event identity: UUIDv7 (RFC 9562). It is timestamp-ordered; it preserves insertion order in
/// the store and simplifies indexing. In JSON only the lowercase hyphenated canonical form is
/// accepted; any other version or format is rejected.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EventId(Uuid);

/// When an event identity cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// Not in UUID form, or not written canonically (lowercase, hyphenated).
    #[error("event_id is not in canonical UUID form: {0:?}")]
    Format(String),
    /// A UUID, but not version 7 (and the RFC 9562 variant).
    #[error("event_id is not UUIDv7: {0}")]
    Version(String),
}

impl EventId {
    /// A new UUIDv7.
    pub fn new() -> EventId {
        EventId(Uuid::now_v7())
    }

    /// The inner UUID.
    pub fn uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for EventId {
    fn default() -> Self {
        EventId::new()
    }
}

impl TryFrom<Uuid> for EventId {
    type Error = IdError;

    fn try_from(u: Uuid) -> Result<EventId, IdError> {
        if u.get_version_num() == 7 && u.get_variant() == Variant::RFC4122 {
            Ok(EventId(u))
        } else {
            Err(IdError::Version(u.hyphenated().to_string()))
        }
    }
}

impl TryFrom<String> for EventId {
    type Error = IdError;

    fn try_from(text: String) -> Result<EventId, IdError> {
        let u = Uuid::try_parse(&text).map_err(|_| IdError::Format(text.chars().take(64).collect()))?;
        if u.hyphenated().to_string() != text {
            return Err(IdError::Format(text.chars().take(64).collect()));
        }
        EventId::try_from(u)
    }
}

impl From<EventId> for String {
    fn from(k: EventId) -> String {
        k.0.hyphenated().to_string()
    }
}

impl fmt::Debug for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventId({})", self.0.hyphenated())
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}
