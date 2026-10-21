//! From raw JSON to event: classified rejection (ADR-0006 "Validation on entry").
//!
//! Order: size -> JSON -> source tag -> schema_version -> serde (schema v1) -> `Event::validate`.
//! Rejection codes are permanent; attacker data in an error message is never carried into a code
//! (only the serde pattern at the start of the message is examined).

use koru_event::Event;
use serde_json::Value;

use crate::{MAX_EVENT_BYTES, RejectReason};

pub(crate) enum ParseOutcome {
    Event(Box<Event>),
    Rejected(RejectReason),
}

fn source_tag_reject(object: &serde_json::Map<String, Value>) -> Option<RejectReason> {
    match object.get("source_tag") {
        None | Some(Value::Null) => Some(RejectReason::UntaggedRecord),
        Some(Value::String(s)) if s.trim().is_empty() => Some(RejectReason::UntaggedRecord),
        Some(Value::String(s)) if matches!(s.as_str(), "synthetic" | "legitimate" | "real") => None,
        Some(_) => Some(RejectReason::InvalidSourceTag),
    }
}

/// The reason according to the serde error message pattern.
fn serde_reason(message: &str) -> RejectReason {
    if message.starts_with("unknown field `") {
        RejectReason::UnknownField
    } else if message.starts_with("missing field `") {
        RejectReason::MissingField
    } else {
        RejectReason::SchemaViolation
    }
}

/// Classifies a JSON value (also used for records read from the store).
pub(crate) fn parse_value(value: Value) -> ParseOutcome {
    let Some(object) = value.as_object() else {
        return ParseOutcome::Rejected(RejectReason::JsonFormat);
    };
    if let Some(reason) = source_tag_reject(object) {
        return ParseOutcome::Rejected(reason);
    }
    if object.get("schema_version").is_some_and(|s| s.as_u64() != Some(1)) {
        return ParseOutcome::Rejected(RejectReason::SchemaVersion);
    }
    match serde_json::from_value::<Event>(value) {
        Err(e) => ParseOutcome::Rejected(serde_reason(&e.to_string())),
        Ok(event) => match event.validate() {
            Ok(()) => ParseOutcome::Event(Box::new(event)),
            Err(_) => ParseOutcome::Rejected(RejectReason::Validation),
        },
    }
}

/// Classifies a raw line.
pub(crate) fn parse_line(line: &str) -> ParseOutcome {
    if line.len() > MAX_EVENT_BYTES {
        return ParseOutcome::Rejected(RejectReason::SizeLimit);
    }
    match serde_json::from_str::<Value>(line) {
        Ok(value) => parse_value(value),
        Err(_) => ParseOutcome::Rejected(RejectReason::JsonFormat),
    }
}

/// Parses a record read from the store: it must pass JSON schema v1 and `Event::validate` and
/// agree with the columns (id, source tag, timestamp, event kind). A mismatch counts as
/// `SchemaViolation`.
pub(crate) fn decode_record(
    id: &str,
    source: &str,
    timestamp: &str,
    kind: &str,
    data: &str,
) -> Result<Event, RejectReason> {
    let Ok(value) = serde_json::from_str::<Value>(data) else {
        return Err(RejectReason::JsonFormat);
    };
    match parse_value(value) {
        ParseOutcome::Rejected(reason) => Err(reason),
        ParseOutcome::Event(event) => {
            let tag = match event.source_tag {
                koru_event::SourceTag::Synthetic => "synthetic",
                koru_event::SourceTag::Legitimate => "legitimate",
                koru_event::SourceTag::Real => "real",
            };
            if event.event_id.to_string() == id
                && tag == source
                && event.timestamp.text() == timestamp
                && event.event_type.to_string() == kind
            {
                Ok(*event)
            } else {
                Err(RejectReason::SchemaViolation)
            }
        }
    }
}
