//! Schema validation on ingest (protected set): a corrupt,
//! incomplete, or untagged event does not enter the store; it is rejected and counted by reason.
//! The rejection classification order: JSON → source tag →
//! schema_version → serde (schema) → Event::validate.

mod common;

use common::*;
use koru_store::{IngestOutcome, MAX_EVENT_BYTES, RejectReason};
use serde_json::{Value, json};

/// How a mutated valid event is classified.
fn result(mutate: impl FnOnce(&mut Value)) -> IngestOutcome {
    let t = temp();
    let mut store_inst = open_store(&t);
    let mut v = event_json_value("file_opened", 1);
    mutate(&mut v);
    let s = store_inst.store_json(&v.to_string()).expect("there must be no store error");
    let expected_records = u64::from(s == IngestOutcome::Stored);
    assert_eq!(store_inst.record_count().unwrap(), expected_records, "a rejected event must not enter the store");
    if let IngestOutcome::Rejected(reason) = s {
        assert_eq!(store_inst.rejected().unwrap(), vec![(reason, 1)]);
        assert_eq!(store_inst.rejected_total().unwrap(), 1);
    }
    s
}

fn rejection(reason: RejectReason) -> IngestOutcome {
    IngestOutcome::Rejected(reason)
}

#[test]
fn valid_event_is_accepted() {
    assert_eq!(result(|_| {}), IngestOutcome::Stored);
}

#[test]
fn non_json_input() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let entries = ["", "   ", "{broken", "[1,2,3]", "\"text\"", "42", "null", "{\"a\":1}}"];
    for input in entries {
        assert_eq!(
            store_inst.store_json(input).unwrap(),
            rejection(RejectReason::JsonFormat),
            "{input:?} is not an event object"
        );
    }
    assert_eq!(store_inst.record_count().unwrap(), 0);
    assert_eq!(store_inst.rejected().unwrap(), vec![(RejectReason::JsonFormat, entries.len() as u64)]);
}

#[test]
fn oversized_input() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let mut v = event_json_value("file_opened", 1);
    set_field(&mut v, "/target/path", json!("a".repeat(MAX_EVENT_BYTES)));
    assert_eq!(store_inst.store_json(&v.to_string()).unwrap(), rejection(RejectReason::SizeLimit));
    assert_eq!(store_inst.record_count().unwrap(), 0);
}

#[test]
fn untagged_event() {
    assert_eq!(result(|v| remove_field(v, "/source_tag")), rejection(RejectReason::UntaggedRecord));
    assert_eq!(result(|v| set_field(v, "/source_tag", Value::Null)), rejection(RejectReason::UntaggedRecord));
    assert_eq!(result(|v| set_field(v, "/source_tag", json!(""))), rejection(RejectReason::UntaggedRecord));
    assert_eq!(result(|v| set_field(v, "/source_tag", json!("  "))), rejection(RejectReason::UntaggedRecord));
}

#[test]
fn invalid_source_tag() {
    for e in [json!("unknown"), json!("Real"), json!("real\u{e7}sidecar"), json!(5), json!(true), json!(["real"])] {
        assert_eq!(
            result(|v| set_field(v, "/source_tag", e.clone())),
            rejection(RejectReason::InvalidSourceTag),
            "{e}"
        );
    }
}

#[test]
fn all_three_tags_are_accepted() {
    for e in ["synthetic", "legitimate", "real"] {
        assert_eq!(result(|v| set_field(v, "/source_tag", json!(e))), IngestOutcome::Stored, "{e}");
    }
}

#[test]
fn tag_check_precedes_other_errors() {
    let s = result(|v| {
        remove_field(v, "/source_tag");
        v["extra_field"] = json!(1);
        v["schema_version"] = json!(2);
    });
    assert_eq!(s, rejection(RejectReason::UntaggedRecord));
}

#[test]
fn unknown_field() {
    assert_eq!(result(|v| v["excess"] = json!(1)), rejection(RejectReason::UnknownField));
    assert_eq!(result(|v| set_field(v, "/process/excess", json!(1))), rejection(RejectReason::UnknownField));
    assert_eq!(result(|v| set_field(v, "/target/excess", json!(null))), rejection(RejectReason::UnknownField));
    assert_eq!(result(|v| set_field(v, "/actor/sidecar", json!("x"))), rejection(RejectReason::UnknownField));
}

#[test]
fn missing_field() {
    for path in [
        "/host",
        "/process/pid",
        "/timestamp",
        "/event_type",
        "/target/path",
        "/detection",
        "/response",
        "/session_id",
        "/tags/verified",
        "/container/id",
    ] {
        assert_eq!(result(|v| remove_field(v, path)), rejection(RejectReason::MissingField), "{path} missing");
    }
}

#[test]
fn unsupported_schema_version() {
    assert_eq!(result(|v| v["schema_version"] = json!(2)), rejection(RejectReason::SchemaVersion));
    assert_eq!(result(|v| v["schema_version"] = json!(0)), rejection(RejectReason::SchemaVersion));
    assert_eq!(result(|v| v["schema_version"] = json!("1")), rejection(RejectReason::SchemaVersion));
    assert_eq!(result(|v| remove_field(v, "/schema_version")), rejection(RejectReason::MissingField));
}

#[test]
fn schema_violation() {
    let mutations: Vec<(&str, &str, Value)> = vec![
        ("kind", "/timestamp_trusted", json!("yes")),
        ("UUIDv4", "/event_id", json!("550e8400-e29b-41d4-a716-446655440000")),
        ("uppercase UUID", "/event_id", json!("01928F3B-6C2E-7A3D-9F41-2B6C8E0D4A17")),
        ("timestamp format", "/timestamp", json!("2026-10-09 15:47:54")),
        ("timestamp month", "/timestamp", json!("2026-13-09T15:47:54.540189619Z")),
        ("event kind", "/event_type", json!("unknown_kind")),
        ("pid kind", "/process/pid", json!(-1)),
        ("confidence range", "/actor/confidence", json!(1.5)),
        ("flag", "/target/flags", json!(["O_UNKNOWN"])),
        ("ATT&CK format", "/tags/mitre_techniques", json!(["X1234"])),
        ("IP", "/target/remote", json!({"ip": "300.1.1.1", "port": 1})),
        ("port range", "/target/remote", json!({"ip": "1.2.3.4", "port": 70000})),
    ];
    for (name, path, value) in mutations {
        assert_eq!(result(|v| set_field(v, path, value)), rejection(RejectReason::SchemaViolation), "{name}");
    }
}

#[test]
fn cross_field_validation() {
    assert_eq!(result(|v| set_field(v, "/process/pid", json!(0))), rejection(RejectReason::Validation));
    assert_eq!(
        result(|v| set_field(v, "/target/path", Value::Null)),
        rejection(RejectReason::Validation),
        "a path is required in a file event"
    );
    assert_eq!(result(|v| set_field(v, "/host", json!(" "))), rejection(RejectReason::Validation));
    assert_eq!(
        result(|v| set_field(v, "/actor", json!({"kind": "ai_agent", "rationale": [], "confidence": 0.5}))),
        rejection(RejectReason::Validation),
        "an actor estimate without a rationale"
    );
    assert_eq!(
        result(|v| set_field(
            v,
            "/detection",
            json!({"rule": "k", "decoy_id": null, "threat_class": "decoy_access", "attack": []})
        )),
        rejection(RejectReason::Validation),
        "detection without ATT&CK"
    );
}

#[test]
fn store_event_does_not_skip_validation() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let mut o = event("file_opened", 1);
    o.host = String::new();
    assert_eq!(store_inst.store_event(&o).unwrap(), rejection(RejectReason::Validation));
    assert_eq!(store_inst.record_count().unwrap(), 0);
    assert_eq!(store_inst.rejected().unwrap(), vec![(RejectReason::Validation, 1)]);
}

#[test]
fn rejections_accumulate_by_reason_and_persist() {
    let t = temp();
    {
        let mut store_inst = open_store(&t);
        for _ in 0..3 {
            store_inst.store_json("{broken").unwrap();
        }
        let mut v = event_json_value("file_opened", 1);
        remove_field(&mut v, "/source_tag");
        store_inst.store_json(&v.to_string()).unwrap();
        let mut v = event_json_value("file_opened", 2);
        v["excess"] = json!(1);
        store_inst.store_json(&v.to_string()).unwrap();
        store_inst.store_json(&event_json("file_opened", 3)).unwrap();
    }
    let store_inst = open_store(&t);
    // In code order: unknown_field, untagged, json_format.
    assert_eq!(
        store_inst.rejected().unwrap(),
        vec![(RejectReason::JsonFormat, 3), (RejectReason::UnknownField, 1), (RejectReason::UntaggedRecord, 1)]
    );
    assert_eq!(store_inst.rejected_total().unwrap(), 5);
    assert_eq!(store_inst.record_count().unwrap(), 1);
}

#[test]
fn reject_codes_are_permanent_and_unique() {
    let expected = [
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
    assert_eq!(RejectReason::all().len(), expected.len());
    for (reason, code) in expected {
        assert_eq!(reason.code(), code);
        assert_eq!(RejectReason::from_code(code), Some(reason));
        assert!(RejectReason::all().contains(&reason));
    }
    assert_eq!(RejectReason::from_code("unknown_code"), None);
    assert_eq!(RejectReason::from_code(""), None);
}
