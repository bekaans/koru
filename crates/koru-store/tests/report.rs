//! The data quality report (protected set): "schema compliance 100% · duplicates 0 · untagged 0 · rejected N". The
//! report re-validates the records in the store in their export form, recomputes the event keys,
//! and lists ingest rejections by reason.

mod common;

use koru_store::{IngestOutcome, QualityReport, RejectReason};
use rusqlite::Connection;
use serde_json::{Value, json};

use common::*;

fn external(t: &tempfile::TempDir) -> Connection {
    Connection::open(store_path(t)).unwrap()
}

#[test]
fn empty_store() {
    let t = temp();
    let r = open_store(&t).quality_report().unwrap();
    assert_eq!(r.summary_line(), "schema compliance 100% · duplicates 0 · untagged 0 · rejected 0");
    assert_eq!(r.record_count, 0);
    assert!(r.is_clean());
}

#[test]
fn clean_store_and_rejections() {
    let t = temp();
    let mut store_inst = open_store(&t);
    for (i, s) in ALL_TEMPLATES.iter().enumerate() {
        store_inst.store_json(&event_json(s, i as u32)).unwrap();
    }
    // Deliberately corrupt: JSON, untagged, unknown field, validation.
    store_inst.store_json("{broken").unwrap();
    store_inst.store_json("{broken2").unwrap();
    let mut v = event_json_value("file_opened", 50);
    v.as_object_mut().unwrap().remove("source_tag");
    store_inst.store_json(&v.to_string()).unwrap();
    let mut v = event_json_value("file_opened", 51);
    v["excess"] = json!(1);
    store_inst.store_json(&v.to_string()).unwrap();
    let mut v = event_json_value("file_opened", 52);
    v["process"]["pid"] = json!(0);
    store_inst.store_json(&v.to_string()).unwrap();
    // Deliberate duplicates (the same fact with a new id), twice.
    let mut copy = event_json_value("file_opened", 0);
    let first = event_json_value("file_opened", 0);
    copy["timestamp"] = first["timestamp"].clone();
    assert_eq!(store_inst.store_json(&copy.to_string()).unwrap(), IngestOutcome::Duplicate);
    assert_eq!(store_inst.store_json(&copy.to_string()).unwrap(), IngestOutcome::Duplicate);
    // Rejections coming from the translation layer.
    store_inst.count_rejected(RejectReason::TranslationInvalidField, 2).unwrap();
    store_inst.count_rejected(RejectReason::TranslationValidation, 1).unwrap();

    let r = store_inst.quality_report().unwrap();
    let n = ALL_TEMPLATES.len() as u64;
    assert_eq!(r.record_count, n);
    assert_eq!(r.schema_compliant, n);
    assert_eq!(r.duplicates, 0, "duplicates were deduplicated on ingest; the store holds none");
    assert_eq!(r.untagged, 0);
    assert_eq!(r.rejected, 8);
    assert_eq!(r.deduplicated_count, 2);
    assert_eq!(
        r.rejected_reasons,
        vec![
            (RejectReason::JsonFormat, 2),
            (RejectReason::TranslationInvalidField, 2),
            (RejectReason::TranslationValidation, 1),
            (RejectReason::UnknownField, 1),
            (RejectReason::UntaggedRecord, 1),
            (RejectReason::Validation, 1),
        ]
    );
    assert!(r.is_clean());
    assert_eq!(r.schema_compliance_percent(), 100);
    assert_eq!(r.summary_line(), "schema compliance 100% · duplicates 0 · untagged 0 · rejected 8");
    let text = r.text();
    assert_eq!(text.lines().next().unwrap(), r.summary_line());
    for expected in [
        format!("records: {n} (schema-compliant {n})"),
        "deduplicated on ingest: 2".to_string(),
        "rejected (by reason):".to_string(),
        "  unknown_field: 1".to_string(),
        "  translation_validation: 1".to_string(),
        "  translation_invalid_field: 2".to_string(),
        "  validation: 1".to_string(),
        "  untagged: 1".to_string(),
        "  json_format: 2".to_string(),
    ] {
        assert!(text.lines().any(|l| l == expected), "missing report line: {expected:?}\n{text}");
    }
}

#[test]
fn no_reasons_heading_without_rejections() {
    let t = temp();
    let mut store_inst = open_store(&t);
    store_inst.store_event(&event("file_opened", 1)).unwrap();
    let r = store_inst.quality_report().unwrap();
    assert!(r.rejected_reasons.is_empty());
    assert!(!r.text().contains("rejected (by reason):"));
}

#[test]
fn tampered_record_lowers_schema_compliance() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let events = events(10);
    for o in &events {
        store_inst.store_event(o).unwrap();
    }
    external(&t)
        .execute(
            "UPDATE events SET data = ?1 WHERE event_id = ?2",
            rusqlite::params!["{tampered", events[3].event_id.to_string()],
        )
        .unwrap();
    let r = store_inst.quality_report().unwrap();
    assert_eq!((r.record_count, r.schema_compliant), (10, 9));
    assert_eq!(r.schema_compliance_percent(), 90);
    assert!(!r.is_clean());
    assert_eq!(r.summary_line(), "schema compliance 90% · duplicates 0 · untagged 0 · rejected 0");
}

#[test]
fn percent_rounds_down_never_to_a_hundred() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let events = events(200);
    for o in &events {
        store_inst.store_event(o).unwrap();
    }
    external(&t)
        .execute("UPDATE events SET data = 'x' WHERE event_id = ?1", rusqlite::params![events[0].event_id.to_string()])
        .unwrap();
    let r = store_inst.quality_report().unwrap();
    assert_eq!(r.schema_compliant, 199);
    assert_eq!(r.schema_compliance_percent(), 99, "99.5% must never appear as 100%");
}

#[test]
fn untagged_record_in_store_counted() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let events = events(4);
    for o in &events {
        store_inst.store_event(o).unwrap();
    }
    let mut v = serde_json::to_value(&events[1]).unwrap();
    v.as_object_mut().unwrap().remove("source_tag");
    external(&t)
        .execute(
            "UPDATE events SET data = ?1 WHERE event_id = ?2",
            rusqlite::params![v.to_string(), events[1].event_id.to_string()],
        )
        .unwrap();
    let r = store_inst.quality_report().unwrap();
    assert_eq!(r.untagged, 1);
    assert_eq!(r.schema_compliant, 3);
    assert!(!r.is_clean());
    assert!(r.summary_line().contains("untagged 1"), "{}", r.summary_line());
}

#[test]
fn column_json_disagreement_is_noncompliant() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let events = events(3);
    for o in &events {
        store_inst.store_event(o).unwrap();
    }
    external(&t)
        .execute(
            "UPDATE events SET source_tag = 'real' WHERE event_id = ?1",
            rusqlite::params![events[0].event_id.to_string()],
        )
        .unwrap();
    let r = store_inst.quality_report().unwrap();
    assert_eq!((r.record_count, r.schema_compliant), (3, 2), "the column and the JSON tag must agree");
}

#[test]
fn duplicate_in_store_found_by_recomputed_key() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let a = event("file_opened", 1);
    let b = event("file_opened", 2);
    store_inst.store_event(&a).unwrap();
    store_inst.store_event(&b).unwrap();
    // Make B's content the same fact as A while leaving the key column unique (the index does not
    // catch the duplicate); the report must recompute the key from content and find it.
    let mut v: Value = serde_json::to_value(&a).unwrap();
    v["event_id"] = json!(b.event_id.to_string());
    external(&t)
        .execute(
            "UPDATE events SET data = ?1, timestamp = ?2 WHERE event_id = ?3",
            rusqlite::params![v.to_string(), a.timestamp.text(), b.event_id.to_string()],
        )
        .unwrap();
    let r: QualityReport = store_inst.quality_report().unwrap();
    assert_eq!(r.duplicates, 1);
    assert!(!r.is_clean());
    assert!(r.summary_line().contains("duplicates 1"), "{}", r.summary_line());
}
