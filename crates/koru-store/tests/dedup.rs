//! Deduplication (protected set): the SHA-256 digest of the
//! event key (ADR-0006 "Event key"). The `event_id` is a UUIDv7, so it does not
//! enter the key; a redelivery of the same fact counts as a duplicate even under a new id.
//!
//! The key encoding is re-implemented independently in this file (`reference_key`); the store
//! implementation must produce exactly the same digest as the ADR-0006 encoding:
//!
//! - Field: `None` → `0x00`; `Some(m)` → `0x01`, the byte length of `m` (u32, big-endian), `m`.
//! - List: the item count (u32, big-endian), then each item as `Some`.
//! - Network endpoint: `None` → `0x00`; `Some` → `0x01`, the `ip` field, the `port` field (decimal text).
//! - Order: the tag `koru-event-key-v1`, schema_version, source_tag, host, timestamp,
//!   event_type, process.pid, process.start_time, target.path, target.new_path, target.flags
//!   (sorted by text), target.hard_link, target.protocol, target.local, target.remote,
//!   target.exit_code, detection.rule, detection.decoy_id.

mod common;

use common::*;
use koru_event::Event;
use koru_store::{IngestOutcome, event_key};
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn field(buf: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => buf.push(0),
        Some(m) => {
            buf.push(1);
            buf.extend_from_slice(&(m.len() as u32).to_be_bytes());
            buf.extend_from_slice(m.as_bytes());
        }
    }
}

fn text_field(buf: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => field(buf, None),
        Value::String(s) => field(buf, Some(s)),
        Value::Bool(b) => field(buf, Some(if *b { "true" } else { "false" })),
        Value::Number(n) => field(buf, Some(&n.to_string())),
        other => panic!("unexpected value: {other}"),
    }
}

fn endpoint(buf: &mut Vec<u8>, v: &Value) {
    if v.is_null() {
        buf.push(0);
    } else {
        buf.push(1);
        text_field(buf, &v["ip"]);
        text_field(buf, &v["port"]);
    }
}

fn reference_key(v: &Value) -> String {
    let mut b = Vec::new();
    field(&mut b, Some("koru-event-key-v1"));
    for path in [
        "/schema_version",
        "/source_tag",
        "/host",
        "/timestamp",
        "/event_type",
        "/process/pid",
        "/process/start_time",
        "/target/path",
        "/target/new_path",
    ] {
        text_field(&mut b, &v.pointer(path).unwrap_or_else(|| panic!("{path}")).clone());
    }
    let mut flags: Vec<String> =
        v["target"]["flags"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
    flags.sort();
    b.extend_from_slice(&(flags.len() as u32).to_be_bytes());
    for x in &flags {
        field(&mut b, Some(x));
    }
    text_field(&mut b, &v["target"]["hard_link"]);
    text_field(&mut b, &v["target"]["protocol"]);
    endpoint(&mut b, &v["target"]["local"]);
    endpoint(&mut b, &v["target"]["remote"]);
    text_field(&mut b, &v["target"]["exit_code"]);
    if v["detection"].is_null() {
        field(&mut b, None);
        field(&mut b, None);
    } else {
        text_field(&mut b, &v["detection"]["rule"]);
        text_field(&mut b, &v["detection"]["decoy_id"]);
    }
    Sha256::digest(&b).iter().map(|x| format!("{x:02x}")).collect()
}

fn event_of(v: &Value) -> Event {
    let o: Event = serde_json::from_value(v.clone()).expect("a valid event");
    o.validate().expect("validation");
    o
}

fn key(v: &Value) -> String {
    event_key(&event_of(v))
}

#[test]
fn key_matches_reference_encoding_and_is_64_hex_digits() {
    for (i, template) in ALL_TEMPLATES.iter().enumerate() {
        let v = event_json_value(template, i as u32);
        let a = key(&v);
        assert_eq!(a.len(), 64, "{template}");
        assert!(a.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "{template}: {a}");
        assert_eq!(a, reference_key(&v), "{template}: must equal the ADR-0006 encoding");
    }
}

#[test]
fn key_is_stable_and_independent_of_event_id() {
    let v = event_json_value("finding", 4);
    let mut other = v.clone();
    other["event_id"] = json!(new_id());
    assert_eq!(key(&v), key(&v));
    assert_eq!(key(&v), key(&other));
}

#[test]
fn fields_not_in_the_key() {
    let base = event_json_value("finding", 2);
    let reference = key(&base);
    let mutations: Vec<(&str, Value)> = vec![
        ("/timestamp_trusted", json!(false)),
        ("/sensor/version", json!("9.9.9")),
        ("/sensor/platform", json!("linux-x86_64")),
        ("/sensor/name", json!("other-sensor")),
        ("/process/ppid", json!(1)),
        ("/process/exe", json!("/tmp/other")),
        ("/process/command_line", json!(["different", "command"])),
        ("/process/environment", json!(["A=1"])),
        ("/process/user", json!({"uid": 0, "gid": 0})),
        ("/process/lineage", json!([])),
        ("/container/id", json!("ab12")),
        ("/actor", json!({"kind": "human", "rationale": ["x"], "confidence": 0.4})),
        ("/tags/intent", json!("discovery")),
        ("/tags/verified", json!(true)),
        ("/session_id", json!("session-1")),
        ("/response", json!({"action": "record", "timestamp": "2026-10-09T15:47:55.000000000Z", "rationale": "g"})),
    ];
    for (path, value) in mutations {
        let mut v = base.clone();
        set_field(&mut v, path, value);
        assert_eq!(key(&v), reference, "{path} must not enter the key (enrichment and estimate fields)");
    }
}

#[test]
fn fields_in_the_key() {
    let base = event_json_value("finding", 2);
    let reference = key(&base);
    let mutations: Vec<(&str, Value)> = vec![
        ("/source_tag", json!("legitimate")),
        ("/host", json!("other-server")),
        ("/timestamp", json!(time_ns(BASE_TIME_NS + 2_000_000_001).text())),
        ("/event_type", json!("file_deleted")),
        ("/process/pid", json!(4321)),
        ("/process/start_time", Value::Null),
        ("/target/path", json!("/home/user/.ssh/other")),
        ("/target/new_path", json!("")),
        ("/target/flags", json!(["O_WRONLY"])),
        ("/target/hard_link", json!(false)),
        ("/detection/rule", json!("koru.other.rule")),
        ("/detection/decoy_id", Value::Null),
        ("/detection", Value::Null),
    ];
    for (path, value) in mutations {
        let mut v = base.clone();
        set_field(&mut v, path, value);
        assert_ne!(key(&v), reference, "{path} must be part of the key");
    }
}

#[test]
fn network_and_exit_fields_enter_key() {
    let ag = event_json_value("network_connection", 1);
    let r = key(&ag);
    for (path, value) in [
        ("/target/protocol", json!("udp")),
        ("/target/local", Value::Null),
        ("/target/local", json!({"ip": "10.0.0.5", "port": 51235})),
        ("/target/remote", json!({"ip": "203.0.113.78", "port": 443})),
        ("/target/remote", json!({"ip": "203.0.113.77", "port": 444})),
        ("/target/remote", json!({"ip": "2001:db8::77", "port": 443})),
    ] {
        let mut v = ag.clone();
        set_field(&mut v, path, value.clone());
        assert_ne!(key(&v), r, "{path} = {value}");
    }
    let exited = event_json_value("process_exited", 1);
    let mut v = exited.clone();
    set_field(&mut v, "/target/exit_code", json!(1));
    assert_ne!(key(&v), key(&exited));
}

#[test]
fn flag_order_does_not_change_key() {
    let mut a = event_json_value("file_opened", 1);
    set_field(&mut a, "/target/flags", json!(["O_RDONLY", "O_NONBLOCK"]));
    let mut b = a.clone();
    set_field(&mut b, "/target/flags", json!(["O_NONBLOCK", "O_RDONLY"]));
    assert_eq!(key(&a), key(&b));
}

#[test]
fn field_boundaries_are_unambiguous() {
    let mut a = event_json_value("file_renamed", 1);
    set_field(&mut a, "/target/path", json!("a"));
    set_field(&mut a, "/target/new_path", json!("bc"));
    let mut b = a.clone();
    set_field(&mut b, "/target/path", json!("ab"));
    set_field(&mut b, "/target/new_path", json!("c"));
    assert_ne!(key(&a), key(&b), "fields must be separated by length prefixes");
    let mut empty = event_json_value("file_opened", 1);
    set_field(&mut empty, "/target/new_path", json!(""));
    assert_ne!(key(&empty), key(&event_json_value("file_opened", 1)), "empty text and null differ");
}

#[test]
fn same_fact_new_id_counts_as_duplicate() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let first = event_json_value("finding", 1);
    assert_eq!(store_inst.store_json(&first.to_string()).unwrap(), IngestOutcome::Stored);
    let mut copy = first.clone();
    copy["event_id"] = json!(new_id());
    set_field(&mut copy, "/process/command_line", json!(["different"]));
    set_field(&mut copy, "/timestamp_trusted", json!(false));
    assert_eq!(store_inst.store_json(&copy.to_string()).unwrap(), IngestOutcome::Duplicate);
    assert_eq!(
        store_inst.store_json(&first.to_string()).unwrap(),
        IngestOutcome::Duplicate,
        "a redelivery of the same line"
    );
    assert_eq!(store_inst.record_count().unwrap(), 1);
    assert_eq!(store_inst.deduplicated_count().unwrap(), 2);
    assert_eq!(store_inst.rejected_total().unwrap(), 0, "a duplicate is not a rejection; it is counted separately");
    let copy_id: koru_event::EventId = copy["event_id"].as_str().unwrap().to_string().try_into().unwrap();
    assert!(store_inst.get_event(&copy_id).unwrap().is_none(), "the deduplicated copy must not enter the store");
}

#[test]
fn same_fact_different_tags_both_stored() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let a = event_json_value("file_opened", 1);
    let mut b = a.clone();
    b["event_id"] = json!(new_id());
    b["source_tag"] = json!("legitimate");
    assert_eq!(store_inst.store_json(&a.to_string()).unwrap(), IngestOutcome::Stored);
    assert_eq!(store_inst.store_json(&b.to_string()).unwrap(), IngestOutcome::Stored, "tags never mix");
    assert_eq!(store_inst.record_count().unwrap(), 2);
}

#[test]
fn store_key_column_matches_digest() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let o = event("finding", 1);
    store_inst.store_event(&o).unwrap();
    let c = Connection::open(store_path(&t)).unwrap();
    let (id, key_column): (String, String) =
        c.query_row("SELECT event_id, event_key FROM events", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!(id, o.event_id.to_string());
    assert_eq!(key_column, event_key(&o));
}
