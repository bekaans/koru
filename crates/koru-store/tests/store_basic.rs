//! Basic store behavior (protected set): WAL, schema,
//! store-get, parameterized SQL, id collision, the `EventStore` interface, concurrency.

mod common;

use common::*;
use koru_event::{EventId, EventStore, InterfaceError, RecordResult};
use koru_store::{DEFAULT_RETENTION_DAYS, IngestOutcome, RejectReason, Store, StoreError, StoreSettings};
use rusqlite::Connection;

fn external_conn(t: &tempfile::TempDir) -> Connection {
    Connection::open(store_path(t)).expect("an external connection")
}

#[test]
fn defaults_nine_hundred_day_retention() {
    assert_eq!(DEFAULT_RETENTION_DAYS, 90);
    let a = StoreSettings::new("/temp/event.db");
    assert_eq!(a.retention_days, 90);
    assert!(a.max_records >= 1);
    assert!(!a.must_exist);
    assert_eq!(a.clone().retention_days(30).retention_days, 30);
    assert_eq!(a.clone().max_records(7).max_records, 7);
    assert!(a.must_exist().must_exist);
}

#[test]
fn every_event_kind_stored_and_returned_unchanged() {
    let t = temp();
    let mut store_inst = open_store(&t);
    for (i, template) in ALL_TEMPLATES.iter().enumerate() {
        let o = event(template, i as u32);
        assert_eq!(store_inst.store_event(&o).unwrap(), IngestOutcome::Stored, "{template}");
        let back = store_inst.get_event(&o.event_id).unwrap().expect("the record must exist");
        assert_eq!(back, o, "{template}: the event returned from the store must be identical");
    }
    assert_eq!(store_inst.record_count().unwrap(), ALL_TEMPLATES.len() as u64);
    assert!(store_inst.get_event(&EventId::new()).unwrap().is_none());
}

#[test]
fn json_line_is_stored() {
    let t = temp();
    let mut store_inst = open_store(&t);
    assert_eq!(store_inst.store_json(&event_json("network_connection", 1)).unwrap(), IngestOutcome::Stored);
    assert_eq!(store_inst.record_count().unwrap(), 1);
}

#[test]
fn records_survive_reopen() {
    let t = temp();
    let o = event("finding", 3);
    {
        let mut store_inst = open_store(&t);
        store_inst.store_event(&o).unwrap();
        store_inst.store_json("{broken").unwrap();
    }
    let store_inst = open_store(&t);
    assert_eq!(store_inst.get_event(&o.event_id).unwrap(), Some(o));
    assert_eq!(store_inst.rejected_total().unwrap(), 1, "the counters are persistent too");
}

#[test]
fn wal_mode_and_schema_version() {
    let t = temp();
    let mut store_inst = open_store(&t);
    store_inst.store_event(&event("file_opened", 0)).unwrap();
    let c = external_conn(&t);
    let mod_: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
    assert_eq!(mod_.to_lowercase(), "wal");
    let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    assert_eq!(version, 2);
}

#[test]
fn fixed_table_structure() {
    let t = temp();
    drop(open_store(&t));
    let c = external_conn(&t);
    let columns = |table: &str| -> Vec<String> {
        let mut s = c.prepare(&format!("SELECT name FROM pragma_table_info('{table}') ORDER BY cid")).unwrap();
        s.query_map([], |r| r.get::<_, String>(0)).unwrap().map(Result::unwrap).collect()
    };
    assert_eq!(columns("events"), ["seq", "event_id", "event_key", "timestamp", "source_tag", "event_type", "data"]);
    assert_eq!(columns("rejected"), ["reason", "count"]);
    assert_eq!(columns("counters"), ["name", "value"]);
}

#[test]
fn schema_does_not_contain_the_word_koru() {
    let t = temp();
    drop(open_store(&t));
    let c = external_conn(&t);
    let sql: String = c
        .query_row("SELECT group_concat(name || ' ' || coalesce(sql, ''), ' ') FROM sqlite_master", [], |r| r.get(0))
        .unwrap();
    assert!(!sql.to_lowercase().contains("koru"), "the schema must not give Koru away: {sql}");
    let application: i64 = c.query_row("PRAGMA application_id", [], |r| r.get(0)).unwrap();
    assert_eq!(application, 0);
}

#[test]
fn sql_injection_is_neutralized() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let mut v = event_json_value("file_opened", 1);
    set_field(&mut v, "/target/path", serde_json::json!("/tmp/x'); DROP TABLE events; --\u{0}\n\"quote'"));
    set_field(&mut v, "/process/command_line", serde_json::json!(["a\" OR 1=1 --", "'; DELETE FROM events; --"]));
    let id: EventId = v["event_id"].as_str().unwrap().to_string().try_into().unwrap();
    assert_eq!(store_inst.store_json(&v.to_string()).unwrap(), IngestOutcome::Stored);
    assert_eq!(
        store_inst.get_event(&id).unwrap().unwrap().target.path.unwrap().untrusted_value(),
        "/tmp/x'); DROP TABLE events; --\u{0}\n\"quote'"
    );
    assert_eq!(store_inst.record_count().unwrap(), 1);
    let c = external_conn(&t);
    let tables: i64 =
        c.query_row("SELECT count(*) FROM sqlite_master WHERE name = 'events'", [], |r| r.get(0)).unwrap();
    assert_eq!(tables, 1, "the table must not be dropped");
}

#[test]
fn same_id_different_content_is_rejected() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let first = event_json_value("file_opened", 1);
    let mut second = event_json_value("file_created", 2);
    second["event_id"] = first["event_id"].clone();
    assert_eq!(store_inst.store_json(&first.to_string()).unwrap(), IngestOutcome::Stored);
    assert_eq!(store_inst.store_json(&second.to_string()).unwrap(), IngestOutcome::Rejected(RejectReason::IdConflict));
    assert_eq!(store_inst.record_count().unwrap(), 1);
    assert_eq!(store_inst.rejected().unwrap(), vec![(RejectReason::IdConflict, 1)]);
}

#[test]
fn event_store_interface() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let iface: &mut dyn EventStore = &mut store_inst;
    let o = event("file_opened", 1);
    assert_eq!(iface.store(&o), Ok(RecordResult::Stored));
    assert_eq!(iface.store(&o), Ok(RecordResult::Duplicate));
    assert_eq!(iface.get(&o.event_id), Ok(Some(o.clone())));
    assert_eq!(iface.rejected_count(), 0);
    let mut broken = event("file_opened", 2);
    broken.process.pid = 0;
    match iface.store(&broken) {
        Err(InterfaceError::Permanent(m)) => {
            assert!(m.contains("validation"), "the rejection reason must be in the message: {m}")
        }
        other => panic!("an invalid event must be rejected with a permanent error: {other:?}"),
    }
    assert_eq!(iface.rejected_count(), 1);
    assert_eq!(iface.get(&broken.event_id), Ok(None), "a rejected event must not enter the store");
}

#[test]
fn settings_errors() {
    let t = temp();
    let path = store_path(&t);
    assert!(matches!(Store::open(StoreSettings::new(&path).retention_days(0)), Err(StoreError::Settings(_))));
    assert!(matches!(Store::open(StoreSettings::new(&path).max_records(0)), Err(StoreError::Settings(_))));
    assert!(!path.exists(), "invalid settings must not create a file");
}

#[test]
fn must_exist_does_not_create() {
    let t = temp();
    let path = store_path(&t);
    let err = Store::open(StoreSettings::new(&path).must_exist()).unwrap_err();
    assert!(matches!(err, StoreError::NotFound { .. }), "{err:?}");
    assert!(!path.exists());
    drop(open_store(&t));
    Store::open(StoreSettings::new(&path).must_exist()).expect("an existing store must open");
}

#[test]
fn store_written_by_newer_version_is_rejected() {
    let t = temp();
    drop(open_store(&t));
    external_conn(&t).execute_batch("PRAGMA user_version = 99").unwrap();
    let err = Store::open(StoreSettings::new(store_path(&t))).unwrap_err();
    assert_eq!(err, StoreError::SchemaVersion { found: 99, supported: 2 });
}

#[test]
fn count_rejection_counts_external_rejections() {
    // `rejected` returns in code order (alphabetic): translation_validation, translation_invalid_field.
    let t = temp();
    {
        let mut store_inst = open_store(&t);
        store_inst.count_rejected(RejectReason::TranslationInvalidField, 3).unwrap();
        store_inst.count_rejected(RejectReason::TranslationValidation, 2).unwrap();
        store_inst.count_rejected(RejectReason::TranslationInvalidField, 1).unwrap();
        store_inst.count_rejected(RejectReason::TranslationValidation, 0).unwrap();
    }
    let store_inst = open_store(&t);
    assert_eq!(
        store_inst.rejected().unwrap(),
        vec![(RejectReason::TranslationInvalidField, 4), (RejectReason::TranslationValidation, 2)]
    );
    assert_eq!(store_inst.rejected_total().unwrap(), 6);
    assert_eq!(store_inst.record_count().unwrap(), 0);
}

#[test]
fn two_connections_write_concurrently() {
    let t = temp();
    drop(open_store(&t));
    let path = store_path(&t);
    let worker = |name: u32| {
        let path = path.clone();
        std::thread::spawn(move || {
            let mut store_inst = Store::open(StoreSettings::new(path)).unwrap();
            for i in 0..40 {
                let o = event("file_opened", name * 1000 + i);
                assert_eq!(store_inst.store_event(&o).unwrap(), IngestOutcome::Stored);
            }
        })
    };
    let (a, b) = (worker(1), worker(2));
    a.join().unwrap();
    b.join().unwrap();
    assert_eq!(open_store(&t).record_count().unwrap(), 80);
}

#[test]
fn same_event_from_two_connections_stored_once() {
    let t = temp();
    let mut a = open_store(&t);
    let mut b = open_store(&t);
    for i in 0..20 {
        let o = event("file_opened", i);
        assert_eq!(a.store_event(&o).unwrap(), IngestOutcome::Stored);
        assert_eq!(b.store_event(&o).unwrap(), IngestOutcome::Duplicate);
    }
    assert_eq!(a.record_count().unwrap(), 20);
    assert_eq!(
        b.deduplicated_count().unwrap(),
        20,
        "deduplicates live in the persistent counter, independent of the connection"
    );
}
