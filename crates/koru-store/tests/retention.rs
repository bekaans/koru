//! Retention and rotation (protected set; privacy law,
//! ADR-0006 "Retention and rotation"): the default is 90 days and configurable; expired records
//! are deleted (the age is counted from the event's `timestamp` field; a record on the boundary
//! stays); past the record cap the oldest records are deleted; the WAL is truncated; deleted data
//! does not remain in the file (secure_delete + VACUUM).

mod common;

use std::fs;
use std::path::Path;

use common::*;
use koru_event::{Event, EventId};
use koru_store::{RotationResult, Store, StoreSettings};
use serde_json::json;

const NOW_NS: i128 = BASE_TIME_NS + 200 * DAY_NS;

fn now() -> koru_event::Timestamp {
    time_ns(NOW_NS)
}

/// A unique event that is `age_ns` old.
fn old_event(n: u32, age_ns: i128) -> Event {
    let mut v = event_json_value("file_opened", n);
    v["timestamp"] = json!(time_ns(NOW_NS - age_ns).text());
    let o: Event = serde_json::from_value(v).unwrap();
    o.validate().unwrap();
    o
}

fn open_configured(t: &tempfile::TempDir, configure: impl FnOnce(StoreSettings) -> StoreSettings) -> Store {
    Store::open(configure(StoreSettings::new(store_path(t)))).unwrap()
}

fn exists(store_inst: &Store, o: &Event) -> bool {
    store_inst.get_event(&o.event_id).unwrap().is_some()
}

fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[test]
fn default_ninety_days_boundary_record_stays() {
    let t = temp();
    let mut store_inst = open_store(&t);
    assert_eq!(store_inst.settings().retention_days, 90);
    let ages: [(i128, bool); 6] = [
        (120 * DAY_NS, false),
        (91 * DAY_NS, false),
        (90 * DAY_NS + 1, false),
        (90 * DAY_NS, true),
        (89 * DAY_NS, true),
        (DAY_NS, true),
    ];
    let events: Vec<(Event, bool)> = ages.iter().enumerate().map(|(i, (y, k))| (old_event(i as u32, *y), *k)).collect();
    for (o, _) in &events {
        store_inst.store_event(o).unwrap();
    }
    let s = store_inst.freeze(now()).unwrap();
    assert_eq!(s, RotationResult { expired: 3, over_limit: 0, remaining: 3 });
    for (o, should_remain) in &events {
        assert_eq!(exists(&store_inst, o), *should_remain, "timestamp {}", o.timestamp);
    }
    assert_eq!(store_inst.record_count().unwrap(), 3);
}

#[test]
fn retention_period_is_configurable() {
    let t = temp();
    let mut store_inst = open_configured(&t, |a| a.retention_days(30));
    let old = old_event(1, 31 * DAY_NS);
    let new = old_event(2, 29 * DAY_NS);
    store_inst.store_event(&old).unwrap();
    store_inst.store_event(&new).unwrap();
    let s = store_inst.freeze(now()).unwrap();
    assert_eq!((s.expired, s.remaining), (1, 1));
    assert!(!exists(&store_inst, &old) && exists(&store_inst, &new));
}

#[test]
fn one_day_retention() {
    let t = temp();
    let mut store_inst = open_configured(&t, |a| a.retention_days(1));
    let o1 = old_event(1, DAY_NS + 1);
    let o2 = old_event(2, DAY_NS);
    store_inst.store_event(&o1).unwrap();
    store_inst.store_event(&o2).unwrap();
    assert_eq!(store_inst.freeze(now()).unwrap().expired, 1);
    assert!(exists(&store_inst, &o2));
}

#[test]
fn repeated_rotation_deletes_nothing_and_works_on_empty_store() {
    let t = temp();
    let mut store_inst = open_store(&t);
    assert_eq!(store_inst.freeze(now()).unwrap(), RotationResult { expired: 0, over_limit: 0, remaining: 0 });
    store_inst.store_event(&old_event(1, 100 * DAY_NS)).unwrap();
    store_inst.store_event(&old_event(2, DAY_NS)).unwrap();
    assert_eq!(store_inst.freeze(now()).unwrap().expired, 1);
    assert_eq!(store_inst.freeze(now()).unwrap(), RotationResult { expired: 0, over_limit: 0, remaining: 1 });
}

#[test]
fn events_after_now_are_not_deleted() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let future = old_event(1, -5 * DAY_NS);
    store_inst.store_event(&future).unwrap();
    assert_eq!(store_inst.freeze(now()).unwrap().expired, 0);
    assert!(exists(&store_inst, &future));
}

#[test]
fn record_cap_deletes_the_oldest() {
    let t = temp();
    let mut store_inst = open_configured(&t, |a| a.max_records(5));
    let events: Vec<Event> = (0..8).map(|i| old_event(i, (10 - i as i128) * DAY_NS)).collect();
    // Ingested in mixed order: the one deleted is the oldest by time, not by insertion.
    for i in [3, 0, 7, 1, 5, 2, 6, 4] {
        store_inst.store_event(&events[i]).unwrap();
    }
    let s = store_inst.freeze(now()).unwrap();
    assert_eq!(s, RotationResult { expired: 0, over_limit: 3, remaining: 5 });
    for (i, o) in events.iter().enumerate() {
        assert_eq!(exists(&store_inst, o), i >= 3, "event {i}");
    }
}

#[test]
fn age_and_cap_together() {
    let t = temp();
    let mut store_inst = open_configured(&t, |a| a.max_records(2).retention_days(90));
    for (i, age) in [200, 150, 50, 40, 30, 20].iter().enumerate() {
        store_inst.store_event(&old_event(i as u32, age * DAY_NS)).unwrap();
    }
    let s = store_inst.freeze(now()).unwrap();
    assert_eq!(s, RotationResult { expired: 2, over_limit: 2, remaining: 2 });
}

#[test]
fn rotation_keeps_counters_and_new_records() {
    let t = temp();
    let mut store_inst = open_store(&t);
    store_inst.store_json("{broken").unwrap();
    store_inst.store_event(&old_event(1, 100 * DAY_NS)).unwrap();
    store_inst.store_event(&old_event(1, 100 * DAY_NS)).unwrap();
    store_inst.freeze(now()).unwrap();
    assert_eq!(store_inst.rejected_total().unwrap(), 1);
    assert_eq!(store_inst.deduplicated_count().unwrap(), 1);
    let new = old_event(9, DAY_NS);
    store_inst.store_event(&new).unwrap();
    assert!(exists(&store_inst, &new), "writing after rotation must work");
}

#[test]
fn rotation_truncates_wal() {
    let t = temp();
    let mut store_inst = open_store(&t);
    for i in 0..300 {
        store_inst.store_event(&old_event(i, DAY_NS)).unwrap();
    }
    let wal = store_path(&t).with_file_name("event.db-wal");
    assert!(file_size(&wal) > 0, "the WAL must be present after writing");
    store_inst.freeze(now()).unwrap();
    assert_eq!(file_size(&wal), 0, "rotation must truncate the WAL");
    assert_eq!(store_inst.record_count().unwrap(), 300);
}

#[test]
fn deleted_space_is_returned() {
    let t = temp();
    {
        let mut store_inst = open_store(&t);
        for i in 0..400 {
            let mut v = event_json_value("file_opened", i);
            v["timestamp"] = json!(time_ns(NOW_NS - 150 * DAY_NS).text());
            v["process"]["command_line"] = json!(["x".repeat(4000)]);
            store_inst.store_json(&v.to_string()).unwrap();
        }
    }
    let mut store_inst = open_store(&t);
    let before = file_size(&store_path(&t));
    assert!(before > 1_000_000, "precondition: the file must have grown ({before})");
    let s = store_inst.freeze(now()).unwrap();
    assert_eq!((s.expired, s.remaining), (400, 0));
    let after = file_size(&store_path(&t));
    assert!(after < before / 4, "VACUUM must return space: before {before}, after {after}");
}

#[test]
fn deleted_personal_data_does_not_remain_in_file() {
    let t = temp();
    let marker = "SECRET-MARKER-198.51.100.123-ZZ";
    let mut store_inst = open_store(&t);
    let mut v = event_json_value("file_opened", 1);
    v["timestamp"] = json!(time_ns(NOW_NS - 150 * DAY_NS).text());
    v["target"]["path"] = json!(format!("/tmp/{marker}"));
    store_inst.store_json(&v.to_string()).unwrap();
    let kept = old_event(2, DAY_NS);
    store_inst.store_event(&kept).unwrap();
    let read = |t: &tempfile::TempDir| -> Vec<u8> {
        let path = store_path(t);
        let mut b = fs::read(&path).unwrap_or_default();
        b.extend(fs::read(path.with_file_name("event.db-wal")).unwrap_or_default());
        b
    };
    let find = |b: &[u8]| b.windows(marker.len()).any(|w| w == marker.as_bytes());
    assert!(find(&read(&t)), "precondition: the marker must be in the file");
    let s = store_inst.freeze(now()).unwrap();
    assert_eq!(s.expired, 1);
    assert!(!find(&read(&t)), "deleted personal data must not remain in the database file or the WAL (privacy law)");
    assert!(exists(&store_inst, &kept));
    // It does not come from a query either.
    let id: EventId = v["event_id"].as_str().unwrap().to_string().try_into().unwrap();
    assert!(store_inst.get_event(&id).unwrap().is_none());
}

#[test]
fn rotation_result_persists_after_reopen() {
    let t = temp();
    {
        let mut store_inst = open_store(&t);
        store_inst.store_event(&old_event(1, 100 * DAY_NS)).unwrap();
        store_inst.store_event(&old_event(2, DAY_NS)).unwrap();
        store_inst.freeze(now()).unwrap();
    }
    assert_eq!(open_store(&t).record_count().unwrap(), 1);
}
