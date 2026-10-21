//! Export (protected set): JSONL and OCSF; `--mask`
//! (privacy law); rejection of mixed source tags; corrupt records are not written.

mod common;

use common::*;
use koru_event::{Event, SourceTag};
use koru_store::{ExportError, ExportFormat, ExportOptions, Store, ocsf_event};
use rusqlite::Connection;
use serde_json::{Value, json};

fn export_all(store_inst: &Store, option: ExportOptions) -> (Result<koru_store::ExportResult, ExportError>, String) {
    let mut output = Vec::new();
    let s = store_inst.export(&option, &mut output);
    (s, String::from_utf8(output).expect("the output must be UTF-8"))
}

fn jsonl(store_inst: &Store) -> String {
    let (s, c) = export_all(store_inst, ExportOptions::new(ExportFormat::Jsonl));
    s.expect("the export must succeed");
    c
}

fn lines(c: &str) -> Vec<&str> {
    c.lines().collect()
}

fn fill_store(store_inst: &mut Store, templates: &[&str]) -> Vec<Event> {
    templates
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let o = event(s, i as u32);
            store_inst.store_event(&o).unwrap();
            o
        })
        .collect()
}

#[test]
fn jsonl_every_line_is_a_valid_event() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let ingested = fill_store(&mut store_inst, ALL_TEMPLATES);
    let (s, c) = export_all(&store_inst, ExportOptions::new(ExportFormat::Jsonl));
    let s = s.unwrap();
    assert_eq!((s.written, s.skipped_corrupt), (ingested.len() as u64, 0));
    assert!(c.ends_with('\n') && !c.contains("\n\n"));
    let back: Vec<Event> = lines(&c)
        .iter()
        .map(|l| {
            let o: Event = serde_json::from_str(l).expect("the line must be schema v1");
            o.validate().expect("the line must pass validation");
            o
        })
        .collect();
    assert_eq!(back, ingested, "in timestamp order and unchanged");
}

#[test]
fn order_by_time_then_id() {
    let t = temp();
    let mut store_inst = open_store(&t);
    for n in [5, 1, 3, 2, 4] {
        store_inst.store_event(&event("file_opened", n)).unwrap();
    }
    let times: Vec<String> = lines(&jsonl(&store_inst))
        .iter()
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["timestamp"].as_str().unwrap().to_string())
        .collect();
    let mut sorted = times.clone();
    sorted.sort();
    assert_eq!(times, sorted);
    assert_eq!(times.len(), 5);
}

#[test]
fn empty_store_empty_output() {
    let t = temp();
    let store_inst = open_store(&t);
    for format in [ExportFormat::Jsonl, ExportFormat::Ocsf] {
        let (s, c) = export_all(&store_inst, ExportOptions::new(format));
        assert_eq!(s.unwrap().written, 0);
        assert!(c.is_empty());
    }
}

#[test]
fn mixed_source_tags_rejected_and_nothing_written() {
    let t = temp();
    let mut store_inst = open_store(&t);
    for (i, e) in ["synthetic", "synthetic", "legitimate", "real"].iter().enumerate() {
        let mut v = event_json_value("file_opened", i as u32);
        v["source_tag"] = json!(e);
        store_inst.store_json(&v.to_string()).unwrap();
    }
    for format in [ExportFormat::Jsonl, ExportFormat::Ocsf] {
        let (s, c) = export_all(&store_inst, ExportOptions::new(format));
        match s {
            Err(ExportError::MixedSources { tags }) => {
                let mut e = tags;
                e.sort_by_key(|x| format!("{x:?}"));
                assert_eq!(e, vec![SourceTag::Legitimate, SourceTag::Real, SourceTag::Synthetic]);
            }
            other => panic!("mixed tags must be rejected: {other:?}"),
        }
        assert!(c.is_empty(), "a rejected export must write nothing");
    }
}

#[test]
fn source_filter_exports_a_single_tag() {
    let t = temp();
    let mut store_inst = open_store(&t);
    for (i, e) in ["synthetic", "legitimate", "legitimate", "synthetic", "real"].iter().enumerate() {
        let mut v = event_json_value("file_opened", i as u32);
        v["source_tag"] = json!(e);
        store_inst.store_json(&v.to_string()).unwrap();
    }
    for (tag, count) in [(SourceTag::Synthetic, 2), (SourceTag::Legitimate, 2), (SourceTag::Real, 1)] {
        for format in [ExportFormat::Jsonl, ExportFormat::Ocsf] {
            let mut sec = ExportOptions::new(format);
            sec.source = Some(tag);
            let (s, c) = export_all(&store_inst, sec);
            assert_eq!(s.unwrap().written, count, "{tag:?} {format:?}");
            assert_eq!(lines(&c).len() as u64, count);
        }
    }
}

#[test]
fn single_tag_store_needs_no_filter() {
    let t = temp();
    let mut store_inst = open_store(&t);
    fill_store(&mut store_inst, &["file_opened", "network_connection"]);
    for format in [ExportFormat::Jsonl, ExportFormat::Ocsf] {
        assert_eq!(export_all(&store_inst, ExportOptions::new(format)).0.unwrap().written, 2);
    }
}

#[test]
fn mask_jsonl_before_and_after() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let ingested = fill_store(
        &mut store_inst,
        &["network_connection", "network_connection_v6", "network_accept", "process_executed"],
    );
    let plain = jsonl(&store_inst);
    for ip in ["203.0.113.77", "10.0.0.5", "198.51.100.7", "2001:db8:abcd:12::99", "203.0.113.9"] {
        assert!(plain.contains(ip), "{ip} must appear in unmasked output");
    }
    let mut sec = ExportOptions::new(ExportFormat::Jsonl);
    sec.mask = true;
    let (s, masked) = export_all(&store_inst, sec);
    assert_eq!(s.unwrap().written, 4);
    for ip in ["203.0.113.77", "10.0.0.5", "198.51.100.7", "2001:db8:abcd:12::99", "203.0.113.9"] {
        assert!(!masked.contains(ip), "{ip} must not appear in masked output");
    }
    for ip in ["203.0.113.0", "10.0.0.0", "198.51.100.0", "2001:db8:abcd::"] {
        assert!(masked.contains(ip), "{ip} must appear in masked output");
    }
    for line in lines(&masked) {
        let o: Event = serde_json::from_str(line).expect("the masked line must match the schema");
        o.validate().expect("the masked event must stay valid");
    }
    assert_eq!(
        store_inst.get_event(&ingested[0].event_id).unwrap().unwrap(),
        ingested[0],
        "the stored record is not masked"
    );
}

#[test]
fn ocsf_lines_match_the_mapping() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let ingested = fill_store(&mut store_inst, ALL_TEMPLATES);
    let (s, c) = export_all(&store_inst, ExportOptions::new(ExportFormat::Ocsf));
    assert_eq!(s.unwrap().written, ingested.len() as u64);
    let lines = lines(&c);
    assert_eq!(lines.len(), ingested.len());
    for (line, o) in lines.iter().zip(&ingested) {
        let v: Value = serde_json::from_str(line).expect("every line must be JSON");
        assert_eq!(v, ocsf_event(o));
        assert_eq!(v["metadata"]["version"], "1.9.0");
    }
}

#[test]
fn masked_ocsf() {
    let t = temp();
    let mut store_inst = open_store(&t);
    fill_store(&mut store_inst, &["network_connection", "network_accept"]);
    let mut sec = ExportOptions::new(ExportFormat::Ocsf);
    sec.mask = true;
    let (s, c) = export_all(&store_inst, sec);
    s.unwrap();
    for ip in ["203.0.113.77", "10.0.0.5", "198.51.100.7"] {
        assert!(!c.contains(ip), "{ip} must be masked");
    }
    assert!(c.contains("203.0.113.0") && c.contains("198.51.100.0"));
}

#[test]
fn corrupt_record_skipped_and_counted() {
    let t = temp();
    let mut store_inst = open_store(&t);
    let ingested = fill_store(&mut store_inst, &["file_opened", "file_deleted", "network_connection"]);
    let c = Connection::open(store_path(&t)).unwrap();
    c.execute(
        "UPDATE events SET data = ?1 WHERE event_id = ?2",
        rusqlite::params!["{tampered", ingested[1].event_id.to_string()],
    )
    .unwrap();
    for format in [ExportFormat::Jsonl, ExportFormat::Ocsf] {
        let (s, output) = export_all(&store_inst, ExportOptions::new(format));
        let s = s.unwrap();
        assert_eq!((s.written, s.skipped_corrupt), (2, 1), "{format:?}");
        assert!(!output.contains("tampered"));
    }
}

#[test]
fn write_error_is_reported() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk present"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let t = temp();
    let mut store_inst = open_store(&t);
    fill_store(&mut store_inst, &["file_opened"]);
    let err = store_inst.export(&ExportOptions::new(ExportFormat::Jsonl), &mut Broken).unwrap_err();
    assert!(matches!(err, ExportError::Write(m) if m.contains("disk present")));
}

#[test]
fn export_does_not_change_store() {
    let t = temp();
    let mut store_inst = open_store(&t);
    fill_store(&mut store_inst, ALL_TEMPLATES);
    let once = store_inst.record_count().unwrap();
    let mut sec = ExportOptions::new(ExportFormat::Ocsf);
    sec.mask = true;
    export_all(&store_inst, sec).0.unwrap();
    assert_eq!(store_inst.record_count().unwrap(), once);
    assert_eq!(store_inst.rejected_total().unwrap(), 0);
}
