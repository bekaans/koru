//! KT-66 in events imported with `koru event ingest`, the `host` and
//! `sensor.*` fields go through strict format validation; IP-like and free-text values are rejected
//! and counted in the data-quality report under the `validation` reason.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::{Value, json};

fn koru(args: &[&str], home_v: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_koru")).args(args).env("HOME", home_v).output().expect("koru could not be run")
}

fn output(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

const BASE_TIME_NS: i128 = 1_791_560_874_000_000_000;

fn event(n: u32, host: &str, sensor_ad: &str) -> Value {
    json!({
        "schema_version": 1,
        "event_id": koru_event::EventId::new().to_string(),
        "timestamp": koru_event::Timestamp::from_unix_nanos(BASE_TIME_NS + i128::from(n) * 1_000_000_000).unwrap().text(),
        "timestamp_trusted": true,
        "source_tag": "synthetic",
        "sensor": {"name": sensor_ad, "version": "0.11.0-alpha.1", "platform": "linux-aarch64"},
        "host": host,
        "process": {
            "pid": 1000 + n, "ppid": 900, "start_time": null, "exe": "/usr/bin/curl",
            "command_line": ["curl", "http://203.0.113.9/x"], "environment": [],
            "user": {"uid": 1000, "gid": 1000}, "lineage": []
        },
        "container": {"id": null, "name": null, "image": null, "image_digest": null, "namespaces": null},
        "event_type": "network_connection",
        "target": {
            "path": null, "new_path": null, "flags": [], "hard_link": null, "protocol": "tcp",
            "local": null, "remote": {"ip": "203.0.113.77", "port": 443}, "exit_code": null
        },
        "actor": {"kind": "unknown", "rationale": [], "confidence": 0.0},
        "detection": null,
        "tags": {"intent": null, "mitre_techniques": [], "verified": false},
        "session_id": null,
        "response": null
    })
}

#[test]
fn ip_like_and_free_text_id_fields_rejected_and_counted() {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    let home_v = tempfile::tempdir().unwrap();
    let lines = [
        event(0, "lab-server", "pulsar"),
        event(1, "10.9.8.7", "pulsar"),
        event(2, "password=secret", "pulsar"),
        event(3, "lab-server", "sensor-10.9.8.7"),
        event(4, "web01.sample.example", "pulsar"),
    ]
    .map(|v| v.to_string())
    .join("\n")
        + "\n";
    let input = root.join("input.jsonl");
    fs::write(&input, lines).unwrap();
    let store = root.join("store").join("event.db").to_string_lossy().into_owned();

    let o = koru(&["event", "ingest", "--store", &store, "--input", &input.to_string_lossy()], home_v.path());
    assert!(o.status.success(), "{}", output(&o));
    assert!(output(&o).contains("Result: stored 2 · duplicates 0 · rejected 3"), "{}", output(&o));

    let r = koru(&["report", "data-quality", "--store", &store], home_v.path());
    let text = output(&r);
    assert!(text.lines().any(|l| l == "  validation: 3"), "{text}");
    assert_eq!(
        text.lines().next().unwrap(),
        "schema compliance 100% · duplicates 0 · untagged 0 · rejected 3",
        "{text}"
    );
}
