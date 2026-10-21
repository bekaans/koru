//! Tests of the `koru report threat --source <jsonl>` command.
//!
//! Every number in the Threat Report rests on the output of
//! `koru report threat --source data/real/...`. These tests verify that the distribution counts are
//! derived from the input one to one and that no report is produced on a corrupt line.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

fn koru(args: &[&str], home_v: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_koru")).args(args).env("HOME", home_v).output().expect("koru could not be run")
}

fn output(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn error(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

const BASE_TIME_NS: i128 = 1_791_560_874_000_000_000;

fn timestamp(ns: i128) -> String {
    koru_event::Timestamp::from_unix_nanos(ns).unwrap().text()
}

/// An event template with a detection (rule `decoy_credential_file`, technique T1552.001) or without.
fn event(n: u32, source: &str, with_detection: bool) -> Value {
    json!({
        "schema_version": 1,
        "event_id": koru_event::EventId::new().to_string(),
        "timestamp": timestamp(BASE_TIME_NS + i128::from(n) * 1_000_000_000),
        "timestamp_trusted": true,
        "source_tag": source,
        "sensor": {"name": "pulsar", "version": "0.11.0-alpha.1", "platform": "linux-aarch64"},
        "host": "lab-server",
        "process": {
            "pid": 1000 + n, "ppid": 900, "start_time": null, "exe": "/usr/bin/cat",
            "command_line": ["cat", "/home/devops/.aws/credentials"], "environment": [],
            "user": {"uid": 1000, "gid": 1000}, "lineage": []
        },
        "container": {"id": null, "name": null, "image": null, "image_digest": null, "namespaces": null},
        "event_type": "file_opened",
        "target": {
            "path": "/home/devops/.aws/credentials", "new_path": null, "flags": ["O_RDONLY"],
            "hard_link": null, "protocol": null, "local": null, "remote": null, "exit_code": null
        },
        "actor": {"kind": "unknown", "rationale": [], "confidence": 0.0},
        "detection": if with_detection {
            json!({"rule": "decoy_credential_file", "decoy_id": null,
                   "threat_class": "decoy_access", "attack": ["T1552.001"]})
        } else {
            Value::Null
        },
        "tags": {"intent": null, "mitre_techniques": [], "verified": false},
        "session_id": null,
        "response": null
    })
}

fn write_jsonl(dir: &Path, lines: &[String]) -> PathBuf {
    let path = dir.join("source.jsonl");
    fs::write(&path, lines.join("\n") + "\n").unwrap();
    path
}

#[test]
fn report_counts_threat_distributions() {
    let t = tempfile::tempdir().unwrap();
    let home_v = tempfile::tempdir().unwrap();
    let input = write_jsonl(
        t.path(),
        &[event(0, "real", true).to_string(), event(1, "real", true).to_string(), event(2, "real", false).to_string()],
    );
    let o = koru(&["report", "threat", "--source", &input.to_string_lossy()], home_v.path());
    assert!(o.status.success(), "{}{}", output(&o), error(&o));
    let m = output(&o);
    for expected in [
        "total events: 3",
        "events with detection: 2",
        "events without detection: 1",
        "  real: 3",
        "  file_opened: 3",
        "  decoy_credential_file: 2",
        "  decoy_access: 2",
        "  T1552.001: 2",
        "  unknown: 3",
        "  /home/devops/.aws/credentials: 3",
    ] {
        assert!(m.contains(expected), "{expected:?} is missing:\n{m}");
    }
}

#[test]
fn report_no_output_on_corrupt_line() {
    let t = tempfile::tempdir().unwrap();
    let home_v = tempfile::tempdir().unwrap();
    let input = write_jsonl(t.path(), &[event(0, "real", true).to_string(), "{broken json".to_string()]);
    let o = koru(&["report", "threat", "--source", &input.to_string_lossy()], home_v.path());
    assert_eq!(o.status.code(), Some(1), "{}{}", output(&o), error(&o));
    assert!(output(&o).is_empty(), "stdout must be empty on corrupt input:\n{}", output(&o));
    assert!(error(&o).contains("line 2"), "{}", error(&o));
}

#[test]
fn report_threat_usage_errors() {
    let home_v = tempfile::tempdir().unwrap();
    for args in [vec!["report", "threat"], vec!["report", "threat", "--store", "/x"]] {
        let o = koru(&args, home_v.path());
        assert_eq!(o.status.code(), Some(2), "{args:?}:\n{}{}", output(&o), error(&o));
    }
    let missing_source = koru(&["report", "threat", "--source", "/nonexistent/file.jsonl"], home_v.path());
    assert_eq!(missing_source.status.code(), Some(1), "{}{}", output(&missing_source), error(&missing_source));
    assert!(output(&missing_source).is_empty());
}

#[test]
fn report_threat_empty_file() {
    let t = tempfile::tempdir().unwrap();
    let home_v = tempfile::tempdir().unwrap();
    let input = write_jsonl(t.path(), &[]);
    let o = koru(&["report", "threat", "--source", &input.to_string_lossy()], home_v.path());
    assert!(o.status.success(), "{}{}", output(&o), error(&o));
    let m = output(&o);
    assert!(m.contains("total events: 0"), "{m}");
    assert!(m.contains("time range: (none)"), "{m}");
}

#[test]
fn help_describes_threat_command() {
    let home_v = tempfile::tempdir().unwrap();
    let o = koru(&["help"], home_v.path());
    assert!(output(&o).contains("report threat"), "{}", output(&o));
}
