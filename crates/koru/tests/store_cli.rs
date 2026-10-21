//! Tests of the `koru event ingest`, `koru report data-quality`, `koru export` and `koru store freeze`
//! commands (protected set).
//!
//! Expected: `koru report data-quality` → "schema compliance 100% · duplicates 0 ·
//! untagged 0 · rejected N". Root and store paths have no defaults (`--store` is required).
//! Tests write only to temporary directories.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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

fn temp() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp directory")
}

fn canonical(t: &tempfile::TempDir) -> PathBuf {
    fs::canonicalize(t.path()).expect("canonical path")
}

const BASE_TIME_NS: i128 = 1_791_560_874_000_000_000;

fn timestamp(ns: i128) -> String {
    koru_event::Timestamp::from_unix_nanos(ns).unwrap().text()
}

/// A valid, unique event (template: the koru-event example); `n` determines id, timestamp and pid.
fn event(n: u32, source: &str) -> Value {
    json!({
        "schema_version": 1,
        "event_id": koru_event::EventId::new().to_string(),
        "timestamp": timestamp(BASE_TIME_NS + i128::from(n) * 1_000_000_000),
        "timestamp_trusted": true,
        "source_tag": source,
        "sensor": {"name": "pulsar", "version": "0.11.0-alpha.1", "platform": "linux-aarch64"},
        "host": "lab-server",
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

fn write_jsonl(dir: &Path, name: &str, lines_v: &[String]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, lines_v.join("\n") + "\n").unwrap();
    path
}

fn store_path(t: &tempfile::TempDir) -> String {
    canonical(t).join("store").join("event.db").to_string_lossy().into_owned()
}

/// Sample input of valid, duplicate and corrupt lines: 3 new, 1 duplicate, 2 rejected, 1 empty line.
fn mixed_input() -> Vec<String> {
    let a = event(1, "synthetic");
    let mut copy = a.clone();
    copy["event_id"] = json!(koru_event::EventId::new().to_string());
    let mut untagged = event(9, "synthetic");
    untagged.as_object_mut().unwrap().remove("source_tag");
    vec![
        event(0, "synthetic").to_string(),
        a.to_string(),
        event(2, "synthetic").to_string(),
        "{broken json".to_string(),
        copy.to_string(),
        String::new(),
        untagged.to_string(),
    ]
}

fn get(store: &str, input: &Path, home_v: &Path) -> Output {
    koru(&["event", "ingest", "--store", store, "--input", &input.to_string_lossy()], home_v)
}

#[test]
fn event_ingest_and_data_quality_report() {
    let t = temp();
    let home_v = temp();
    let store = store_path(&t);
    let input = write_jsonl(&canonical(&t), "input.jsonl", &mixed_input());
    let o = get(&store, &input, home_v.path());
    assert!(o.status.success(), "{}{}", output(&o), error(&o));
    assert!(output(&o).contains("Result: stored 3 · duplicates 1 · rejected 2"), "{}", output(&o));

    let r = koru(&["report", "data-quality", "--store", &store], home_v.path());
    assert!(r.status.success(), "{}{}", output(&r), error(&r));
    let text = output(&r);
    assert_eq!(
        text.lines().next().unwrap(),
        "schema compliance 100% · duplicates 0 · untagged 0 · rejected 2",
        "{text}"
    );
    assert!(text.lines().any(|l| l == "records: 3 (schema-compliant 3)"), "{text}");
    assert!(text.lines().any(|l| l == "deduplicated on ingest: 1"), "{text}");
    assert!(text.lines().any(|l| l == "  json_format: 1"), "{text}");
    assert!(text.lines().any(|l| l == "  untagged: 1"), "{text}");
}

#[test]
fn event_ingest_reads_stdin() {
    let t = temp();
    let home_v = temp();
    let store = store_path(&t);
    let mut child = Command::new(env!("CARGO_BIN_EXE_koru"))
        .args(["event", "ingest", "--store", &store])
        .env("HOME", home_v.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all((event(0, "legitimate").to_string() + "\n").as_bytes()).unwrap();
    let o = child.wait_with_output().unwrap();
    assert!(o.status.success(), "{}{}", output(&o), error(&o));
    assert!(output(&o).contains("stored 1 · duplicates 0 · rejected 0"), "{}", output(&o));
}

#[test]
fn store_dir_0700_file_0600() {
    let t = temp();
    let home_v = temp();
    let store = store_path(&t);
    let input = write_jsonl(&canonical(&t), "input.jsonl", &[event(0, "synthetic").to_string()]);
    assert!(get(&store, &input, home_v.path()).status.success());
    let mod_ = |y: &Path| fs::metadata(y).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mod_(Path::new(&store)), 0o600);
    assert_eq!(mod_(Path::new(&store).parent().unwrap()), 0o700);
}

#[test]
fn report_does_not_create_a_missing_store() {
    let t = temp();
    let home_v = temp();
    let store = store_path(&t);
    let r = koru(&["report", "data-quality", "--store", &store], home_v.path());
    assert_eq!(r.status.code(), Some(1), "{}{}", output(&r), error(&r));
    assert!(!error(&r).is_empty());
    assert!(
        !Path::new(&store).exists() && !Path::new(&store).parent().unwrap().exists(),
        "the report must not create the store"
    );
}

#[test]
fn relative_store_path_rejected() {
    let home_v = temp();
    let r = koru(&["report", "data-quality", "--store", "event.db"], home_v.path());
    assert_eq!(r.status.code(), Some(1), "{}{}", output(&r), error(&r));
}

#[test]
fn usage_errors_exit_2() {
    let home_v = temp();
    for args in [
        vec!["report", "data-quality"],
        vec!["report"],
        vec!["report", "unknown_key", "--store", "/x"],
        vec!["event", "ingest"],
        vec!["event"],
        vec!["export", "--store", "/x"],
        vec!["export", "--store", "/x", "--format", "csv"],
        vec!["export", "--store", "/x", "--format", "jsonl", "--source", "unknown"],
        vec!["export", "--store", "/x", "--format", "jsonl", "--unknown_key", "1"],
        vec!["store"],
        vec!["store", "freeze"],
        vec!["store", "freeze", "--store", "/x", "--retention-days", "zero"],
        vec!["store", "freeze", "--store", "/x", "--retention-days", "0"],
    ] {
        let o = koru(&args, home_v.path());
        assert_eq!(o.status.code(), Some(2), "{args:?}:\n{}{}", output(&o), error(&o));
    }
}

fn filled_store(t: &tempfile::TempDir, home_v: &Path, references: &[&str]) -> String {
    let store = store_path(t);
    let lines_v: Vec<String> = references.iter().enumerate().map(|(i, k)| event(i as u32, k).to_string()).collect();
    let input = write_jsonl(&canonical(t), "input.jsonl", &lines_v);
    let o = get(&store, &input, home_v);
    assert!(o.status.success(), "{}{}", output(&o), error(&o));
    store
}

#[test]
fn export_writes_jsonl_and_ocsf() {
    let t = temp();
    let home_v = temp();
    let store = filled_store(&t, home_v.path(), &["synthetic", "synthetic", "synthetic"]);
    let j = koru(&["export", "--store", &store, "--format", "jsonl"], home_v.path());
    assert!(j.status.success(), "{}", error(&j));
    let lines_v: Vec<Value> = output(&j).lines().map(|l| serde_json::from_str(l).expect("JSONL line")).collect();
    assert_eq!(lines_v.len(), 3);
    assert!(lines_v.iter().all(|v| v["schema_version"] == 1 && v["source_tag"] == "synthetic"));
    assert!(error(&j).contains("exported: 3"), "{}", error(&j));

    let c = koru(&["export", "--store", &store, "--format", "ocsf"], home_v.path());
    assert!(c.status.success(), "{}", error(&c));
    let ocsf: Vec<Value> = output(&c).lines().map(|l| serde_json::from_str(l).expect("OCSF line")).collect();
    assert_eq!(ocsf.len(), 3);
    assert!(ocsf.iter().all(|v| v["class_uid"] == 4001 && v["metadata"]["version"] == "1.9.0"));
}

#[test]
fn export_masks_ips() {
    let t = temp();
    let home_v = temp();
    let store = filled_store(&t, home_v.path(), &["synthetic", "synthetic"]);
    let public_v = koru(&["export", "--store", &store, "--format", "jsonl"], home_v.path());
    assert!(output(&public_v).contains("203.0.113.77") && output(&public_v).contains("203.0.113.9"));
    for format in ["jsonl", "ocsf"] {
        let m = koru(&["export", "--store", &store, "--format", format, "--mask"], home_v.path());
        assert!(m.status.success(), "{}", error(&m));
        let c = output(&m);
        assert!(!c.contains("203.0.113.77") && !c.contains("203.0.113.9"), "{format}: IP must be masked:\n{c}");
        assert!(c.contains("203.0.113.0"), "{format}");
    }
}

#[test]
fn export_rejects_mixed_sources_and_exports_with_a_filter() {
    let t = temp();
    let home_v = temp();
    let store = filled_store(&t, home_v.path(), &["synthetic", "legitimate", "legitimate"]);
    for format in ["jsonl", "ocsf"] {
        let o = koru(&["export", "--store", &store, "--format", format], home_v.path());
        assert_eq!(o.status.code(), Some(1), "{format}");
        assert!(output(&o).is_empty(), "nothing must be written in a mixed export");
        assert!(error(&o).contains("mixed"), "{}", error(&o));
    }
    let m = koru(&["export", "--store", &store, "--format", "jsonl", "--source", "legitimate"], home_v.path());
    assert!(m.status.success(), "{}", error(&m));
    assert_eq!(output(&m).lines().count(), 2);
    let s = koru(&["export", "--store", &store, "--format", "jsonl", "--source", "synthetic"], home_v.path());
    assert_eq!(output(&s).lines().count(), 1);
}

#[test]
fn export_output_file_0600_and_never_overwrites() {
    let t = temp();
    let home_v = temp();
    let store = filled_store(&t, home_v.path(), &["synthetic"]);
    let target = canonical(&t).join("output.jsonl");
    let target_text = target.to_string_lossy().into_owned();
    let o = koru(&["export", "--store", &store, "--format", "jsonl", "--output", &target_text], home_v.path());
    assert!(o.status.success(), "{}", error(&o));
    assert!(output(&o).is_empty(), "stdout is empty when writing to a file");
    assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o7777, 0o600);
    assert_eq!(fs::read_to_string(&target).unwrap().lines().count(), 1);
    // An existing file is not overwritten.
    fs::write(&target, "IMPORTANT").unwrap();
    let again = koru(&["export", "--store", &store, "--format", "jsonl", "--output", &target_text], home_v.path());
    assert_eq!(again.status.code(), Some(1));
    assert_eq!(fs::read_to_string(&target).unwrap(), "IMPORTANT");
    // Symlinks are not followed.
    let connection = canonical(&t).join("connection.jsonl");
    std::os::unix::fs::symlink(canonical(&t).join("other-file"), &connection).unwrap();
    let b = koru(
        &["export", "--store", &store, "--format", "jsonl", "--output", &connection.to_string_lossy()],
        home_v.path(),
    );
    assert_eq!(b.status.code(), Some(1));
    assert!(!canonical(&t).join("other-file").exists());
}

#[test]
fn store_rotate_deletes_expired() {
    let t = temp();
    let home_v = temp();
    let store = store_path(&t);
    let mut too_old = event(0, "synthetic");
    too_old["event_id"] = json!(koru_event::EventId::new().to_string());
    too_old["timestamp"] = json!("2020-01-01T00:00:00.000000000Z");
    let now = koru_event::Timestamp::now();
    let mut new = event(1, "synthetic");
    new["timestamp"] = json!(now.text());
    let input = write_jsonl(&canonical(&t), "input.jsonl", &[too_old.to_string(), new.to_string()]);
    assert!(get(&store, &input, home_v.path()).status.success());
    let d = koru(&["store", "freeze", "--store", &store], home_v.path());
    assert!(d.status.success(), "{}{}", output(&d), error(&d));
    assert!(output(&d).contains("Rotation completed: expired 1 · over limit 0 · remaining 1"), "{}", output(&d));
    // Retention is configurable: 1 day; the new event (now) stays.
    let d2 = koru(&["store", "freeze", "--store", &store, "--retention-days", "1"], home_v.path());
    assert!(output(&d2).contains("remaining 1"), "{}", output(&d2));
    let r = koru(&["report", "data-quality", "--store", &store], home_v.path());
    assert!(output(&r).contains("records: 1 (schema-compliant 1)"), "{}", output(&r));
}

#[test]
fn help_describes_new_commands() {
    let home_v = temp();
    let o = koru(&["help"], home_v.path());
    let m = output(&o);
    for piece in ["event ingest", "report data-quality", "export", "store freeze", "--mask", "--store"] {
        assert!(m.contains(piece), "the help has no {piece:?}:\n{m}");
    }
}
