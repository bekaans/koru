//! Shared helpers for the koru-store tests (protected set).
//!
//! Tests write only to temporary directories. Events are JSON templates derived from the schema
//! v1 examples (koru-event `tests/data/valid`); each call produces a unique id, timestamp, and
//! pid, so deduplication never kicks in by accident.

#![allow(dead_code)]

use std::path::PathBuf;

use koru_event::{Event, EventId, Timestamp};
use koru_store::{Store, StoreSettings};
use serde_json::{Value, json};

/// 2026-10-09T15:47:54Z, ns.
pub const BASE_TIME_NS: i128 = 1_791_560_874_000_000_000;
pub const DAY_NS: i128 = 86_400 * 1_000_000_000;

pub fn temp() -> tempfile::TempDir {
    let t = tempfile::tempdir().expect("temp dir");
    std::fs::set_permissions(t.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700)).expect("0700");
    t
}

/// The symlink-free (canonical) path of the temp dir; on macOS `/var` is a link.
pub fn canonical(t: &tempfile::TempDir) -> PathBuf {
    std::fs::canonicalize(t.path()).expect("canonical path")
}

pub fn store_path(t: &tempfile::TempDir) -> PathBuf {
    canonical(t).join("event.db")
}

pub fn open_store(t: &tempfile::TempDir) -> Store {
    Store::open(StoreSettings::new(store_path(t))).expect("the store must open")
}

pub fn time_ns(ns: i128) -> Timestamp {
    Timestamp::from_unix_nanos(ns).expect("a valid timestamp")
}

/// The timestamp at second `n`.
pub fn time_n(n: u32) -> Timestamp {
    time_ns(BASE_TIME_NS + i128::from(n) * 1_000_000_000)
}

pub fn new_id() -> String {
    EventId::new().to_string()
}

fn base(id: &str, timestamp: &str, n: u32) -> Value {
    json!({
        "schema_version": 1,
        "event_id": id,
        "timestamp": timestamp,
        "timestamp_trusted": true,
        "source_tag": "synthetic",
        "sensor": {"name": "pulsar", "version": "0.11.0-alpha.1+0bb7bc20", "platform": "linux-aarch64"},
        "host": "lab-server",
        "process": {
            "pid": 1000 + n,
            "ppid": 900,
            "start_time": "2026-10-09T15:47:54.537356193Z",
            "exe": "/usr/bin/cat",
            "command_line": ["cat", "/home/user/.ssh/id_ed25519"],
            "environment": [],
            "user": {"uid": 1000, "gid": 1000},
            "lineage": [
                {"pid": 900, "exe": "/usr/bin/bash", "command_line": ["bash"]},
                {"pid": 1, "exe": "/usr/lib/systemd/systemd", "command_line": ["/sbin/init"]}
            ]
        },
        "container": {
            "id": null, "name": null, "image": null, "image_digest": null,
            "namespaces": {"uts": 4026531838u32, "ipc": 4026531839u32, "mnt": 4026531841u32, "pid": 4026531836u32,
                             "net": 4026531840u32, "time": 4026531834u32, "cgroup": 4026531835u32}
        },
        "event_type": "file_opened",
        "target": {
            "path": "/home/user/.ssh/id_ed25519", "new_path": null, "flags": ["O_RDONLY"],
            "hard_link": null, "protocol": null, "local": null, "remote": null, "exit_code": null
        },
        "actor": {"kind": "unknown", "rationale": [], "confidence": 0.0},
        "detection": null,
        "tags": {"intent": null, "mitre_techniques": [], "verified": false},
        "session_id": null,
        "response": null
    })
}

/// Template names: file_opened, file_created, file_deleted, file_renamed,
/// file_link, directory_created, directory_deleted, process_executed, process_exited,
/// network_connection, network_connection_v6, network_accept, finding (with_detection file_opened), containerized.
pub fn event_json_value(template: &str, n: u32) -> Value {
    let timestamp = time_n(n).text();
    let mut v = base(&new_id(), &timestamp, n);
    match template {
        "file_opened" => {}
        "file_created" | "file_deleted" | "directory_created" | "directory_deleted" => {
            v["event_type"] = json!(template);
            v["target"]["path"] = json!("/var/tmp/sample-dir/file.txt");
            v["target"]["flags"] = json!([]);
        }
        "file_renamed" => {
            v["event_type"] = json!(template);
            v["target"]["path"] = json!("/var/tmp/old.txt");
            v["target"]["new_path"] = json!("/var/tmp/new.txt");
            v["target"]["flags"] = json!([]);
        }
        "file_link" => {
            v["event_type"] = json!(template);
            v["target"]["path"] = json!("/var/tmp/connection");
            v["target"]["new_path"] = json!("/etc/shadow");
            v["target"]["hard_link"] = json!(true);
            v["target"]["flags"] = json!([]);
        }
        "process_executed" => {
            v["event_type"] = json!(template);
            v["process"]["exe"] = json!("/usr/bin/curl");
            v["process"]["command_line"] = json!(["curl", "http://203.0.113.9:8080/upload.sh"]);
            v["target"]["path"] = json!("/usr/bin/curl");
            v["target"]["flags"] = json!([]);
        }
        "process_exited" => {
            v["event_type"] = json!(template);
            v["target"]["path"] = Value::Null;
            v["target"]["flags"] = json!([]);
            v["target"]["exit_code"] = json!(0);
        }
        "network_connection" => {
            v["event_type"] = json!(template);
            v["target"]["path"] = Value::Null;
            v["target"]["flags"] = json!([]);
            v["target"]["protocol"] = json!("tcp");
            v["target"]["local"] = json!({"ip": "10.0.0.5", "port": 51234});
            v["target"]["remote"] = json!({"ip": "203.0.113.77", "port": 443});
        }
        "network_connection_v6" => {
            v["event_type"] = json!("network_connection");
            v["target"]["path"] = Value::Null;
            v["target"]["flags"] = json!([]);
            v["target"]["protocol"] = json!("udp");
            v["target"]["remote"] = json!({"ip": "2001:db8:abcd:12::99", "port": 53});
        }
        "network_accept" => {
            v["event_type"] = json!(template);
            v["target"]["path"] = Value::Null;
            v["target"]["flags"] = json!([]);
            v["target"]["protocol"] = json!("tcp");
            v["target"]["local"] = json!({"ip": "10.0.0.5", "port": 22});
            v["target"]["remote"] = json!({"ip": "198.51.100.7", "port": 40222});
        }
        "finding" => {
            v["detection"] = json!({
                "rule": "koru.decoy.ssh-private-key-read",
                "decoy_id": "decoy-0192a1",
                "threat_class": "suspected_hijacked_agent",
                "attack": ["T1552.004", "T1005"]
            });
            v["tags"]["mitre_techniques"] = json!(["T1552.004", "T1005"]);
            v["actor"] = json!({"kind": "ai_agent", "rationale": ["coding assistant in lineage"], "confidence": 0.85});
        }
        "containerized" => {
            v["container"]["id"] = json!("ac723a96d4435aa4f5e400cafd7a9152b565e49c810a74f0b6485e2cef06506f");
            v["container"]["name"] = json!("silly_cartwright");
            v["container"]["image"] = json!("docker.io/library/alpine:3.22");
            v["container"]["image_digest"] =
                json!("sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8");
        }
        other => panic!("unknown template: {other}"),
    }
    v
}

pub fn event_json(template: &str, n: u32) -> String {
    event_json_value(template, n).to_string()
}

pub fn event(template: &str, n: u32) -> Event {
    let v = event_json_value(template, n);
    let o: Event = serde_json::from_value(v).expect("the template must match the schema");
    o.validate().expect("the template must pass validation");
    o
}

/// `n` distinct valid events (id, timestamp, pid).
pub fn events(n: u32) -> Vec<Event> {
    (0..n).map(|i| event("file_opened", i)).collect()
}

/// One event from each template (export and OCSF tests).
pub const ALL_TEMPLATES: &[&str] = &[
    "file_opened",
    "file_created",
    "file_deleted",
    "file_renamed",
    "file_link",
    "directory_created",
    "directory_deleted",
    "process_executed",
    "process_exited",
    "network_connection",
    "network_connection_v6",
    "network_accept",
    "finding",
    "containerized",
];

/// Replaces the field at the `/a/b/0/c` path of a JSON value.
pub fn set_field(v: &mut Value, path: &str, value: Value) {
    let mut valid = v;
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    for (i, p) in parts.iter().enumerate() {
        let last = i == parts.len() - 1;
        let target = if let Ok(idx) = p.parse::<usize>() { &mut valid[idx] } else { &mut valid[*p] };
        if last {
            *target = value;
            return;
        }
        valid = target;
    }
}

/// Deletes the field at the `/a/b` path (an object key).
pub fn remove_field(v: &mut Value, path: &str) {
    let (parent, name) = path.rsplit_once('/').expect("path");
    let parent_value = if parent.is_empty() { &mut *v } else { v.pointer_mut(parent).expect("the parent field") };
    parent_value.as_object_mut().expect("object").remove(name);
}

pub fn file_mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path).expect("meta").permissions().mode() & 0o7777
}
