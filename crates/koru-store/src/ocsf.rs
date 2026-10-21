//! OCSF mapping (ADR-0006 "OCSF mapping"). The target version is OCSF 1.9.0.
//!
//! - With a detection, Detection Finding (2004); otherwise file events are File System Activity
//!   (1001), process events Process Activity (1007), network events Network Activity (4001).
//! - Koru fields with no schema counterpart (actor estimate, tags, container, sensor, untrusted
//!   field paths) are carried under `unmapped.koru`; no other non-standard attribute is written.
//! - Attacker data (path, command line) is carried as values only.

use koru_event::{
    AncestorProcess, Event, EventType, NetworkEndpoint, NetworkProtocol, Process, ThreatClass, UNTRUSTED_FIELDS,
};
use serde_json::{Map, Value, json};

/// The OCSF schema version the mapping is based on.
pub const OCSF_VERSION: &str = "1.9.0";

fn ms(z: koru_event::Timestamp) -> i64 {
    i64::try_from(z.unix_nanos().div_euclid(1_000_000)).unwrap_or(0)
}

fn base_name(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit('/').next() {
        Some(a) if !a.is_empty() => a.to_string(),
        _ => "/".to_string(),
    }
}

fn file_obj(path: &str, type_id: u8) -> Value {
    json!({"name": base_name(path), "path": path, "type_id": type_id})
}

fn process_object(pid: u32, exe: &str, command: &[String]) -> Map<String, Value> {
    let mut p = Map::new();
    p.insert("pid".into(), json!(pid));
    if !exe.is_empty() {
        p.insert("name".into(), json!(base_name(exe)));
        p.insert("file".into(), file_obj(exe, 1));
    }
    if !command.is_empty() {
        p.insert("cmd_line".into(), json!(command.join(" ")));
    }
    p
}

fn ancestor_chain(ancestors: &[AncestorProcess]) -> Option<Value> {
    let (first, remaining) = ancestors.split_first()?;
    let mut p = process_object(first.pid, first.exe.untrusted_value(), first.command_line.untrusted_value());
    if let Some(parent) = ancestor_chain(remaining) {
        p.insert("parent_process".into(), parent);
    }
    Some(Value::Object(p))
}

fn as_process(s: &Process, exe: &str) -> Value {
    let mut p = process_object(s.pid, exe, s.command_line.untrusted_value());
    p.insert("user".into(), json!({"uid": s.user.uid.to_string()}));
    if let Some(z) = s.start_time {
        p.insert("created_time".into(), json!(ms(z)));
    }
    if let Some(parent_proc) = ancestor_chain(&s.lineage) {
        p.insert("parent_process".into(), parent_proc);
    } else if s.ppid > 0 {
        p.insert("parent_process".into(), json!({"pid": s.ppid}));
    }
    Value::Object(p)
}

fn endpoint(u: &NetworkEndpoint) -> Value {
    json!({"ip": u.ip.to_string(), "port": u.port})
}

fn severity(class: ThreatClass) -> u8 {
    match class {
        ThreatClass::DecoyAccess | ThreatClass::SelfProtection => 4,
        ThreatClass::BreadcrumbAccess => 2,
        ThreatClass::SuspectedHijackedAgent => 5,
    }
}

fn class_name(class: ThreatClass) -> &'static str {
    match class {
        ThreatClass::DecoyAccess => "decoy_access",
        ThreatClass::BreadcrumbAccess => "breadcrumb_access",
        ThreatClass::SuspectedHijackedAgent => "suspected_hijacked_agent",
        ThreatClass::SelfProtection => "self_protection",
    }
}

fn connection_info(event: &Event) -> Value {
    let h = &event.target;
    let direction = if event.event_type == EventType::NetworkAccept { 1 } else { 2 };
    let mut b = Map::new();
    b.insert("direction_id".into(), json!(direction));
    if let Some(p) = h.protocol {
        let (name, num) = match p {
            NetworkProtocol::Tcp => ("tcp", 6),
            NetworkProtocol::Udp => ("udp", 17),
        };
        b.insert("protocol_name".into(), json!(name));
        b.insert("protocol_num".into(), json!(num));
        if let Some(u) = h.remote.or(h.local) {
            b.insert("protocol_ver_id".into(), json!(if u.ip.is_ipv4() { 4 } else { 6 }));
        }
    }
    Value::Object(b)
}

fn endpoints(event: &Event) -> (Option<Value>, Option<Value>) {
    let h = &event.target;
    if event.event_type == EventType::NetworkAccept {
        (h.remote.as_ref().map(endpoint), h.local.as_ref().map(endpoint))
    } else {
        (h.local.as_ref().map(endpoint), h.remote.as_ref().map(endpoint))
    }
}

fn koru_fields(event: &Event) -> Value {
    let mut k = Map::new();
    k.insert("schema_version".into(), json!(u32::from(event.schema_version)));
    k.insert("source_tag".into(), serde_json::to_value(event.source_tag).unwrap_or(Value::Null));
    k.insert("timestamp_trusted".into(), json!(event.timestamp_trusted));
    k.insert("event_type".into(), json!(event.event_type.to_string()));
    k.insert(
        "sensor".into(),
        json!({"name": event.sensor.name, "version": event.sensor.version, "platform": event.sensor.platform}),
    );
    k.insert("actor".into(), serde_json::to_value(&event.actor).unwrap_or(Value::Null));
    k.insert("tags".into(), serde_json::to_value(&event.tags).unwrap_or(Value::Null));
    k.insert("container".into(), serde_json::to_value(&event.container).unwrap_or(Value::Null));
    k.insert("flags".into(), serde_json::to_value(&event.target.flags).unwrap_or(Value::Null));
    k.insert("user_group".into(), json!(event.process.user.gid));
    if let Some(s) = event.target.hard_link {
        k.insert("hard_link".into(), json!(s));
    }
    k.insert("decoy_id".into(), json!(event.detection.as_ref().and_then(|t| t.decoy_id.clone())));
    k.insert("untrusted_fields".into(), json!(UNTRUSTED_FIELDS));
    json!({ "koru": Value::Object(k) })
}

fn common_fields(event: &Event, class: u32, category: u32, activity: u32, severity_id: u8) -> Map<String, Value> {
    let mut v = Map::new();
    v.insert("class_uid".into(), json!(class));
    v.insert("category_uid".into(), json!(category));
    v.insert("activity_id".into(), json!(activity));
    v.insert("type_uid".into(), json!(class * 100 + activity));
    v.insert("severity_id".into(), json!(severity_id));
    v.insert("time".into(), json!(ms(event.timestamp)));
    v.insert(
        "metadata".into(),
        json!({
            "version": OCSF_VERSION,
            "product": {"name": "Koru", "vendor_name": "Koru", "version": env!("CARGO_PKG_VERSION")},
            "uid": event.event_id.to_string(),
            "original_time": event.timestamp.text(),
            "labels": [format!("source:{}", source_name(event))],
        }),
    );
    v.insert("device".into(), json!({"type_id": 0, "hostname": event.host}));
    v.insert("unmapped".into(), koru_fields(event));
    v
}

fn source_name(event: &Event) -> &'static str {
    match event.source_tag {
        koru_event::SourceTag::Synthetic => "synthetic",
        koru_event::SourceTag::Legitimate => "legitimate",
        koru_event::SourceTag::Real => "real",
    }
}

fn actor(event: &Event) -> Value {
    json!({
        "process": as_process(&event.process, event.process.exe.untrusted_value()),
        "user": {"uid": event.process.user.uid.to_string()},
    })
}

fn path(event: &Event) -> Option<&str> {
    event.target.path.as_ref().map(|y| y.untrusted_value().as_str())
}

fn new_path(event: &Event) -> Option<&str> {
    event.target.new_path.as_ref().map(|y| y.untrusted_value().as_str())
}

fn finding(event: &Event, t: &koru_event::Detection) -> Value {
    let mut v = common_fields(event, 2004, 2, 1, severity(t.threat_class));
    v.insert("status_id".into(), json!(1));
    v.insert("is_alert".into(), json!(true));
    v.insert("message".into(), json!(format!("Koru detection: {} ({})", t.rule, class_name(t.threat_class))));
    let attacks_list: Vec<Value> = t
        .attack
        .iter()
        .map(|m| match m.as_str().split_once('.') {
            Some((main_id, _)) => json!({"technique": {"uid": main_id}, "sub_technique": {"uid": m.as_str()}}),
            None => json!({"technique": {"uid": m.as_str()}}),
        })
        .collect();
    v.insert(
        "finding_info".into(),
        json!({
            "uid": event.event_id.to_string(),
            "title": t.rule,
            "types": [class_name(t.threat_class)],
            "analytic": {"name": t.rule, "type_id": 1, "type": "Rule"},
            "created_time": ms(event.timestamp),
            "attacks": attacks_list,
        }),
    );
    let mut evidence = Map::new();
    evidence.insert("process".into(), as_process(&event.process, event.process.exe.untrusted_value()));
    if let Some(y) = path(event) {
        evidence.insert("file".into(), file_obj(y, 0));
    }
    let (source, target) = endpoints(event);
    if let Some(k) = source {
        evidence.insert("src_endpoint".into(), k);
    }
    if let Some(h) = target {
        evidence.insert("dst_endpoint".into(), h);
    }
    v.insert("evidences".into(), json!([Value::Object(evidence)]));
    Value::Object(v)
}

fn file_activity(event: &Event) -> Value {
    let (activity, dir) = match event.event_type {
        EventType::FileOpened => (14, false),
        EventType::FileCreated => (1, false),
        EventType::FileDeleted => (4, false),
        EventType::FileRenamed => (5, false),
        EventType::DirectoryCreated => (1, true),
        EventType::DirectoryDeleted => (4, true),
        _ => (99, false),
    };
    let mut v = common_fields(event, 1001, 1, activity, 1);
    let path_text = path(event).unwrap_or("");
    v.insert("file".into(), file_obj(path_text, if dir { 2 } else { 0 }));
    if matches!(event.event_type, EventType::FileRenamed | EventType::FileLink) {
        v.insert("file_result".into(), file_obj(new_path(event).unwrap_or(""), 0));
    }
    if event.event_type == EventType::FileLink {
        v.insert("activity_name".into(), json!("Link"));
    }
    v.insert("actor".into(), actor(event));
    Value::Object(v)
}

fn process_activity(event: &Event) -> Value {
    let executed = event.event_type == EventType::ProcessExecuted;
    let mut v = common_fields(event, 1007, 1, if executed { 1 } else { 2 }, 1);
    if executed {
        v.insert("process".into(), as_process(&event.process, path(event).unwrap_or("")));
        v.insert("launch_type_id".into(), json!(3));
    } else {
        v.insert("process".into(), as_process(&event.process, event.process.exe.untrusted_value()));
        if let Some(k) = event.target.exit_code {
            v.insert("exit_code".into(), json!(k));
        }
    }
    v.insert("actor".into(), actor(event));
    Value::Object(v)
}

fn network_activity(event: &Event) -> Value {
    let mut v = common_fields(event, 4001, 4, 1, 1);
    let (source, target) = endpoints(event);
    if let Some(k) = source {
        v.insert("src_endpoint".into(), k);
    }
    if let Some(h) = target {
        v.insert("dst_endpoint".into(), h);
    }
    v.insert("connection_info".into(), connection_info(event));
    v.insert("actor".into(), actor(event));
    Value::Object(v)
}

/// Maps the event to an OCSF event: with a detection, Detection Finding (2004); otherwise file
/// events are File System Activity (1001), process events Process Activity (1007), network events
/// Network Activity
/// (4001).
pub fn ocsf_event(event: &Event) -> Value {
    if let Some(t) = &event.detection {
        return finding(event, t);
    }
    match event.event_type {
        EventType::ProcessExecuted | EventType::ProcessExited => process_activity(event),
        EventType::NetworkConnection | EventType::NetworkAccept => network_activity(event),
        _ => file_activity(event),
    }
}
