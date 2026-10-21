//! koru-event schema v1 tests (protected set).
//!
//! What is checked:
//! - Malformed, incomplete events and events with unknown fields are rejected (`deny_unknown_fields`).
//! - `schema_version`, `source_tag`, actor kind, container fields, and the `x-koru-untrusted`
//!   marks exist in both the JSON schema (`schemas/event.v1.json`) and the Rust types, and agree.
//! - Fields an attacker can control are `Untrusted<T>` typed.
//!
//! The JSON schema is checked with a small validator in this file (type, const, enum, minimum,
//! maximum, minLength, properties, required, additionalProperties, items and local $ref).
//! `pattern` is not checked by this validator; pattern rules are tested separately on the Rust side.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use koru_event::{
    ActorKind, Event, EventId, EventType, SCHEMA_VERSION, SourceTag, Timestamp, UNTRUSTED_FIELDS, Untrusted,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn schema() -> Value {
    let path = repo_root().join("schemas/event.v1.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("schemas/event.v1.json must be valid JSON")
}

fn valid_examples() -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/valid");
    let mut examples: Vec<(String, Value)> = fs::read_dir(&dir)
        .expect("could not read tests/data/valid")
        .map(|g| g.unwrap().path())
        .filter(|y| y.extension().is_some_and(|u| u == "json"))
        .map(|y| {
            let name = y.file_name().unwrap().to_string_lossy().into_owned();
            let value = serde_json::from_str(&fs::read_to_string(&y).unwrap()).unwrap();
            (name, value)
        })
        .collect();
    examples.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(examples.len() >= 5, "at least 5 valid examples are expected");
    examples
}

fn base_example() -> Value {
    valid_examples().into_iter().find(|(name, _)| name == "file-opened.json").expect("file-opened.json").1
}

/// The Rust side: serde parsing + `Event::validate` (cross-field rules).
fn rust_parse(text: &str) -> Result<Event, String> {
    let event: Event = serde_json::from_str(text).map_err(|e| format!("serde: {e}"))?;
    event.validate().map_err(|e| format!("validate: {e}"))?;
    Ok(event)
}

fn resolve_ref<'a>(root: &'a Value, node: &'a Value) -> &'a Value {
    match node.get("$ref").and_then(Value::as_str) {
        Some(r) => {
            let name = r.strip_prefix("#/$defs/").unwrap_or_else(|| panic!("local $ref only: {r}"));
            root["$defs"].get(name).unwrap_or_else(|| panic!("undefined $ref: {r}"))
        }
        None => node,
    }
}

fn kind_matches(kind: &str, d: &Value) -> bool {
    match kind {
        "null" => d.is_null(),
        "boolean" => d.is_boolean(),
        "string" => d.is_string(),
        "integer" => d.is_i64() || d.is_u64(),
        "number" => d.is_number(),
        "array" => d.is_array(),
        "object" => d.is_object(),
        other => panic!("unknown kind: {other}"),
    }
}

/// A small JSON schema validator (see the file header).
fn validate_schema(root: &Value, node: &Value, d: &Value, path: &str, errors: &mut Vec<String>) {
    let s = resolve_ref(root, node);
    if let Some(kind) = s.get("type") {
        let kinds: Vec<&str> = match kind {
            Value::String(t) => vec![t.as_str()],
            Value::Array(a) => a.iter().map(|t| t.as_str().unwrap()).collect(),
            _ => panic!("invalid type: {kind}"),
        };
        if !kinds.iter().any(|t| kind_matches(t, d)) {
            errors.push(format!("{path}: expected type {kinds:?}, got {d}"));
            return;
        }
    }
    if let Some(c) = s.get("const")
        && c != d
    {
        errors.push(format!("{path}: expected {c}, got {d}"));
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array)
        && !e.contains(d)
    {
        errors.push(format!("{path}: {d} is not one of the allowed values"));
    }
    if let (Some(min), Some(n)) = (s.get("minimum").and_then(Value::as_f64), d.as_f64())
        && n < min
    {
        errors.push(format!("{path}: {n} < {min}"));
    }
    if let (Some(max), Some(n)) = (s.get("maximum").and_then(Value::as_f64), d.as_f64())
        && n > max
    {
        errors.push(format!("{path}: {n} > {max}"));
    }
    if let (Some(min), Some(m)) = (s.get("minLength").and_then(Value::as_u64), d.as_str())
        && (m.chars().count() as u64) < min
    {
        errors.push(format!("{path}: length < {min}"));
    }
    if let (Some(properties), Some(object)) = (s.get("properties").and_then(Value::as_object), d.as_object()) {
        if let Some(required) = s.get("required").and_then(Value::as_array) {
            for field in required {
                let field = field.as_str().unwrap();
                if !object.contains_key(field) {
                    errors.push(format!("{path}/{field}: required field missing"));
                }
            }
        }
        for (key, child) in object {
            match properties.get(key) {
                Some(sub_schema) => validate_schema(root, sub_schema, child, &format!("{path}/{key}"), errors),
                None => {
                    if s.get("additionalProperties") == Some(&Value::Bool(false)) {
                        errors.push(format!("{path}/{key}: unknown_key field"));
                    }
                }
            }
        }
    }
    if let (Some(item), Some(array)) = (s.get("items"), d.as_array()) {
        for (i, child) in array.iter().enumerate() {
            validate_schema(root, item, child, &format!("{path}/{i}"), errors);
        }
    }
}

fn schema_errors(d: &Value) -> Vec<String> {
    let root = schema();
    let mut errors = Vec::new();
    validate_schema(&root, &root, d, "", &mut errors);
    errors
}

/// The paths of fields marked `x-koru-untrusted: true` in the schema (array items are `*`).
fn untrusted_paths(root: &Value, node: &Value, path: &str, outcome: &mut BTreeSet<String>) {
    let s = resolve_ref(root, node);
    if let Some(properties) = s.get("properties").and_then(Value::as_object) {
        for (name, child) in properties {
            let subpath = format!("{path}/{name}");
            let alt_s = resolve_ref(root, child);
            if child.get("x-koru-untrusted") == Some(&Value::Bool(true))
                || alt_s.get("x-koru-untrusted") == Some(&Value::Bool(true))
            {
                outcome.insert(subpath.clone());
            }
            untrusted_paths(root, child, &subpath, outcome);
        }
    }
    if let Some(item) = s.get("items") {
        untrusted_paths(root, item, &format!("{path}/*"), outcome);
    }
}

/// All object definitions in the schema (root, $defs, nested properties and items).
fn object_schemas<'a>(node: &'a Value, path: String, outcome: &mut Vec<(String, &'a Value)>) {
    if node.get("properties").is_some() {
        outcome.push((path.clone(), node));
    }
    if let Some(properties) = node.get("properties").and_then(Value::as_object) {
        for (name, child) in properties {
            object_schemas(child, format!("{path}/{name}"), outcome);
        }
    }
    if let Some(item) = node.get("items") {
        object_schemas(item, format!("{path}/*"), outcome);
    }
    if let Some(definitions) = node.get("$defs").and_then(Value::as_object) {
        for (name, child) in definitions {
            object_schemas(child, format!("$defs/{name}"), outcome);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The JSON schema file
// ---------------------------------------------------------------------------------------------

#[test]
fn schema_file_is_draft_2020_12_with_an_id() {
    let s = schema();
    assert_eq!(s["$schema"], "https://json-schema.org/draft/2020-12/schema");
    assert!(s["$id"].as_str().is_some_and(|i| i.ends_with("event.v1.json")), "$id must end with event.v1.json");
    assert_eq!(s["type"], "object");
}

#[test]
fn schema_version_field_is_fixed_at_1() {
    assert_eq!(SCHEMA_VERSION, 1);
    let s = schema();
    assert_eq!(s["properties"]["schema_version"]["const"], json!(1));
    assert!(s["required"].as_array().unwrap().contains(&json!("schema_version")));
}

#[test]
fn source_tag_has_three_values_and_is_required() {
    let s = schema();
    assert_eq!(s["properties"]["source_tag"]["enum"], json!(["synthetic", "legitimate", "real"]));
    assert!(s["required"].as_array().unwrap().contains(&json!("source_tag")));
    for (tag, text) in
        [(SourceTag::Synthetic, "synthetic"), (SourceTag::Legitimate, "legitimate"), (SourceTag::Real, "real")]
    {
        assert_eq!(serde_json::to_value(tag).unwrap(), json!(text));
        assert_eq!(serde_json::from_value::<SourceTag>(json!(text)).unwrap(), tag);
    }
}

#[test]
fn actor_kind_has_three_values() {
    let s = schema();
    let actor = resolve_ref(&s, &s["properties"]["actor"]);
    assert_eq!(actor["properties"]["kind"]["enum"], json!(["human", "ai_agent", "unknown"]));
    for k in ["kind", "rationale", "confidence"] {
        assert!(actor["properties"].get(k).is_some(), "actor.{k} is missing from the schema");
    }
    assert_eq!(actor["properties"]["confidence"]["minimum"], json!(0));
    assert_eq!(actor["properties"]["confidence"]["maximum"], json!(1));
    for (kind, text) in [(ActorKind::Human, "human"), (ActorKind::AiAgent, "ai_agent"), (ActorKind::Unknown, "unknown")]
    {
        assert_eq!(serde_json::to_value(kind).unwrap(), json!(text));
    }
}

#[test]
fn container_fields_and_namespaces() {
    let s = schema();
    let container = resolve_ref(&s, &s["properties"]["container"]);
    for k in ["id", "name", "image", "image_digest", "namespaces"] {
        assert!(container["properties"].get(k).is_some(), "container.{k} is missing from the schema");
    }
    let ns = resolve_ref(&s, &container["properties"]["namespaces"]);
    let expected: BTreeSet<&str> = ["uts", "ipc", "mnt", "pid", "net", "time", "cgroup"].into();
    let found: BTreeSet<&str> = ns["properties"].as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(found, expected);
}

#[test]
fn core_fields_and_phase_placeholders_are_in_the_schema() {
    let s = schema();
    let expected: BTreeSet<&str> = [
        "schema_version",
        "event_id",
        "timestamp",
        "timestamp_trusted",
        "source_tag",
        "sensor",
        "host",
        "process",
        "container",
        "event_type",
        "target",
        "actor",
        "detection",
        "tags",
        "session_id",
        "response",
    ]
    .into();
    let found: BTreeSet<&str> = s["properties"].as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(found, expected);
    let process = resolve_ref(&s, &s["properties"]["process"]);
    for k in ["pid", "ppid", "exe", "command_line", "user", "lineage"] {
        assert!(process["properties"].get(k).is_some(), "process.{k} is missing from the schema");
    }
    let detection = resolve_ref(&s, &s["properties"]["detection"]);
    for k in ["rule", "decoy_id", "threat_class", "attack"] {
        assert!(detection["properties"].get(k).is_some(), "detection.{k} is missing from the schema");
    }
    let tags = resolve_ref(&s, &s["properties"]["tags"]);
    for k in ["intent", "mitre_techniques", "verified"] {
        assert!(tags["properties"].get(k).is_some(), "tags.{k} is missing from the schema");
    }
}

#[test]
fn untrusted_marks_match_between_schema_and_rust_list() {
    let s = schema();
    let mut in_schema = BTreeSet::new();
    untrusted_paths(&s, &s, "", &mut in_schema);
    let in_rust: BTreeSet<String> = UNTRUSTED_FIELDS.iter().map(|y| y.to_string()).collect();
    assert_eq!(in_schema, in_rust);
    // At least the file name, command line, and environment variables must be marked.
    for required in
        ["/process/exe", "/process/command_line", "/process/environment", "/target/path", "/target/new_path"]
    {
        assert!(in_schema.contains(required), "{required} is not marked x-koru-untrusted");
    }
}

#[test]
fn all_objects_are_closed_with_required_fields() {
    let s = schema();
    let mut objects = Vec::new();
    object_schemas(&s, String::new(), &mut objects);
    assert!(objects.len() >= 10, "fewer object definitions than expected: {}", objects.len());
    for (path, n) in objects {
        assert_eq!(
            n.get("additionalProperties"),
            Some(&Value::Bool(false)),
            "{path}: additionalProperties must be false"
        );
        let properties: BTreeSet<&str> = n["properties"].as_object().unwrap().keys().map(String::as_str).collect();
        let required: BTreeSet<&str> = n["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{path}: required field missing"))
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        assert_eq!(properties, required, "{path}: all fields must be required (nullable ones take null)");
    }
}

// ---------------------------------------------------------------------------------------------
// Valid examples: schema + Rust + round-trip
// ---------------------------------------------------------------------------------------------

#[test]
fn valid_examples_pass_the_schema_and_the_rust_type() {
    for (name, value) in valid_examples() {
        let errors = schema_errors(&value);
        assert!(errors.is_empty(), "{name}: schema errors: {errors:?}");
        let event = rust_parse(&value.to_string()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let back = serde_json::to_value(&event).unwrap();
        assert_eq!(back, value, "{name}: round-trip must produce the same JSON");
        let back_errors = schema_errors(&back);
        assert!(back_errors.is_empty(), "{name}: Rust output must pass the schema: {back_errors:?}");
    }
}

#[test]
fn example_contents_parse_with_the_expected_types() {
    let examples = valid_examples();
    let find = |name: &str| -> Event {
        let d = &examples.iter().find(|(a, _)| a == name).unwrap().1;
        rust_parse(&d.to_string()).unwrap()
    };
    let o = find("container-decoy-access.json");
    assert_eq!(o.source_tag, SourceTag::Legitimate);
    assert_eq!(o.actor.kind, ActorKind::AiAgent);
    assert_eq!(o.event_type, EventType::FileOpened);
    assert_eq!(
        o.container.id.as_ref().map(|k| k.untrusted_value().as_str()),
        Some("ac723a96d4435aa4f5e400cafd7a9152b565e49c810a74f0b6485e2cef06506f")
    );
    assert_eq!(o.container.namespaces.as_ref().map(|n| n.mnt), Some(4026532418));
    assert!(o.detection.is_some());
    let s = find("process-exited.json");
    assert_eq!(s.source_tag, SourceTag::Real);
    assert!(!s.timestamp_trusted);
    assert_eq!(s.event_type, EventType::ProcessExited);
    assert_eq!(s.target.exit_code, Some(1));
    assert!(s.container.namespaces.is_none());
}

// ---------------------------------------------------------------------------------------------
// Invalid events: malformed, incomplete, unknown fields, out of rule
// ---------------------------------------------------------------------------------------------

type Mutation = fn(&mut Value);

/// (name, change, must the schema validator reject it too). Entries whose second column is `false`
/// are cross-field rules or patterns; only the Rust side (`validate` and the newtypes) catches them.
fn invalid_changes() -> Vec<(&'static str, Mutation, bool)> {
    vec![
        (
            "unknown root field",
            |d| {
                d["extra"] = json!(1);
            },
            true,
        ),
        (
            "unknown process field",
            |d| {
                d["process"]["extra"] = json!("x");
            },
            true,
        ),
        (
            "unknown container field",
            |d| {
                d["container"]["extra"] = json!(null);
            },
            true,
        ),
        (
            "unknown namespace field",
            |d| {
                d["container"]["namespaces"]["user"] = json!(1);
            },
            true,
        ),
        (
            "unknown target field",
            |d| {
                d["target"]["extra"] = json!(false);
            },
            true,
        ),
        (
            "unknown actor field",
            |d| {
                d["actor"]["extra"] = json!(0);
            },
            true,
        ),
        (
            "unknown lineage field",
            |d| {
                d["process"]["lineage"][0]["extra"] = json!(0);
            },
            true,
        ),
        (
            "missing process.pid",
            |d| {
                d["process"].as_object_mut().unwrap().remove("pid");
            },
            true,
        ),
        (
            "missing container.namespaces",
            |d| {
                d["container"].as_object_mut().unwrap().remove("namespaces");
            },
            true,
        ),
        (
            "missing container.id",
            |d| {
                d["container"].as_object_mut().unwrap().remove("id");
            },
            true,
        ),
        (
            "missing target.path",
            |d| {
                d["target"].as_object_mut().unwrap().remove("path");
            },
            true,
        ),
        (
            "missing actor.confidence",
            |d| {
                d["actor"].as_object_mut().unwrap().remove("confidence");
            },
            true,
        ),
        (
            "missing tags.verified",
            |d| {
                d["tags"].as_object_mut().unwrap().remove("verified");
            },
            true,
        ),
        (
            "schema_version 2",
            |d| {
                d["schema_version"] = json!(2);
            },
            true,
        ),
        (
            "schema_version text",
            |d| {
                d["schema_version"] = json!("1");
            },
            true,
        ),
        (
            "source_tag unknown_key",
            |d| {
                d["source_tag"] = json!("test");
            },
            true,
        ),
        (
            "source_tag in uppercase",
            |d| {
                d["source_tag"] = json!("Synthetic");
            },
            true,
        ),
        (
            "source_tag null",
            |d| {
                d["source_tag"] = json!(null);
            },
            true,
        ),
        (
            "actor.kind unknown_key",
            |d| {
                d["actor"]["kind"] = json!("robot");
            },
            true,
        ),
        (
            "actor.confidence greater than 1",
            |d| {
                d["actor"]["confidence"] = json!(1.5);
            },
            true,
        ),
        (
            "actor.confidence negative",
            |d| {
                d["actor"]["confidence"] = json!(-0.1);
            },
            true,
        ),
        (
            "event_type unknown_key",
            |d| {
                d["event_type"] = json!("not_an_event_type");
            },
            true,
        ),
        (
            "negative pid",
            |d| {
                d["process"]["pid"] = json!(-1);
            },
            true,
        ),
        (
            "pid zero",
            |d| {
                d["process"]["pid"] = json!(0);
            },
            true,
        ),
        (
            "timestamp_trusted text",
            |d| {
                d["timestamp_trusted"] = json!("yes");
            },
            true,
        ),
        (
            "command line not an array",
            |d| {
                d["process"]["command_line"] = json!("cat x");
            },
            true,
        ),
        (
            "host empty",
            |d| {
                d["host"] = json!("");
            },
            true,
        ),
        (
            "sensor.name empty",
            |d| {
                d["sensor"]["name"] = json!("");
            },
            true,
        ),
        (
            "unknown flag",
            |d| {
                d["target"]["flags"] = json!(["O_MAGIC"]);
            },
            true,
        ),
        (
            "event_id UUIDv4",
            |d| {
                d["event_id"] = json!("9b2c1d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d");
            },
            false,
        ),
        (
            "event_id broken",
            |d| {
                d["event_id"] = json!("not-an-id");
            },
            false,
        ),
        (
            "timestamp not UTC",
            |d| {
                d["timestamp"] = json!("2026-10-09T18:47:54.540189619+03:00");
            },
            false,
        ),
        (
            "timestamp without fraction",
            |d| {
                d["timestamp"] = json!("2026-10-09T15:47:54Z");
            },
            false,
        ),
        (
            "timestamp broken",
            |d| {
                d["timestamp"] = json!("yesterday");
            },
            false,
        ),
        (
            "ATT&CK technique malformed",
            |d| {
                d["tags"]["mitre_techniques"] = json!(["X1234"]);
            },
            false,
        ),
        (
            "target.path null in a file event",
            |d| {
                d["target"]["path"] = json!(null);
            },
            false,
        ),
        (
            "ai_agent without a rationale",
            |d| {
                d["actor"] = json!({"kind": "ai_agent", "rationale": [], "confidence": 0.9});
            },
            false,
        ),
        (
            "network_connection without a remote endpoint",
            |d| {
                d["event_type"] = json!("network_connection");
            },
            false,
        ),
        (
            "process_exited without an exit code",
            |d| {
                d["event_type"] = json!("process_exited");
                d["target"]["path"] = json!(null);
                d["target"]["flags"] = json!([]);
            },
            false,
        ),
    ]
}

#[test]
fn missing_unknown_and_out_of_rule_fields_are_rejected() {
    let base = base_example();
    assert!(rust_parse(&base.to_string()).is_ok(), "the base example must be valid");
    for (name, mutate, schema_rejects) in invalid_changes() {
        let mut d = base.clone();
        mutate(&mut d);
        assert!(rust_parse(&d.to_string()).is_err(), "the Rust side must reject: {name}");
        if schema_rejects {
            assert!(!schema_errors(&d).is_empty(), "the JSON schema must reject: {name}");
        }
    }
}

#[test]
fn all_root_fields_are_required() {
    let base = base_example();
    for field in base.as_object().unwrap().keys() {
        let mut d = base.clone();
        d.as_object_mut().unwrap().remove(field);
        assert!(rust_parse(&d.to_string()).is_err(), "a missing root field was accepted: {field}");
        assert!(!schema_errors(&d).is_empty(), "the schema accepted a missing root field: {field}");
    }
}

#[test]
fn nullable_fields_cannot_be_omitted_either() {
    // Option fields must be present in JSON (the value may be null).
    let base = base_example();
    for (parent, field) in [
        ("", "detection"),
        ("", "session_id"),
        ("", "response"),
        ("process", "start_time"),
        ("target", "new_path"),
        ("target", "exit_code"),
        ("tags", "intent"),
    ] {
        let mut d = base.clone();
        let target = if parent.is_empty() { &mut d } else { &mut d[parent] };
        target.as_object_mut().unwrap().remove(field);
        assert!(rust_parse(&d.to_string()).is_err(), "missing nullable field was accepted: {parent}.{field}");
    }
}

#[test]
fn malformed_json_is_rejected() {
    let text = base_example().to_string();
    for broken in [&text[..text.len() / 2], "", "null", "[]", "{", "{\"schema_version\": 1}"] {
        assert!(rust_parse(broken).is_err(), "broken input was accepted: {broken:.40}");
    }
}

// ---------------------------------------------------------------------------------------------
// Rust types
// ---------------------------------------------------------------------------------------------

#[test]
fn attacker_controlled_fields_are_untrusted_typed() {
    let event = rust_parse(&base_example().to_string()).unwrap();
    // Compile-time check: the fields must be Untrusted<T> typed.
    let _: &Untrusted<String> = &event.process.exe;
    let _: &Untrusted<Vec<String>> = &event.process.command_line;
    let _: &Untrusted<Vec<String>> = &event.process.environment;
    let _: &Option<Untrusted<String>> = &event.target.path;
    let _: &Option<Untrusted<String>> = &event.target.new_path;
    let _: &Option<Untrusted<String>> = &event.container.id;
    let _: &Option<Untrusted<String>> = &event.container.name;
    let _: &Option<Untrusted<String>> = &event.container.image;
    let _: &Option<Untrusted<String>> = &event.container.image_digest;
    for parent in &event.process.lineage {
        let _: &Untrusted<String> = &parent.exe;
        let _: &Untrusted<Vec<String>> = &parent.command_line;
    }
    assert_eq!(event.process.exe.untrusted_value(), "/usr/bin/cat");
}

#[test]
fn untrusted_serializes_transparently() {
    let g = Untrusted::new("/tmp/a b".to_string());
    assert_eq!(serde_json::to_value(&g).unwrap(), json!("/tmp/a b"));
    let back: Untrusted<String> = serde_json::from_value(json!("/tmp/a b")).unwrap();
    assert_eq!(back, g);
    let v = Untrusted::new(vec!["cat".to_string(), "x".to_string()]);
    assert_eq!(serde_json::to_value(&v).unwrap(), json!(["cat", "x"]));
}

#[test]
fn safe_display_neutralizes_control_and_bidi_characters() {
    let dangerous = "a\u{1b}[31mb\nc\r\u{7}d\u{7f}e\u{9b}f\u{202e}g\u{2066}h\u{0}i";
    let g = Untrusted::new(dangerous.to_string());
    let rendering = g.safe_display();
    for c in rendering.chars() {
        assert!(!c.is_control(), "a control character remains: {c:?}");
        assert!(!matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'), "a bidi character remains: {c:?}");
    }
    // Visible content is preserved in order (escape renderings may intervene).
    let mut pos = 0;
    for piece in ["a", "[31mb", "c", "d", "e", "f", "g", "h", "i"] {
        let found =
            rendering[pos..].find(piece).unwrap_or_else(|| panic!("visible content lost: {piece} / {rendering}"));
        pos += found + piece.len();
    }
    // Harmless text stays as-is (non-ASCII characters included; escapes keep this file ASCII-only).
    let plain = Untrusted::new(
        "/home/koru/\u{00e9}t\u{00e9}/\u{011f}\u{00fc}\u{015f}\u{0131}\u{00f6}\u{00e7} \u{0130} file.txt".to_string(),
    );
    assert_eq!(
        plain.safe_display(),
        "/home/koru/\u{00e9}t\u{00e9}/\u{011f}\u{00fc}\u{015f}\u{0131}\u{00f6}\u{00e7} \u{0130} file.txt"
    );
    // The same rule for command lines.
    let command = Untrusted::new(vec!["cat".to_string(), "a\u{1b}]0;x\u{7}b".to_string()]);
    let command_display = command.safe_display();
    assert!(command_display.contains("cat"));
    assert!(!command_display.chars().any(char::is_control));
    // Debug output does not contain a raw escape sequence either.
    assert!(!format!("{g:?}").contains('\u{1b}'));
}

#[test]
fn event_identity_is_uuidv7() {
    let id = EventId::new();
    let text = serde_json::to_value(id).unwrap().as_str().unwrap().to_string();
    assert_eq!(text.len(), 36);
    assert_eq!(&text[14..15], "7", "version must be 7: {text}");
    assert!(matches!(&text[19..20], "8" | "9" | "a" | "b"), "RFC 9562 variant: {text}");
    assert_ne!(EventId::new(), EventId::new());
    assert!(serde_json::from_value::<EventId>(json!(text)).is_ok());
    assert!(serde_json::from_value::<EventId>(json!("9b2c1d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d")).is_err());
}

#[test]
fn time_is_utc_with_nanosecond_precision() {
    let st = UNIX_EPOCH + Duration::new(1_791_560_874, 540_189_619);
    let z = Timestamp::try_from(st).unwrap();
    assert_eq!(serde_json::to_value(z).unwrap(), json!("2026-10-09T15:47:54.540189619Z"));
    let back: Timestamp = serde_json::from_value(json!("2026-10-09T15:47:54.540189619Z")).unwrap();
    assert_eq!(back, z);
    assert_eq!(SystemTime::from(back), st);
    let whole = Timestamp::try_from(UNIX_EPOCH + Duration::new(1_791_560_874, 0)).unwrap();
    assert_eq!(serde_json::to_value(whole).unwrap(), json!("2026-10-09T15:47:54.000000000Z"));
    for invalid in [
        "2026-10-09T15:47:54.540189619+00:00",
        "2026-10-09T15:47:54.540189619z",
        "2026-10-09T15:47:54.54Z",
        "2026-10-09 15:47:54.540189619Z",
        "2026-13-09T15:47:54.540189619Z",
    ] {
        assert!(serde_json::from_value::<Timestamp>(json!(invalid)).is_err(), "must not be accepted: {invalid}");
    }
}
