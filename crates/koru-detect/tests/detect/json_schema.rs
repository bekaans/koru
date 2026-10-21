//! A small JSON Schema validator: to apply `schemas/rule-pack.v1.json` and
//! `schemas/agent-signature.v1.json` independently of the Rust types.
//!
//! Supported: `type` (a single type or a list of types), `const`, `enum`, `minimum`, `maximum`, `minLength`,
//! `maxLength`, `minItems`, `maxItems`, `minProperties`, `properties`, `required`,
//! and `additionalProperties` (boolean or schema), `items`, `contains`, `oneOf`, and
//! local `$ref`. `pattern` and `propertyNames` patterns are not applied here (no regex engine
//! in tests); those rules live on the Rust side and are tested separately.

use std::fs;

use serde_json::Value;

use crate::common::repo_root;

pub fn schema(name: &str) -> Value {
    let path = repo_root().join("schemas").join(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{} could not be read: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name} is not valid JSON: {e}"))
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
        "string" => d.is_string(),
        "integer" => d.is_i64() || d.is_u64(),
        "number" => d.is_number(),
        "boolean" => d.is_boolean(),
        "object" => d.is_object(),
        "array" => d.is_array(),
        "null" => d.is_null(),
        other => panic!("unsupported kind: {other}"),
    }
}

pub fn validate(root: &Value, schema: &Value, d: &Value, path: &str) -> Result<(), String> {
    let schema = resolve_ref(root, schema);
    if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
        let matched = branches.iter().filter(|branch| validate(root, branch, d, path).is_ok()).count();
        if matched != 1 {
            return Err(format!("{path}: {matched} oneOf branches matched (1 expected)"));
        }
    }
    match schema.get("type") {
        Some(Value::String(t)) if !kind_matches(t, d) => return Err(format!("{path}: not of kind {t}")),
        Some(Value::Array(kinds)) if !kinds.iter().any(|t| kind_matches(t.as_str().unwrap(), d)) => {
            return Err(format!("{path}: not of kind {kinds:?}"));
        }
        _ => {}
    }
    if let Some(c) = schema.get("const")
        && c != d
    {
        return Err(format!("{path}: must be {c}"));
    }
    if let Some(e) = schema.get("enum").and_then(Value::as_array)
        && !e.contains(d)
    {
        return Err(format!("{path}: not one of the allowed values: {d}"));
    }
    if let Some(n) = d.as_f64() {
        if let Some(min) = schema.get("minimum").and_then(Value::as_f64)
            && n < min
        {
            return Err(format!("{path}: {n} < {min}"));
        }
        if let Some(max) = schema.get("maximum").and_then(Value::as_f64)
            && n > max
        {
            return Err(format!("{path}: {n} > {max}"));
        }
    }
    if let Some(s) = d.as_str() {
        let length = s.chars().count() as u64;
        if let Some(min) = schema.get("minLength").and_then(Value::as_u64)
            && length < min
        {
            return Err(format!("{path}: length {length} < {min}"));
        }
        if let Some(max) = schema.get("maxLength").and_then(Value::as_u64)
            && length > max
        {
            return Err(format!("{path}: length {length} > {max}"));
        }
    }
    if let Some(array) = d.as_array() {
        if let Some(min) = schema.get("minItems").and_then(Value::as_u64)
            && (array.len() as u64) < min
        {
            return Err(format!("{path}: item count < {min}"));
        }
        if let Some(max) = schema.get("maxItems").and_then(Value::as_u64)
            && (array.len() as u64) > max
        {
            return Err(format!("{path}: item count > {max}"));
        }
        if let Some(item) = schema.get("items") {
            for (i, o) in array.iter().enumerate() {
                validate(root, item, o, &format!("{path}[{i}]"))?;
            }
        }
        if let Some(contains_clause) = schema.get("contains")
            && !array.iter().any(|o| validate(root, contains_clause, o, path).is_ok())
        {
            return Err(format!("{path}: no item satisfies contains"));
        }
    }
    if let Some(object) = d.as_object() {
        if let Some(min) = schema.get("minProperties").and_then(Value::as_u64)
            && (object.len() as u64) < min
        {
            return Err(format!("{path}: field count < {min}"));
        }
        if let Some(required_fields) = schema.get("required").and_then(Value::as_array) {
            for field in required_fields {
                let field = field.as_str().expect("required consists of strings");
                if !object.contains_key(field) {
                    return Err(format!("{path}: required_fields field missing: {field}"));
                }
            }
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        for (key, value) in object {
            let subpath = format!("{path}.{key}");
            match properties.and_then(|o| o.get(key)) {
                Some(child) => validate(root, child, value, &subpath)?,
                None => match schema.get("additionalProperties") {
                    Some(Value::Bool(false)) => return Err(format!("{path}: unknown_key field: {key}")),
                    Some(child @ Value::Object(_)) => validate(root, child, value, &subpath)?,
                    _ => {}
                },
            }
        }
    }
    Ok(())
}

/// Validates the document against the given schema.
pub fn with_schema(name: &str, d: &Value) -> Result<(), String> {
    let root = schema(name);
    validate(&root, &root, d, "$")
}

#[test]
fn schemas_are_valid_json_with_expected_top_level() {
    for name in ["rule-pack.v1.json", "agent-signature.v1.json"] {
        let s = schema(name);
        assert_eq!(s["$schema"], "https://json-schema.org/draft/2020-12/schema", "{name}");
        assert_eq!(s["$id"], format!("https://korusecurity.com/schemas/{name}"), "{name}");
        assert_eq!(s["type"], "object", "{name}");
        assert_eq!(s["additionalProperties"], false, "{name}: an unknown field must be rejected");
        assert!(s["required"].as_array().is_some_and(|r| !r.is_empty()), "{name}");
        assert!(s["description"].as_str().is_some_and(|d| d.len() > 100), "{name}: a description");
    }
    let k = schema("rule-pack.v1.json");
    let required_fields: Vec<&str> = k["required"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    for field in ["title", "id", "name", "logsource", "detection", "level", "tags", "koru"] {
        assert!(required_fields.contains(&field), "{field} must be required in the rule schema");
    }
    assert_eq!(
        k["properties"]["koru"]["properties"]["threat_class"]["enum"],
        serde_json::json!(["decoy_access", "breadcrumb_access", "suspected_hijacked_agent", "self_protection"])
    );
    let a = schema("agent-signature.v1.json");
    assert_eq!(
        a["properties"]["kind"]["enum"],
        serde_json::json!(["coding_assistant", "mcp_server", "agent_framework"])
    );
}
