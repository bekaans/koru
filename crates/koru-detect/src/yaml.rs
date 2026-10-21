//! The YAML → JSON data model (ADR-0005). Runs on yaml-rust2's event parser with bounds
//! against an attacker-crafted rule file.
//!
//! Events are pulled one by one; parsing stops the moment a bound is exceeded (a rule file
//! has hundreds of nodes, the bounds sit far above that). The tree is built with an explicit
//! stack and no recursion; thanks to the depth bound, dropping the `serde_json::Value` cannot
//! overflow the stack either.

use serde_json::{Map, Value};
use yaml_rust2::parser::{Event, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};

use crate::RuleError;

/// The largest input (bytes).
pub(crate) const MAX_ENTRIES: usize = 1024 * 1024;
/// The deepest nesting (array and map count).
const MAX_DEPTH: usize = 32;
/// The most nodes (scalars, array and map starts).
const MAX_NODES: usize = 10_000;

/// An array or map still open while the tree is built.
enum YamlContainer {
    Array(Vec<Value>),
    Object { map: Map<String, Value>, key: Option<String> },
}

fn error<T>(marker: Option<&Marker>, message: &str) -> Result<T, RuleError> {
    Err(RuleError::Yaml(match marker {
        Some(i) => format!("{message} (line {}, column {})", i.line(), i.col()),
        None => message.to_string(),
    }))
}

/// Converts a YAML document to the JSON data model.
///
/// Rules:
/// - A single document; an empty or multi-document input is rejected.
/// - Anchors and aliases ("billion laughs"), tags (`!!str`, `!custom`), duplicate keys, and
///   non-string (complex) keys are rejected.
/// - Nesting depth, node count, and input size are bounded; no stack overflow.
/// - Quoted scalars are always strings. For unquoted scalars, the YAML 1.2 core schema:
///   `true`/`false` are booleans, `null`/`~`/empty is `null`, a decimal integer is a number;
///   everything else (e.g. `yes`, `1.5`, `0x10`, `2026-10-10`) is a string.
pub fn yaml_json(text: &str) -> Result<Value, RuleError> {
    if text.len() > MAX_ENTRIES {
        return error(None, &format!("input too large (at most {MAX_ENTRIES} bytes)"));
    }
    let mut parser = Parser::new_from_str(text);
    let mut stack: Vec<YamlContainer> = Vec::new();
    let mut root: Option<Value> = None;
    let mut document_started = false;
    let mut node_count = 0usize;

    loop {
        let (event, marker) = parser.next_token().map_err(|e| {
            let m = e.marker();
            RuleError::Yaml(format!("could not be parsed: {} (line {}, column {})", e.info(), m.line(), m.col()))
        })?;
        let i = Some(&marker);
        match event {
            Event::Nothing | Event::StreamStart | Event::DocumentEnd => {}
            Event::StreamEnd => break,
            Event::DocumentStart => {
                if document_started {
                    return error(i, "multiple YAML documents cannot be ignored (exactly one document expected)");
                }
                document_started = true;
            }
            Event::Alias(_) => return error(i, "an alias cannot be used"),
            Event::Scalar(value, style, anchor, tag) => {
                if anchor != 0 {
                    return error(i, "an anchor cannot be used");
                }
                if tag.is_some() {
                    return error(i, "a tag cannot be used");
                }
                count_nodes(&mut node_count, i)?;
                if let Some(YamlContainer::Object { map, key: key @ None }) = stack.last_mut() {
                    // In a map, the next scalar is a key; a string whatever its key style.
                    if map.contains_key(&value) {
                        return error(i, &format!("duplicates key: {}", sanitize(&value)));
                    }
                    *key = Some(value);
                } else {
                    append(&mut stack, &mut root, scalar(value, style), i)?;
                }
            }
            Event::SequenceStart(anchor, tag) => {
                open(&mut stack, YamlContainer::Array(Vec::new()), anchor, tag.is_some(), &mut node_count, i)?;
            }
            Event::MappingStart(anchor, tag) => {
                let object = YamlContainer::Object { map: Map::new(), key: None };
                open(&mut stack, object, anchor, tag.is_some(), &mut node_count, i)?;
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let value = match stack.pop() {
                    Some(YamlContainer::Array(d)) => Value::Array(d),
                    Some(YamlContainer::Object { map, key: None }) => Value::Object(map),
                    // A key without a value: the parser gives an empty scalar; unreachable.
                    Some(YamlContainer::Object { .. }) | None => {
                        return error(i, "the parser produced an inconsistent event");
                    }
                };
                append(&mut stack, &mut root, value, i)?;
            }
        }
    }
    match root {
        None | Some(Value::Null) => error(None, "the document is empty"),
        Some(k) => Ok(k),
    }
}

/// An array or map start: anchor, tag, complex-key, node, and depth checks.
fn open(
    stack: &mut Vec<YamlContainer>,
    container: YamlContainer,
    anchor: usize,
    tagged: bool,
    node_count: &mut usize,
    marker: Option<&Marker>,
) -> Result<(), RuleError> {
    if anchor != 0 {
        return error(marker, "an anchor cannot be used");
    }
    if tagged {
        return error(marker, "a tag cannot be used");
    }
    count_nodes(node_count, marker)?;
    if matches!(stack.last(), Some(YamlContainer::Object { key: None, .. })) {
        return error(marker, "a key must be a string (complex keys cannot be used)");
    }
    if stack.len() >= MAX_DEPTH {
        return error(marker, &format!("the nesting depth bound was exceeded (at most {MAX_DEPTH})"));
    }
    stack.push(container);
    Ok(())
}

fn count_nodes(counter: &mut usize, marker: Option<&Marker>) -> Result<(), RuleError> {
    *counter += 1;
    if *counter > MAX_NODES {
        return error(marker, &format!("the node count bound was exceeded (at most {MAX_NODES})"));
    }
    Ok(())
}

/// Adds a completed value to the open array or map (or as the root).
fn append(
    stack: &mut [YamlContainer],
    root: &mut Option<Value>,
    value: Value,
    marker: Option<&Marker>,
) -> Result<(), RuleError> {
    match stack.last_mut() {
        Some(YamlContainer::Array(d)) => d.push(value),
        Some(YamlContainer::Object { map, key }) => match key.take() {
            Some(a) => {
                map.insert(a, value);
            }
            None => return error(marker, "a value without a key"),
        },
        None => {
            if root.is_some() {
                return error(marker, "the document has more than one root value");
            }
            *root = Some(value);
        }
    }
    Ok(())
}

/// Converts a scalar to a JSON value (this project's subset of the YAML 1.2 core schema).
fn scalar(value: String, style: TScalarStyle) -> Value {
    if style != TScalarStyle::Plain {
        return Value::String(value);
    }
    match value.as_str() {
        "" | "~" | "null" | "Null" | "NULL" => Value::Null,
        "true" | "True" | "TRUE" => Value::Bool(true),
        "false" | "False" | "FALSE" => Value::Bool(false),
        s => match decimal_integer(s) {
            Some(n) => Value::from(n),
            None => Value::String(value),
        },
    }
}

/// `[-+]?[0-9]+`; `None` if it does not fit i64 (stays a string).
fn decimal_integer(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['-', '+']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.strip_prefix('+').unwrap_or(s).parse().ok()
}

/// Shortens untrusted text entering an error message and neutralizes control characters.
fn sanitize(text: &str) -> String {
    let short: String = text.chars().take(40).collect();
    koru_event::Untrusted::new(short).safe_display()
}
