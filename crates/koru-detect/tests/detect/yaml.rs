//! The YAML → JSON data model (ADR-0005): scalar kinds and safety bounds.
//!
//! Rule files come from contributors and are read by the root agent (KT-12, KT-35): anchors
//! and aliases ("billion laughs"), tags, duplicate keys, multiple documents, excessive depth,
//! and excessive size are rejected; none opens a crash or stack-overflow path.

use std::time::Instant;

use koru_detect::yaml_json;
use serde_json::json;

#[test]
fn scalar_kinds_follow_the_yaml_1_2_core_schema() {
    let d = yaml_json(
        "a: 1\nb: 'x'\nc: true\nd: null\ne: ~\nf: yes\ng: 1.5\nh: 0x10\ni: 2026-10-10\nj: -3\nk: False\nl:\nm: \"12\"\nn: 'true'\n",
    )
    .unwrap();
    assert_eq!(
        d,
        json!({
            "a": 1, "b": "x", "c": true, "d": null, "e": null, "f": "yes", "g": "1.5", "h": "0x10",
            "i": "2026-10-10", "j": -3, "k": false, "l": null, "m": "12", "n": "true"
        })
    );
}

#[test]
fn nested_values_and_dotted_keys() {
    let d = yaml_json(
        "detection:\n    choice:\n        koru.decoy_id|exists: true\n        Image|endswith:\n            - '/cat'\n            - '/less'\n    condition: choice\nstring_list:\n    - a: 1\n    - b: [x, y]\n",
    )
    .unwrap();
    assert_eq!(
        d,
        json!({
            "detection": {
                "choice": {"koru.decoy_id|exists": true, "Image|endswith": ["/cat", "/less"]},
                "condition": "choice"
            },
            "string_list": [{"a": 1}, {"b": ["x", "y"]}]
        })
    );
    assert_eq!(yaml_json("- a\n- 2\n").unwrap(), json!(["a", 2]));
}

#[test]
fn multiline_strings_are_preserved() {
    let d = yaml_json("a: |\n    line one\n    line two\nb: >\n    folded\n    text\n").unwrap();
    assert_eq!(d, json!({"a": "line one\nline two\n", "b": "folded text\n"}));
}

#[test]
fn anchors_and_aliases_are_rejected() {
    assert!(yaml_json("a: &x 1\nb: *x\n").is_err());
    assert!(yaml_json("a: &x\n    c: 1\n").is_err(), "an unused anchor is also rejected");
    // "billion laughs": rejected fast, without a crash.
    let mut text = String::from("a0: &a0 [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n");
    for i in 1..10 {
        let previous = format!("*a{}", i - 1);
        text.push_str(&format!("a{i}: &a{i} [{}]\n", vec![previous; 9].join(",")));
    }
    let start = Instant::now();
    assert!(yaml_json(&text).is_err());
    assert!(start.elapsed().as_secs() < 2, "an alias bomb must be rejected fast");
}

#[test]
fn a_tag_is_rejected() {
    assert!(yaml_json("a: !!str 1\n").is_err());
    assert!(yaml_json("a: !custom x\n").is_err());
    assert!(yaml_json("!!map\na: 1\n").is_err());
}

#[test]
fn a_duplicate_key_is_rejected() {
    assert!(yaml_json("a: 1\na: 2\n").is_err());
    assert!(yaml_json("d:\n    s: 1\n    s: 1\n").is_err());
    assert!(yaml_json("a: 1\n'a': 2\n").is_err(), "the same key quoted and unquoted");
}

#[test]
fn a_complex_key_is_rejected() {
    assert!(yaml_json("? [a, b]\n: 1\n").is_err());
    assert!(yaml_json("? {a: 1}\n: 1\n").is_err());
}

#[test]
fn multi_and_empty_documents_are_rejected() {
    assert!(yaml_json("a: 1\n---\nb: 2\n").is_err());
    assert!(yaml_json("").is_err());
    assert!(yaml_json("# only a comment\n").is_err());
    assert_eq!(yaml_json("---\na: 1\n").unwrap(), json!({"a": 1}), "a single document header is accepted");
}

#[test]
fn broken_yaml_is_rejected() {
    assert!(yaml_json("a:\n\tb: 1\n").is_err(), "tab in indentation");
    assert!(yaml_json("a: [1, 2\n").is_err());
    assert!(yaml_json("a: 'unclosed\n").is_err());
}

#[test]
fn excessive_depth_is_rejected_without_a_crash() {
    let flow = format!("a: {}1{}\n", "[".repeat(5000), "]".repeat(5000));
    assert!(yaml_json(&flow).is_err());
    let mut block = String::new();
    for i in 0..200 {
        block.push_str(&" ".repeat(i * 2));
        block.push_str(&format!("k{i}:\n"));
    }
    block.push_str(&" ".repeat(400));
    block.push_str("last: 1\n");
    assert!(yaml_json(&block).is_err());
    // A reasonable depth is accepted.
    assert!(yaml_json("a:\n  b:\n    c:\n      d:\n        e: [[1]]\n").is_ok());
}

#[test]
fn oversize_is_rejected() {
    let text = format!("a: '{}'\n", "x".repeat(2 * 1024 * 1024));
    assert!(yaml_json(&text).is_err());
    let many_nodes = format!("a: [{}]\n", vec!["1"; 300_000].join(","));
    assert!(yaml_json(&many_nodes).is_err());
}
