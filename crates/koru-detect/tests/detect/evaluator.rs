//! The evaluator: Sigma v2.1.0 meaning (selections, value lists, modifiers, wildcards,
//! escaping, condition). Fields are given directly; enrichment is covered by the `scenarios`
//! tests.

use std::time::Instant;

use koru_detect::{FieldSet, Rule, parse_rule};

/// A valid rule with the given `detection` body (4-space-indented lines).
fn rule(detection: &str) -> Rule {
    let text = format!(
        "title: 'Evaluator test'
id: 0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d
name: evaluator_test
status: test
description: 'Evaluator test.'
date: 2026-10-10
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    product: linux
    category: process_creation
detection:
{detection}level: low
koru:
    threat_class: decoy_access
"
    );
    parse_rule(&text).unwrap_or_else(|e| panic!("the test rule is invalid: {e}\n{text}"))
}

fn cat() -> FieldSet {
    FieldSet::new()
        .text("Image", "/usr/bin/cat")
        .text("CommandLine", "cat /home/devops/.aws/credentials")
        .number("ProcessId", 4242)
        .boolean("koru.modified", false)
}

#[test]
fn field_set_values() {
    let a = cat();
    assert_eq!(a.get("Image"), Some(&koru_detect::FieldValue::Text("/usr/bin/cat".to_string())));
    assert_eq!(a.get("ProcessId"), Some(&koru_detect::FieldValue::Number(4242)));
    assert_eq!(a.get("koru.modified"), Some(&koru_detect::FieldValue::Bool(false)));
    assert_eq!(a.get("ParentImage"), None);
}

#[test]
fn default_matching_is_case_insensitive() {
    let k = rule("    s:\n        Image: '/USR/BIN/CAT'\n    condition: s\n");
    assert!(k.matches_pattern(&cat()));
    let k = rule("    s:\n        Image: '/usr/bin/cat'\n    condition: s\n");
    assert!(k.matches_pattern(&FieldSet::new().text("Image", "/USR/bin/Cat")));
    assert!(!k.matches_pattern(&FieldSet::new().text("Image", "/usr/bin/cats")), "an exact match, not a prefix");
}

#[test]
fn cased_is_case_sensitive() {
    let k = rule("    s:\n        Image|cased: '/USR/BIN/CAT'\n    condition: s\n");
    assert!(!k.matches_pattern(&cat()));
    assert!(k.matches_pattern(&FieldSet::new().text("Image", "/USR/BIN/CAT")));
    let k = rule("    s:\n        Image|endswith|cased: '/Cat'\n    condition: s\n");
    assert!(!k.matches_pattern(&cat()));
}

#[test]
fn wildcards() {
    assert!(rule("    s:\n        Image: '/usr/bin/c?t'\n    condition: s\n").matches_pattern(&cat()));
    assert!(rule("    s:\n        Image: '/usr/*/cat'\n    condition: s\n").matches_pattern(&cat()));
    assert!(rule("    s:\n        Image: '*'\n    condition: s\n").matches_pattern(&cat()));
    assert!(!rule("    s:\n        Image: '/usr/bin/c?'\n    condition: s\n").matches_pattern(&cat()));
    assert!(!rule("    s:\n        Image: '/usr/*/dog'\n    condition: s\n").matches_pattern(&cat()));
}

#[test]
fn escaping() {
    let star = FieldSet::new().text("CommandLine", "echo *");
    let x = FieldSet::new().text("CommandLine", "echo x");
    let k = rule("    s:\n        CommandLine: 'echo \\*'\n    condition: s\n");
    assert!(k.matches_pattern(&star));
    assert!(!k.matches_pattern(&x), "an escaped * is not a wildcard");
    // A backslash before a non-wildcard character stays as is; \\ is one backslash.
    let path = FieldSet::new().text("CommandLine", "C:\\Windows\\x");
    assert!(rule("    s:\n        CommandLine: 'C:\\Windows\\x'\n    condition: s\n").matches_pattern(&path));
    assert!(rule("    s:\n        CommandLine: 'C:\\\\Windows\\\\x'\n    condition: s\n").matches_pattern(&path));
    // \\* : a backslash followed by a wildcard.
    let k = rule("    s:\n        CommandLine: 'a\\\\*'\n    condition: s\n");
    assert!(k.matches_pattern(&FieldSet::new().text("CommandLine", "a\\bcd")));
    assert!(!k.matches_pattern(&FieldSet::new().text("CommandLine", "abcd")));
}

#[test]
fn modifiers_contains_startswith_endswith() {
    assert!(rule("    s:\n        CommandLine|contains: '.aws/'\n    condition: s\n").matches_pattern(&cat()));
    assert!(rule("    s:\n        CommandLine|startswith: 'CAT '\n    condition: s\n").matches_pattern(&cat()));
    assert!(rule("    s:\n        Image|endswith: '/cat'\n    condition: s\n").matches_pattern(&cat()));
    assert!(!rule("    s:\n        Image|startswith: '/cat'\n    condition: s\n").matches_pattern(&cat()));
    assert!(!rule("    s:\n        Image|endswith: '/usr'\n    condition: s\n").matches_pattern(&cat()));
    // A value's own wildcards also work with a modifier.
    assert!(rule("    s:\n        CommandLine|contains: '.aws/c*s'\n    condition: s\n").matches_pattern(&cat()));
}

#[test]
fn value_lists_or_and_all_and() {
    let k = rule("    s:\n        Image|endswith:\n            - '/less'\n            - '/cat'\n    condition: s\n");
    assert!(k.matches_pattern(&cat()));
    let k = rule(
        "    s:\n        CommandLine|contains|all:\n            - 'cat'\n            - '.aws'\n    condition: s\n",
    );
    assert!(k.matches_pattern(&cat()));
    let k = rule(
        "    s:\n        CommandLine|contains|all:\n            - 'cat'\n            - '.ssh'\n    condition: s\n",
    );
    assert!(!k.matches_pattern(&cat()));
}

#[test]
fn selection_fields_and_selection_list_or() {
    let k = rule("    s:\n        Image|endswith: '/cat'\n        CommandLine|contains: '.ssh'\n    condition: s\n");
    assert!(!k.matches_pattern(&cat()), "map fields combine with and");
    let k =
        rule("    s:\n        - Image|endswith: '/less'\n        - CommandLine|contains: '.aws'\n    condition: s\n");
    assert!(k.matches_pattern(&cat()), "a selection list combines with or");
}

#[test]
fn exists_null_and_empty_value() {
    assert!(rule("    s:\n        Image|exists: true\n    condition: s\n").matches_pattern(&cat()));
    assert!(!rule("    s:\n        ParentImage|exists: true\n    condition: s\n").matches_pattern(&cat()));
    assert!(rule("    s:\n        ParentImage|exists: false\n    condition: s\n").matches_pattern(&cat()));
    assert!(rule("    s:\n        ParentImage: null\n    condition: s\n").matches_pattern(&cat()));
    assert!(!rule("    s:\n        Image: null\n    condition: s\n").matches_pattern(&cat()));
    let k = rule("    s:\n        CommandLine: ''\n    condition: s\n");
    assert!(!k.matches_pattern(&cat()));
    assert!(k.matches_pattern(&FieldSet::new().text("CommandLine", "")));
    assert!(!k.matches_pattern(&FieldSet::new()), "empty text does not match an absent field");
}

#[test]
fn number_and_boolean_values() {
    assert!(rule("    s:\n        ProcessId: 4242\n    condition: s\n").matches_pattern(&cat()));
    assert!(rule("    s:\n        ProcessId: '42*'\n    condition: s\n").matches_pattern(&cat()));
    assert!(!rule("    s:\n        ProcessId: 424\n    condition: s\n").matches_pattern(&cat()));
    assert!(rule("    s:\n        koru.modified: false\n    condition: s\n").matches_pattern(&cat()));
    assert!(!rule("    s:\n        koru.modified: true\n    condition: s\n").matches_pattern(&cat()));
    assert!(rule("    s:\n        koru.modified: 'FALSE'\n    condition: s\n").matches_pattern(&cat()));
}

#[test]
fn condition_operators_and_precedence() {
    let a = "    a:\n        Image: '/usr/bin/cat'\n";
    let b = "    b:\n        Image: '/usr/bin/less'\n";
    let c = "    c:\n        ProcessId: 1\n";
    let k = |condition: &str| rule(&format!("{a}{b}{c}    condition: {condition}\n")).matches_pattern(&cat());
    assert!(k("a"));
    assert!(!k("not a"));
    assert!(k("a or b"));
    assert!(!k("a and b"));
    assert!(k("a or b and c"), "and binds tighter than or: a or (b and c)");
    assert!(!k("(a or b) and c"));
    assert!(k("not b and a"), "not binds tighter than and");
    assert!(!k("not (b or a)"));
    assert!(k("not not a"));
    assert!(k("((a))"));
}

#[test]
fn of_expressions_and_them() {
    let body = "    choice_cat:\n        Image: '/usr/bin/cat'\n    choice_less:\n        Image: '/usr/bin/less'\n    _filter_set:\n        ProcessId: 4242\n";
    let k = |condition: &str| rule(&format!("{body}    condition: {condition}\n")).matches_pattern(&cat());
    assert!(k("1 of choice_*"));
    assert!(!k("all of choice_*"));
    assert!(k("1 of them"));
    assert!(!k("all of them"), "_filter is not in them scope even on a match; choice_less does not match");
    assert!(k("1 of choice_* and _filter_set"));
    assert!(!k("1 of choice_* and not 1 of _filt*"));
    assert!(k("all of choice_c*"));
}

#[test]
fn a_list_condition_joins_with_or() {
    let body = "    a:\n        Image: '/usr/bin/less'\n    b:\n        Image: '/usr/bin/cat'\n";
    assert!(rule(&format!("{body}    condition:\n        - a\n        - b\n")).matches_pattern(&cat()));
    assert!(!rule(&format!("{body}    condition:\n        - a\n        - not b\n")).matches_pattern(&cat()));
}

#[test]
fn a_missing_field_fails_but_matches_with_not() {
    let k = rule("    s:\n        ParentImage|endswith: '/bash'\n    condition: s\n");
    assert!(!k.matches_pattern(&cat()));
    let k = rule("    s:\n        ParentImage|endswith: '/bash'\n    condition: not s\n");
    assert!(k.matches_pattern(&cat()));
}

#[test]
fn wildcard_matching_on_long_values_is_fast() {
    // An attacker can supply a long command line; matching ends in bounded time even with many
    // wildcards (no regex backtracking).
    let long_name: String = "ab".repeat(50_000);
    let fields = FieldSet::new().text("CommandLine", &long_name);
    let k = rule("    s:\n        CommandLine: '*a*a*a*a*a*a*a*a*a*a*c'\n    condition: s\n");
    let start = Instant::now();
    assert!(!k.matches_pattern(&fields));
    assert!(start.elapsed().as_secs() < 2, "wildcard matching is too slow");
}
