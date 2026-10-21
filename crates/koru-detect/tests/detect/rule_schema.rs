//! The rule-pack schema: `schemas/rule-pack.v1.json` and the Rust types (`deny_unknown_fields`).
//!
//! The same examples go to both sides: the JSON schema via the `json_schema` validator, the
//! Rust side via `parse_rule`. Patterns (`pattern`) and semantic rules (ATT&CK, field names,
//! modifiers, condition, dates, uniqueness) live on the Rust side only and are tested
//! separately.

use std::collections::BTreeSet;
use std::fs;

use koru_detect::{
    Level, RuleStatus, attack_technique, parse_rule, read_rule_file, read_rule_pack, validate_rule_dir, yaml_json,
};
use koru_event::{MitreTechnique, ThreatClass};

use crate::common::{files, rules_directory, temporary};
use crate::json_schema::with_schema;

const SCHEMA: &str = "rule-pack.v1.json";

/// A valid sample rule; negative examples derive from it.
pub const SAMPLE_RULE: &str = "title: 'Sample rule'
id: 5b0f6a1e-3c2d-4e5f-8a9b-0c1d2e3f4a5b
name: sample_rule
status: experimental
description: 'A sample rule for tests.'
references:
    - 'https://attack.mitre.org/techniques/T1552/001/'
author: 'Koru'
date: 2026-10-10
tags:
    - attack.credential-access
    - attack.t1552.001
logsource:
    product: linux
    category: file_access
detection:
    choice:
        TargetFilename|endswith: '/.aws/credentials'
        koru.modified: false
    filter:
        Image: '/usr/bin/backup'
    condition: choice and not filter
falsepositives:
    - 'NotFound.'
level: high
koru:
    threat_class: decoy_access
";

fn replace_in(old: &str, new: &str) -> String {
    assert!(SAMPLE_RULE.contains(old), "not in the sample: {old}");
    SAMPLE_RULE.replacen(old, new, 1)
}

/// Both sides must reject.
fn both_sides_reject(name: &str, text: &str) {
    let json = yaml_json(text).unwrap_or_else(|e| panic!("{name}: YAML could not be parsed: {e}"));
    assert!(with_schema(SCHEMA, &json).is_err(), "{name}: the JSON schema accepted it");
    assert!(parse_rule(text).is_err(), "{name}: Rust accepted it");
}

/// A Rust-side rule only; the JSON schema (pattern-free) may accept it.
fn rust_rejects(name: &str, text: &str) -> String {
    match parse_rule(text) {
        Ok(_) => panic!("{name}: Rust accepted it"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn a_sample_rule_is_valid_on_both_sides() {
    with_schema(SCHEMA, &yaml_json(SAMPLE_RULE).unwrap()).unwrap();
    let k = parse_rule(SAMPLE_RULE).unwrap();
    assert_eq!(k.name(), "sample_rule");
    assert_eq!(k.id(), "5b0f6a1e-3c2d-4e5f-8a9b-0c1d2e3f4a5b");
    assert_eq!(k.title(), "Sample rule");
    assert_eq!(k.severity(), Level::High);
    assert_eq!(k.status(), RuleStatus::Experimental);
    assert_eq!(k.threat_class(), ThreatClass::DecoyAccess);
    assert_eq!(k.attack(), &[MitreTechnique::new("T1552.001").unwrap()]);
}

#[test]
fn every_repo_rule_is_valid_on_both_sides() {
    let files = files(&rules_directory(), "yml");
    assert!(files.len() >= 17, "packages/rules must hold at least 17 rules: {}", files.len());
    let mut names = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for file in &files {
        let text = fs::read_to_string(file).unwrap();
        let name = file.file_stem().unwrap().to_string_lossy().into_owned();
        with_schema(SCHEMA, &yaml_json(&text).unwrap()).unwrap_or_else(|e| panic!("{name}: JSON schema: {e}"));
        let k = read_rule_file(file).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(k.name(), name, "the file name must equal the rule name");
        assert!(!k.attack().is_empty(), "{name}: no ATT&CK technique");
        assert!(names.insert(k.name().to_string()));
        assert!(ids.insert(k.id().to_string()));
    }
    let pack = read_rule_pack(&rules_directory()).unwrap();
    assert_eq!(pack.rules().len(), files.len());
    assert!(pack.find("decoy_ssh_key").is_some());
    assert!(pack.find("no_such_rule").is_none());
}

#[test]
fn repo_rule_classes_and_attack_mapping() {
    let pack = read_rule_pack(&rules_directory()).unwrap();
    let t = |s: &str| MitreTechnique::new(s).unwrap();
    let expected: &[(&str, ThreatClass, &[&str])] = &[
        ("decoy_credential_file", ThreatClass::DecoyAccess, &["T1552.001"]),
        ("decoy_ssh_key", ThreatClass::DecoyAccess, &["T1552.004"]),
        ("decoy_database_dump", ThreatClass::DecoyAccess, &["T1005", "T1552.001"]),
        ("decoy_ai_note", ThreatClass::DecoyAccess, &["T1005", "T1552.001"]),
        ("decoy_general", ThreatClass::DecoyAccess, &["T1552.001"]),
        ("breadcrumb_shell_history", ThreatClass::BreadcrumbAccess, &["T1552.003"]),
        ("breadcrumb_ssh", ThreatClass::BreadcrumbAccess, &["T1018"]),
        ("breadcrumb_general", ThreatClass::BreadcrumbAccess, &["T1083"]),
        ("koru_decoy_modified", ThreatClass::SelfProtection, &["T1685"]),
        ("koru_config_modified", ThreatClass::SelfProtection, &["T1685"]),
        ("koru_secret_read", ThreatClass::SelfProtection, &["T1552.001"]),
        ("koru_store_modified", ThreatClass::SelfProtection, &["T1070", "T1565.001"]),
        ("koru_binary_modified", ThreatClass::SelfProtection, &["T1554", "T1685"]),
        ("koru_service_unit_modified", ThreatClass::SelfProtection, &["T1543.002", "T1685"]),
        ("koru_service_stop", ThreatClass::SelfProtection, &["T1489", "T1685"]),
        ("koru_process_kill", ThreatClass::SelfProtection, &["T1489", "T1685"]),
        ("koru_stopped", ThreatClass::SelfProtection, &["T1489", "T1685"]),
    ];
    for (name, class, techniques) in expected {
        let k = pack.find(name).unwrap_or_else(|| panic!("{name} is missing from the pack"));
        assert_eq!(k.threat_class(), *class, "{name}");
        let expected: Vec<MitreTechnique> = techniques.iter().map(|x| t(x)).collect();
        assert_eq!(k.attack(), expected.as_slice(), "{name}");
    }
    // Every technique is valid in ATT&CK v20.0.
    for k in pack.rules() {
        for technique in k.attack() {
            let a = attack_technique(technique.as_str())
                .unwrap_or_else(|| panic!("{}: {} is missing from the catalog", k.name(), technique.as_str()));
            assert_eq!(a.status, koru_detect::AttackStatus::Current, "{}: {}", k.name(), technique.as_str());
        }
    }
}

#[test]
fn every_decoy_template_class_has_its_own_rule() {
    // A new class falls to the general rules; the classes of the repo's templates must appear
    // by name in their own rules (the general rule is only for classes appended via data).
    let mut classes = BTreeSet::new();
    for file in files(&crate::common::repo_root().join("packages/decoys"), "toml") {
        let value: toml::Value = toml::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        classes.insert((value["kind"].as_str().unwrap().to_string(), value["class"].as_str().unwrap().to_string()));
    }
    assert!(classes.len() >= 10);
    let text = |name: &str| fs::read_to_string(rules_directory().join(format!("{name}.yml"))).unwrap();
    let specific_decoy: String =
        ["decoy_credential_file", "decoy_ssh_key", "decoy_database_dump", "decoy_ai_note", "decoy_report_archive"]
            .iter()
            .map(|a| text(a))
            .collect();
    let specific_breadcrumb: String = ["breadcrumb_shell_history", "breadcrumb_ssh"].iter().map(|a| text(a)).collect();
    for (kind, class) in &classes {
        let sought = format!("'{class}'");
        match kind.as_str() {
            "decoy" => {
                assert!(specific_decoy.contains(&sought), "no specific decoy rule for {class}");
                assert!(text("decoy_general").contains(&sought), "{class} is not among decoy_general's known classes");
            }
            "breadcrumb" => {
                assert!(specific_breadcrumb.contains(&sought), "no specific breadcrumb rule for {class}");
                assert!(text("breadcrumb_general").contains(&sought), "{class} missing from breadcrumb_general");
            }
            other => panic!("unknown kind {other}"),
        }
    }
}

#[test]
fn rules_rejected_by_both_sides() {
    let examples: Vec<(&str, String)> = vec![
        ("an unknown top field", format!("{SAMPLE_RULE}extra_field: 1\n")),
        ("no title", replace_in("title: 'Sample rule'\n", "")),
        ("an empty title", replace_in("title: 'Sample rule'", "title: ''")),
        ("a wrong severity", replace_in("level: high", "level: hgh")),
        ("a wrong status", replace_in("status: experimental", "status: draft")),
        (
            "category and service together",
            replace_in("    category: file_access\n", "    category: file_access\n    service: koru\n"),
        ),
        ("neither category nor service", replace_in("    category: file_access\n", "")),
        ("a non-linux product", replace_in("product: linux", "product: windows")),
        ("unsupported category", replace_in("category: file_access", "category: registry_event")),
        ("unknown field in logsource", replace_in("    product: linux\n", "    product: linux\n    version: 2\n")),
        ("condition missing", replace_in("    condition: choice and not filter\n", "")),
        ("an empty condition", replace_in("condition: choice and not filter", "condition: ''")),
        ("no koru section", replace_in("koru:\n    threat_class: decoy_access\n", "")),
        ("an unknown threat class", replace_in("threat_class: decoy_access", "threat_class: critical")),
        ("an extra field in the koru section", format!("{SAMPLE_RULE}    priority: 1\n")),
        ("an empty value list", replace_in("Image: '/usr/bin/backup'", "Image: []")),
        (
            "null in a list",
            replace_in("Image: '/usr/bin/backup'", "Image:\n            - '/usr/bin/backup'\n            - null"),
        ),
        ("a nested value list", replace_in("Image: '/usr/bin/backup'", "Image:\n            - ['/a', '/b']")),
        (
            "a keyword list",
            replace_in("    filter:\n        Image: '/usr/bin/backup'\n", "    filter:\n        - 'backup'\n"),
        ),
        ("an empty selection", replace_in("    filter:\n        Image: '/usr/bin/backup'\n", "    filter: {}\n")),
        ("an object as a value", replace_in("Image: '/usr/bin/backup'", "Image:\n            child: 1")),
        ("tag missing", replace_in("tags:\n    - attack.credential-access\n    - attack.t1552.001\n", "")),
        (
            "an empty tag list",
            replace_in("tags:\n    - attack.credential-access\n    - attack.t1552.001\n", "tags: []\n"),
        ),
        ("taxonomy is not sigma", format!("{SAMPLE_RULE}taxonomy: windows\n")),
        (
            "references is not a list",
            replace_in("references:\n    - 'https://attack.mitre.org/techniques/T1552/001/'\n", "references: 'x'\n"),
        ),
        (
            "a wrong relation kind",
            format!("{SAMPLE_RULE}related:\n    - id: 5b0f6a1e-3c2d-4e5f-8a9b-0c1d2e3f4a5c\n      type: sibling\n"),
        ),
    ];
    for (name, text) in &examples {
        both_sides_reject(name, text);
    }
}

#[test]
fn rust_side_only_rules() {
    // A rule without an ATT&CK technique tag is rejected.
    let e = rust_rejects("without ATT&CK", &replace_in("    - attack.t1552.001\n", ""));
    assert!(e.contains("ATT&CK"), "{e}");
    // A technique revoked in ATT&CK v20.0: the error names its replacement.
    let e = rust_rejects(
        "a revoked technique",
        &replace_in("    - attack.credential-access\n    - attack.t1552.001\n", "    - attack.t1562.001\n"),
    );
    assert!(e.contains("T1562.001") && e.contains("T1685"), "{e}");
    rust_rejects("nonexistent technique", &replace_in("attack.t1552.001", "attack.t9999"));
    rust_rejects("an uppercase tag", &replace_in("attack.t1552.001", "attack.T1552.001"));
    rust_rejects(
        "a tactic the technique does not belong to",
        &replace_in("attack.credential-access", "attack.discovery"),
    );
    rust_rejects("unknown_key tactic", &replace_in("attack.credential-access", "attack.defense-evasion-x"));
    rust_rejects("an unknown tag namespace", &replace_in("    - attack.credential-access\n", "    - custom.tag\n"));
    // Field names and modifiers.
    let e = rust_rejects("unsupported field", &replace_in("Image: '/usr/bin/backup'", "User: 'root'"));
    assert!(e.contains("User"), "{e}");
    rust_rejects("an unknown koru-prefixed field", &replace_in("koru.modified: false", "koru.madeup: false"));
    let e = rust_rejects("the re modifier", &replace_in("Image: '/usr/bin/backup'", "Image|re: '.*backup'"));
    assert!(e.contains("re"), "{e}");
    rust_rejects("the base64 modifier", &replace_in("Image: '/usr/bin/backup'", "Image|base64: 'x'"));
    rust_rejects("an unknown modifier", &replace_in("Image: '/usr/bin/backup'", "Image|similar: 'x'"));
    rust_rejects("exists is not a boolean", &replace_in("Image: '/usr/bin/backup'", "Image|exists: 'yes'"));
    rust_rejects(
        "exists with another modifier",
        &replace_in("Image: '/usr/bin/backup'", "Image|contains|exists: true"),
    );
    rust_rejects("all with a single value", &replace_in("Image: '/usr/bin/backup'", "Image|contains|all: 'x'"));
    rust_rejects(
        "startswith and endswith together",
        &replace_in("Image: '/usr/bin/backup'", "Image|startswith|endswith: 'x'"),
    );
    rust_rejects("the same modifier twice", &replace_in("Image: '/usr/bin/backup'", "Image|contains|contains: 'x'"));
    rust_rejects("a modifier with null", &replace_in("Image: '/usr/bin/backup'", "Image|contains: null"));
    // condition.
    rust_rejects("an undefined identifier", &replace_in("choice and not filter", "choice and not missing"));
    rust_rejects("a truncated expression", &replace_in("choice and not filter", "choice and"));
    rust_rejects("unclosed parenthesis", &replace_in("choice and not filter", "(choice and not filter"));
    rust_rejects("extra parenthesis", &replace_in("choice and not filter", "choice)"));
    rust_rejects("2 of", &replace_in("choice and not filter", "2 of sec*"));
    rust_rejects("a pattern matching nothing", &replace_in("choice and not filter", "1 of missing*"));
    rust_rejects("uppercase operators", &replace_in("choice and not filter", "choice AND NOTE filter"));
    let deep_cond = format!("{}choice{}", "(".repeat(300), ")".repeat(300));
    rust_rejects("an overly deep condition", &replace_in("choice and not filter", &deep_cond));
    rust_rejects("a keyword identifier", &replace_in("    filter:\n", "    them:\n").replace("not filter", "not them"));
    // Formats.
    rust_rejects("an invalid date", &replace_in("date: 2026-10-10", "date: 2026-13-40"));
    rust_rejects("date format", &replace_in("date: 2026-10-10", "date: 10.10.2026"));
    rust_rejects("an uppercase name", &replace_in("name: sample_rule", "name: Sample_Rule"));
    rust_rejects("id that is not a UUID", &replace_in("id: 5b0f6a1e-3c2d-4e5f-8a9b-0c1d2e3f4a5b", "id: rule-1"));
    rust_rejects(
        "a YAML alias",
        &replace_in(
            "    filter:\n        Image: '/usr/bin/backup'\n",
            "    filter: &f\n        Image: '/usr/bin/backup'\n    _f2: *f\n",
        ),
    );
    rust_rejects("multiple documents", &format!("{SAMPLE_RULE}---\n{SAMPLE_RULE}"));
    rust_rejects("a root list", "- a\n- b\n");
}

#[test]
fn a_list_condition_and_underscored_identifiers_are_accepted() {
    let text = replace_in(
        "    condition: choice and not filter\n",
        "    _helper:\n        Image: '/x'\n    condition:\n        - choice and not filter\n        - 1 of _help*\n",
    );
    with_schema(SCHEMA, &yaml_json(&text).unwrap()).unwrap();
    parse_rule(&text).unwrap();
}

#[test]
fn pack_and_directory_validation() {
    // Duplicate id and name.
    let d = temporary();
    fs::write(d.path.join("sample_rule.yml"), SAMPLE_RULE).unwrap();
    fs::write(d.path.join("second.yml"), SAMPLE_RULE.replace("name: sample_rule", "name: second")).unwrap();
    let e = read_rule_pack(&d.path).unwrap_err().to_string();
    assert!(e.contains("5b0f6a1e"), "the duplicate id must be reported: {e}");

    // A file-name/name mismatch (e.g. iCloud's "name 2.yml" copy).
    let d = temporary();
    fs::write(d.path.join("sample_rule 2.yml"), SAMPLE_RULE).unwrap();
    assert!(read_rule_pack(&d.path).is_err());
    assert!(read_rule_file(&d.path.join("sample_rule 2.yml")).is_err());

    // The .yaml extension is not silently skipped.
    let d = temporary();
    fs::write(d.path.join("sample_rule.yaml"), SAMPLE_RULE).unwrap();
    assert!(read_rule_pack(&d.path).is_err());

    // Empty and missing directories.
    let d = temporary();
    assert!(read_rule_pack(&d.path).is_err());
    assert!(read_rule_pack(&d.path.join("missing")).is_err());

    // Other extensions (e.g. a README) are ignored.
    let d = temporary();
    fs::write(d.path.join("sample_rule.yml"), SAMPLE_RULE).unwrap();
    fs::write(d.path.join("README.md"), "# rules\n").unwrap();
    assert_eq!(read_rule_pack(&d.path).unwrap().rules().len(), 1);

    // An oversized file is not read.
    let d = temporary();
    fs::write(d.path.join("large.yml"), format!("{SAMPLE_RULE}# {}\n", "x".repeat(2 * 1024 * 1024))).unwrap();
    assert!(read_rule_file(&d.path.join("large.yml")).is_err());
}

#[test]
fn directory_validation_report() {
    let d = temporary();
    fs::write(d.path.join("sample_rule.yml"), SAMPLE_RULE).unwrap();
    fs::write(d.path.join("broken.yml"), format!("{SAMPLE_RULE}extra_field: 1\n").replace("sample_rule", "broken"))
        .unwrap();
    let no_attack = SAMPLE_RULE
        .replace("name: sample_rule", "name: no_attack")
        .replace("5b0f6a1e-3c2d-4e5f-8a9b-0c1d2e3f4a5b", "5b0f6a1e-3c2d-4e5f-8a9b-0c1d2e3f4a5d")
        .replace("    - attack.t1552.001\n", "");
    fs::write(d.path.join("no_attack.yml"), no_attack).unwrap();
    let r = validate_rule_dir(&d.path);
    assert!(!r.succeeded());
    assert_eq!(r.files.len(), 3);
    assert_eq!(r.without_attack_count(), 1);
    let outcome = |name: &str| r.files.iter().find(|s| s.file.file_name().unwrap() == name).unwrap();
    assert!(outcome("sample_rule.yml").error.is_none());
    assert_eq!(outcome("sample_rule.yml").name.as_deref(), Some("sample_rule"));
    assert_eq!(outcome("sample_rule.yml").techniques, vec!["T1552.001".to_string()]);
    assert!(outcome("broken.yml").error.is_some());
    assert!(!outcome("broken.yml").no_attack);
    assert!(outcome("no_attack.yml").no_attack);
    assert!(outcome("no_attack.yml").error.as_deref().is_some_and(|h| h.contains("ATT&CK")));

    let r = validate_rule_dir(&rules_directory());
    assert!(r.succeeded(), "{:?}", r);
    assert_eq!(r.without_attack_count(), 0);
    assert!(r.package_error.is_none());

    // A single file can be validated too.
    let r = validate_rule_dir(&rules_directory().join("decoy_ssh_key.yml"));
    assert!(r.succeeded());
    assert_eq!(r.files.len(), 1);

    // A missing path is a pack error.
    let r = validate_rule_dir(&d.path.join("missing"));
    assert!(!r.succeeded());
    assert!(r.package_error.is_some());
}
