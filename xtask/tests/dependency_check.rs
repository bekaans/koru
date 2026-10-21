//! Tests for `cargo xtask dependency-check` (protected set).
//!
//! Dependency matrix: each crate may have only allowed internal Koru
//! dependencies and the external dependencies listed with their rationale in `dependency-rules.toml`;
//! only koru-pulsar depends on Pulsar directly; a transitive Pulsar dependency is caught too.
//! The tests run with small synthetic inputs in `cargo metadata` format and with the real workspace.

use std::path::PathBuf;

use serde_json::{Value, json};
use xtask::{DependencyKind, Violation, check, parse_metadata, parse_rules, read_metadata};

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
const PULSAR: &str = "git+https://github.com/exein-io/pulsar?tag=v0.10.1#e79d2eb3771b7ad657c0029ca2c7bbaeac5e61fb";

/// The synthetic tests' rules: a reduced form of the dependency matrix.
const RULES: &str = r#"
version = 1
pulsar_source = "git+https://github.com/exein-io/pulsar"

[crate.koru-event]
internal = []
pulsar_direct = false
pulsar_transitive = false
[crate.koru-event.external.serde]
kinds = ["normal"]
rationale = "serialization"
[crate.koru-event.external.serde_json]
kinds = ["dev"]
rationale = "schema tests"

[crate.koru-pulsar]
internal = ["koru-event"]
pulsar_direct = true
pulsar_transitive = true
[crate.koru-pulsar.external.pulsar-core]
kinds = ["normal"]
source = "git+https://github.com/exein-io/pulsar?tag=v0.10.1"
rationale = "the sensor"

[crate.koru-detect]
internal = ["koru-event"]
pulsar_direct = false
pulsar_transitive = false
[crate.koru-detect.external.middle-crate]
kinds = ["normal"]
rationale = "synthetic test: the middle crate for the transitive Pulsar path"

[crate.koru]
internal = ["koru-event", "koru-pulsar", "koru-detect"]
pulsar_direct = false
pulsar_transitive = true
"#;

/// Package id: path-sourced for workspace members, the given source otherwise.
fn id(name: &str, source: Option<&str>) -> String {
    match source {
        None => format!("path+file:///workspace/{name}#0.1.0"),
        Some(k) => format!("{k}#{name}@1.0.0"),
    }
}

/// Produces a synthetic output in `cargo metadata --format-version 1` format.
/// `packages_v`: (name, source; None = workspace member). `links`: (from, to, kind: "normal" | "dev" | "build").
fn metadata(packages_v: &[(&str, Option<&str>)], links: &[(&str, &str, &str)]) -> String {
    let find_source =
        |name: &str| packages_v.iter().find(|(a, _)| *a == name).unwrap_or_else(|| panic!("no such package: {name}")).1;
    let pkgs: Vec<Value> = packages_v
        .iter()
        .map(|(name, source)| {
            json!({
                "name": name,
                "version": if source.is_none() { "0.1.0" } else { "1.0.0" },
                "id": id(name, *source),
                "source": source,
                "manifest_path": format!("/workspace/{name}/Cargo.toml"),
            })
        })
        .collect();
    let members: Vec<String> = packages_v.iter().filter(|(_, k)| k.is_none()).map(|(name, _)| id(name, None)).collect();
    let nodes: Vec<Value> = packages_v
        .iter()
        .map(|(name, source)| {
            let deps: Vec<Value> = links
                .iter()
                .filter(|(from, _, _)| from == name)
                .map(|(_, to, kind)| {
                    let kind_value = if *kind == "normal" { Value::Null } else { json!(kind) };
                    json!({
                        "name": to.replace('-', "_"),
                        "pkg": id(to, find_source(to)),
                        "dep_kinds": [{"kind": kind_value, "target": null}],
                    })
                })
                .collect();
            json!({"id": id(name, *source), "deps": deps, "dependencies": [], "features": []})
        })
        .collect();
    json!({
        "packages": pkgs,
        "workspace_members": members,
        "resolve": {"nodes": nodes, "root": null},
        "workspace_root": "/workspace",
        "target_directory": "/workspace/target",
        "version": 1,
    })
    .to_string()
}

fn clean_packages() -> Vec<(&'static str, Option<&'static str>)> {
    vec![
        ("koru-event", None),
        ("koru-pulsar", None),
        ("koru-detect", None),
        ("koru", None),
        ("serde", Some(CRATES_IO)),
        ("serde_json", Some(CRATES_IO)),
        ("middle-crate", Some(CRATES_IO)),
        ("pulsar-core", Some(PULSAR)),
        ("bpf-common", Some(PULSAR)),
    ]
}

fn clean_links() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("koru-event", "serde", "normal"),
        ("koru-event", "serde_json", "dev"),
        ("koru-pulsar", "koru-event", "normal"),
        ("koru-pulsar", "pulsar-core", "normal"),
        ("pulsar-core", "bpf-common", "normal"),
        ("koru-detect", "koru-event", "normal"),
        ("koru-detect", "middle-crate", "normal"),
        ("koru", "koru-event", "normal"),
        ("koru", "koru-pulsar", "normal"),
        ("koru", "koru-detect", "normal"),
    ]
}

fn run_check(packages_v: &[(&str, Option<&str>)], links: &[(&str, &str, &str)]) -> Vec<Violation> {
    let m = parse_metadata(&metadata(packages_v, links)).expect("could not parse the synthetic metadata");
    let k = parse_rules(RULES).expect("could not parse the synthetic rules");
    check(&m, &k)
}

#[test]
fn a_compliant_workspace_has_no_violations() {
    let violations = run_check(&clean_packages(), &clean_links());
    assert!(violations.is_empty(), "unexpected violations: {violations:?}");
}

#[test]
fn an_off_matrix_external_dependency_is_caught() {
    let mut p = clean_packages();
    p.push(("regex", Some(CRATES_IO)));
    let mut b = clean_links();
    b.push(("koru-event", "regex", "normal"));
    let violations = run_check(&p, &b);
    assert!(
        violations.iter().any(|i| matches!(i, Violation::UnlistedExternal { crate_name, dependency, .. }
            if crate_name == "koru-event" && dependency == "regex")),
        "{violations:?}"
    );
}

#[test]
fn a_disallowed_internal_dependency_is_caught() {
    let mut b = clean_links();
    b.push(("koru-event", "koru-detect", "normal"));
    let violations = run_check(&clean_packages(), &b);
    assert!(
        violations.iter().any(|i| matches!(i, Violation::DisallowedInternal { crate_name, dependency }
            if crate_name == "koru-event" && dependency == "koru-detect")),
        "{violations:?}"
    );
}

#[test]
fn a_transitive_pulsar_dependency_is_caught() {
    // koru-detect -> middle-crate -> pulsar-core: koru-detect must not know Pulsar.
    let mut b = clean_links();
    b.push(("middle-crate", "pulsar-core", "normal"));
    let violations = run_check(&clean_packages(), &b);
    let found = violations.iter().find_map(|i| match i {
        Violation::TransitivePulsar { crate_name, path } if crate_name == "koru-detect" => Some(path.clone()),
        _ => None,
    });
    let path = found.unwrap_or_else(|| panic!("transitive Pulsar was not caught: {violations:?}"));
    assert_eq!(path.first().map(String::as_str), Some("koru-detect"));
    assert!(path.iter().any(|a| a == "middle-crate"), "the path must show the middle crate: {path:?}");
    assert_eq!(path.last().map(String::as_str), Some("pulsar-core"));
}

#[test]
fn transitive_pulsar_via_an_internal_crate_is_caught() {
    // koru-detect -> koru-pulsar: both a matrix violation and transitive Pulsar.
    let mut b = clean_links();
    b.push(("koru-detect", "koru-pulsar", "normal"));
    let violations = run_check(&clean_packages(), &b);
    assert!(
        violations
            .iter()
            .any(|i| matches!(i, Violation::DisallowedInternal { crate_name, .. } if crate_name == "koru-detect"))
    );
    assert!(
        violations
            .iter()
            .any(|i| matches!(i, Violation::TransitivePulsar { crate_name, .. } if crate_name == "koru-detect"))
    );
}

#[test]
fn direct_pulsar_dependency_only_in_koru_pulsar() {
    // The koru CLI may see Pulsar transitively but cannot depend on it directly.
    let mut b = clean_links();
    b.push(("koru", "pulsar-core", "normal"));
    let violations = run_check(&clean_packages(), &b);
    assert!(
        violations.iter().any(|i| matches!(i, Violation::DirectPulsar { crate_name, .. } if crate_name == "koru")),
        "{violations:?}"
    );
}

#[test]
fn pulsar_via_a_dev_dependency_is_also_caught() {
    let mut b = clean_links();
    b.push(("koru-event", "pulsar-core", "dev"));
    let violations = run_check(&clean_packages(), &b);
    assert!(
        violations
            .iter()
            .any(|i| matches!(i, Violation::DirectPulsar { crate_name, .. } if crate_name == "koru-event"))
    );
    assert!(
        violations
            .iter()
            .any(|i| matches!(i, Violation::TransitivePulsar { crate_name, .. } if crate_name == "koru-event"))
    );
}

#[test]
fn an_allowed_dependency_with_a_disallowed_kind_is_caught() {
    // serde_json may be only a dev (test) dependency in koru-event.
    let mut b = clean_links();
    b.retain(|(from, to, _)| !(*from == "koru-event" && *to == "serde_json"));
    b.push(("koru-event", "serde_json", "normal"));
    let violations = run_check(&clean_packages(), &b);
    assert!(
        violations.iter().any(|i| matches!(i, Violation::DisallowedKind { crate_name, dependency, kind }
            if crate_name == "koru-event" && dependency == "serde_json" && *kind == DependencyKind::Normal)),
        "{violations:?}"
    );
}

#[test]
fn an_unexpected_source_is_caught() {
    // A same-named crate coming from outside crates.io (e.g. another git repository) is a violation.
    let mut p = clean_packages();
    p.retain(|(name, _)| *name != "serde");
    p.push(("serde", Some("git+https://github.com/example/serde-fork")));
    let violations = run_check(&p, &clean_links());
    assert!(
        violations.iter().any(|i| matches!(i, Violation::WrongSource { crate_name, dependency, .. }
            if crate_name == "koru-event" && dependency == "serde")),
        "{violations:?}"
    );
}

#[test]
fn a_crate_without_a_rule_is_caught() {
    let mut p = clean_packages();
    p.push(("koru-new", None));
    let violations = run_check(&p, &clean_links());
    assert!(
        violations.iter().any(|i| matches!(i, Violation::CrateWithoutRule { crate_name } if crate_name == "koru-new")),
        "{violations:?}"
    );
}

#[test]
fn a_rule_without_a_rationale_is_caught() {
    let rules = RULES.replace("rationale = \"serialization\"", "rationale = \"  \"");
    let m = parse_metadata(&metadata(&clean_packages(), &clean_links())).unwrap();
    let k = parse_rules(&rules).unwrap();
    let violations = check(&m, &k);
    assert!(
        violations.iter().any(|i| matches!(i, Violation::EmptyRationale { crate_name, dependency }
            if crate_name == "koru-event" && dependency == "serde")),
        "{violations:?}"
    );
}

#[test]
fn a_broken_rules_file_is_rejected() {
    assert!(parse_rules("this = [not toml").is_err());
    assert!(parse_rules(&format!("{RULES}\nunknown_field = 1\n")).is_err());
    assert!(parse_rules(&RULES.replace("version = 1", "version = 2")).is_err());
    assert!(parse_metadata("{}").is_err());
}

// ---------------------------------------------------------------------------------------------
// The real workspace and the real rules file
// ---------------------------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn real_rules() -> xtask::Rules {
    let text = std::fs::read_to_string(repo_root().join("dependency-rules.toml"))
        .expect("could not read dependency-rules.toml");
    parse_rules(&text).expect("could not parse dependency-rules.toml")
}

#[test]
fn the_rules_file_matches_the_plan_matrix() {
    let k = real_rules();
    let internal_of = |name: &str| -> Vec<String> {
        let mut v = k.crate_rule(name).unwrap_or_else(|| panic!("no rule: {name}")).internal.clone();
        v.sort();
        v
    };
    let event = vec!["koru-event".to_string()];
    assert!(internal_of("koru-event").is_empty());
    assert!(internal_of("xtask").is_empty());
    for name in ["koru-pulsar", "koru-decoy", "koru-detect", "koru-store", "koru-notify"] {
        assert_eq!(internal_of(name), event, "{name}: may depend only on koru-event");
    }
    let mut all: Vec<String> = ["koru-notify", "koru-store", "koru-event", "koru-pulsar", "koru-detect", "koru-decoy"]
        .map(String::from)
        .to_vec();
    all.sort();
    assert_eq!(internal_of("koru"), all);
    for name in ["koru-event", "koru-pulsar", "koru-decoy", "koru-detect", "koru-store", "koru-notify", "koru", "xtask"]
    {
        let rule = k.crate_rule(name).unwrap();
        assert_eq!(rule.pulsar_direct, name == "koru-pulsar", "{name}: only koru-pulsar depends on Pulsar directly");
        assert_eq!(
            rule.pulsar_transitive,
            name == "koru-pulsar" || name == "koru",
            "{name}: transitive Pulsar permission"
        );
        for (dep, ext) in &rule.external {
            assert!(!ext.rationale.trim().is_empty(), "{name} -> {dep}: rationale is empty");
        }
    }
    // koru-event: no external dependency beyond serde, thiserror, uuid, time (+ serde_json with its rationale).
    let allowed = ["serde", "thiserror", "uuid", "time", "serde_json"];
    for dep in k.crate_rule("koru-event").unwrap().external.keys() {
        assert!(allowed.contains(&dep.as_str()), "off-matrix dependency for koru-event: {dep}");
    }
}

#[test]
fn the_real_workspace_has_no_violations() {
    let m = read_metadata(&repo_root()).expect("could not run cargo metadata");
    let violations = check(&m, &real_rules());
    assert!(violations.is_empty(), "the workspace violates the dependency matrix: {violations:#?}");
}
