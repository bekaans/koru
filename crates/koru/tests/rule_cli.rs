//! Tests of the `koru rule` commands (protected set).
//!
//! Expected: `koru rule validate packages/rules/` → all pass, rules without
//! ATT&CK 0; a corrupt or ATT&CK-less rule is rejected with a non-zero code. `koru rule coverage`
//! produces the coverage table and the Navigator layer. Tests write only to temporary directories.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rule_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packages/rules")
}

fn koru(args: &[&str], home_v: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_koru")).args(args).env("HOME", home_v).output().expect("koru could not be run")
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn temp() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp directory")
}

fn sample_rule() -> String {
    fs::read_to_string(rule_dir().join("decoy_ssh_key.yml")).unwrap()
}

#[test]
fn verify_passes_all_repo_rules_zero_without_attack() {
    let home_v = temp();
    let o = koru(&["rule", "validate", &rule_dir().to_string_lossy()], home_v.path());
    let output = text(&o);
    assert!(o.status.success(), "validate failed:\n{output}");
    assert!(output.contains("Rules without ATT&CK: 0"), "{output}");
    let mut number = 0;
    for g in fs::read_dir(rule_dir()).unwrap() {
        let name = g.unwrap().file_name().to_string_lossy().into_owned();
        if name.ends_with(".yml") {
            assert!(output.contains(&name), "{name} is not in the output:\n{output}");
            number += 1;
        }
    }
    assert!(number >= 17);
    assert!(output.contains(&format!("Result: {number} rules, {number} passed, 0 failed")), "{output}");
    assert!(!output.contains("ERROR"), "{output}");
}

#[test]
fn verify_rejects_corrupt_rule() {
    let home_v = temp();
    let d = temp();
    fs::write(d.path().join("decoy_ssh_key.yml"), format!("{}extra_field: 1\n", sample_rule())).unwrap();
    let o = koru(&["rule", "validate", &d.path().to_string_lossy()], home_v.path());
    assert_eq!(o.status.code(), Some(1), "a corrupt rule must be rejected:\n{}", text(&o));
    assert!(text(&o).contains("FAIL"), "{}", text(&o));
    assert!(text(&o).contains("extra_field"), "the error message must name the field:\n{}", text(&o));
}

#[test]
fn verify_rejects_and_counts_rule_without_attack() {
    let home_v = temp();
    let d = temp();
    let without_attack: String =
        sample_rule().lines().filter(|s| !s.contains("attack.t")).map(|s| format!("{s}\n")).collect();
    assert_ne!(without_attack, sample_rule());
    fs::write(d.path().join("decoy_ssh_key.yml"), without_attack).unwrap();
    let o = koru(&["rule", "validate", &d.path().to_string_lossy()], home_v.path());
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("Rules without ATT&CK: 1"), "{}", text(&o));
}

#[test]
fn verify_single_file_and_bad_usage() {
    let home_v = temp();
    let o = koru(&["rule", "validate", &rule_dir().join("koru_stopped.yml").to_string_lossy()], home_v.path());
    assert!(o.status.success(), "{}", text(&o));
    let o = koru(&["rule", "validate", "/nonexistent/dir/koru-test"], home_v.path());
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert_eq!(koru(&["rule", "validate"], home_v.path()).status.code(), Some(2));
    assert_eq!(koru(&["rule", "validate", "a", "b"], home_v.path()).status.code(), Some(2));
    assert_eq!(koru(&["rule", "bogus"], home_v.path()).status.code(), Some(2));
    assert_eq!(koru(&["rule"], home_v.path()).status.code(), Some(2));
}

#[test]
fn verify_output_has_no_control_or_direction_chars() {
    // KT-15: rule files come from contributors. Terminal escape sequences and direction
    // (Trojan Source) characters that slipped into a field name or file name are not printed raw;
    // the message still shows the offending field.
    let home_v = temp();
    let d = temp();
    let bad_field = format!("{}\"\\x1b[2J\\u202eextra\": 1\n", sample_rule());
    fs::write(d.path().join("decoy_ssh_key.yml"), bad_field).unwrap();
    fs::write(d.path().join("bad\u{1b}[31m.yml"), sample_rule()).unwrap();
    let o = koru(&["rule", "validate", &d.path().to_string_lossy()], home_v.path());
    let output = text(&o);
    assert_eq!(o.status.code(), Some(1), "{output:?}");
    assert!(output.contains("FAIL") && output.contains("extra"), "{output:?}");
    for c in output.chars() {
        assert!(!c.is_control() || c == '\n' || c == '\t', "raw control character: {:?} in {output:?}", c);
        assert!(!('\u{202a}'..='\u{202e}').contains(&c) && !('\u{2066}'..='\u{2069}').contains(&c), "{c:?}");
    }
}

#[test]
fn coverage_table_and_navigator_layer() {
    let home_v = temp();
    let dir = rule_dir().to_string_lossy().into_owned();
    let o = koru(&["rule", "coverage", &dir], home_v.path());
    assert!(o.status.success(), "{}", text(&o));
    let md = String::from_utf8(o.stdout.clone()).unwrap();
    assert!(md.contains("T1552.001") && md.contains("T1685") && md.contains("v20.0"), "{md}");
    let document =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/reports/attack-coverage.md"))
            .unwrap();
    assert_eq!(md, document, "docs/reports/attack-coverage.md is produced by this command");

    let o = koru(&["rule", "coverage", &dir, "--format", "navigator"], home_v.path());
    assert!(o.status.success(), "{}", text(&o));
    let j: serde_json::Value = serde_json::from_slice(&o.stdout).expect("the Navigator layer must be JSON");
    assert_eq!(j["versions"]["layer"], "4.5");
    assert_eq!(j["domain"], "enterprise-attack");

    assert_eq!(koru(&["rule", "coverage", &dir, "--format", "pdf"], home_v.path()).status.code(), Some(2));
    assert_eq!(koru(&["rule", "coverage", "/nonexistent/dir/koru-test"], home_v.path()).status.code(), Some(1));
}

#[test]
fn help_describes_rule_commands() {
    let home_v = temp();
    let o = koru(&["help"], home_v.path());
    assert!(o.status.success());
    assert!(text(&o).contains("rule validate"), "{}", text(&o));
    assert!(text(&o).contains("rule coverage"), "{}", text(&o));
}

#[test]
fn export_sigma_stdout_and_dir() {
    let home_v = temp();
    // Default: source packages/rules, output to stdout (multi-document YAML).
    let o = koru(&["rule", "export", "--format", "sigma"], home_v.path());
    let output = text(&o);
    assert!(o.status.success(), "Sigma export failed:\n{output}");
    let sample = sample_rule();
    assert!(output.contains(sample.trim()), "the export must contain the source rule");
    assert!(output.matches("\n---").count() >= 10, "must be multi-document:\n{output}");
    // --output writes the files into the directory.
    let target = home_v.path().join("sigma-output");
    let o = koru(&["rule", "export", "--format", "sigma", "--output", &target.to_string_lossy()], home_v.path());
    assert!(o.status.success(), "{}", text(&o));
    let written = fs::read_to_string(target.join("decoy_ssh_key.yml")).expect("the file must have been written");
    assert_eq!(written, sample);
    // An unknown format is rejected.
    let o = koru(&["rule", "export", "--format", "unknown_key"], home_v.path());
    assert!(!o.status.success());
}
