//! The ATT&CK v20.0 catalog, the coverage table, and the Navigator layer.
//!
//! `docs/reports/attack-coverage.md` and `docs/reports/attack-layer.json` are generated files
//! (`koru rule coverage`); do not hand-edit them; they must stay current with the rule pack.

use std::collections::BTreeSet;
use std::fs;

use koru_detect::{
    ATTACK_VERSION, AttackStatus, Level, attack_tactic, attack_technique, coverage, coverage_markdown, navigator_layer,
};
use koru_event::ThreatClass;
use serde_json::Value;

use crate::common::{repo_root, rules};

#[test]
fn catalog_version_and_sample_techniques() {
    assert_eq!(ATTACK_VERSION, "20.0");
    let t = attack_technique("T1552.001").unwrap();
    assert_eq!(t.name, "Credentials In Files");
    assert_eq!(t.tactics, vec!["credential-access".to_string()]);
    assert_eq!(t.status, AttackStatus::Current);
    // Defense Evasion split in v19: T1562.001 was revoked, replaced by T1685.
    let revoked = attack_technique("T1562.001").unwrap();
    assert_eq!(revoked.status, AttackStatus::Revoked { replaced_by: vec!["T1685".to_string()] });
    let new = attack_technique("T1685").unwrap();
    assert_eq!(new.name, "Disable or Modify Tools");
    assert_eq!(new.tactics, vec!["defense-impairment".to_string()]);
    assert_eq!(attack_technique("T1489").unwrap().name, "Service Stop");
    assert_eq!(attack_technique("T1078").unwrap().status, AttackStatus::Current);
    assert!(attack_technique("T9999").is_none());
    assert!(attack_technique("t1552.001").is_none(), "ids are uppercase");
    let tactic = attack_tactic("defense-impairment").unwrap();
    assert_eq!((tactic.id.as_str(), tactic.name.as_str()), ("TA0112", "Defense Impairment"));
    assert_eq!(attack_tactic("stealth").unwrap().id, "TA0005");
    assert!(attack_tactic("defense-evasion").is_none(), "v19 has no defense-evasion tactic");
}

#[test]
fn the_catalog_file_is_generated_from_the_official_bundle() {
    let text = fs::read_to_string(repo_root().join("crates/koru-detect/data/attack-enterprise-v20.0.tsv")).unwrap();
    assert!(text.contains("# SHA-256: 81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"));
    assert!(text.lines().any(|s| s == "version\t20.0"));
    let valid =
        text.lines().filter(|s| s.starts_with("technique\t") && s.split('\t').nth(2) == Some("current")).count();
    assert!(valid >= 600, "valid technique count: {valid}");
}

#[test]
fn coverage_is_derived_from_a_rule_pack() {
    let pack = rules();
    let k = coverage(&pack);
    let techniques: Vec<&str> = k.techniques.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(
        techniques,
        [
            "T1005",
            "T1018",
            "T1070",
            "T1083",
            "T1489",
            "T1543.002",
            "T1552.001",
            "T1552.003",
            "T1552.004",
            "T1554",
            "T1565.001",
            "T1685"
        ]
    );
    let t = k.techniques.iter().find(|t| t.id == "T1552.001").unwrap();
    assert_eq!(t.name, "Credentials In Files");
    assert_eq!(
        t.rules,
        ["decoy_ai_note", "decoy_credential_file", "decoy_database_dump", "decoy_general", "koru_secret_read"]
    );
    assert_eq!(k.rules.len(), pack.rules().len());
    let mut names = BTreeSet::new();
    for rule in &k.rules {
        assert!(!rule.techniques.is_empty(), "{}: no ATT&CK", rule.name);
        assert!(names.insert(rule.name.clone()));
    }
    let stopped = k.rules.iter().find(|r| r.name == "koru_stopped").unwrap();
    assert_eq!(stopped.threat_class, ThreatClass::SelfProtection);
    assert_eq!(stopped.severity, Level::High);
    assert_eq!(stopped.techniques, ["T1489", "T1685"]);
}

#[test]
fn the_coverage_table_is_deterministic_and_matches_the_doc() {
    let k = coverage(&rules());
    let md = coverage_markdown(&k);
    assert_eq!(md, coverage_markdown(&coverage(&rules())), "the output must be deterministic");
    assert!(md.contains("ATT&CK"));
    assert!(md.contains("v20.0"));
    assert!(md.contains("| T1685 | Disable or Modify Tools |"), "{md}");
    for rule in rules().rules() {
        assert!(md.contains(rule.name()), "{} missing from the table", rule.name());
    }
    let document = fs::read_to_string(repo_root().join("docs/reports/attack-coverage.md"))
        .expect("docs/reports/attack-coverage.md must be generated: koru rule coverage packages/rules/");
    assert_eq!(document, md, "the document is stale; regenerate with koru rule coverage");
}

#[test]
fn the_navigator_layer_is_format_4_5_and_matches_the_doc() {
    let k = coverage(&rules());
    let text = navigator_layer(&k);
    assert_eq!(text, navigator_layer(&coverage(&rules())));
    let j: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(j["domain"], "enterprise-attack");
    assert_eq!(j["versions"]["attack"], "19");
    assert_eq!(j["versions"]["layer"], "4.5");
    assert_eq!(j["versions"]["navigator"], "5.3.2");
    assert!(j["name"].as_str().is_some_and(|n| !n.is_empty()));
    let techniques = j["techniques"].as_array().unwrap();
    let scored: BTreeSet<&str> =
        techniques.iter().filter(|t| t.get("score").is_some()).map(|t| t["techniqueID"].as_str().unwrap()).collect();
    let expected: BTreeSet<&str> = k.techniques.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(scored, expected);
    for t in techniques {
        let id = t["techniqueID"].as_str().unwrap();
        assert!(attack_technique(id).is_some_and(|a| a.status == AttackStatus::Current), "{id}");
        if let Some(score) = t.get("score") {
            let rules = k.techniques.iter().find(|x| x.id == id).unwrap().rules.len();
            assert_eq!(score.as_u64(), Some(rules as u64), "{id}: the score is the number of covering rules");
            assert!(t["comment"].as_str().is_some_and(|c| !c.is_empty()));
        }
    }
    // A parent technique with a marked sub-technique appears with sub-techniques shown open.
    let upper = techniques.iter().find(|t| t["techniqueID"] == "T1552").expect("the T1552 parent technique");
    assert_eq!(upper["showSubtechniques"], true);
    let document = fs::read_to_string(repo_root().join("docs/reports/attack-layer.json"))
        .expect("docs/reports/attack-layer.json must be generated: koru rule coverage --format navigator");
    assert_eq!(document, text, "the document is stale; regenerate with koru rule coverage --format navigator");
}
