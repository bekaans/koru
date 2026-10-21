//! The MITRE ATT&CK Enterprise v20.0 catalog (`data/attack-enterprise-v20.0.tsv`), the
//! coverage table, and the ATT&CK Navigator layer.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::OnceLock;

use koru_event::ThreatClass;
use serde_json::{Value, json};

use crate::{Level, RulePack};

/// The ATT&CK version in use.
pub const ATTACK_VERSION: &str = "20.0";

/// The catalog generated from the official STIX bundle (`tools/attack-catalog-gen.py`).
const CATALOG_DATA: &str = include_str!("../data/attack-enterprise-v20.0.tsv");

/// A technique's state in the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackStatus {
    /// Valid.
    Current,
    /// Revoked; replaced by other techniques.
    Revoked {
        /// The replacement technique ids.
        replaced_by: Vec<String>,
    },
    /// Deprecated.
    Deprecated,
}

/// An ATT&CK technique or sub-technique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackTechnique {
    /// Identity (T1234 or T1234.001).
    pub id: String,
    /// Name.
    pub name: String,
    /// Short tactic names (e.g. `credential-access`).
    pub tactics: Vec<String>,
    /// StateDir.
    pub status: AttackStatus,
}

/// An ATT&CK tactic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackTactic {
    /// Identity (TA0006).
    pub id: String,
    /// The short name (`credential-access`).
    pub short_name: String,
    /// Name.
    pub name: String,
}

struct Catalog {
    techniques: BTreeMap<String, AttackTechnique>,
    tactics: BTreeMap<String, AttackTactic>,
}

fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        resolve_catalog(CATALOG_DATA).unwrap_or_else(|e| panic!("the embedded ATT&CK catalog is corrupt: {e}"))
    })
}

fn with_commas(text: &str) -> Vec<String> {
    text.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect()
}

fn resolve_catalog(data: &str) -> Result<Catalog, String> {
    let mut techniques = BTreeMap::new();
    let mut tactics = BTreeMap::new();
    let mut version = None;
    for (no, line) in data.lines().enumerate() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        match fields.as_slice() {
            ["version", s] => version = Some(s.to_string()),
            ["tactic", id, short_name, name] => {
                tactics.insert(
                    short_name.to_string(),
                    AttackTactic { id: id.to_string(), short_name: short_name.to_string(), name: name.to_string() },
                );
            }
            ["technique", id, status, tactics, name, replaced_by] => {
                let status = match *status {
                    "current" => AttackStatus::Current,
                    "revoked" => AttackStatus::Revoked { replaced_by: with_commas(replaced_by) },
                    "deprecated" => AttackStatus::Deprecated,
                    other => return Err(format!("line {}: unknown state {other:?}", no + 1)),
                };
                techniques.insert(
                    id.to_string(),
                    AttackTechnique {
                        id: id.to_string(),
                        name: name.to_string(),
                        tactics: with_commas(tactics),
                        status,
                    },
                );
            }
            _ => return Err(format!("line {}: unrecognized shape", no + 1)),
        }
    }
    if version.as_deref() != Some(ATTACK_VERSION) {
        return Err(format!("catalog version {version:?}, expected {ATTACK_VERSION}"));
    }
    Ok(Catalog { techniques, tactics })
}

/// The technique in the catalog, or `None`.
pub fn attack_technique(id: &str) -> Option<&'static AttackTechnique> {
    catalog().techniques.get(id)
}

/// The tactic in the catalog (by short name); `None` if absent.
pub fn attack_tactic(short_name: &str) -> Option<&'static AttackTactic> {
    catalog().tactics.get(short_name)
}

/// A rule pack's ATT&CK coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    /// Covered techniques (sorted by id).
    pub techniques: Vec<TechniqueCoverage>,
    /// Rules (sorted by name).
    pub rules: Vec<RuleCoverage>,
}

/// The rules covering one technique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechniqueCoverage {
    /// The technique id.
    pub id: String,
    /// The technique name.
    pub name: String,
    /// Tactics.
    pub tactics: Vec<String>,
    /// Rule names (sorted).
    pub rules: Vec<String>,
}

/// One rule's techniques.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCoverage {
    /// The rule name.
    pub name: String,
    /// The title.
    pub title: String,
    /// The threat class.
    pub threat_class: ThreatClass,
    /// Level.
    pub severity: Level,
    /// Technique ids (sorted).
    pub techniques: Vec<String>,
}

/// Computes a pack's coverage. Only evaluated rules count (deprecated and unsupported rules
/// cover no technique).
pub fn coverage(pack: &RulePack) -> Coverage {
    let mut rules = Vec::new();
    let mut technique_rules: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for k in pack.rules().iter().filter(|k| k.is_evaluated()) {
        let techniques: Vec<String> = k.attack().iter().map(|t| t.as_str().to_string()).collect();
        for t in &techniques {
            technique_rules.entry(t.clone()).or_default().push(k.name().to_string());
        }
        rules.push(RuleCoverage {
            name: k.name().to_string(),
            title: k.title().to_string(),
            threat_class: k.threat_class(),
            severity: k.severity(),
            techniques,
        });
    }
    rules.sort_by(|a, b| a.name.cmp(&b.name));
    let techniques = technique_rules
        .into_iter()
        .map(|(id, mut names)| {
            names.sort();
            let (name, tactics) = match attack_technique(&id) {
                Some(t) => (t.name.clone(), t.tactics.clone()),
                None => (String::new(), Vec::new()),
            };
            TechniqueCoverage { id, name, tactics, rules: names }
        })
        .collect();
    Coverage { techniques, rules }
}

/// A Markdown table cell: neutralizes control characters, escapes `|` and newlines.
fn cell(text: &str) -> String {
    let sanitize = koru_event::Untrusted::new(text.to_string()).safe_display();
    sanitize.replace('|', "\\|")
}

fn threat_class_name(s: ThreatClass) -> &'static str {
    match s {
        ThreatClass::DecoyAccess => "decoy_access",
        ThreatClass::BreadcrumbAccess => "breadcrumb_access",
        ThreatClass::SuspectedHijackedAgent => "suspected_hijacked_agent",
        ThreatClass::SelfProtection => "self_protection",
    }
}

/// The coverage table (Markdown; `docs/reports/attack-coverage.md`). Output is deterministic.
pub fn coverage_markdown(cov: &Coverage) -> String {
    let mut m = String::new();
    // `write!` into a `String` never errors.
    let _ = writeln!(m, "# ATT&CK coverage table");
    let _ = writeln!(m);
    let _ = writeln!(
        m,
        "This file is generated by `koru rule coverage packages/rules/`; do not edit it by hand. \
         Version in use: MITRE ATT&CK Enterprise v{ATTACK_VERSION}. Every rule links to at least one technique."
    );
    let _ = writeln!(m);
    let _ = writeln!(m, "- Rule count: {}", cov.rules.len());
    let _ = writeln!(m, "- Covered technique count: {}", cov.techniques.len());
    let _ = writeln!(m);
    let _ = writeln!(m, "## Techniques");
    let _ = writeln!(m);
    let _ = writeln!(m, "| Technique | Name | Tactics | Rules |");
    let _ = writeln!(m, "|---|---|---|---|");
    for t in &cov.techniques {
        let rules: Vec<String> = t.rules.iter().map(|k| format!("`{}`", cell(k))).collect();
        let _ = writeln!(
            m,
            "| {} | {} | {} | {} |",
            cell(&t.id),
            cell(&t.name),
            cell(&t.tactics.join(", ")),
            rules.join(", ")
        );
    }
    let _ = writeln!(m);
    let _ = writeln!(m, "## Rules");
    let _ = writeln!(m);
    let _ = writeln!(m, "| Rule | Title | Threat class | Level | Techniques |");
    let _ = writeln!(m, "|---|---|---|---|---|");
    for k in &cov.rules {
        let _ = writeln!(
            m,
            "| `{}` | {} | {} | {} | {} |",
            cell(&k.name),
            cell(&k.title),
            threat_class_name(k.threat_class),
            k.severity.sigma_name(),
            cell(&k.techniques.join(", "))
        );
    }
    m
}

/// The ATT&CK Navigator layer (format 4.5; `docs/reports/attack-layer.json`). Output is
/// deterministic.
pub fn navigator_layer(cov: &Coverage) -> String {
    // Each covered sub-technique's parent is added too, and sub-techniques shown expanded.
    let mut entries: BTreeMap<String, Value> = BTreeMap::new();
    for t in &cov.techniques {
        if let Some((upper, _)) = t.id.split_once('.') {
            let e = entries.entry(upper.to_string()).or_insert_with(|| json!({ "techniqueID": upper }));
            e["showSubtechniques"] = json!(true);
        }
        let comment = format!("Covering rules: {}", t.rules.join(", "));
        let mut input = json!({
            "techniqueID": t.id,
            "score": t.rules.len(),
            "comment": comment,
            "enabled": true,
        });
        // If the parent is also scored, the sub-technique entry (if any) left it expanded.
        input["showSubtechniques"] = entries.get(&t.id).map_or(json!(false), |e| e["showSubtechniques"].clone());
        entries.insert(t.id.clone(), input);
    }
    let highest = cov.techniques.iter().map(|t| t.rules.len()).max().unwrap_or(1).max(1);
    let layer = json!({
        "name": format!("Koru rule pack coverage (ATT&CK v{ATTACK_VERSION})"),
        "versions": { "attack": "19", "navigator": "5.3.2", "layer": "4.5" },
        "domain": "enterprise-attack",
        "description": "ATT&CK techniques covered by the Koru detection rules. The score is the number of rules covering a technique. \
                        Generated by `koru rule coverage packages/rules/ --format navigator`; do not edit by hand.",
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "max",
            "showID": true,
            "showName": true,
            "showAggregatedTechniques": false,
            "countUnscored": false,
            "expandedSubtechniques": "annotated"
        },
        "hideDisabled": false,
        "techniques": entries.into_values().collect::<Vec<Value>>(),
        "gradient": { "colors": ["#cfe8ff", "#1f6fb5"], "minValue": 1, "maxValue": highest },
        "legendItems": [],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": false,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": true,
        "selectSubtechniquesWithParent": false,
        "selectVisibleTechniques": false
    });
    let mut text = serde_json::to_string_pretty(&layer).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_reads_from_embedded_data() {
        let k = catalog();
        assert!(k.techniques.len() > 800);
        assert_eq!(k.tactics.len(), 15);
    }

    #[test]
    fn malformed_catalog_rejected() {
        assert!(resolve_catalog("version\t20.0\ntechnique\tT1\tcurrent\n").is_err());
        assert!(resolve_catalog("version\t18.0\n").is_err());
        assert!(resolve_catalog("technique\tT1\tcurrent\ta\tName\t\n").is_err(), "no version line");
        assert!(resolve_catalog("version\t20.0\ntechnique\tT1\tunknown_state\ta\tName\t\n").is_err());
    }
}
