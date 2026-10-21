#![forbid(unsafe_code)]
//! # xtask
//!
//! Koru development tasks. `cargo xtask dependency-check` checks the workspace's
//! dependencies against `dependency-rules.toml`:
//!
//! - Every workspace member must have a rule; a rule for a crate absent from the workspace is also a violation.
//! - Internal Koru dependencies may come only from the `internal` list.
//! - External dependencies must appear in the `external` table, with an allowed kind (normal,
//!   dev, build), an allowed source (crates.io by default), and a non-empty rationale.
//! - A direct dependency on a Pulsar package may exist only in a crate with `pulsar_direct = true`.
//! - A Pulsar package may appear in the dependency tree (transitively) only in a crate with
//!   `pulsar_transitive = true`. On the first step every dependency kind is followed; on later
//!   steps, normal and build dependencies.
//!
//! The dependency graph is read from the output of `cargo metadata --format-version 1 --locked`;
//! no platform filter is applied, so dependencies compiled only on Linux (Pulsar) are checked
//! on every platform.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

/// crates.io `cargo metadata` source strings (git index and sparse index).
pub const CRATES_IO_SOURCES: [&str; 2] =
    ["registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"];

/// The supported rules-file version.
pub const RULES_FILE_VERSION: u32 = 1;

/// Dependency kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// `[dependencies]`.
    Normal,
    /// `[dev-dependencies]`.
    Dev,
    /// `[build-dependencies]`.
    Build,
}

impl fmt::Display for DependencyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DependencyKind::Normal => "normal",
            DependencyKind::Dev => "dev",
            DependencyKind::Build => "build",
        })
    }
}

/// `dependency-rules.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    /// The file-format version.
    pub version: u32,
    /// The source prefix that identifies Pulsar packages.
    pub pulsar_source: String,
    /// Crate rules (key: crate name).
    #[serde(rename = "crate")]
    pub crates: BTreeMap<String, CrateRule>,
}

impl Rules {
    /// The crate's rule.
    pub fn crate_rule(&self, name: &str) -> Option<&CrateRule> {
        self.crates.get(name)
    }
}

/// A workspace member's rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrateRule {
    /// Allowed internal Koru dependencies.
    pub internal: Vec<String>,
    /// Permission for a direct dependency on a Pulsar package.
    pub pulsar_direct: bool,
    /// Permission for a Pulsar package to appear in the dependency tree.
    pub pulsar_transitive: bool,
    /// Allowed external dependencies (key: package name).
    #[serde(default)]
    pub external: BTreeMap<String, ExternalRule>,
}

/// An allowed external dependency.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRule {
    /// Allowed kinds.
    pub kinds: Vec<DependencyKind>,
    /// Source prefix; crates.io only when absent.
    #[serde(default)]
    pub source: Option<String>,
    /// Rationale (must not be empty).
    pub rationale: String,
}

/// The needed part of `cargo metadata --format-version 1` output.
#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    /// All packages.
    pub packages: Vec<Package>,
    /// Package ids of the workspace members.
    pub workspace_members: Vec<String>,
    /// The resolved dependency graph.
    pub resolve: Resolution,
}

/// Package.
#[derive(Debug, Clone, Deserialize)]
pub struct Package {
    /// Package name.
    pub name: String,
    /// Package id.
    pub id: String,
    /// Source; `null` for workspace members and path dependencies.
    pub source: Option<String>,
}

/// The resolved graph.
#[derive(Debug, Clone, Deserialize)]
pub struct Resolution {
    /// Nodes.
    pub nodes: Vec<Node>,
}

/// A package in the graph.
#[derive(Debug, Clone, Deserialize)]
pub struct Node {
    /// Package id.
    pub id: String,
    /// Direct dependencies.
    pub deps: Vec<NodeDep>,
}

/// An edge in the graph.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeDep {
    /// The depended-on package's id.
    pub pkg: String,
    /// Dependency kinds.
    pub dep_kinds: Vec<DepKind>,
}

/// The edge's kind (`null` normal, `dev`, `build`).
#[derive(Debug, Clone, Deserialize)]
pub struct DepKind {
    /// Kind.
    pub kind: Option<String>,
}

/// The checker's own errors (not violations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckError {
    /// The rules file could not be read or is invalid.
    Rules(String),
    /// The `cargo metadata` output could not be read or is invalid.
    Metadata(String),
    /// `cargo metadata` could not be run.
    Cargo(String),
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckError::Rules(e) => write!(f, "dependency-rules.toml is invalid: {e}"),
            CheckError::Metadata(e) => write!(f, "cargo metadata output is invalid: {e}"),
            CheckError::Cargo(e) => write!(f, "could not run cargo metadata: {e}"),
        }
    }
}

impl std::error::Error for CheckError {}

/// A dependency-rule violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// The workspace member has no rule.
    CrateWithoutRule {
        /// Crate.
        crate_name: String,
    },
    /// The crate with a rule is not in the workspace.
    RuleForUnknownCrate {
        /// Crate.
        crate_name: String,
    },
    /// The internal Koru dependency is not in the matrix.
    DisallowedInternal {
        /// The dependent crate.
        crate_name: String,
        /// The dependency.
        dependency: String,
    },
    /// The external dependency is not in the rules file.
    UnlistedExternal {
        /// The dependent crate.
        crate_name: String,
        /// The dependency.
        dependency: String,
        /// Kind.
        kind: DependencyKind,
    },
    /// The external dependency is allowed, but not with this kind.
    DisallowedKind {
        /// The dependent crate.
        crate_name: String,
        /// The dependency.
        dependency: String,
        /// Kind.
        kind: DependencyKind,
    },
    /// The external dependency does not come from an allowed source.
    WrongSource {
        /// The dependent crate.
        crate_name: String,
        /// The dependency.
        dependency: String,
        /// The source found.
        source: String,
    },
    /// An unpermitted direct dependency on a Pulsar package.
    DirectPulsar {
        /// The dependent crate.
        crate_name: String,
        /// The Pulsar package.
        dependency: String,
    },
    /// An unpermitted Pulsar package in the dependency tree.
    TransitivePulsar {
        /// The dependent crate.
        crate_name: String,
        /// The shortest path from the crate to the Pulsar package.
        path: Vec<String>,
    },
    /// The rule's rationale is empty.
    EmptyRationale {
        /// The crate.
        crate_name: String,
        /// The dependency.
        dependency: String,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Violation::CrateWithoutRule { crate_name } => {
                write!(f, "{crate_name}: a workspace member but has no rule in dependency-rules.toml")
            }
            Violation::RuleForUnknownCrate { crate_name } => {
                write!(f, "{crate_name}: present in the rules file but not a workspace member")
            }
            Violation::DisallowedInternal { crate_name, dependency } => {
                write!(
                    f,
                    "{crate_name} -> {dependency}: an internal Koru dependency not allowed by the dependency matrix"
                )
            }
            Violation::UnlistedExternal { crate_name, dependency, kind } => {
                write!(f, "{crate_name} -> {dependency} ({kind}): an external dependency absent from the rules file")
            }
            Violation::DisallowedKind { crate_name, dependency, kind } => {
                write!(f, "{crate_name} -> {dependency}: this dependency is not allowed with kind {kind}")
            }
            Violation::WrongSource { crate_name, dependency, source } => {
                write!(f, "{crate_name} -> {dependency}: disallowed source {source}")
            }
            Violation::DirectPulsar { crate_name, dependency } => {
                write!(f, "{crate_name} -> {dependency}: only koru-pulsar may depend on Pulsar directly")
            }
            Violation::TransitivePulsar { crate_name, path } => {
                write!(f, "{crate_name}: transitive Pulsar dependency: {}", path.join(" -> "))
            }
            Violation::EmptyRationale { crate_name, dependency } => {
                write!(f, "{crate_name} -> {dependency}: the rationale in the rules file is empty")
            }
        }
    }
}

/// Parses the rules file; unknown fields and unsupported versions are rejected.
pub fn parse_rules(text: &str) -> Result<Rules, CheckError> {
    let rules: Rules = toml::from_str(text).map_err(|e| CheckError::Rules(e.to_string()))?;
    if rules.version != RULES_FILE_VERSION {
        return Err(CheckError::Rules(format!(
            "unsupported version {} (expected {RULES_FILE_VERSION})",
            rules.version
        )));
    }
    if rules.pulsar_source.trim().is_empty() {
        return Err(CheckError::Rules("pulsar_source is empty".to_string()));
    }
    Ok(rules)
}

/// Parses `cargo metadata --format-version 1` output.
pub fn parse_metadata(text: &str) -> Result<Metadata, CheckError> {
    let m: Metadata = serde_json::from_str(text).map_err(|e| CheckError::Metadata(e.to_string()))?;
    for node in &m.resolve.nodes {
        for bag in &node.deps {
            for kind in &bag.dep_kinds {
                kind_of(kind).map_err(CheckError::Metadata)?;
            }
        }
    }
    Ok(m)
}

/// Runs `cargo metadata --format-version 1 --locked` at the workspace root.
pub fn read_metadata(workspace_root: &Path) -> Result<Metadata, CheckError> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| CheckError::Cargo(e.to_string()))?;
    if !output.status.success() {
        return Err(CheckError::Cargo(String::from_utf8_lossy(&output.stderr).into_owned()));
    }
    let text = String::from_utf8(output.stdout).map_err(|e| CheckError::Metadata(e.to_string()))?;
    parse_metadata(&text)
}

fn kind_of(kind: &DepKind) -> Result<DependencyKind, String> {
    match kind.kind.as_deref() {
        None => Ok(DependencyKind::Normal),
        Some("dev") => Ok(DependencyKind::Dev),
        Some("build") => Ok(DependencyKind::Build),
        Some(other) => Err(format!("unknown dependency kind: {other}")),
    }
}

fn source_matches(source: &str, expected: Option<&str>) -> bool {
    match expected {
        Some(prefix) => source.starts_with(prefix),
        None => CRATES_IO_SOURCES.contains(&source),
    }
}

/// Checks the dependencies against the rules; an empty list when there is no violation.
pub fn check(metadata: &Metadata, rules: &Rules) -> Vec<Violation> {
    let packages_v: HashMap<&str, &Package> = metadata.packages.iter().map(|p| (p.id.as_str(), p)).collect();
    let nodes: HashMap<&str, &Node> = metadata.resolve.nodes.iter().map(|d| (d.id.as_str(), d)).collect();
    let member_ids: BTreeSet<&str> = metadata.workspace_members.iter().map(String::as_str).collect();
    let mut members: Vec<&Package> = member_ids.iter().filter_map(|k| packages_v.get(k).copied()).collect();
    members.sort_by(|a, b| a.name.cmp(&b.name));
    let is_pulsar = |p: &Package| p.source.as_deref().is_some_and(|k| k.starts_with(rules.pulsar_source.as_str()));

    let mut violations = Vec::new();
    let member_names: BTreeSet<&str> = members.iter().map(|p| p.name.as_str()).collect();
    for name in rules.crates.keys() {
        if !member_names.contains(name.as_str()) {
            violations.push(Violation::RuleForUnknownCrate { crate_name: name.clone() });
        }
    }

    for member in members {
        let Some(rule) = rules.crate_rule(&member.name) else {
            violations.push(Violation::CrateWithoutRule { crate_name: member.name.clone() });
            continue;
        };
        for (dep, ext) in &rule.external {
            if ext.rationale.trim().is_empty() {
                violations.push(Violation::EmptyRationale { crate_name: member.name.clone(), dependency: dep.clone() });
            }
        }
        let Some(node) = nodes.get(member.id.as_str()) else { continue };
        for edge in &node.deps {
            let Some(target) = packages_v.get(edge.pkg.as_str()) else { continue };
            let kinds: BTreeSet<DependencyKind> = edge.dep_kinds.iter().filter_map(|t| kind_of(t).ok()).collect();
            if member_ids.contains(target.id.as_str()) {
                if !rule.internal.contains(&target.name) {
                    violations.push(Violation::DisallowedInternal {
                        crate_name: member.name.clone(),
                        dependency: target.name.clone(),
                    });
                }
                continue;
            }
            if is_pulsar(target) && !rule.pulsar_direct {
                violations
                    .push(Violation::DirectPulsar { crate_name: member.name.clone(), dependency: target.name.clone() });
            }
            let source = target.source.clone().unwrap_or_else(|| "path dependency".to_string());
            match rule.external.get(&target.name) {
                None => {
                    for kind in kinds {
                        violations.push(Violation::UnlistedExternal {
                            crate_name: member.name.clone(),
                            dependency: target.name.clone(),
                            kind,
                        });
                    }
                }
                Some(ext) => {
                    for kind in kinds {
                        if !ext.kinds.contains(&kind) {
                            violations.push(Violation::DisallowedKind {
                                crate_name: member.name.clone(),
                                dependency: target.name.clone(),
                                kind,
                            });
                        }
                    }
                    if !source_matches(&source, ext.source.as_deref()) {
                        violations.push(Violation::WrongSource {
                            crate_name: member.name.clone(),
                            dependency: target.name.clone(),
                            source,
                        });
                    }
                }
            }
        }
        if !rule.pulsar_transitive
            && let Some(path) = pulsar_path(member, &packages_v, &nodes, &is_pulsar)
        {
            violations.push(Violation::TransitivePulsar { crate_name: member.name.clone(), path });
        }
    }
    violations
}

/// The shortest path from a member to a Pulsar package (breadth-first search). On the first
/// step every kind is followed; on later steps, normal and build dependencies.
fn pulsar_path(
    member: &Package,
    packages_v: &HashMap<&str, &Package>,
    nodes: &HashMap<&str, &Node>,
    is_pulsar: &dyn Fn(&Package) -> bool,
) -> Option<Vec<String>> {
    let mut previous: HashMap<&str, &str> = HashMap::new();
    let mut queue: VecDeque<(&str, bool)> = VecDeque::from([(member.id.as_str(), true)]);
    let mut seen: BTreeSet<&str> = BTreeSet::from([member.id.as_str()]);
    while let Some((id, first_step)) = queue.pop_front() {
        let Some(node) = nodes.get(id) else { continue };
        for edge in &node.deps {
            let followed = first_step
                || edge
                    .dep_kinds
                    .iter()
                    .any(|t| matches!(kind_of(t), Ok(DependencyKind::Normal | DependencyKind::Build)));
            if !followed || !seen.insert(edge.pkg.as_str()) {
                continue;
            }
            previous.insert(edge.pkg.as_str(), id);
            if packages_v.get(edge.pkg.as_str()).is_some_and(|p| is_pulsar(p)) {
                let mut path = vec![edge.pkg.as_str()];
                let mut current = edge.pkg.as_str();
                while let Some(&prev) = previous.get(current) {
                    path.push(prev);
                    current = prev;
                }
                path.reverse();
                return Some(
                    path.iter().map(|k| packages_v.get(k).map_or(k.to_string(), |p| p.name.clone())).collect(),
                );
            }
            queue.push_back((edge.pkg.as_str(), false));
        }
    }
    None
}
