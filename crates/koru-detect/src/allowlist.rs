//! The allowlist (KT-01, KT-15).
//!
//! An entry applies only when the exe path and the identity (inode) of the file at that path
//! match together. A process name, command line, or user id alone can never be an entry: an
//! attacker can imitate those. Self-protection rules cannot be silenced by the allowlist.
//!
//! If a short-lived process's `/proc/<pid>/exe` identity cannot be read, the entry does not
//! apply and a finding is produced (the safe direction): the allowlist silences only
//! verifiable processes.

use std::collections::BTreeSet;
use std::path::Path;

use koru_event::ThreatClass;
use serde::Deserialize;

use crate::file::{read_regular_file, sanitize, serde_message};
use crate::{FileIdentity, IdentitySource, Rule, RulePack, normalize_path};

/// An allowlist error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AllowlistError {
    /// A schema or semantic violation.
    #[error("allowlist: {0}")]
    Invalid(String),
}

fn invalid<T>(message: impl Into<String>) -> Result<T, AllowlistError> {
    Err(AllowlistError::Invalid(message.into()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAllowlist {
    version: u32,
    #[serde(default)]
    input: Vec<RawEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    exe: String,
    #[serde(default)]
    rules: Vec<String>,
    rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryDefinition {
    exe: String,
    rules: Vec<String>,
    rationale: String,
}

/// A parsed but not yet resolved allowlist (inodes not read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistDefinition {
    entries: Vec<EntryDefinition>,
}

/// The maximum entry count.
const MAX_ENTRIES: usize = 1024;

/// Parses allowlist text (TOML):
///
/// ```toml
/// version = 1
/// [[input]]
/// exe = "/usr/local/bin/backup"      # absolute path, no wildcards
/// rules = ["decoy_credential_file"]  # empty: every rule except self-protection
/// rationale = "nightly backup"       # required
/// ```
pub fn parse_allowlist(text: &str) -> Result<AllowlistDefinition, AllowlistError> {
    let raw: RawAllowlist = toml::from_str(text).map_err(|e| AllowlistError::Invalid(serde_message(e.message())))?;
    if raw.version != 1 {
        return invalid(format!("unsupported version {} (expected 1)", raw.version));
    }
    if raw.input.len() > MAX_ENTRIES {
        return invalid(format!("at most {MAX_ENTRIES} entries allowed"));
    }
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    for g in raw.input {
        if normalize_path(&g.exe).as_deref() != Some(g.exe.as_str()) {
            return invalid(format!(
                "exe must be a normalized absolute path (no //, /./, .., or trailing /): {}",
                sanitize(&g.exe)
            ));
        }
        if g.exe == "/" || g.exe.contains(['*', '?']) || g.exe.chars().any(char::is_control) {
            return invalid(format!(
                "exe must be a full file path and cannot hold a wildcard or control character: {}",
                sanitize(&g.exe)
            ));
        }
        if g.rationale.trim().is_empty() {
            return invalid(format!("rationale required_arg: {}", sanitize(&g.exe)));
        }
        if g.rules.iter().any(|k| k.trim().is_empty()) {
            return invalid(format!("rules cannot hold an empty name: {}", sanitize(&g.exe)));
        }
        if !seen.insert(g.exe.clone()) {
            return invalid(format!("the same exe cannot be listed twice: {}", sanitize(&g.exe)));
        }
        entries.push(EntryDefinition { exe: g.exe, rules: g.rules, rationale: g.rationale });
    }
    Ok(AllowlistDefinition { entries })
}

/// Reads (a regular file, at most 256 KiB) and parses an allowlist file.
pub fn read_allowlist(file: &Path) -> Result<AllowlistDefinition, AllowlistError> {
    let text = read_regular_file(file, 256 * 1024)
        .map_err(|reason| AllowlistError::Invalid(format!("{}: {reason}", sanitize(&file.display().to_string()))))?;
    parse_allowlist(&text)
}

impl AllowlistDefinition {
    /// Reads the identity of the file at each entry's exe path and checks rule names against
    /// the pack. Errors if a file is missing, a rule is undefined, or a self-protection rule
    /// is listed.
    pub fn resolve(&self, source: &dyn IdentitySource, rules: &RulePack) -> Result<Allowlist, AllowlistError> {
        let mut entries = Vec::with_capacity(self.entries.len());
        for g in &self.entries {
            let Some(file) = source.path_id(&g.exe) else {
                return invalid(format!("the exe file was not found (identity unreadable): {}", sanitize(&g.exe)));
            };
            for name in &g.rules {
                match rules.find(name) {
                    None => return invalid(format!("an undefined rule: {}", sanitize(name))),
                    Some(k) if k.threat_class() == ThreatClass::SelfProtection => {
                        return invalid(format!(
                            "self-protection rules cannot be silenced by the allowlist: {}",
                            sanitize(name)
                        ));
                    }
                    Some(_) => {}
                }
            }
            entries.push(Entry {
                exe: g.exe.clone(),
                file,
                rules: g.rules.iter().cloned().collect(),
                rationale: g.rationale.clone(),
            });
        }
        Ok(Allowlist { entries })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    exe: String,
    file: FileIdentity,
    /// Empty: every rule except self-protection.
    rules: BTreeSet<String>,
    rationale: String,
}

/// A resolved allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Allowlist {
    entries: Vec<Entry>,
}

impl Allowlist {
    /// An empty list.
    pub fn empty() -> Allowlist {
        Allowlist::default()
    }

    /// The entry count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether it is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The exe identity of the entry matching the event's (normalized) exe path and covering
    /// the rule. No entry applies to a self-protection rule. For suppression, the process's
    /// real exe must also match this identity and the same path
    /// (`IdentitySource::verify_process_exe`): both conditions together, so "open then exec"
    /// cannot slip past.
    pub(crate) fn candidate_file(&self, event_exe_normal: &str, rule: &Rule) -> Option<FileIdentity> {
        if rule.threat_class() == ThreatClass::SelfProtection {
            return None;
        }
        self.entries
            .iter()
            .find(|g| g.exe == event_exe_normal && (g.rules.is_empty() || g.rules.contains(rule.name())))
            .map(|g| g.file)
    }

    /// Entries as `(exe path, rationale)`; for reports and auditing.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|g| (g.exe.as_str(), g.rationale.as_str()))
    }
}
