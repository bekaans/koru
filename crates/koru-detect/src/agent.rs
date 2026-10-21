//! AI-agent process signatures (`packages/agents/*.toml`, `schemas/agent-signature.v1.json`).
//!
//! Matching rests on the exe path and the command line; both are under attacker control
//! (KT-02). A signature feeds actor-kind estimation and the "suspected hijacked agent"
//! class; decoy access produces a finding regardless of signatures.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

use crate::file::{directory_entries, read_regular_file, sanitize, serde_message};
use crate::normalize_path;
use crate::pattern::Pattern;
use crate::rule::valid_date;

/// A signature error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AgentError {
    /// A schema or semantic violation.
    #[error("{0}")]
    Invalid(String),
    /// A file or directory could not be read.
    #[error("{path}: {reason}")]
    Unreadable {
        /// The path.
        path: String,
        /// The reason.
        reason: String,
    },
}

/// An AI agent's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    /// A coding assistant (Claude Code, Cursor, Codex CLI, Aider, Gemini CLI ...).
    CodingAssistant,
    /// An MCP server.
    McpServer,
    /// An agent framework (LangGraph, CrewAI, AutoGen ...).
    AgentFramework,
}

impl AgentKind {
    /// Its name in the data file (`coding_assistant`, `mcp_server`, `agent_framework`).
    pub fn name(self) -> &'static str {
        match self {
            AgentKind::CodingAssistant => "coding_assistant",
            AgentKind::McpServer => "mcp_server",
            AgentKind::AgentFramework => "agent_framework",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignature {
    schema: u32,
    id: String,
    name: String,
    kind: AgentKind,
    references: Vec<String>,
    description: String,
    validation_date: String,
    condition: Vec<RawCondition>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCondition {
    exe_name: Option<Vec<String>>,
    exe_path_contains: Option<Vec<String>>,
    argv0_name: Option<Vec<String>>,
    script_name: Option<Vec<String>>,
    argument_contains: Option<Vec<String>>,
    python_module: Option<Vec<String>>,
}

/// A compiled condition: every present field must hold; in each field, any one value suffices.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct SignatureCondition {
    exe_name: Vec<Pattern>,
    exe_path_contains: Vec<String>,
    argv0_name: Vec<Pattern>,
    script_name: Vec<Pattern>,
    argument_contains: Vec<String>,
    python_module: Vec<Pattern>,
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The module name from a `python -m <module>` command line. Python options come before the
/// script name; the search stops at a script or `-c`.
fn python_module(command: &[String]) -> Option<&str> {
    let mut i = 1;
    while i < command.len() {
        let a = command[i].as_str();
        if a == "-m" {
            return command.get(i + 1).map(String::as_str);
        }
        if let Some(m) = a.strip_prefix("-m")
            && !m.is_empty()
            && !a.starts_with("--")
        {
            return Some(m);
        }
        if a == "-c" || a == "-" || !a.starts_with('-') {
            return None;
        }
        // Options whose value is a separate argument.
        i += if a == "-W" || a == "-X" { 2 } else { 1 };
    }
    None
}

impl SignatureCondition {
    fn matches(&self, exe: Option<&str>, command: &[String]) -> bool {
        let has_pattern = |patterns: &[Pattern], name: Option<&str>| {
            name.is_some_and(|a| patterns.iter().any(|d| d.matches_pattern(a)))
        };
        if !self.exe_name.is_empty() && !has_pattern(&self.exe_name, exe.map(base_name)) {
            return false;
        }
        if !self.exe_path_contains.is_empty()
            && !exe.is_some_and(|e| self.exe_path_contains.iter().any(|a| e.contains(a.as_str())))
        {
            return false;
        }
        if !self.argv0_name.is_empty() && !has_pattern(&self.argv0_name, command.first().map(|a| base_name(a))) {
            return false;
        }
        if !self.script_name.is_empty() && !has_pattern(&self.script_name, command.get(1).map(|a| base_name(a))) {
            return false;
        }
        if !self.argument_contains.is_empty()
            && !command.iter().any(|a| self.argument_contains.iter().any(|s| a.contains(s.as_str())))
        {
            return false;
        }
        if !self.python_module.is_empty() {
            let Some(module_name) = python_module(command) else {
                return false;
            };
            // A submodule like `aider.main` also matches the parent package.
            let upper = module_name.split('.').next().unwrap_or(module_name);
            if !self.python_module.iter().any(|d| d.matches_pattern(module_name) || d.matches_pattern(upper)) {
                return false;
            }
        }
        true
    }
}

/// A validated signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSignature {
    /// The identity (same as the file name).
    pub id: String,
    /// Readable name.
    pub name: String,
    /// The kind.
    pub kind: AgentKind,
    /// Resmî references (https).
    pub references: Vec<String>,
    /// The description.
    pub description: String,
    /// When the sources were last verified.
    pub validation_date: String,
    conditions: Vec<SignatureCondition>,
}

impl AgentSignature {
    /// Whether a process (exe and command line) matches the signature. The exe path is normalized lexically.
    pub fn matches(&self, exe: &str, command_line: &[String]) -> bool {
        let exe = normalize_path(exe);
        self.conditions.iter().any(|k| k.matches(exe.as_deref(), command_line))
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T, AgentError> {
    Err(AgentError::Invalid(message.into()))
}

/// Wildcard patterns: at least two literal characters; only `*` and `?` are special.
fn resolve_patterns(field: &str, values: Option<Vec<String>>) -> Result<Vec<Pattern>, AgentError> {
    let mut outcome = Vec::new();
    for d in string_list(field, values, 2)? {
        let pattern = Pattern::simple_token(&d, true);
        if pattern.literal_char_count() < 2 {
            return invalid(format!("{field}: a pattern must hold at least two literal characters: {}", sanitize(&d)));
        }
        outcome.push(pattern);
    }
    Ok(outcome)
}

fn resolve_substrings(field: &str, values: Option<Vec<String>>) -> Result<Vec<String>, AgentError> {
    let l = string_list(field, values, 3)?;
    if l.iter().any(|d| d.contains('\0')) {
        return invalid(format!("{field} cannot hold a NUL character"));
    }
    Ok(l)
}

/// Empty when absent; when present, 1-32 items, each `min..=256` characters.
fn string_list(field: &str, values: Option<Vec<String>>, min: usize) -> Result<Vec<String>, AgentError> {
    let Some(l) = values else {
        return Ok(Vec::new());
    };
    if l.is_empty() || l.len() > 32 {
        return invalid(format!("{field} must hold 1 to 32 values"));
    }
    for d in &l {
        let n = d.chars().count();
        if n < min || n > 256 {
            return invalid(format!("{field}: each value must be {min} to 256 characters: {}", sanitize(d)));
        }
    }
    Ok(l)
}

fn valid_id(k: &str) -> bool {
    (2..=64).contains(&k.len())
        && k.split('-').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
}

/// Parses and validates signature text (TOML).
pub fn parse_agent_signature(text: &str) -> Result<AgentSignature, AgentError> {
    let raw: RawSignature = toml::from_str(text).map_err(|e| AgentError::Invalid(serde_message(e.message())))?;
    if raw.schema != 1 {
        return invalid(format!("unsupported schema version {} (expected 1)", raw.schema));
    }
    if !valid_id(&raw.id) {
        return invalid(format!(
            "id must be lowercase letters, digits and hyphens (2-64 characters): {}",
            sanitize(&raw.id)
        ));
    }
    let name_len = raw.name.chars().count();
    if name_len == 0 || name_len > 80 {
        return invalid("name must be 1 to 80 characters");
    }
    let description_len = raw.description.chars().count();
    if description_len == 0 || description_len > 2000 {
        return invalid("description must be 1 to 2000 characters");
    }
    if raw.references.is_empty() || raw.references.len() > 8 {
        return invalid("references must hold 1 to 8 official links");
    }
    for k in &raw.references {
        if !k.starts_with("https://") || k.len() < 9 || k.len() > 512 || k.chars().any(|c| c.is_control() || c == ' ') {
            return invalid(format!("source must be an https link: {}", sanitize(k)));
        }
    }
    if !valid_date(&raw.validation_date) {
        return invalid(format!("validation_date must be a valid YYYY-MM-DD date: {}", sanitize(&raw.validation_date)));
    }
    if raw.condition.is_empty() || raw.condition.len() > 16 {
        return invalid("condition must hold 1 to 16 blocks");
    }
    let mut conditions = Vec::new();
    for h in raw.condition {
        let k = SignatureCondition {
            exe_name: resolve_patterns("exe_name", h.exe_name)?,
            exe_path_contains: resolve_substrings("exe_path_contains", h.exe_path_contains)?,
            argv0_name: resolve_patterns("argv0_name", h.argv0_name)?,
            script_name: resolve_patterns("script_name", h.script_name)?,
            argument_contains: resolve_substrings("argument_contains", h.argument_contains)?,
            python_module: resolve_patterns("python_module", h.python_module)?,
        };
        if k == SignatureCondition::default() {
            return invalid("a condition block cannot be empty: at least one field must be given");
        }
        conditions.push(k);
    }
    Ok(AgentSignature {
        id: raw.id,
        name: raw.name,
        kind: raw.kind,
        references: raw.references,
        description: raw.description,
        validation_date: raw.validation_date,
        conditions,
    })
}

/// A signature set; identities are unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSignatures {
    signatures: Vec<AgentSignature>,
}

impl AgentSignatures {
    /// Builds a set from signatures; duplicate ids are rejected.
    pub fn new(mut signatures: Vec<AgentSignature>) -> Result<AgentSignatures, AgentError> {
        let mut seen = BTreeSet::new();
        for i in &signatures {
            if !seen.insert(i.id.as_str()) {
                return invalid(format!("a duplicate signature identity: {}", sanitize(&i.id)));
            }
        }
        signatures.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(AgentSignatures { signatures })
    }

    /// An empty set.
    pub fn empty() -> AgentSignatures {
        AgentSignatures { signatures: Vec::new() }
    }

    /// Signatures (sorted by identity).
    pub fn signatures(&self) -> &[AgentSignature] {
        &self.signatures
    }

    /// The first signature a process matches (in id order).
    pub fn match_pattern(&self, exe: &str, command_line: &[String]) -> Option<&AgentSignature> {
        let normal = normalize_path(exe);
        self.signatures.iter().find(|i| i.conditions.iter().any(|k| k.matches(normal.as_deref(), command_line)))
    }
}

/// The largest signature file (bytes).
const MAX_FILES: u64 = 64 * 1024;

fn file_error(path: &Path, reason: String) -> AgentError {
    AgentError::Unreadable { path: sanitize(&path.display().to_string()), reason }
}

/// Reads every `.toml` signature in a directory; file name must equal the identity (all or nothing).
pub fn read_agent_signatures(directory: &Path) -> Result<AgentSignatures, AgentError> {
    let entries = directory_entries(directory).map_err(|n| file_error(directory, n))?;
    let mut signatures = Vec::new();
    for (name, path) in entries {
        let Some(root) = name.strip_suffix(".toml") else {
            continue;
        };
        let text = read_regular_file(&path, MAX_FILES).map_err(|n| file_error(&path, n))?;
        let signature =
            parse_agent_signature(&text).map_err(|e| AgentError::Invalid(format!("{}: {e}", sanitize(&name))))?;
        if signature.id != root {
            return invalid(format!(
                "the file name ({}) must equal the signature identity ({})",
                sanitize(root),
                sanitize(&signature.id)
            ));
        }
        signatures.push(signature);
    }
    if signatures.is_empty() {
        return invalid(format!("no .toml signature in the {} directory", sanitize(&directory.display().to_string())));
    }
    AgentSignatures::new(signatures)
}
