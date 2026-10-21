//! Sigma-compatible rules: schema v1 (`schemas/rule-pack.v1.json`), validation and evaluation.
//!
//! Rule files come from contributors and are read by the root agent (KT-12, KT-35): YAML
//! first passes a bounded parser (`yaml_json`), then `deny_unknown_fields` types and semantic
//! checks (ATT&CK, field names, modifiers, the condition). Evaluation uses a linear bounded
//! wildcard matcher; there is no regex.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use koru_event::{EventType, MitreTechnique, ThreatClass};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::file::{directory_entries, io_reason, read_regular_file, sanitize, serde_message};
use crate::pattern::Pattern;
use crate::yaml::MAX_ENTRIES;
use crate::{AttackStatus, FieldSet, FieldValue, SUPPORTED_FIELDS, attack_tactic, attack_technique, yaml_json};

/// A rule error. The message names the offending field and the reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    /// YAML did not parse or hit a safety bound.
    #[error("YAML: {0}")]
    Yaml(String),
    /// A schema violation (a missing, unknown, or mistyped field).
    #[error("schema: {0}")]
    Schema(String),
    /// A semantic violation (ATT&CK, field name, modifier, condition, date, uniqueness).
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

/// A rule's severity (Sigma `level`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// informational
    Info,
    /// low
    Low,
    /// medium
    Medium,
    /// high
    High,
    /// critical
    Critical,
}

impl Level {
    /// Its Sigma name (`informational`, `low`, `medium`, `high`, `critical`).
    pub fn sigma_name(self) -> &'static str {
        match self {
            Level::Info => "informational",
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
            Level::Critical => "critical",
        }
    }
}

/// A rule's state (Sigma `status`). `deprecated` and `unsupported` are not evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleStatus {
    /// stable
    Stable,
    /// test
    Test,
    /// experimental
    Experimental,
    /// deprecated
    Deprecated,
    /// unsupported
    Unsupported,
}

// ---------------------------------------------------------------------------------------------
// Raw (schema) types
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    title: String,
    id: String,
    name: String,
    related: Option<Vec<RawRelated>>,
    taxonomy: Option<String>,
    status: RawStatus,
    description: String,
    license: Option<String>,
    references: Option<Vec<String>>,
    author: Option<String>,
    date: String,
    modified: Option<String>,
    logsource: RawSource,
    detection: Map<String, Value>,
    fields: Option<Vec<String>>,
    falsepositives: Option<Vec<String>>,
    level: RawLevel,
    tags: Vec<String>,
    scope: Option<Vec<String>>,
    koru: RawKoru,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelated {
    id: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawStatus {
    Stable,
    Test,
    Experimental,
    Deprecated,
    Unsupported,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawLevel {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSource {
    product: String,
    category: Option<String>,
    service: Option<String>,
    definition: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKoru {
    threat_class: ThreatClass,
}

// ---------------------------------------------------------------------------------------------
// Compiled rule
// ---------------------------------------------------------------------------------------------

/// The event source a rule watches (Sigma `logsource`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleSource {
    /// `process_creation`: `process_executed`.
    ProcessCreation,
    /// `process_termination`: `process_exited`.
    ProcessTermination,
    /// `file_access`: `file_opened`.
    FileAccess,
    /// `file_event`: all file and directory events.
    FileEvent,
    /// `file_delete`: `file_deleted` and `directory_deleted`.
    FileDelete,
    /// `file_rename`: `file_renamed`.
    FileRename,
    /// `network_connection`: `network_connection` and `network_accept`.
    NetworkConnection,
    /// `service: koru`: only events Koru itself produced.
    Koru,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FieldConditionKind {
    /// `|exists: true|false`
    Present(bool),
    /// A `null` value: the field is absent.
    Empty,
    /// Value patterns; with `all_values`, `|all` (and), otherwise or.
    Values { patterns: Vec<Pattern>, all_values: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FieldCondition {
    field: String,
    kind: FieldConditionKind,
}

/// A selection: one of the alternatives (or); within one alternative, all field conditions (and).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Choice {
    name: String,
    alternatives: Vec<Vec<FieldCondition>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Condition {
    Select(usize),
    Not(Box<Condition>),
    And(Vec<Condition>),
    Or(Vec<Condition>),
    OneOf(Vec<usize>),
    AllOf(Vec<usize>),
}

/// A validated rule.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    name: String,
    id: String,
    title: String,
    severity: Level,
    status: RuleStatus,
    threat_class: ThreatClass,
    attack: Vec<MitreTechnique>,
    source: RuleSource,
    selections: Vec<Choice>,
    condition: Condition,
}

impl Rule {
    /// Readable name (`name`); `detection.rule` in findings.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// UUID (`id`).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The title (`title`).
    pub fn title(&self) -> &str {
        &self.title
    }

    /// The severity.
    pub fn severity(&self) -> Level {
        self.severity
    }

    /// StateDir.
    pub fn status(&self) -> RuleStatus {
        self.status
    }

    /// The threat class (`koru.threat_class`).
    pub fn threat_class(&self) -> ThreatClass {
        self.threat_class
    }

    /// ATT&CK techniques (from tags; at least one, sorted, deduplicated).
    pub fn attack(&self) -> &[MitreTechnique] {
        &self.attack
    }

    /// Whether the rule is evaluated (`deprecated` and `unsupported` are not).
    pub fn is_evaluated(&self) -> bool {
        !matches!(self.status, RuleStatus::Deprecated | RuleStatus::Unsupported)
    }

    /// Whether the rule's `logsource` covers this event. `is_koru_event`: did Koru itself
    /// produce the event; Koru's events go only to `service: koru` rules, sensor events only
    /// to `category` rules.
    pub(crate) fn matches_source(&self, kind: EventType, is_koru_event: bool) -> bool {
        use EventType::{
            DirectoryCreated, DirectoryDeleted, FileCreated, FileDeleted, FileLink, FileOpened, FileRenamed,
            NetworkAccept, NetworkConnection, ProcessExecuted, ProcessExited,
        };
        if (self.source == RuleSource::Koru) != is_koru_event {
            return false;
        }
        match self.source {
            RuleSource::Koru => true,
            RuleSource::ProcessCreation => kind == ProcessExecuted,
            RuleSource::ProcessTermination => kind == ProcessExited,
            RuleSource::FileAccess => kind == FileOpened,
            RuleSource::FileEvent => matches!(
                kind,
                FileOpened | FileCreated | FileDeleted | FileRenamed | FileLink | DirectoryCreated | DirectoryDeleted
            ),
            RuleSource::FileDelete => matches!(kind, FileDeleted | DirectoryDeleted),
            RuleSource::FileRename => kind == FileRenamed,
            RuleSource::NetworkConnection => matches!(kind, NetworkConnection | NetworkAccept),
        }
    }

    /// Whether the `detection` section matches the fields (logsource ignored).
    pub fn matches_pattern(&self, fields: &FieldSet) -> bool {
        let mut cache = vec![None; self.selections.len()];
        evaluate_condition(&self.condition, &self.selections, fields, &mut cache)
    }
}

fn make_text(d: &FieldValue) -> Cow<'_, str> {
    match d {
        FieldValue::Text(m) => Cow::Borrowed(m.as_str()),
        FieldValue::Bool(b) => Cow::Borrowed(if *b { "true" } else { "false" }),
        FieldValue::Number(n) => Cow::Owned(n.to_string()),
    }
}

fn condition_holds(condition: &FieldCondition, fields: &FieldSet) -> bool {
    let value = fields.get(&condition.field);
    match &condition.kind {
        FieldConditionKind::Present(wanted) => value.is_some() == *wanted,
        FieldConditionKind::Empty => value.is_none(),
        FieldConditionKind::Values { patterns, all_values } => match value {
            None => false,
            Some(d) => {
                let text = make_text(d);
                if *all_values {
                    patterns.iter().all(|p| p.matches_pattern(&text))
                } else {
                    patterns.iter().any(|p| p.matches_pattern(&text))
                }
            }
        },
    }
}

fn evaluate_condition(k: &Condition, selections: &[Choice], fields: &FieldSet, cache: &mut [Option<bool>]) -> bool {
    match k {
        Condition::Select(i) => selection_matches(*i, selections, fields, cache),
        Condition::Not(i) => !evaluate_condition(i, selections, fields, cache),
        Condition::And(operands) => operands.iter().all(|i| evaluate_condition(i, selections, fields, cache)),
        Condition::Or(operands) => operands.iter().any(|i| evaluate_condition(i, selections, fields, cache)),
        Condition::OneOf(idler) => idler.iter().any(|i| selection_matches(*i, selections, fields, cache)),
        Condition::AllOf(idler) => idler.iter().all(|i| selection_matches(*i, selections, fields, cache)),
    }
}

fn selection_matches(i: usize, selections: &[Choice], fields: &FieldSet, cache: &mut [Option<bool>]) -> bool {
    if let Some(outcome) = cache[i] {
        return outcome;
    }
    let outcome = selections[i].alternatives.iter().any(|child| child.iter().all(|s| condition_holds(s, fields)));
    cache[i] = Some(outcome);
    outcome
}

// ---------------------------------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------------------------------

fn invalid<T>(message: impl Into<String>) -> Result<T, RuleError> {
    Err(RuleError::Invalid(message.into()))
}

fn schema<T>(message: impl Into<String>) -> Result<T, RuleError> {
    Err(RuleError::Schema(message.into()))
}

/// Rewrites a serde_json error message in plain words.
fn serde_error(e: &serde_json::Error) -> String {
    serde_message(&e.to_string())
}

fn non_empty(name: &str, d: &str) -> Result<(), RuleError> {
    if d.trim().is_empty() { schema(format!("{name} cannot be empty")) } else { Ok(()) }
}

fn list_items_non_empty(name: &str, l: &Option<Vec<String>>) -> Result<(), RuleError> {
    for o in l.iter().flatten() {
        non_empty(name, o)?;
    }
    Ok(())
}

pub(crate) fn valid_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

pub(crate) fn valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let number = |a: usize, z: usize| -> Option<u32> {
        let p = &s[a..z];
        if p.bytes().all(|c| c.is_ascii_digit()) { p.parse().ok() } else { None }
    };
    let (Some(y), Some(a), Some(g)) = (number(0, 4), number(5, 7), number(8, 10)) else {
        return false;
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days_in_month = match a {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    y >= 1 && (1..=days_in_month).contains(&g)
}

fn resolve_source(k: &RawSource) -> Result<RuleSource, RuleError> {
    if k.product != "linux" {
        return schema(format!("logsource.product can only be linux: {}", sanitize(&k.product)));
    }
    if let Some(d) = &k.definition {
        non_empty("logsource.definition", d)?;
    }
    match (&k.category, &k.service) {
        (Some(_), Some(_)) => schema("logsource: category and service cannot be combined"),
        (None, None) => schema("logsource: category or service is required"),
        (None, Some(s)) if s == "koru" => Ok(RuleSource::Koru),
        (None, Some(s)) => schema(format!("logsource.service can only be koru: {}", sanitize(s))),
        (Some(c), None) => match c.as_str() {
            "process_creation" => Ok(RuleSource::ProcessCreation),
            "process_termination" => Ok(RuleSource::ProcessTermination),
            "file_access" => Ok(RuleSource::FileAccess),
            "file_event" => Ok(RuleSource::FileEvent),
            "file_delete" => Ok(RuleSource::FileDelete),
            "file_rename" => Ok(RuleSource::FileRename),
            "network_connection" => Ok(RuleSource::NetworkConnection),
            other => schema(format!("logsource.category is not supported: {}", sanitize(other))),
        },
    }
}

/// Validates ATT&CK tags: only the `attack.` namespace; at least one technique; techniques
/// valid in ATT&CK v20.0 (not revoked, not deprecated); tactics exist in the catalog and
/// belong to at least one tagged technique.
fn resolve_tags(tags: &[String]) -> Result<Vec<MitreTechnique>, RuleError> {
    let mut techniques = BTreeSet::new();
    let mut tactics: Vec<&str> = Vec::new();
    for e in tags {
        let Some(remaining) = e.strip_prefix("attack.") else {
            return invalid(format!("tag: an unknown namespace (only attack. is used): {}", sanitize(e)));
        };
        let technique_tag = remaining.strip_prefix('t').is_some_and(|r| {
            let (primary, child) = match r.split_once('.') {
                Some((a, b)) => (a, Some(b)),
                None => (r, None),
            };
            primary.len() == 4
                && primary.bytes().all(|b| b.is_ascii_digit())
                && child.is_none_or(|a| a.len() == 3 && a.bytes().all(|b| b.is_ascii_digit()))
        });
        if technique_tag {
            let id = remaining.to_ascii_uppercase();
            match attack_technique(&id) {
                None => return invalid(format!("no such technique in ATT&CK v20.0: {id}")),
                Some(t) => match &t.status {
                    AttackStatus::Current => {}
                    AttackStatus::Revoked { replaced_by: replacement } if !replacement.is_empty() => {
                        return invalid(format!(
                            "{id} is revoked in ATT&CK v20.0; use {} instead",
                            replacement.join(", ")
                        ));
                    }
                    AttackStatus::Revoked { .. } => return invalid(format!("{id} is revoked in ATT&CK v20.0")),
                    AttackStatus::Deprecated => {
                        return invalid(format!("{id} is deprecated in ATT&CK v20.0"));
                    }
                },
            }
            match MitreTechnique::new(&id) {
                Ok(m) => {
                    techniques.insert(m);
                }
                Err(h) => return invalid(h),
            }
        } else {
            tactics.push(remaining);
        }
    }
    if techniques.is_empty() {
        return invalid("no ATT&CK mapping: at least one technique tag is required (e.g. attack.t1552.001)");
    }
    for t in tactics {
        let short = t.replace('_', "-");
        if attack_tactic(&short).is_none() {
            return invalid(format!("no such tactic in ATT&CK v20.0: {}", sanitize(t)));
        }
        let matched =
            techniques.iter().any(|m| attack_technique(m.as_str()).is_some_and(|a| a.tactics.contains(&short)));
        if !matched {
            return invalid(format!(
                "the tactic tag belongs to none of the techniques tagged attack.{}",
                sanitize(&short)
            ));
        }
    }
    Ok(techniques.into_iter().collect())
}

const KEYWORDS: &[&str] = &["and", "or", "not", "of", "all", "them"];
const MAX_CONDITION_DEPTH: usize = 32;
const MAX_CONDITION_LEN: usize = 4096;

fn valid_identifier(name: &str) -> bool {
    let mut k = name.chars();
    name.len() <= 64
        && k.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && k.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Modifier {
    Contains,
    StartsWith,
    EndsWith,
    All,
    Exists,
    Cased,
}

fn resolve_modifier(name: &str) -> Result<Modifier, RuleError> {
    match name {
        "contains" => Ok(Modifier::Contains),
        "startswith" => Ok(Modifier::StartsWith),
        "endswith" => Ok(Modifier::EndsWith),
        "all" => Ok(Modifier::All),
        "exists" => Ok(Modifier::Exists),
        "cased" => Ok(Modifier::Cased),
        other => invalid(format!(
            "unsupported modifier: {} (supported: contains, startswith, endswith, all, exists, cased)",
            sanitize(other)
        )),
    }
}

/// Converts one value (string, integer, boolean) to pattern text.
fn value_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn resolve_field_condition(key: &str, value: &Value) -> Result<FieldCondition, RuleError> {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or("");
    let field_valid = field.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
    if !field_valid {
        return invalid(format!("an invalid field name: {}", sanitize(field)));
    }
    if !SUPPORTED_FIELDS.contains(&field) {
        return invalid(format!("unsupported field: {} (supported: {})", sanitize(field), SUPPORTED_FIELDS.join(", ")));
    }
    let mut modifiers = Vec::new();
    for p in parts {
        let d = resolve_modifier(p)?;
        if modifiers.contains(&d) {
            return invalid(format!("{}: the same modifier cannot be used twice: {p}", sanitize(field)));
        }
        modifiers.push(d);
    }
    let has = |d: Modifier| modifiers.contains(&d);

    if has(Modifier::Exists) {
        if modifiers.len() != 1 {
            return invalid(format!("{}: exists cannot be combined with another modifier", sanitize(field)));
        }
        return match value {
            Value::Bool(b) => Ok(FieldCondition { field: field.to_string(), kind: FieldConditionKind::Present(*b) }),
            _ => invalid(format!("{}: the exists value must be true or false", sanitize(field))),
        };
    }
    let match_kinds = [Modifier::Contains, Modifier::StartsWith, Modifier::EndsWith];
    if match_kinds.iter().filter(|d| has(**d)).count() > 1 {
        return invalid(format!("{}: contains, startswith, and endswith cannot be combined", sanitize(field)));
    }
    if matches!(value, Value::Null) {
        if modifiers.is_empty() {
            return Ok(FieldCondition { field: field.to_string(), kind: FieldConditionKind::Empty });
        }
        return invalid(format!("{}: a null value cannot be used with a modifier", sanitize(field)));
    }
    let values: Vec<&Value> = match value {
        Value::Array(l) if l.is_empty() => {
            return invalid(format!("{}: a value list cannot be empty", sanitize(field)));
        }
        Value::Array(l) => l.iter().collect(),
        single => vec![single],
    };
    let all_values = has(Modifier::All);
    if all_values && !matches!(value, Value::Array(l) if l.len() >= 2) {
        return invalid(format!("{}: all needs a list of at least two values", sanitize(field)));
    }
    let case_sensitive = has(Modifier::Cased);
    let mut patterns = Vec::with_capacity(values.len());
    for v in values {
        let Some(text) = value_text(v) else {
            return invalid(format!("{}: values must be strings, integers, or booleans", sanitize(field)));
        };
        let d = Pattern::sigma(&text, case_sensitive);
        patterns.push(if has(Modifier::Contains) {
            d.containing()
        } else if has(Modifier::StartsWith) {
            d.starting_with()
        } else if has(Modifier::EndsWith) {
            d.ending_with()
        } else {
            d
        });
    }
    Ok(FieldCondition { field: field.to_string(), kind: FieldConditionKind::Values { patterns, all_values } })
}

fn resolve_selection(name: &str, value: &Value) -> Result<Choice, RuleError> {
    let maps: Vec<&Value> = match value {
        Value::Array(l) if l.is_empty() => return invalid(format!("selection {name}: a list cannot be empty")),
        Value::Array(l) => l.iter().collect(),
        single => vec![single],
    };
    let mut alternatives = Vec::new();
    for h in maps {
        let Value::Object(map) = h else {
            return invalid(format!(
                "selection {name}: keyword lists without field names are unsupported; a selection must be field: value pairs"
            ));
        };
        if map.is_empty() {
            return invalid(format!("selection {name}: cannot be empty"));
        }
        let mut conditions = Vec::with_capacity(map.len());
        for (key, v) in map {
            conditions.push(resolve_field_condition(key, v).map_err(|e| match e {
                RuleError::Invalid(m) => RuleError::Invalid(format!("selection {name}: {m}")),
                other => other,
            })?);
        }
        alternatives.push(conditions);
    }
    Ok(Choice { name: name.to_string(), alternatives })
}

// --- condition ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token<'a> {
    Open,
    Close,
    Word(&'a str),
}

fn tokenize(text: &str) -> Result<Vec<Token<'_>>, String> {
    let mut tokens = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        let separator = c.is_whitespace() || c == '(' || c == ')';
        if separator {
            if let Some(b) = start.take() {
                tokens.push(Token::Word(&text[b..i]));
            }
            match c {
                '(' => tokens.push(Token::Open),
                ')' => tokens.push(Token::Close),
                _ => {}
            }
        } else {
            if !(c.is_ascii_alphanumeric() || c == '_' || c == '*') {
                return Err(format!("an invalid character in the condition: {}", sanitize(&c.to_string())));
            }
            start.get_or_insert(i);
        }
    }
    if let Some(b) = start {
        tokens.push(Token::Word(&text[b..]));
    }
    Ok(tokens)
}

struct ConditionParser<'a> {
    tokens: Vec<Token<'a>>,
    pos: usize,
    selections: &'a [Choice],
    depth: usize,
}

impl<'a> ConditionParser<'a> {
    fn current(&self) -> Option<Token<'a>> {
        self.tokens.get(self.pos).copied()
    }

    fn is_word(&self, s: &str) -> bool {
        self.current() == Some(Token::Word(s))
    }

    fn descend(&mut self) -> Result<(), String> {
        self.depth += 1;
        if self.depth > MAX_CONDITION_DEPTH {
            return Err(format!("the condition is nested too deeply (at most {MAX_CONDITION_DEPTH} levels)"));
        }
        Ok(())
    }

    fn fn_or(&mut self) -> Result<Condition, String> {
        self.descend()?;
        let mut branches = vec![self.fn_and()?];
        while self.is_word("or") {
            self.pos += 1;
            branches.push(self.fn_and()?);
        }
        self.depth -= 1;
        Ok(if branches.len() == 1 { branches.remove(0) } else { Condition::Or(branches) })
    }

    fn fn_and(&mut self) -> Result<Condition, String> {
        let mut branches = vec![self.fn_not()?];
        while self.is_word("and") {
            self.pos += 1;
            branches.push(self.fn_not()?);
        }
        Ok(if branches.len() == 1 { branches.remove(0) } else { Condition::And(branches) })
    }

    fn fn_not(&mut self) -> Result<Condition, String> {
        if self.is_word("not") {
            self.pos += 1;
            self.descend()?;
            let inner = self.fn_not()?;
            self.depth -= 1;
            return Ok(Condition::Not(Box::new(inner)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Condition, String> {
        match self.current() {
            None => Err("condition expression is missing".to_string()),
            Some(Token::Close) => Err("unexpected ')' in condition".to_string()),
            Some(Token::Open) => {
                self.pos += 1;
                let inner = self.fn_or()?;
                if self.current() != Some(Token::Close) {
                    return Err("missing ')' in condition".to_string());
                }
                self.pos += 1;
                Ok(inner)
            }
            Some(Token::Word(s)) => {
                self.pos += 1;
                if s == "1" || s == "all" {
                    return self.of(s == "all");
                }
                if s.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(format!("condition: only '1 of' and 'all of' are supported: {s} of"));
                }
                if KEYWORDS.contains(&s) || s.contains('*') {
                    return Err(format!("an unexpected word in the condition: {}", sanitize(s)));
                }
                match self.selections.iter().position(|x| x.name == s) {
                    Some(i) => Ok(Condition::Select(i)),
                    None => Err(format!("condition: an undefined identifier: {}", sanitize(s))),
                }
            }
        }
    }

    /// `1 of <target>` and `all of <target>` (`1` or `all` was read).
    fn of(&mut self, all_values: bool) -> Result<Condition, String> {
        if !self.is_word("of") {
            return Err("condition: 'of' expected".to_string());
        }
        self.pos += 1;
        let Some(Token::Word(target)) = self.current() else {
            return Err("condition: expected 'them' or a pattern after 'of'".to_string());
        };
        self.pos += 1;
        let idler: Vec<usize> = if target == "them" {
            (0..self.selections.len()).filter(|i| !self.selections[*i].name.starts_with('_')).collect()
        } else {
            let pattern = Pattern::simple_token(target, true);
            (0..self.selections.len()).filter(|i| pattern.matches_pattern(&self.selections[*i].name)).collect()
        };
        if idler.is_empty() {
            return Err(format!("condition: '{}' matches no selection", sanitize(target)));
        }
        Ok(if all_values { Condition::AllOf(idler) } else { Condition::OneOf(idler) })
    }
}

fn resolve_condition(text: &str, selections: &[Choice]) -> Result<Condition, RuleError> {
    if text.len() > MAX_CONDITION_LEN {
        return invalid(format!("the condition is too long (at most {MAX_CONDITION_LEN} characters)"));
    }
    let tokens = tokenize(text).map_err(RuleError::Invalid)?;
    let mut a = ConditionParser { tokens, pos: 0, selections, depth: 0 };
    let k = a.fn_or().map_err(RuleError::Invalid)?;
    if let Some(leap) = a.current() {
        let ne = match leap {
            Token::Open => "(".to_string(),
            Token::Close => ")".to_string(),
            Token::Word(s) => sanitize(s),
        };
        return invalid(format!("unexpected token in condition: {ne}"));
    }
    Ok(k)
}

fn resolve_detection(detection: &Map<String, Value>) -> Result<(Vec<Choice>, Condition), RuleError> {
    let mut selections = Vec::new();
    let mut condition_texts: Vec<String> = Vec::new();
    for (name, value) in detection {
        if name == "condition" {
            let string_list: Vec<&Value> = match value {
                Value::Array(l) => l.iter().collect(),
                single => vec![single],
            };
            if string_list.is_empty() {
                return schema("detection.condition cannot be empty");
            }
            for v in string_list {
                match v {
                    Value::String(s) if !s.trim().is_empty() => condition_texts.push(s.clone()),
                    _ => return schema("detection.condition must be a string or a list of strings"),
                }
            }
            continue;
        }
        if !valid_identifier(name) {
            return invalid(format!("an invalid selection name: {}", sanitize(name)));
        }
        if KEYWORDS.contains(&name.as_str()) {
            return invalid(format!("a selection name cannot be a keyword: {name}"));
        }
        selections.push(resolve_selection(name, value)?);
    }
    if condition_texts.is_empty() {
        return schema("detection.condition required_arg");
    }
    if selections.is_empty() {
        return schema("detection must hold at least one selection");
    }
    let mut conditions = Vec::new();
    for m in &condition_texts {
        conditions.push(resolve_condition(m, &selections)?);
    }
    let condition = if conditions.len() == 1 { conditions.remove(0) } else { Condition::Or(conditions) };
    Ok((selections, condition))
}

fn from_rule_value(value: Value) -> Result<Rule, RuleError> {
    if !value.is_object() {
        return schema("a rule must be a YAML mapping (key: value)");
    }
    let raw: RawRule = serde_json::from_value(value).map_err(|e| RuleError::Schema(serde_error(&e)))?;

    let title_len = raw.title.chars().count();
    if title_len == 0 || title_len > 256 {
        return schema("title must be 1 to 256 characters");
    }
    if !valid_uuid(&raw.id) {
        return schema(format!("id must be a lowercase UUID: {}", sanitize(&raw.id)));
    }
    let name_valid = (3..=64).contains(&raw.name.len())
        && raw.name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !name_valid {
        return schema(format!("name must be 3-64 characters of a-z, 0-9, and _ only: {}", sanitize(&raw.name)));
    }
    if raw.description.trim().is_empty() || raw.description.len() > 65535 {
        return schema("description cannot be empty and can be at most 65535 bytes");
    }
    if !valid_date(&raw.date) {
        return schema(format!("date must be a valid YYYY-MM-DD date: {}", sanitize(&raw.date)));
    }
    if let Some(m) = &raw.modified
        && !valid_date(m)
    {
        return schema(format!("modified must be a valid YYYY-MM-DD date: {}", sanitize(m)));
    }
    if let Some(t) = &raw.taxonomy
        && t != "sigma"
    {
        return schema(format!("taxonomy can only be sigma: {}", sanitize(t)));
    }
    for (name, value) in [("license", &raw.license), ("author", &raw.author)] {
        if let Some(d) = value {
            non_empty(name, d)?;
        }
    }
    list_items_non_empty("references", &raw.references)?;
    list_items_non_empty("fields", &raw.fields)?;
    list_items_non_empty("falsepositives", &raw.falsepositives)?;
    list_items_non_empty("scope", &raw.scope)?;
    if let Some(l) = &raw.related {
        if l.is_empty() {
            return schema("related cannot be empty");
        }
        for i in l {
            if !valid_uuid(&i.id) {
                return schema(format!("related.id must be a lowercase UUID: {}", sanitize(&i.id)));
            }
            if !["derived", "obsolete", "merged", "renamed", "similar"].contains(&i.kind.as_str()) {
                return schema(format!("related.type is invalid: {}", sanitize(&i.kind)));
            }
        }
    }
    if raw.tags.is_empty() {
        return schema("tags cannot be empty");
    }

    let source = resolve_source(&raw.logsource)?;
    let attack = resolve_tags(&raw.tags)?;
    let (selections, condition) = resolve_detection(&raw.detection)?;

    Ok(Rule {
        name: raw.name,
        id: raw.id,
        title: raw.title,
        severity: match raw.level {
            RawLevel::Informational => Level::Info,
            RawLevel::Low => Level::Low,
            RawLevel::Medium => Level::Medium,
            RawLevel::High => Level::High,
            RawLevel::Critical => Level::Critical,
        },
        status: match raw.status {
            RawStatus::Stable => RuleStatus::Stable,
            RawStatus::Test => RuleStatus::Test,
            RawStatus::Experimental => RuleStatus::Experimental,
            RawStatus::Deprecated => RuleStatus::Deprecated,
            RawStatus::Unsupported => RuleStatus::Unsupported,
        },
        threat_class: raw.koru.threat_class,
        attack,
        source,
        selections,
        condition,
    })
}

/// Parses and validates rule text (a single YAML document).
pub fn parse_rule(text: &str) -> Result<Rule, RuleError> {
    from_rule_value(yaml_json(text)?)
}

/// Whether the file name (no extension) equals the rule name; an error if not.
fn check_file_name(file: &Path, rule: &Rule) -> Result<(), RuleError> {
    let root = file.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    if root == rule.name {
        Ok(())
    } else {
        invalid(format!(
            "the file name ({}) must equal the rule's name field ({})",
            sanitize(&root),
            sanitize(&rule.name)
        ))
    }
}

fn file_error(file: &Path, reason: String) -> RuleError {
    RuleError::Unreadable { path: sanitize(&file.display().to_string()), reason }
}

/// Reads a rule file; the file name (no extension) must equal the rule's `name` field.
pub fn read_rule_file(file: &Path) -> Result<Rule, RuleError> {
    let text = read_regular_file(file, MAX_ENTRIES as u64).map_err(|n| file_error(file, n))?;
    let rule = parse_rule(&text)?;
    check_file_name(file, &rule)?;
    Ok(rule)
}

/// Validated rules; `id` and `name` are unique.
#[derive(Debug, Clone, PartialEq)]
pub struct RulePack {
    rules: Vec<Rule>,
}

fn find_duplicates<'a>(rules: impl Iterator<Item = (&'a str, &'a str)>) -> Option<String> {
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for (id, name) in rules {
        if !ids.insert(id) {
            return Some(format!("a duplicate rule identity (id): {id}"));
        }
        if !names.insert(name) {
            return Some(format!("a duplicate rule name (name): {}", sanitize(name)));
        }
    }
    None
}

impl RulePack {
    /// Builds a pack from rules; a duplicate `id` or `name` is rejected.
    pub fn new(mut rules: Vec<Rule>) -> Result<RulePack, RuleError> {
        if let Some(h) = find_duplicates(rules.iter().map(|k| (k.id.as_str(), k.name.as_str()))) {
            return invalid(h);
        }
        rules.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(RulePack { rules })
    }

    /// Rules (sorted by name).
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// A rule by name.
    pub fn find(&self, name: &str) -> Option<&Rule> {
        self.rules.binary_search_by(|k| k.name.as_str().cmp(name)).ok().map(|i| &self.rules[i])
    }
}

/// Reads every `.yml` rule in a directory. Errors (all or nothing) if one rule is invalid,
/// a `.yaml` file is present, or the directory holds no rule.
pub fn read_rule_pack(directory: &Path) -> Result<RulePack, RuleError> {
    let entries = directory_entries(directory).map_err(|n| file_error(directory, n))?;
    let mut rules = Vec::new();
    for (name, path) in entries {
        if name.ends_with(".yaml") {
            return Err(file_error(&path, "rule files must use the .yml extension (.yaml is not read)".to_string()));
        }
        if name.ends_with(".yml") {
            rules.push(read_rule_file(&path).map_err(|e| match e {
                RuleError::Unreadable { .. } => e,
                other => RuleError::Invalid(format!("{}: {other}", sanitize(&name))),
            })?);
        }
    }
    if rules.is_empty() {
        return invalid(format!("no .yml rule in the {} directory", sanitize(&directory.display().to_string())));
    }
    RulePack::new(rules)
}

/// A per-file report for `koru rule validate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleValidationReport {
    /// Each rule file's result (sorted by file name).
    pub files: Vec<RuleFileResult>,
    /// The pack-level error (e.g. a duplicate id, an unreadable directory, no rules).
    pub package_error: Option<String>,
}

impl RuleValidationReport {
    /// Whether every file passed and there is no pack error.
    pub fn succeeded(&self) -> bool {
        self.package_error.is_none() && self.files.iter().all(|d| d.error.is_none())
    }

    /// The count of rules with no ATT&CK technique tag.
    pub fn without_attack_count(&self) -> usize {
        self.files.iter().filter(|d| d.no_attack).count()
    }
}

/// One rule file's validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFileResult {
    /// Unreadable.
    pub file: PathBuf,
    /// The rule's name if valid.
    pub name: Option<String>,
    /// The ATT&CK techniques if valid.
    pub techniques: Vec<String>,
    /// The error message; `None` if valid.
    pub error: Option<String>,
    /// Whether the rule has no ATT&CK technique tag at all.
    pub no_attack: bool,
}

/// Whether the raw document holds an ATT&CK technique tag (`attack.t1234[.567]`). Independent
/// of the parse result, so counting works even if the rule is invalid for another reason.
fn no_raw_attack(text: &str) -> bool {
    let Ok(Value::Object(root)) = yaml_json(text) else {
        return false;
    };
    let has_technique = root.get("tags").and_then(Value::as_array).is_some_and(|l| {
        l.iter().filter_map(Value::as_str).any(|e| {
            e.strip_prefix("attack.t").is_some_and(|r| {
                let (primary, child) = r.split_once('.').map_or((r, None), |(a, b)| (a, Some(b)));
                primary.len() == 4
                    && primary.bytes().all(|b| b.is_ascii_digit())
                    && child.is_none_or(|a| a.len() == 3 && a.bytes().all(|b| b.is_ascii_digit()))
            })
        })
    });
    !has_technique
}

fn file_result(path: &Path) -> (RuleFileResult, Option<Rule>) {
    let mut outcome =
        RuleFileResult { file: path.to_path_buf(), name: None, techniques: Vec::new(), error: None, no_attack: false };
    let text = match read_regular_file(path, MAX_ENTRIES as u64) {
        Ok(m) => m,
        Err(reason) => {
            outcome.error = Some(reason);
            return (outcome, None);
        }
    };
    match parse_rule(&text).and_then(|k| check_file_name(path, &k).map(|()| k)) {
        Ok(k) => {
            outcome.name = Some(k.name.clone());
            outcome.techniques = k.attack.iter().map(|t| t.as_str().to_string()).collect();
            (outcome, Some(k))
        }
        Err(e) => {
            outcome.error = Some(e.to_string());
            outcome.no_attack = no_raw_attack(&text);
            (outcome, None)
        }
    }
}

/// Validates a directory (or a single file) and reports per file.
pub fn validate_rule_dir(path: &Path) -> RuleValidationReport {
    let mut report = RuleValidationReport { files: Vec::new(), package_error: None };
    let name = sanitize(&path.display().to_string());
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            report.package_error = Some(format!("{name}: {}", io_reason(&e)));
            return report;
        }
    };
    if meta.is_file() {
        report.files.push(file_result(path).0);
        return report;
    }
    if !meta.is_dir() {
        report.package_error = Some(format!("{name}: not a directory or a regular file"));
        return report;
    }
    let entries = match directory_entries(path) {
        Ok(g) => g,
        Err(reason) => {
            report.package_error = Some(format!("{name}: {reason}"));
            return report;
        }
    };
    let mut valid_rules = Vec::new();
    for (file_name, file_path) in entries {
        if file_name.ends_with(".yaml") {
            report.files.push(RuleFileResult {
                file: file_path,
                name: None,
                techniques: Vec::new(),
                error: Some("rule files must use the .yml extension (.yaml is not read)".to_string()),
                no_attack: false,
            });
        } else if file_name.ends_with(".yml") {
            let (outcome, rule) = file_result(&file_path);
            report.files.push(outcome);
            valid_rules.extend(rule);
        }
    }
    if report.files.is_empty() {
        report.package_error = Some(format!("no .yml rule in the {name} directory"));
    } else if let Some(h) = find_duplicates(valid_rules.iter().map(|k| (k.id.as_str(), k.name.as_str()))) {
        report.package_error = Some(h);
    }
    report
}
