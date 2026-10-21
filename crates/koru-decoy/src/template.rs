//! The decoy template schema v1 (`schemas/decoy-template.v1.json`; ADR-0004 "Template format").
//!
//! A template is a TOML file holding only placeholders; values are generated with the CSPRNG at
//! install time. The Rust types carry `deny_unknown_fields`: an unknown, missing, or wrongly
//! typed field is rejected. [`Template::validate`] applies the cross-field rules (placeholders,
//! path safety, the "koru" string, mode rules, the constant-secret ban). Cross-references and
//! the format of generated content are checked at the package level (`read_package`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::format;
use crate::placeholder::{self, Placeholder};

/// The supported template schema version.
pub const TEMPLATE_SCHEMA_VERSION: u32 = 1;

/// The maximum size of a template file (bytes).
pub(crate) const MAX_TEMPLATE: usize = 256 * 1024;
/// The maximum size of a content template (bytes).
const MAX_CONTENT: usize = 64 * 1024;

/// Reserved value names: another template's path, the file's natural timestamp, the repeat index.
pub(crate) const RESERVED_NAMES: [&str; 3] = ["path", "file_time", "index"];
/// The sub-fields of timestamp values.
pub(crate) const TIME_FIELDS: [&str; 6] = ["date", "time", "datetime", "iso", "unix", "year"];
/// The sub-fields of SSH key values.
pub(crate) const SSH_FIELDS: [&str; 3] = ["private", "public", "public_key"];

/// A decoy or a breadcrumb. The detection layer treats the two as separate signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyKind {
    /// A file carrying fake credential or secret values.
    Decoy,
    /// A record pointing at fake targets (`~/.bash_history`, `~/.ssh/config`, `known_hosts`).
    Breadcrumb,
}

/// The placement form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Placement {
    /// A new file; if the target exists, installation is rejected (never overwritten).
    NewFile,
    /// Appended to an existing file (a backup is taken first); created if the file is absent.
    Append,
}

/// The format of generated content; package validation parses the content by this format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// Free-form text.
    Text,
    /// `KEY=VALUE` lines.
    Env,
    /// INI (section + `key = value`).
    Ini,
    /// JSON.
    Json,
    /// An MCP configuration (JSON; remote servers only, a reserved address; KT-17).
    McpJson,
    /// An SQL dump.
    Sql,
    /// An OpenSSH private key file (only the key placeholder).
    OpensshPrivateKey,
    /// Entries of `~/.ssh/config`.
    SshConfig,
    /// `known_hosts` lines.
    KnownHosts,
    /// Shell history lines.
    BashHistory,
    /// Markdown not.
    Markdown,
}

/// Alphabet of the random string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Alphabet {
    /// `0-9a-f`
    Hex,
    /// `0-9A-F`
    HexUpper,
    /// `A-Za-z0-9`
    Base62,
    /// `A-Za-z0-9+/`
    Base64,
    /// `A-Za-z0-9-_`
    Base64url,
    /// `A-Z2-7`
    Base32,
    /// `0-9`
    Digits,
    /// `a-z`
    Lowercase,
    /// `a-z0-9`
    LowercaseDigits,
    /// `A-Z0-9`
    UppercaseDigits,
    /// `A-Za-z`
    Letters,
}

impl Alphabet {
    pub(crate) fn characters(self) -> &'static [u8] {
        match self {
            Alphabet::Hex => b"0123456789abcdef",
            Alphabet::HexUpper => b"0123456789ABCDEF",
            Alphabet::Base62 => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            Alphabet::Base64 => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            Alphabet::Base64url => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            Alphabet::Base32 => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
            Alphabet::Digits => b"0123456789",
            Alphabet::Lowercase => b"abcdefghijklmnopqrstuvwxyz",
            Alphabet::LowercaseDigits => b"abcdefghijklmnopqrstuvwxyz0123456789",
            Alphabet::UppercaseDigits => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            Alphabet::Letters => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        }
    }
}

/// A value generator. Values are generated with the CSPRNG at install time.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Value {
    /// A random string from an alphabet; optional constant prefix and suffix.
    Random {
        /// Alphabet.
        alphabet: Alphabet,
        /// The length of the random part (1-4096).
        length: u32,
        /// A constant prefix (e.g. `AKIA`).
        #[serde(default)]
        prefix: String,
        /// Fixed suffix.
        #[serde(default)]
        suffix: String,
    },
    /// A random pick from a list.
    Choice {
        /// The options (1-1000).
        options: Vec<String>,
    },
    /// A random integer in a range (both ends included).
    Number {
        /// The lower bound.
        min: u64,
        /// The upper bound.
        max: u64,
    },
    /// A random UUID (version 4).
    Uuid4 {},
    /// A bcrypt-format password-hash-looking random value (`$2b$<cost>$...`).
    Bcrypt {
        /// Cost (4–31).
        cost: u32,
    },
    /// In GitHub personal access token format (`ghp_` + 30 characters + a CRC32 check).
    GithubToken {},
    /// A newly generated ed25519 key pair. Sub-fields: `private` (the OpenSSH private key file),
    /// `public_part` (`ssh-ed25519 AAAA… comment`), `public_key` (without the comment).
    SshEd25519 {
        /// The key comment; it can reference the template's own simple values by placeholder.
        comment: String,
    },
    /// An IPv4 address from the RFC 5737 documentation networks (TEST-NET-1/2/3).
    TestNetIpv4 {},
    /// A natural timestamp in the past (work hours, weekday-weighted). Sub-fields: date, time,
    /// datetime, iso, unix, year.
    Timestamp {
        /// At least this many days ago.
        min_days: u32,
        /// At most this many days ago.
        max_days: u32,
    },
    /// A random number of repetitions of an inner template; inner values are regenerated per repetition.
    Repeat {
        /// Minimum repeat count.
        min: u32,
        /// The maximum repetitions.
        max: u32,
        /// The separator between repetitions.
        separator: String,
        /// The inner template; it can reference inner values, `{{index}}`, and the template's own values.
        template: String,
        /// The inner values (cannot hold a repeat).
        #[serde(default)]
        values: BTreeMap<String, Value>,
    },
}

impl Value {
    pub(crate) fn kind_name(&self) -> &'static str {
        match self {
            Value::Random { .. } => "random",
            Value::Choice { .. } => "choice",
            Value::Number { .. } => "number",
            Value::Uuid4 {} => "uuid4",
            Value::Bcrypt { .. } => "bcrypt",
            Value::GithubToken {} => "github_token",
            Value::SshEd25519 { .. } => "ssh_ed25519",
            Value::TestNetIpv4 {} => "test_net_ipv4",
            Value::Timestamp { .. } => "timestamp",
            Value::Repeat { .. } => "repeat",
        }
    }

    /// Is the placeholder's sub-field valid for this value kind?
    pub(crate) fn is_valid_subfield(&self, child: Option<&str>) -> Result<(), String> {
        match (self, child) {
            (Value::SshEd25519 { .. }, Some(a)) if SSH_FIELDS.contains(&a) => Ok(()),
            (Value::SshEd25519 { .. }, _) => {
                Err(format!("an ssh_ed25519 value requires a sub-field: {}", SSH_FIELDS.join(", ")))
            }
            (Value::Timestamp { .. }, Some(a)) if TIME_FIELDS.contains(&a) => Ok(()),
            (Value::Timestamp { .. }, _) => {
                Err(format!("a timestamp value requires a sub-field: {}", TIME_FIELDS.join(", ")))
            }
            (_, None) => Ok(()),
            (d, Some(a)) => Err(format!("a {} value has no sub-field: .{a}", d.kind_name())),
        }
    }

    /// Can it be used in single-line places like a path or a comment?
    pub(crate) fn is_simple(&self) -> bool {
        !matches!(self, Value::SshEd25519 { .. } | Value::Repeat { .. })
    }
}

/// Target file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// A path relative to the root (home) directory, or an absolute path under an allowed root.
    /// Cannot hold `..`, `.`, or an empty component. May hold placeholders.
    pub path: String,
    /// The file mode (e.g. `0o600`). No execute bit, no group/other write bit.
    pub mode: u32,
    /// The placement form.
    pub placement: Placement,
}

/// The file's natural timestamp range (days back from now).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeRange {
    /// At least this many days ago (1-3650).
    pub min_days: u32,
    /// At most this many days ago (min_days-3650).
    pub max_days: u32,
}

/// A decoy template (schema v1).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    /// The schema version; 1.
    pub schema: u32,
    /// The template's unique id (`[a-z0-9-]`, 3-64 characters).
    pub id: String,
    /// What the template is (free text); never enters installed content.
    pub description: String,
    /// A decoy or a breadcrumb.
    pub kind: DecoyKind,
    /// A free class label (`[a-z][a-z0-9_]`); used in reports and detection.
    pub class: String,
    /// The format of generated content.
    pub format: Format,
    /// Does it carry secret values? If true, the mode must be 0600.
    pub secret: bool,
    /// The content with placeholders.
    pub content: String,
    /// Target file.
    pub target: Target,
    /// The natural timestamp range.
    pub timestamp: TimeRange,
    /// The value generators (key: value name).
    #[serde(default)]
    pub values: BTreeMap<String, Value>,
}

/// When a template cannot be read or validated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{field}: {reason}")]
pub struct TemplateError {
    /// The field the error is in.
    pub field: String,
    /// Reason.
    pub reason: String,
}

fn error(field: impl Into<String>, reason: impl Into<String>) -> TemplateError {
    TemplateError { field: field.into(), reason: reason.into() }
}

/// Reads a template from TOML text and validates it ([`Template::validate`]).
pub fn parse_template(text: &str) -> Result<Template, TemplateError> {
    if text.len() > MAX_TEMPLATE {
        return Err(error("file", format!("a template cannot exceed {MAX_TEMPLATE} bytes")));
    }
    let template: Template = toml::from_str(text).map_err(|e| error("toml", e.to_string().trim().to_string()))?;
    template.validate()?;
    Ok(template)
}

/// Does the text hold the "koru" string (case-insensitive)? Koru never reveals itself to an
/// attacker (KT-23).
pub(crate) fn contains_koru(text: &str) -> bool {
    text.to_lowercase().contains("koru")
}

fn control_character(text: &str, allowed: &[char]) -> bool {
    text.chars().any(|c| c.is_control() && !allowed.contains(&c))
}

fn validate_identity(id: &str) -> Result<(), TemplateError> {
    let current =
        (3..=64).contains(&id.len()) && placeholder::is_template_id(id) && !id.ends_with('-') && !id.contains("--");
    if !current {
        return Err(error("id", "3-64 characters; lowercase letters, digits, and hyphens; cannot end with a hyphen"));
    }
    if contains_koru(id) {
        return Err(error("id", "cannot hold the \"koru\" string"));
    }
    Ok(())
}

fn validate_value_name(field: &str, name: &str) -> Result<(), TemplateError> {
    let mut c = name.chars();
    let current = c.next().is_some_and(|i| i.is_ascii_lowercase())
        && c.all(|k| k.is_ascii_lowercase() || k.is_ascii_digit() || k == '_')
        && name.len() <= 48;
    if !current {
        return Err(error(field, "a value name starts with a lowercase letter; lowercase letters, digits, and _"));
    }
    if RESERVED_NAMES.contains(&name) {
        return Err(error(field, format!("{name} is a reserved name")));
    }
    if contains_koru(name) {
        return Err(error(field, "cannot hold the \"koru\" string"));
    }
    Ok(())
}

/// Constant (template-written) text: the control-character, "koru", and secret-like constant bans.
fn validate_literal(field: &str, text: &str, allowed_control: &[char]) -> Result<(), TemplateError> {
    if control_character(text, allowed_control) {
        return Err(error(field, "cannot hold a control character"));
    }
    if contains_koru(text) {
        return Err(error(field, "cannot hold the \"koru\" string (Koru never reveals itself)"));
    }
    let plain = placeholder::plain_text(text).map_err(|e| error(field, e))?;
    if let Some(reason) = format::fixed_secret(&plain) {
        return Err(error(
            field,
            format!(
                "the template holds a constant that could be a real secret ({reason}); values are generated at install time via placeholders"
            ),
        ));
    }
    Ok(())
}

/// Checks the placeholder-free part of a template target path. Components holding placeholders
/// then checked again ([`path_components`]).
fn validate_target_path(path: &str) -> Result<(), TemplateError> {
    if path.is_empty() || path.len() > 1024 {
        return Err(error("target.path", "cannot be empty, at most 1024 bytes"));
    }
    if path.contains('\\') {
        return Err(error("target.path", "cannot hold a backslash"));
    }
    // The path is checked component by component: since '/' is a base64 character, the whole
    // path is not treated as one "high-entropy" string.
    for component in path.split('/') {
        validate_literal("target.path", component, &[])?;
    }
    path_components(path).map_err(|e| error("target.path", e))?;
    Ok(())
}

/// The path components; `..`, `.`, and an empty component are rejected. In an absolute path the first element is `/`.
pub(crate) fn path_components(path: &str) -> Result<(bool, Vec<&str>), String> {
    if path.is_empty() {
        return Err("an empty path".into());
    }
    if path.chars().any(char::is_control) || path.contains('\\') {
        return Err("a control character or a backslash".into());
    }
    let (absolute, body) = match path.strip_prefix('/') {
        Some(g) => (true, g),
        None => (false, path),
    };
    let components: Vec<&str> = body.split('/').collect();
    for b in &components {
        match *b {
            "" => return Err("an empty component (// or a trailing /)".into()),
            "." => return Err("a '.' component".into()),
            ".." => return Err("a '..' component (path traversal)".into()),
            b if b.len() > 255 => return Err("a component longer than 255 bytes".into()),
            _ => {}
        }
    }
    Ok((absolute, components))
}

/// Mode rules: no execute bit, no group/other write bit, no special bits; the owner can read.
fn validate_mode(mode: u32, secret: bool) -> Result<(), TemplateError> {
    if mode > 0o777 {
        return Err(error("target.mode", "special bits (setuid, setgid, sticky) cannot be used"));
    }
    if mode & 0o111 != 0 {
        return Err(error("target.mode", "no execute bit is allowed"));
    }
    if mode & 0o022 != 0 {
        return Err(error("target.mode", "no group/other write bit is allowed"));
    }
    if mode & 0o400 == 0 {
        return Err(error("target.mode", "owner must be able to read"));
    }
    if secret && mode != 0o600 {
        return Err(error("target.mode", "a file carrying secret values must be 0600"));
    }
    Ok(())
}

/// The check of a single value's own fields; if `inner` is true it sits inside a repeat.
fn validate_value(field: &str, value: &Value, own: &BTreeMap<String, Value>, inner: bool) -> Result<(), TemplateError> {
    match value {
        Value::Random { length, prefix, suffix, .. } => {
            if !(1..=4096).contains(length) {
                return Err(error(field, "length must be 1-4096"));
            }
            for (name, s) in [("prefix", prefix), ("suffix", suffix)] {
                if s.chars().count() > 64 || s.contains("{{") {
                    return Err(error(format!("{field}.{name}"), "at most 64 characters, cannot hold a placeholder"));
                }
                validate_literal(&format!("{field}.{name}"), s, &[])?;
            }
        }
        Value::Choice { options } => {
            if options.is_empty() || options.len() > 1000 {
                return Err(error(field, "must hold 1-1000 options"));
            }
            for s in options {
                if s.is_empty() || s.chars().count() > 256 || s.contains("{{") || s.contains(['"', '\\']) {
                    return Err(error(
                        field,
                        "an option is 1-256 characters; cannot hold a placeholder, a double quote, or a backslash",
                    ));
                }
                validate_literal(field, s, &[])?;
            }
        }
        Value::Number { min, max } => {
            if min > max {
                return Err(error(field, "min cannot exceed max"));
            }
        }
        Value::Uuid4 {} | Value::GithubToken {} | Value::TestNetIpv4 {} => {}
        Value::Bcrypt { cost } => {
            if !(4..=31).contains(cost) {
                return Err(error(field, "cost must be 4-31"));
            }
        }
        Value::SshEd25519 { comment } => {
            if comment.chars().count() > 128 {
                return Err(error(field, "the comment is at most 128 characters"));
            }
            validate_literal(&format!("{field}.comment"), comment, &[])?;
            for y in placeholder::placeholders(comment).map_err(|e| error(format!("{field}.comment"), e))? {
                let valid = y.template.is_none()
                    && y.child.is_none()
                    && own.get(&y.name).is_some_and(|d| d.is_simple() && !matches!(d, Value::Timestamp { .. }));
                if !valid {
                    return Err(error(
                        format!("{field}.comment"),
                        "it can reference only the template's own simple values",
                    ));
                }
            }
        }
        Value::Timestamp { min_days, max_days } => {
            if min_days > max_days || *max_days > 3650 {
                return Err(error(field, "must satisfy 0 <= min_days <= max_days <= 3650"));
            }
        }
        Value::Repeat { min, max, separator, template, values } => {
            if inner {
                return Err(error(field, "a repeat cannot be nested"));
            }
            if *min == 0 || min > max || *max > 1000 {
                return Err(error(field, "must satisfy 1 <= min <= max <= 1000"));
            }
            if separator.chars().count() > 16 {
                return Err(error(field, "the separator is at most 16 characters"));
            }
            validate_literal(&format!("{field}.separator"), separator, &['\n'])?;
            if template.is_empty() || template.len() > 4096 {
                return Err(error(field, "the inner template must be 1-4096 bytes"));
            }
            validate_literal(&format!("{field}.template"), template, &['\n', '\t'])?;
            for (name, d) in values {
                validate_value_name(&format!("{field}.values.{name}"), name)?;
                validate_value(&format!("{field}.values.{name}"), d, values, true)?;
            }
            for y in placeholder::placeholders(template).map_err(|e| error(format!("{field}.template"), e))? {
                if y.template.is_some() {
                    return Err(error(
                        format!("{field}.template"),
                        "a cross-reference cannot be used in an inner template",
                    ));
                }
                if y.name == "index" && y.child.is_none() {
                    continue;
                }
                let d = values
                    .get(&y.name)
                    .or_else(|| own.get(&y.name).filter(|d| !matches!(d, Value::Repeat { .. })))
                    .ok_or_else(|| error(format!("{field}.template"), format!("undefined value: {}", y.name)))?;
                d.is_valid_subfield(y.child.as_deref()).map_err(|e| error(format!("{field}.template"), e))?;
            }
        }
    }
    Ok(())
}

/// Appending (to an existing file) happens only in line-based formats.
fn supports_append(format: Format) -> bool {
    matches!(
        format,
        Format::Text
            | Format::Env
            | Format::Ini
            | Format::BashHistory
            | Format::SshConfig
            | Format::KnownHosts
            | Format::Markdown
    )
}

impl Template {
    /// The rules of a single template. Cross-reference targets, unused values, and the format
    /// of generated content are checked at the package level.
    pub fn validate(&self) -> Result<(), TemplateError> {
        if self.schema != TEMPLATE_SCHEMA_VERSION {
            return Err(error("schema", format!("the supported version is {TEMPLATE_SCHEMA_VERSION}")));
        }
        validate_identity(&self.id)?;
        if self.description.trim().is_empty() || self.description.chars().count() > 500 {
            return Err(error("description", "cannot be empty, at most 500 characters"));
        }
        if control_character(&self.description, &['\n']) {
            return Err(error("description", "cannot hold a control character"));
        }
        let class_valid = self.class.len() >= 2
            && self.class.len() <= 40
            && self.class.starts_with(|c: char| c.is_ascii_lowercase())
            && self.class.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !class_valid {
            return Err(error(
                "class",
                "2-40 characters; starts with a lowercase letter; lowercase letters, digits, and _",
            ));
        }
        if contains_koru(&self.class) {
            return Err(error("class", "cannot hold the \"koru\" string"));
        }
        if self.content.is_empty() || self.content.len() > MAX_CONTENT {
            return Err(error("content", format!("must be 1-{MAX_CONTENT} bytes")));
        }
        validate_literal("content", &self.content, &['\n', '\t'])?;
        validate_target_path(&self.target.path)?;
        validate_mode(self.target.mode, self.secret)?;
        if self.target.placement == Placement::Append && !supports_append(self.format) {
            return Err(error("target.placement", format!("a {:?} file cannot be appended to", self.format)));
        }
        let TimeRange { min_days, max_days } = self.timestamp;
        if min_days == 0 || min_days > max_days || max_days > 3650 {
            return Err(error("timestamp", "must satisfy 1 <= min_days <= max_days <= 3650"));
        }
        if self.values.len() > 256 {
            return Err(error("values", "at most 256 values"));
        }
        for (name, d) in &self.values {
            validate_value_name(&format!("values.{name}"), name)?;
            validate_value(&format!("values.{name}"), d, &self.values, false)?;
        }
        for y in placeholder::placeholders(&self.content).map_err(|e| error("content", e))? {
            self.validate_placeholder("content", &y, false)?;
        }
        for y in placeholder::placeholders(&self.target.path).map_err(|e| error("target.path", e))? {
            self.validate_placeholder("target.path", &y, true)?;
        }
        if self.format == Format::OpensshPrivateKey {
            self.validate_key_file()?;
        }
        if self.format == Format::McpJson {
            for forbidden in ["\"command\"", "\"args\"", "\"env\""] {
                if self.content.contains(forbidden) {
                    return Err(error(
                        "content",
                        format!("the {forbidden} field cannot be used in an MCP decoy (KT-17)"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// The check of a local placeholder. Cross-references are checked as syntax only.
    fn validate_placeholder(&self, field: &str, y: &Placeholder, in_path: bool) -> Result<(), TemplateError> {
        if y.template.is_some() {
            if in_path && y.name == "path" {
                return Err(error(field, "another template's path cannot be used in a target path"));
            }
            return Ok(());
        }
        match y.name.as_str() {
            "file_time" => match y.child.as_deref() {
                Some(a) if TIME_FIELDS.contains(&a) => Ok(()),
                _ => Err(error(field, format!("file_time needs a sub-field: {}", TIME_FIELDS.join(", ")))),
            },
            "path" | "index" => Err(error(field, format!("{{{{{}}}}} cannot be used here", y.name))),
            name => {
                let d = self.values.get(name).ok_or_else(|| error(field, format!("undefined value: {name}")))?;
                d.is_valid_subfield(y.child.as_deref()).map_err(|e| error(field, e))?;
                if in_path && !d.is_simple() {
                    return Err(error(field, format!("a {} value cannot be used in a target path", d.kind_name())));
                }
                Ok(())
            }
        }
    }

    /// An OpenSSH key file consists of a single `{{name.private}}` placeholder.
    fn validate_key_file(&self) -> Result<(), TemplateError> {
        let parts = placeholder::parse_parts(self.content.trim_end_matches('\n')).map_err(|e| error("content", e))?;
        let single_key = match parts.as_slice() {
            [placeholder::Part::Placeholder(y)] => {
                y.template.is_none()
                    && y.child.as_deref() == Some("private")
                    && y.filter.is_none()
                    && matches!(self.values.get(&y.name), Some(Value::SshEd25519 { .. }))
            }
            _ => false,
        };
        if !single_key {
            return Err(error("content", "openssh_private_key content can only be {{<ssh_ed25519 value>.private}}"));
        }
        if !self.secret || self.target.placement != Placement::NewFile {
            return Err(error("secret", "a private key requires secret = true and new_file"));
        }
        Ok(())
    }
}
