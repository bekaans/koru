//! A single configuration file (TOML): validated, with safe defaults.
//!
//! - **Self-hiding (ADR-0008 §3):** the process name, service name and directories are configurable;
//!   the defaults carry the name `system-observer` and contain neither "koru" nor "pulsar". Directories and files
//!   are derived from the service name.
//! - **Safe defaults:** raw events are not kept (findings only), IP masking in notifications is on,
//!   retention is 90 days. The source tag and the decoy root have no default: decoys never land in
//!   a real home directory by accident, and synthetic and real data do not mix.
//! - **Validation:** unknown fields are rejected (`deny_unknown_fields`); paths are absolute, normal text
//!   without control characters; paths entering the unit file carry only
//!   `[A-Za-z0-9._/-]` characters (no systemd specifier or variable injection);
//!   directories may not nest inside each other or the decoy roots.
//! - **Read:** [`Config::read`] reads the file without following symlinks, with owner and mode checks,
//!   at most 64 KiB.

use std::path::{Path, PathBuf};

use koru_detect::SelfProtection;
use koru_event::{SourceTag, is_valid_host};
use serde::Deserialize;

use crate::safe_read::{self, ReadMode};

/// Default name: the binary, service and directories carry it; it does not reveal Koru (ADR-0008 §3).
pub const DEFAULT_NAME: &str = "system-observer";

/// Maximum size of the configuration file (bytes).
const MAX_BYTES: u64 = 64 * 1024;

/// Configuration schema version.
pub const SCHEMA_VERSION: u32 = 1;

const PROCESS_NAME_MAX: usize = 15; // the kernel's comm limit
const SERVICE_NAME_MAX: usize = 40;

/// A configuration error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn error<T>(text: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(text.into()))
}

/// Process and service names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Executable file name (`comm`; shown by `ps` and `/proc`).
    pub process_name: String,
    /// systemd service name (`<service_name>.service`).
    pub service_name: String,
}

/// Directories (all absolute).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directories {
    /// Where the version directories and the `current` symlink live.
    pub install: PathBuf,
    /// Configuration, environment and Pulsar settings.
    pub config: PathBuf,
    /// StateDir: store, queue, decoy integrity record, install record.
    pub state: PathBuf,
    /// Runtime directory (`RuntimeDirectory`; socket). Must be under `/run`.
    pub runtime: PathBuf,
    /// systemd unit directory.
    pub unit: PathBuf,
}

/// Agent settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    /// The install's source tag (comes from here, not from the event; KT-19).
    pub source_tag: SourceTag,
    /// Host name; when absent, the kernel's host name is used.
    pub host: Option<String>,
    /// How many ancestors at most are collected in the process lineage.
    pub lineage_depth: usize,
}

/// Decoy settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoyConfig {
    /// The home directory the decoys are planted in.
    pub root: PathBuf,
    /// Extra roots that absolute template paths may point into.
    pub allowed_roots: Vec<PathBuf>,
    /// Owner of the decoy files (uid, gid); defaults to the root's owner.
    pub owner: Option<(u32, u32)>,
}

/// Store settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreConfig {
    /// How long records are kept (days).
    pub retention_days: u32,
    /// Keep raw events alongside findings (default: no).
    pub store_raw_events: bool,
}

/// Notification settings (secrets live in the environment file, not the config).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyConfig {
    /// Heartbeat interval (seconds).
    pub heartbeat_seconds: u64,
}

/// Detection settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionConfig {
    /// Allowlist file (optional).
    pub allowlist: Option<PathBuf>,
}

/// A validated configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Names.
    pub id: Identity,
    /// Directories.
    pub directories: Directories,
    /// Agent.
    pub agent: AgentConfig,
    /// Decoys.
    pub decoy: DecoyConfig,
    /// Store.
    pub store: StoreConfig,
    /// Notification.
    pub notify: NotifyConfig,
    /// Detection.
    pub detection: DetectionConfig,
}

// ---------------------------------------------------------------------------------------------
// RawConfig (TOML) types
// ---------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    schema_version: Option<u32>,
    id: Option<RawIdentity>,
    directories: Option<RawDirectories>,
    agent: Option<RawAgent>,
    decoy: Option<RawDecoy>,
    store: Option<RawStore>,
    notify: Option<RawNotify>,
    detection: Option<RawDetection>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    process_name: Option<String>,
    service_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDirectories {
    install: Option<PathBuf>,
    config: Option<PathBuf>,
    state: Option<PathBuf>,
    runtime: Option<PathBuf>,
    unit: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgent {
    source_tag: Option<String>,
    host: Option<String>,
    lineage_depth: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDecoy {
    root: Option<PathBuf>,
    allowed_roots: Option<Vec<PathBuf>>,
    owner: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStore {
    retention_days: Option<u32>,
    store_raw_events: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNotify {
    heartbeat_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDetection {
    allowlist: Option<PathBuf>,
}

// ---------------------------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------------------------

/// Name rule: lowercase letters, digits and `-`; does not start or end with `-`; contains neither "koru" nor "pulsar".
pub fn valid_name(name: &str, max: usize) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
        && !name.contains("koru")
        && !name.contains("pulsar")
}

/// Process name rule (at most 15 characters: the kernel's `comm` limit).
pub fn valid_process_name(name: &str) -> bool {
    valid_name(name, PROCESS_NAME_MAX)
}

/// Service name rule.
pub fn valid_service_name(name: &str) -> bool {
    valid_name(name, SERVICE_NAME_MAX)
}

fn check_name(field: &str, name: &str, max: usize) -> Result<(), ConfigError> {
    if valid_name(name, max) {
        Ok(())
    } else {
        error(format!(
            "{field} is invalid ({name:?}): at most {max} characters of lowercase letters, digits and '-', \
             'koru' and 'pulsar' must not appear"
        ))
    }
}

fn is_bidi_format_char(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// An absolute, normal path (no `//`, `.`, `..` or trailing `/`) without control or direction characters.
fn check_path(field: &str, path: &Path) -> Result<String, ConfigError> {
    let Some(m) = path.to_str() else {
        return error(format!("{field}: the path must be UTF-8"));
    };
    if !m.starts_with('/') || m.len() < 2 {
        return error(format!("{field} must be an absolute path and may not be '/': {m:?}"));
    }
    if m.chars().any(|c| c.is_control() || is_bidi_format_char(c)) {
        return error(format!("{field}: the path may not contain control characters"));
    }
    if m[1..].split('/').any(|b| b.is_empty() || b == "." || b == "..") {
        return error(format!("{field}: the path must be normal (no '..', '.', '//' or trailing '/'): {m:?}"));
    }
    Ok(m.to_string())
}

/// The narrow character set for paths entering the unit file.
fn check_unit_path(field: &str, path: &Path) -> Result<String, ConfigError> {
    let m = check_path(field, path)?;
    if !m.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-')) {
        return error(format!("{field}: only A-Z a-z 0-9 . _ / - characters may be used: {m:?}"));
    }
    Ok(m)
}

fn is_nested(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

fn resolve_source_tag(text: &str) -> Result<SourceTag, ConfigError> {
    match text {
        "synthetic" => Ok(SourceTag::Synthetic),
        "legitimate" => Ok(SourceTag::Legitimate),
        "real" => Ok(SourceTag::Real),
        other => error(format!("agent.source_tag must be synthetic, legitimate or real: {other:?}")),
    }
}

/// Parses a source tag from the command line (`synthetic`, `legitimate`, `real`).
pub fn source_tag_from_str(text: &str) -> Result<SourceTag, ConfigError> {
    resolve_source_tag(text)
}

fn source_tag_text(e: SourceTag) -> &'static str {
    match e {
        SourceTag::Synthetic => "synthetic",
        SourceTag::Legitimate => "legitimate",
        SourceTag::Real => "real",
    }
}

fn resolve_owner(text: &str) -> Result<(u32, u32), ConfigError> {
    let bad = || ConfigError(format!("decoy.owner must be numbers in uid:gid form: {text:?}"));
    let (u, g) = text.split_once(':').ok_or_else(bad)?;
    Ok((u.parse().map_err(|_| bad())?, g.parse().map_err(|_| bad())?))
}

fn range<T: PartialOrd + std::fmt::Display>(field: &str, d: T, min: T, max: T) -> Result<T, ConfigError> {
    if d < min || d > max {
        return error(format!("{field} must be between {min} and {max}: {d}"));
    }
    Ok(d)
}

// ---------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------

impl Config {
    /// A default configuration for the given name (source tag and decoy root have no default).
    pub fn defaults(name: &str, source: SourceTag, decoy_root: &Path) -> Result<Config, ConfigError> {
        let y = Config::by_name(name, name, source, decoy_root.to_path_buf());
        y.validate()?;
        Ok(y)
    }

    fn by_name(process_name: &str, service_name: &str, source: SourceTag, decoy_root: PathBuf) -> Config {
        let name = service_name;
        Config {
            id: Identity { process_name: process_name.to_string(), service_name: service_name.to_string() },
            directories: Directories {
                install: PathBuf::from(format!("/usr/libexec/{name}")),
                config: PathBuf::from(format!("/etc/{name}")),
                state: PathBuf::from(format!("/var/lib/{name}")),
                runtime: PathBuf::from(format!("/run/{name}")),
                unit: PathBuf::from("/etc/systemd/system"),
            },
            agent: AgentConfig { source_tag: source, host: None, lineage_depth: 16 },
            decoy: DecoyConfig { root: decoy_root, allowed_roots: Vec::new(), owner: None },
            store: StoreConfig { retention_days: 90, store_raw_events: false },
            notify: NotifyConfig { heartbeat_seconds: 60 },
            detection: DetectionConfig { allowlist: None },
        }
    }

    /// Parses TOML text, applies defaults and validates.
    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        let raw: RawConfig =
            toml::from_str(text).map_err(|e| ConfigError(format!("the configuration could not be parsed: {e}")))?;
        match raw.schema_version {
            None => return error("schema_version is required"),
            Some(SCHEMA_VERSION) => {}
            Some(d) => return error(format!("schema_version must be {SCHEMA_VERSION}: {d}")),
        }
        let (process, service_v) = {
            let k = raw.id.as_ref();
            match (k.and_then(|k| k.process_name.clone()), k.and_then(|k| k.service_name.clone())) {
                (Some(a), Some(b)) => (a, b),
                (Some(a), None) => (a.clone(), a),
                (None, Some(b)) => (b.clone(), b),
                (None, None) => (DEFAULT_NAME.to_string(), DEFAULT_NAME.to_string()),
            }
        };
        let Some(tag) = raw.agent.as_ref().and_then(|a| a.source_tag.as_deref()) else {
            return error("agent.source_tag is required (synthetic, legitimate or real)");
        };
        let source = resolve_source_tag(tag)?;
        let Some(root) = raw.decoy.as_ref().and_then(|t| t.root.clone()) else {
            return error("decoy.root is required (the home directory the decoys are planted in)");
        };
        let mut y = Config::by_name(&process, &service_v, source, root);
        if let Some(d) = raw.directories {
            y.directories.install = d.install.unwrap_or(y.directories.install);
            y.directories.config = d.config.unwrap_or(y.directories.config);
            y.directories.state = d.state.unwrap_or(y.directories.state);
            y.directories.runtime = d.runtime.unwrap_or(y.directories.runtime);
            y.directories.unit = d.unit.unwrap_or(y.directories.unit);
        }
        if let Some(a) = raw.agent {
            y.agent.host = a.host;
            y.agent.lineage_depth = a.lineage_depth.unwrap_or(y.agent.lineage_depth);
        }
        if let Some(t) = raw.decoy {
            y.decoy.allowed_roots = t.allowed_roots.unwrap_or_default();
            y.decoy.owner = t.owner.as_deref().map(resolve_owner).transpose()?;
        }
        if let Some(d) = raw.store {
            y.store.retention_days = d.retention_days.unwrap_or(y.store.retention_days);
            y.store.store_raw_events = d.store_raw_events.unwrap_or(y.store.store_raw_events);
        }
        if let Some(b) = raw.notify {
            y.notify.heartbeat_seconds = b.heartbeat_seconds.unwrap_or(y.notify.heartbeat_seconds);
        }
        if let Some(t) = raw.detection {
            y.detection.allowlist = t.allowlist;
        }
        y.validate()?;
        Ok(y)
    }

    /// Reads a file safely (no symlinks, owner euid or root, not writable by group/others,
    /// at most 64 KiB) and parses it with [`Config::parse`].
    pub fn read(path: &Path) -> Result<Config, ConfigError> {
        let bytes = safe_read::read(path, MAX_BYTES, ReadMode::Public).map_err(ConfigError)?;
        let text = String::from_utf8(bytes).map_err(|_| ConfigError(format!("{}: not valid UTF-8", path.display())))?;
        Config::parse(&text)
    }

    /// Checks the field rules (called by `parse` and `defaults`).
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_name("id.process_name", &self.id.process_name, PROCESS_NAME_MAX)?;
        check_name("id.service_name", &self.id.service_name, SERVICE_NAME_MAX)?;
        let d = &self.directories;
        let directories: [(&str, &Path); 5] = [
            ("directories.install", &d.install),
            ("directories.config", &d.config),
            ("directories.state", &d.state),
            ("directories.runtime", &d.runtime),
            ("directories.unit", &d.unit),
        ];
        for (field, path) in directories {
            check_unit_path(field, path)?;
        }
        if d.runtime.strip_prefix("/run").map_or(true, |k| k.as_os_str().is_empty()) {
            return error(format!(
                "directories.runtime must be under /run (systemd RuntimeDirectory): {}",
                d.runtime.display()
            ));
        }
        check_path("decoy.root", &self.decoy.root)?;
        for (i, k) in self.decoy.allowed_roots.iter().enumerate() {
            check_path(&format!("decoy.allowed_roots[{i}]"), k)?;
        }
        if let Some(p) = &self.detection.allowlist {
            check_path("detection.allowlist", p)?;
        }
        // Directories may not nest inside each other.
        for (i, (a_name, a)) in directories.iter().enumerate() {
            for (b_name, b) in &directories[i + 1..] {
                if is_nested(a, b) {
                    return error(format!(
                        "{a_name} and {b_name} may not be equal or nested: {} and {}",
                        a.display(),
                        b.display()
                    ));
                }
            }
        }
        // Directories must stay outside the decoy roots (ADR-0004: the state directory may not nest with the roots).
        for k in std::iter::once(&self.decoy.root).chain(self.decoy.allowed_roots.iter()) {
            for (name, dir) in directories {
                if is_nested(dir, k) {
                    return error(format!(
                        "{name} may not be inside or above the decoy roots ({}): {}",
                        k.display(),
                        dir.display()
                    ));
                }
            }
        }
        if let Some(a) = &self.agent.host
            && !is_valid_host(a)
        {
            return error(format!("agent.host must be an RFC 1123 host name (IP addresses are not allowed): {a:?}"));
        }
        range("agent.lineage_depth", self.agent.lineage_depth, 1, 64)?;
        range("store.retention_days", self.store.retention_days, 1, 3650)?;
        range("notify.heartbeat_seconds", self.notify.heartbeat_seconds, 10, 3600)?;
        Ok(())
    }

    /// Normalized TOML text (the full configuration; reads back with [`Config::parse`]).
    pub fn toml(&self) -> String {
        let mut s = String::new();
        let line = |s: &mut String, a: &str, d: String| s.push_str(&format!("{a} = {d}\n"));
        line(&mut s, "schema_version", SCHEMA_VERSION.to_string());
        s.push_str("\n[id]\n");
        line(&mut s, "process_name", toml_text(&self.id.process_name));
        line(&mut s, "service_name", toml_text(&self.id.service_name));
        s.push_str("\n[directories]\n");
        let d = &self.directories;
        for (a, y) in [
            ("install", &d.install),
            ("config", &d.config),
            ("state", &d.state),
            ("runtime", &d.runtime),
            ("unit", &d.unit),
        ] {
            line(&mut s, a, toml_text(&y.display().to_string()));
        }
        s.push_str("\n[agent]\n");
        line(&mut s, "source_tag", toml_text(source_tag_text(self.agent.source_tag)));
        if let Some(a) = &self.agent.host {
            line(&mut s, "host", toml_text(a));
        }
        line(&mut s, "lineage_depth", self.agent.lineage_depth.to_string());
        s.push_str("\n[decoy]\n");
        line(&mut s, "root", toml_text(&self.decoy.root.display().to_string()));
        let roots: Vec<String> = self.decoy.allowed_roots.iter().map(|k| toml_text(&k.display().to_string())).collect();
        line(&mut s, "allowed_roots", format!("[{}]", roots.join(", ")));
        if let Some((u, g)) = self.decoy.owner {
            line(&mut s, "owner", toml_text(&format!("{u}:{g}")));
        }
        s.push_str("\n[store]\n");
        line(&mut s, "retention_days", self.store.retention_days.to_string());
        line(&mut s, "store_raw_events", self.store.store_raw_events.to_string());
        s.push_str("\n[notify]\n");
        line(&mut s, "heartbeat_seconds", self.notify.heartbeat_seconds.to_string());
        s.push_str("\n[detection]\n");
        if let Some(p) = &self.detection.allowlist {
            line(&mut s, "allowlist", toml_text(&p.display().to_string()));
        }
        s
    }

    // --- derived paths ---------------------------------------------------------------------

    /// `<config>/config.toml`.
    pub fn config_file(&self) -> PathBuf {
        self.directories.config.join("config.toml")
    }

    /// `<config>/environment` (notify secrets; 0600).
    pub fn env_file(&self) -> PathBuf {
        self.directories.config.join("environment")
    }

    /// `<config>/sensor.toml` (the sensor library's settings). The file name does not reveal Pulsar.
    pub fn pulsar_config(&self) -> PathBuf {
        self.directories.config.join("sensor.toml")
    }

    /// Pulsar engine API socket: `<runtime>/api.sock`.
    pub fn engine_socket(&self) -> PathBuf {
        self.directories.runtime.join("api.sock")
    }

    /// `<state>/event.db`.
    pub fn store_file(&self) -> PathBuf {
        self.directories.state.join("event.db")
    }

    /// `<state>/queue`.
    pub fn queue_dir(&self) -> PathBuf {
        self.directories.state.join("queue")
    }

    /// `<state>/decoy` (decoy integrity record and backups).
    pub fn decoy_state_dir(&self) -> PathBuf {
        self.directories.state.join("decoy")
    }

    /// `<state>/install.toml` (the install record).
    pub fn install_record(&self) -> PathBuf {
        self.directories.state.join("install.toml")
    }

    /// `<unit>/<service_v>.service`.
    pub fn service_file(&self) -> PathBuf {
        self.directories.unit.join(format!("{}.service", self.id.service_name))
    }

    /// `<install>/versions/<version>`.
    pub fn version_dir(&self, version: &str) -> PathBuf {
        self.directories.install.join("versions").join(version)
    }

    /// `<install>/current` (the symlink to the active version).
    pub fn current_link(&self) -> PathBuf {
        self.directories.install.join("current")
    }

    /// `<install>/current/<process_name>`.
    pub fn agent_binary(&self) -> PathBuf {
        self.current_link().join(&self.id.process_name)
    }

    /// The detection layer's protected paths and names (self-protection).
    pub fn self_protection(&self) -> SelfProtection {
        let path = |p: &Path| p.display().to_string();
        let store = path(&self.store_file());
        let service_v = path(&self.service_file());
        SelfProtection {
            config: vec![path(&self.directories.config)],
            secret: vec![path(&self.env_file())],
            store: vec![store.clone(), format!("{store}-wal"), format!("{store}-shm")],
            state: vec![path(&self.directories.state)],
            binaries: vec![path(&self.directories.install)],
            service_files: vec![service_v.clone(), format!("{service_v}.d")],
            service_names: vec![self.id.service_name.clone()],
            process_names: vec![self.id.process_name.clone()],
        }
    }
}

/// A TOML basic string: `"`, `\` and control characters are escaped.
pub(crate) fn toml_text(m: &str) -> String {
    let mut s = String::with_capacity(m.len() + 2);
    s.push('"');
    for c in m.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => s.push_str(&format!("\\u{:04X}", c as u32)),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}
