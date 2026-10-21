//! Distribution and lifecycle: install_distribution, uninstall, upgrade, downgrade (ADR-0008).
//!
//! - **Verify first:** the version package (`SHA256SUMS` + `SHA256SUMS.sig`) is verified by signature and SHA-256
//!   before anything is written. Verification and install use the same in-memory content
//!   (a file cannot be swapped between verification and copying). The package must not contain files
//!   missing from the list, symlinks, or entries escaping the path.
//! - **Versioned directories:** each version lives under `versions/<version>`; the active version is shown
//!   by the `current` symlink and switched atomically. On upgrade the previous version is kept for
//!   downgrade; a failed health check rolls back automatically.
//! - **Clean uninstall:** everything the install created is removed; mtimes of pre-existing parent directories
//!   are restored; decoys are rolled back per koru-decoy's record. A modified
//!   decoy is not deleted; it is reported and its record stays.
//! - **Secrecy:** only notify variables pass into the environment file; other secrets such as the signing key
//!   never reach the target machine.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, FileTimes, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::{Config, toml_text};
use crate::safe_read::{self, ReadMode};

/// The public key (PEM) verifying version packages; `distribution/signing-public-key.pem`.
pub const EMBEDDED_PUBLIC_KEY: &str = include_str!("../../../distribution/signing-public-key.pem");

/// Unit template (`distribution/unit.template`).
const UNIT_TEMPLATE: &str = include_str!("../../../distribution/unit.template");

/// Variables allowed into the environment file. Any other variable, e.g.
/// `KORU_SIGNING_KEY*`, `KORU_LAB_LLM_*`, `CLOUDFLARE_*`, never reaches the target machine.
const ENV_ALLOWLIST: [&str; 12] = [
    "KORU_NTFY_URL",
    "KORU_NTFY_TOKEN",
    "KORU_TELEGRAM_BOT_TOKEN",
    "KORU_TELEGRAM_CHAT_ID",
    "KORU_SMTP_HOST",
    "KORU_SMTP_PORT",
    "KORU_SMTP_USER",
    "KORU_SMTP_PASSWORD",
    "KORU_SMTP_FROM",
    "KORU_SMTP_TO",
    "KORU_HEARTBEAT_URL",
    "KORU_NOTIFY_MASK_IP",
];

const RECORD_VERSION: u32 = 1;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FILE_COUNT: usize = 4000;
const MAX_DEPTH: usize = 12;

/// A distribution error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributionError(pub String);

impl std::fmt::Display for DistributionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DistributionError {}

fn error<T>(m: impl Into<String>) -> Result<T, DistributionError> {
    Err(DistributionError(m.into()))
}

fn io_error(path: &Path, e: impl std::fmt::Display) -> DistributionError {
    DistributionError(format!("{}: {e}", path.display()))
}

// ---------------------------------------------------------------------------------------------
// systemd
// ---------------------------------------------------------------------------------------------

/// systemd operations. The real implementation calls `systemctl`; tests use a fake implementation.
pub trait Systemd {
    /// `systemctl daemon-reload`.
    fn daemon_reload(&self) -> Result<(), String>;
    /// `systemctl enable --now <service_v>`.
    fn enable_start(&self, service_v: &str) -> Result<(), String>;
    /// `systemctl disable --now <service_v>`.
    fn stop_disable(&self, service_v: &str) -> Result<(), String>;
    /// `systemctl restart <service_v>`.
    fn restart(&self, service_v: &str) -> Result<(), String>;
    /// `systemctl is-active --quiet <service_v>`.
    fn is_active(&self, service_v: &str) -> Result<bool, String>;
}

/// Does nothing (no-systemd environments, tests): everything succeeds, the service is active.
pub struct NoSystemd;

impl Systemd for NoSystemd {
    fn daemon_reload(&self) -> Result<(), String> {
        Ok(())
    }
    fn enable_start(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn stop_disable(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn restart(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn is_active(&self, _: &str) -> Result<bool, String> {
        Ok(true)
    }
}

/// The real implementation calling `systemctl`. The environment is cleaned; only a fixed `PATH` is given.
pub struct RealSystemd;

impl RealSystemd {
    fn run(args: &[&str]) -> Result<std::process::Output, String> {
        Command::new("systemctl")
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("systemctl could not run: {e}"))
    }

    fn run_systemctl(args: &[&str]) -> Result<(), String> {
        let o = Self::run(args)?;
        if o.status.success() {
            Ok(())
        } else {
            let error = String::from_utf8_lossy(&o.stderr);
            Err(format!("systemctl {} failed ({}): {}", args.join(" "), o.status, error.trim()))
        }
    }
}

impl Systemd for RealSystemd {
    fn daemon_reload(&self) -> Result<(), String> {
        Self::run_systemctl(&["daemon-reload"])
    }
    fn enable_start(&self, service_v: &str) -> Result<(), String> {
        Self::run_systemctl(&["enable", "--now", &format!("{service_v}.service")])
    }
    fn stop_disable(&self, service_v: &str) -> Result<(), String> {
        Self::run_systemctl(&["disable", "--now", &format!("{service_v}.service")])
    }
    fn restart(&self, service_v: &str) -> Result<(), String> {
        Self::run_systemctl(&["restart", &format!("{service_v}.service")])
    }
    fn is_active(&self, service_v: &str) -> Result<bool, String> {
        Ok(Self::run(&["is-active", "--quiet", &format!("{service_v}.service")])?.status.success())
    }
}

// ---------------------------------------------------------------------------------------------
// Context, options, reports
// ---------------------------------------------------------------------------------------------

/// Operation context.
pub struct LineContext<'a> {
    /// The systemd implementation.
    pub systemd_ctl: &'a dyn Systemd,
    /// The public key (PEM text) verifying version signatures.
    pub public_key_pem: String,
    /// Number of consecutive health probes after restart (all must report active).
    pub health_probe: u32,
    /// Wait between probes.
    pub health_wait: Duration,
}

/// Install options.
pub struct InstallOptions {
    /// Version package directory to verify.
    pub version_dir: PathBuf,
    /// Configuration (directories and names).
    pub config: Config,
    /// `.env`-format file (0600) to read notification secrets from.
    pub env_file: Option<PathBuf>,
}

/// Install report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    /// Installed version.
    pub version: String,
}

/// Uninstall report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallReport {
    /// Was everything removed; if not, the record stays and the command can be re-run.
    pub completed: bool,
    /// Warnings (decoys left behind, directories whose mtime was not restored).
    pub warnings: Vec<String>,
}

/// Upgrade report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeReport {
    /// Previous version.
    pub previous: String,
    /// New version.
    pub new: String,
}

/// Downgrade report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackReport {
    /// The version active before the switch.
    pub previous: String,
    /// The version now active.
    pub new: String,
}

// ---------------------------------------------------------------------------------------------
// Version package verification
// ---------------------------------------------------------------------------------------------

/// A verified version package: all content in memory.
pub struct Package {
    /// The version in the VERSION file.
    pub version: String,
    /// `(relative path, content)`; only verified files (meta files excluded).
    files: BTreeMap<String, Vec<u8>>,
}

impl Package {
    /// File paths in the package (to show the plan).
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Version string: `X.Y.Z` with an optional `-prerelease`.
fn parse_version(m: &str) -> Option<(u64, u64, u64, Option<String>)> {
    let (core, pre) = match m.split_once('-') {
        Some((c, o)) => (c, Some(o)),
        None => (m, None),
    };
    let p: Vec<&str> = core.split('.').collect();
    if p.len() != 3 || !p.iter().all(|x| !x.is_empty() && x.len() <= 9 && x.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    if let Some(o) = pre
        && (o.is_empty() || o.len() > 32 || !o.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
    {
        return None;
    }
    Some((p[0].parse().ok()?, p[1].parse().ok()?, p[2].parse().ok()?, pre.map(str::to_string)))
}

/// Is version `a` strictly newer than `b` (a prerelease is older than stable at the same core).
fn newer(a: &str, b: &str) -> bool {
    match (parse_version(a), parse_version(b)) {
        (Some(x), Some(y)) => {
            let sort_key = |t: &(u64, u64, u64, Option<String>)| (t.0, t.1, t.2, t.3.is_none(), t.3.clone());
            sort_key(&x) > sort_key(&y)
        }
        _ => false,
    }
}

fn is_valid_package_path(y: &str) -> bool {
    !y.is_empty()
        && y.len() <= 200
        && !y.starts_with('/')
        && !y.chars().any(|c| c.is_control() || c == '\\')
        && y.split('/').all(|b| !b.is_empty() && b != "." && b != "..")
}

fn collect_package_files(
    root: &Path,
    dir: &Path,
    depth: usize,
    output: &mut Vec<(String, PathBuf)>,
) -> Result<(), DistributionError> {
    if depth > MAX_DEPTH {
        return error("the version package is too deep");
    }
    for g in fs::read_dir(dir).map_err(|e| io_error(dir, e))? {
        let path = g.map_err(|e| io_error(dir, e))?.path();
        let m = fs::symlink_metadata(&path).map_err(|e| io_error(&path, e))?;
        let relative = path.strip_prefix(root).map_err(|e| io_error(&path, e))?.to_string_lossy().into_owned();
        if m.file_type().is_symlink() {
            return error(format!("there is a symlink in the version package: {relative}"));
        }
        if m.is_dir() {
            collect_package_files(root, &path, depth + 1, output)?;
        } else if m.is_file() {
            if output.len() >= MAX_FILE_COUNT {
                return error("there are too many files in the version package");
            }
            output.push((relative, path));
        } else {
            return error(format!("there is a special file in the version package: {relative}"));
        }
    }
    Ok(())
}

/// `openssl dgst -sha256 -verify`: prints "Verified OK" when the signature verifies. Key, signature and data
/// are written to a 0700 temporary directory for this call only.
fn verify_signature(public_key_pem: &str, data: &[u8], signature: &[u8]) -> Result<(), DistributionError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let temp = std::env::temp_dir().join(format!(
        "sig-{}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos())
    ));
    DirBuilder::new().mode(0o700).create(&temp).map_err(|e| io_error(&temp, e))?;
    let result = (|| {
        let (k, i, v) = (temp.join("key.pem"), temp.join("sig"), temp.join("data"));
        for (path, content) in [(&k, public_key_pem.as_bytes()), (&i, signature), (&v, data)] {
            write_new(path, content, 0o600)?;
        }
        let output = Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"])
            .arg(&k)
            .arg("-signature")
            .arg(&i)
            .arg(&v)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                DistributionError(format!("openssl could not run (it is required for signature verification): {e}"))
            })?;
        let text = String::from_utf8_lossy(&output.stdout);
        if output.status.success() && text.contains("Verified OK") {
            Ok(())
        } else {
            error("the version signature could not be verified (SHA256SUMS.sig does not match the public key)")
        }
    })();
    let _ = fs::remove_dir_all(&temp);
    result
}

/// Reads and verifies a version package: signature, digest list, file set, SHA-256 and mandatory content.
pub fn read_package(dir: &Path, public_key_pem: &str) -> Result<Package, DistributionError> {
    let m = fs::symlink_metadata(dir).map_err(|e| io_error(dir, e))?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return error(format!("{}: the version package must be a directory (not a symlink)", dir.display()));
    }
    let mut files = Vec::new();
    collect_package_files(dir, dir, 0, &mut files)?;
    let read = |name: &str| -> Result<Vec<u8>, DistributionError> {
        let path = dir.join(name);
        let m = fs::symlink_metadata(&path)
            .map_err(|_| DistributionError(format!("there is no {name} in the version package")))?;
        if m.len() > MAX_FILE_BYTES {
            return error(format!("{name} is too large"));
        }
        fs::read(&path).map_err(|e| io_error(&path, e))
    };
    let signature = read("SHA256SUMS.sig")
        .map_err(|_| DistributionError("there is no signature file in the version package (SHA256SUMS.sig)".into()))?;
    let sums = read("SHA256SUMS")?;
    verify_signature(public_key_pem, &sums, &signature)?;

    // Digest list: "<64 lowercase hex>  <path>"; paths unique and safe.
    let sums_text = String::from_utf8(sums).map_err(|_| DistributionError("SHA256SUMS is not valid UTF-8".into()))?;
    let mut listed: BTreeMap<String, String> = BTreeMap::new();
    for line in sums_text.lines() {
        let Some((digest_v, path)) = line.split_once("  ") else {
            return error(format!("invalid SHA256SUMS line: {line:?}"));
        };
        if digest_v.len() != 64 || !digest_v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return error(format!("invalid SHA256SUMS digest: {line:?}"));
        }
        if !is_valid_package_path(path) {
            return error(format!("invalid SHA256SUMS path: {path:?}"));
        }
        if listed.insert(path.to_string(), digest_v.to_string()).is_some() {
            return error(format!("duplicate path in SHA256SUMS: {path}"));
        }
    }
    // Files in the directory must match the list exactly (meta files excluded).
    let present_v: BTreeSet<&str> =
        files.iter().map(|(g, _)| g.as_str()).filter(|g| *g != "SHA256SUMS" && *g != "SHA256SUMS.sig").collect();
    if let Some(extra_v) = present_v.iter().find(|g| !listed.contains_key(**g)) {
        return error(format!("the package holds a file not in the list: {extra_v}"));
    }
    if let Some(missing_v) = listed.keys().find(|g| !present_v.contains(g.as_str())) {
        return error(format!("a listed file is missing from the package: {missing_v}"));
    }
    let mut contents = BTreeMap::new();
    for (relative, digest_v) in &listed {
        let data = read(relative)?;
        if sha256_hex(&data) != *digest_v {
            return error(format!("SHA-256 digest does not match: {relative}"));
        }
        contents.insert(relative.clone(), data);
    }
    // Mandatory content.
    let version_text = contents
        .get("VERSION")
        .ok_or_else(|| DistributionError("there is no VERSION file in the version package".into()))?;
    let version = String::from_utf8_lossy(version_text).trim().to_string();
    if parse_version(&version).is_none() {
        return error(format!("invalid VERSION (expected X.Y.Z): {version:?}"));
    }
    for required in ["koru-agent", "thresholds.toml"] {
        if !contents.contains_key(required) {
            return error(format!("there is no {required} in the version package"));
        }
    }
    for dir in ["packages/rules/", "packages/agents/", "packages/decoys/"] {
        if !contents.keys().any(|k| k.starts_with(dir)) {
            return error(format!("{dir} is empty or missing in the version package"));
        }
    }
    Ok(Package { version, files: contents })
}

// ---------------------------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------------------------

fn write_new(path: &Path, content: &[u8], mode: u32) -> Result<(), DistributionError> {
    let mut f = OpenOptions::new().write(true).create_new(true).mode(mode).open(path).map_err(|e| io_error(path, e))?;
    f.write_all(content).map_err(|e| io_error(path, e))?;
    f.set_permissions(fs::Permissions::from_mode(mode)).map_err(|e| io_error(path, e))?;
    f.sync_all().map_err(|e| io_error(path, e))
}

/// Writes atomically over an existing file (temporary file in the same directory + `rename`).
fn write_atomic(path: &Path, content: &[u8], mode: u32) -> Result<(), DistributionError> {
    let temp = path.with_extension("new");
    let _ = fs::remove_file(&temp);
    write_new(&temp, content, mode)?;
    fs::rename(&temp, path).map_err(|e| io_error(path, e))
}

fn make_dir(path: &Path, mode: u32) -> Result<(), DistributionError> {
    DirBuilder::new().mode(mode).create(path).map_err(|e| io_error(path, e))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| io_error(path, e))
}

fn read_mtime(path: &Path) -> Option<(i64, u32)> {
    let m = fs::symlink_metadata(path).ok()?;
    Some((m.mtime(), u32::try_from(m.mtime_nsec()).ok()?))
}

fn write_mtime(path: &Path, sn: i64, ns: u32) -> std::io::Result<()> {
    let sn = u64::try_from(sn).map_err(|_| std::io::Error::other("negative timestamp"))?;
    let f = fs::File::open(path)?;
    f.set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::new(sn, ns)))
}

fn replace_valid_symlink(y: &Config, version: &str) -> Result<(), DistributionError> {
    let connection = y.current_link();
    let temp = connection.with_extension("new");
    let _ = fs::remove_file(&temp);
    symlink(format!("versions/{version}"), &temp).map_err(|e| io_error(&temp, e))?;
    fs::rename(&temp, &connection).map_err(|e| io_error(&connection, e))
}

// ---------------------------------------------------------------------------------------------
// Install record
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MtimeRecord {
    path: String,
    sn: i64,
    ns: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    record_version: u32,
    active: String,
    previous: Option<String>,
    #[serde(default)]
    created_dirs: Vec<String>,
    #[serde(default)]
    dir_mtimes: Vec<MtimeRecord>,
}

impl Record {
    fn toml(&self) -> String {
        let mut s = format!("record_version = {RECORD_VERSION}\nactive = {}\n", toml_text(&self.active));
        if let Some(o) = &self.previous {
            s.push_str(&format!("previous = {}\n", toml_text(o)));
        }
        let list: Vec<String> = self.created_dirs.iter().map(|d| toml_text(d)).collect();
        s.push_str(&format!("created_dirs = [{}]\n", list.join(", ")));
        for m in &self.dir_mtimes {
            s.push_str(&format!("\n[[dir_mtimes]]\npath = {}\nsn = {}\nns = {}\n", toml_text(&m.path), m.sn, m.ns));
        }
        s
    }

    fn record_mtime(&mut self, path: &Path) {
        let y = path.display().to_string();
        if self.dir_mtimes.iter().any(|m| m.path == y) {
            return;
        }
        if let Some((sn, ns)) = read_mtime(path) {
            self.dir_mtimes.push(MtimeRecord { path: y, sn, ns });
        }
    }

    fn restore_mtime(&self, warnings: &mut Vec<String>) {
        for m in &self.dir_mtimes {
            if Path::new(&m.path).exists() && write_mtime(Path::new(&m.path), m.sn, m.ns).is_err() {
                warnings.push(format!("{}: the mtime could not be restored", m.path));
            }
        }
    }
}

fn read_record(y: &Config) -> Result<Option<Record>, DistributionError> {
    let path = y.install_record();
    if fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    let bytes = safe_read::read(&path, 1024 * 1024, ReadMode::Secret).map_err(DistributionError)?;
    let text =
        String::from_utf8(bytes).map_err(|_| DistributionError(format!("{}: not valid UTF-8", path.display())))?;
    let k: Record = toml::from_str(&text)
        .map_err(|e| DistributionError(format!("{}: the install record is corrupt: {e}", path.display())))?;
    if k.record_version != RECORD_VERSION || parse_version(&k.active).is_none() {
        return error(format!("{}: the install record is unsupported or corrupt", path.display()));
    }
    Ok(Some(k))
}

fn write_record(y: &Config, k: &Record) -> Result<(), DistributionError> {
    let path = y.install_record();
    if fs::symlink_metadata(&path).is_ok() {
        write_atomic(&path, k.toml().as_bytes(), 0o600)
    } else {
        write_new(&path, k.toml().as_bytes(), 0o600)
    }
}

/// Creates and records the missing parent directories of the target directory; records the mtime of the
/// nearest existing parent (restored on uninstall).
fn dir_chain(target: &Path, mode: u32, record: &mut Record) -> Result<(), DistributionError> {
    let mut missing_v = Vec::new();
    let mut p = target;
    while fs::symlink_metadata(p).is_err() {
        missing_v.push(p);
        p = p.parent().ok_or_else(|| DistributionError(format!("{}: no parent directory", target.display())))?;
    }
    if !fs::symlink_metadata(p).map_err(|e| io_error(p, e))?.is_dir() {
        return error(format!("{}: not a directory", p.display()));
    }
    record.record_mtime(p);
    for (i, d) in missing_v.iter().rev().enumerate() {
        let last = i == missing_v.len() - 1;
        make_dir(d, if last { mode } else { 0o755 })?;
        record.created_dirs.push(d.display().to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Unit and environment
// ---------------------------------------------------------------------------------------------

/// systemd unit file text from the config (template: `distribution/unit.template`; `#` comments in the template
/// are stripped).
pub fn render_unit(y: &Config) -> String {
    let runtime =
        y.directories.runtime.strip_prefix("/run").map_or_else(|_| String::new(), |p| p.display().to_string());
    let body: Vec<&str> = UNIT_TEMPLATE.lines().filter(|s| !s.starts_with('#')).collect();
    let text = body
        .join("\n")
        .replace("@SERVICE@", &y.id.service_name)
        .replace("@EXEC@", &y.agent_binary().display().to_string())
        .replace("@CONFIG@", &y.config_file().display().to_string())
        .replace("@RUNTIME@", &runtime)
        .replace("@STATE@", &y.directories.state.display().to_string());
    let mut text = text.trim_start().to_string();
    text.push('\n');
    text
}

/// Filters only the notify variables out of an environment file (other secrets never reach the target machine).
pub fn filter_env(input: &BTreeMap<String, String>) -> String {
    let mut s = String::new();
    for name in ENV_ALLOWLIST {
        if let Some(d) = input.get(name)
            && !d.is_empty()
            && !d.chars().any(char::is_control)
        {
            s.push_str(&format!("{name}={d}\n"));
        }
    }
    s
}

fn env_contents(file: Option<&Path>) -> Result<String, DistributionError> {
    let Some(path) = file else { return Ok(String::new()) };
    let bytes = safe_read::read(path, 64 * 1024, ReadMode::Secret).map_err(DistributionError)?;
    let text =
        String::from_utf8(bytes).map_err(|_| DistributionError(format!("{}: not valid UTF-8", path.display())))?;
    Ok(filter_env(&koru_notify::parse_dotenv(&text)))
}

// ---------------------------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------------------------

/// The service must be active in all `health_probe` consecutive attempts.
fn is_healthy(b: &LineContext<'_>, service_v: &str) -> bool {
    for i in 0..b.health_probe.max(1) {
        if i > 0 {
            std::thread::sleep(b.health_wait);
        }
        if !matches!(b.systemd_ctl.is_active(service_v), Ok(true)) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------------------------

fn write_version_files(y: &Config, p: &Package) -> Result<(), DistributionError> {
    let root = y.version_dir(&p.version);
    let mut directories: BTreeSet<PathBuf> = BTreeSet::new();
    let mut to_write: Vec<(PathBuf, &Vec<u8>, u32)> = Vec::new();
    // The agent binary under the process name in the config; data files under `data/`.
    to_write.push((root.join(&y.id.process_name), &p.files["koru-agent"], 0o755));
    for (relative, content) in &p.files {
        let target = if let Some(child) = relative.strip_prefix("packages/") {
            root.join("data").join(child)
        } else if relative == "thresholds.toml" {
            root.join("data/thresholds.toml")
        } else {
            continue;
        };
        to_write.push((target, content, 0o644));
    }
    for (target, _, _) in &to_write {
        let mut parent = target.parent();
        while let Some(u) = parent {
            if u == root {
                break;
            }
            directories.insert(u.to_path_buf());
            parent = u.parent();
        }
    }
    make_dir(&root, 0o755)?;
    for d in &directories {
        // BTreeSet sorts by path components: a parent directory comes before its children.
        if fs::symlink_metadata(d).is_err() {
            make_dir(d, 0o755)?;
        }
    }
    for (target, content, mode) in to_write {
        write_new(&target, content, mode)?;
    }
    Ok(())
}

/// Rolls back a half-finished install.
fn rollback_install(b: &LineContext<'_>, y: &Config, record: &Record, systemd_touched: bool, decoy_attempted: bool) {
    if systemd_touched {
        let _ = b.systemd_ctl.stop_disable(&y.id.service_name);
    }
    if decoy_attempted {
        let _ = koru_decoy::uninstall(&y.decoy_state_dir());
    }
    let _ = fs::remove_file(y.service_file());
    if systemd_touched {
        let _ = b.systemd_ctl.daemon_reload();
    }
    cleanup_dirs(y, record, false);
    let mut u = Vec::new();
    record.restore_mtime(&mut u);
}

/// Deletes the directories the install created and their contents. With `keep_data`, only the store
/// and the queue remain in the state directory.
fn cleanup_dirs(y: &Config, record: &Record, keep_data: bool) {
    let our_state = record.created_dirs.iter().any(|d| Path::new(d) == y.directories.state);
    let _ = fs::remove_dir_all(&y.directories.install);
    let _ = fs::remove_dir_all(&y.directories.config);
    if !keep_data && our_state {
        let _ = fs::remove_dir_all(&y.directories.state);
    } else {
        // Data is kept or the state directory pre-dates the install: only what the install wrote is deleted.
        let _ = fs::remove_dir_all(y.decoy_state_dir());
        let _ = fs::remove_file(y.install_record());
    }
    // Delete created parent directories (when empty) in reverse order. The directory holding kept data stays.
    for d in record.created_dirs.iter().rev() {
        let _ = fs::remove_dir(d);
    }
}

/// Verifies and installs the version package; places decoys, writes the unit, starts the service.
pub fn install_distribution(b: &LineContext<'_>, s: &InstallOptions) -> Result<InstallReport, DistributionError> {
    let y = &s.config;
    if fs::symlink_metadata(y.install_record()).is_ok()
        || fs::symlink_metadata(&y.directories.install).is_ok()
        || fs::symlink_metadata(&y.directories.config).is_ok()
        || fs::symlink_metadata(y.service_file()).is_ok()
    {
        return error(format!(
            "Koru seems to be installed already ({}); uninstall first",
            y.directories.install.display()
        ));
    }
    // 1) Verification and input reading: before anything is written.
    let package = read_package(&s.version_dir, &b.public_key_pem)?;
    let environment = env_contents(s.env_file.as_deref())?;

    // 2) Directories and files. On InputError, what was created is rolled back.
    let mut record = Record { record_version: RECORD_VERSION, active: package.version.clone(), ..Record::default() };
    let mut systemd_touched = false;
    let mut decoy_attempted = false;
    let result = (|| -> Result<(), DistributionError> {
        // The install directory is root-only: names of rule files (koru_*.yml) stay invisible to
        // unprivileged users (self-hiding; ADR-0008 §3).
        dir_chain(&y.directories.install, 0o700, &mut record)?;
        dir_chain(&y.directories.config, 0o700, &mut record)?;
        if fs::symlink_metadata(&y.directories.state).is_err() {
            dir_chain(&y.directories.state, 0o700, &mut record)?;
        } else {
            let st = fs::symlink_metadata(&y.directories.state).map_err(|e| io_error(&y.directories.state, e))?;
            if !st.is_dir() || st.mode() & 0o077 != 0 {
                return error(format!(
                    "{}: the state directory must be a 0700 directory",
                    y.directories.state.display()
                ));
            }
        }
        record.record_mtime(&y.directories.unit);
        if fs::symlink_metadata(&y.directories.unit).is_err() {
            dir_chain(&y.directories.unit, 0o755, &mut record)?;
        }
        record.record_mtime(&y.directories.unit.join("multi-user.target.wants"));
        make_dir(&y.directories.install.join("versions"), 0o755)?;
        write_version_files(y, &package)?;
        write_new(&y.config_file(), y.toml().as_bytes(), 0o600)?;
        write_new(&y.env_file(), environment.as_bytes(), 0o600)?;
        let pulsar = format!("[pulsar]\napi_socket_path = {}\n", toml_text(&y.engine_socket().display().to_string()));
        write_new(&y.pulsar_config(), pulsar.as_bytes(), 0o600)?;
        symlink(format!("versions/{}", package.version), y.current_link())
            .map_err(|e| io_error(&y.current_link(), e))?;
        // Decoys and breadcrumbs (koru-decoy).
        let decoy_package = koru_decoy::read_package(&y.version_dir(&package.version).join("data/decoys"))
            .map_err(|e| DistributionError(format!("decoy package: {e}")))?;
        let mut settings_v = koru_decoy::InstallSettings::new(y.decoy.root.clone(), y.decoy_state_dir());
        for k in &y.decoy.allowed_roots {
            settings_v = settings_v.allowed_root(k.clone());
        }
        if let Some((u, g)) = y.decoy.owner {
            settings_v = settings_v.owner(u, g);
        }
        decoy_attempted = true;
        koru_decoy::install(&decoy_package, &settings_v)
            .map_err(|e| DistributionError(format!("decoy installation: {e}")))?;
        write_new(&y.service_file(), render_unit(y).as_bytes(), 0o644)?;
        write_record(y, &record)?;
        systemd_touched = true;
        b.systemd_ctl.daemon_reload().map_err(DistributionError)?;
        b.systemd_ctl.enable_start(&y.id.service_name).map_err(DistributionError)?;
        Ok(())
    })();
    if let Err(e) = result {
        rollback_install(b, y, &record, systemd_touched, decoy_attempted);
        return Err(e);
    }
    if !is_healthy(b, &y.id.service_name) {
        return error(format!(
            "installed, but the service did not become active ({}); `systemctl status` and the journal, then uninstall or fix it",
            y.id.service_name
        ));
    }
    Ok(InstallReport { version: package.version })
}

// ---------------------------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------------------------

/// Rolls back the install. A modified decoy is not deleted; the record stays and the command can be re-run.
pub fn uninstall(b: &LineContext<'_>, y: &Config, keep_data: bool) -> Result<UninstallReport, DistributionError> {
    let Some(record) = read_record(y)? else {
        return error("Koru is not installed (no install record)");
    };
    let mut warnings = Vec::new();
    if let Err(e) = b.systemd_ctl.stop_disable(&y.id.service_name) {
        warnings.push(format!("the service could not be stopped: {e}"));
    }
    // Decoys are rolled back per koru-decoy's record.
    if fs::symlink_metadata(y.decoy_state_dir()).is_ok() {
        let report = koru_decoy::uninstall(&y.decoy_state_dir())
            .map_err(|e| DistributionError(format!("decoy uninstall: {e}")))?;
        warnings.extend(report.warnings.iter().cloned());
        if !report.completed() {
            for s in &report.results {
                if let koru_decoy::RemovalStatus::Left { reason } = &s.state {
                    warnings.push(format!("left behind: {} ({reason})", s.path));
                }
            }
            return Ok(UninstallReport { completed: false, warnings });
        }
    }
    let _ = fs::remove_file(y.service_file());
    b.systemd_ctl.daemon_reload().map_err(DistributionError)?;
    cleanup_dirs(y, &record, keep_data);
    record.restore_mtime(&mut warnings);
    Ok(UninstallReport { completed: true, warnings })
}

// ---------------------------------------------------------------------------------------------
// Upgrade and downgrade
// ---------------------------------------------------------------------------------------------

fn prune_versions(y: &Config, keep: &[&str]) {
    let Ok(entries) = fs::read_dir(y.directories.install.join("versions")) else { return };
    for g in entries.flatten() {
        let name = g.file_name().to_string_lossy().into_owned();
        if !keep.contains(&name.as_str()) {
            let _ = fs::remove_dir_all(g.path());
        }
    }
}

/// Switches to the new version; keeps the previous one for downgrade. A failed health check rolls back.
pub fn upgrade(b: &LineContext<'_>, y: &Config, version_dir: &Path) -> Result<UpgradeReport, DistributionError> {
    let Some(mut record) = read_record(y)? else {
        return error("Koru is not installed (no install record)");
    };
    let package = read_package(version_dir, &b.public_key_pem)?;
    if !newer(&package.version, &record.active) {
        return error(format!(
            "an upgrade needs a version newer than the active one ({}); package: {}",
            record.active, package.version
        ));
    }
    let old_active = record.active.clone();
    let old_record = record.clone();
    let old_unit = fs::read(y.service_file()).ok();
    // An old same-named version directory (e.g. left from a downgrade) is refreshed with verified content.
    let new_dir = y.version_dir(&package.version);
    if fs::symlink_metadata(&new_dir).is_ok() {
        fs::remove_dir_all(&new_dir).map_err(|e| io_error(&new_dir, e))?;
    }
    let rollback = || {
        let _ = replace_valid_symlink(y, &old_active);
        let _ = fs::remove_dir_all(y.version_dir(&package.version));
        if let Some(old_v) = &old_unit {
            let _ = write_atomic(&y.service_file(), old_v, 0o644);
            let _ = b.systemd_ctl.daemon_reload();
        }
        let _ = write_record(y, &old_record);
        let _ = b.systemd_ctl.restart(&y.id.service_name);
    };
    let result = (|| -> Result<(), DistributionError> {
        write_version_files(y, &package)?;
        let new_unit = render_unit(y);
        let unit_changed = old_unit.as_deref() != Some(new_unit.as_bytes());
        if unit_changed {
            write_atomic(&y.service_file(), new_unit.as_bytes(), 0o644)?;
        }
        replace_valid_symlink(y, &package.version)?;
        record.previous = Some(old_active.clone());
        record.active = package.version.clone();
        write_record(y, &record)?;
        if unit_changed {
            b.systemd_ctl.daemon_reload().map_err(DistributionError)?;
        }
        b.systemd_ctl.restart(&y.id.service_name).map_err(DistributionError)?;
        Ok(())
    })();
    if let Err(e) = result {
        rollback();
        return error(format!("the upgrade failed; rolled back to {old_active}: {e}"));
    }
    if !is_healthy(b, &y.id.service_name) {
        rollback();
        return error(format!(
            "the service did not become active after the upgrade; rolled back to {old_active} (tried: {})",
            package.version
        ));
    }
    prune_versions(y, &[&package.version, &old_active]);
    Ok(UpgradeReport { previous: old_active, new: package.version })
}

/// Goes back to the previous version (calling again moves forward). A failed health check
/// restores the previous state.
pub fn rollback(b: &LineContext<'_>, y: &Config) -> Result<RollbackReport, DistributionError> {
    let Some(mut record) = read_record(y)? else {
        return error("Koru is not installed (no install record)");
    };
    let Some(previous) = record.previous.clone() else {
        return error("there is no previous version to go back to");
    };
    let target_dir = y.version_dir(&previous);
    if !fs::symlink_metadata(&target_dir).is_ok_and(|m| m.is_dir()) {
        return error(format!("the previous version directory is missing: {}", target_dir.display()));
    }
    let old_v = record.clone();
    let current_version = record.active.clone();
    replace_valid_symlink(y, &previous)?;
    record.active = previous.clone();
    record.previous = Some(current_version.clone());
    write_record(y, &record)?;
    let again_v = b.systemd_ctl.restart(&y.id.service_name);
    if again_v.is_err() || !is_healthy(b, &y.id.service_name) {
        let _ = replace_valid_symlink(y, &current_version);
        let _ = write_record(y, &old_v);
        let _ = b.systemd_ctl.restart(&y.id.service_name);
        return error(format!(
            "downgrade failed: the service did not become active on {previous}; back on {current_version}"
        ));
    }
    Ok(RollbackReport { previous: current_version, new: previous })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_cmp_numeric_and_prerelease_aware() {
        assert!(newer("1.10.0", "1.9.0"));
        assert!(newer("2.0.0", "1.99.99"));
        assert!(!newer("1.2.0", "1.2.0"));
        assert!(!newer("1.1.9", "1.2.0"));
        assert!(newer("1.2.0", "1.2.0-rc.1"), "stable is newer than the prerelease");
        assert!(!newer("1.2.0-rc.1", "1.2.0"));
        assert!(newer("1.2.0-rc.2", "1.2.0-rc.1"));
        assert!(!newer("x", "1.0.0"));
        assert!(
            parse_version("1.2").is_none() && parse_version("1.2.3.4").is_none() && parse_version("1.2.3-").is_none()
        );
        assert!(parse_version("1.2.3-beta.1").is_some());
    }

    #[test]
    fn package_path_rules() {
        for good in ["koru-agent", "packages/rules/a.yml", "thresholds.toml"] {
            assert!(is_valid_package_path(good), "{good}");
        }
        for bad in ["", "/etc/passwd", "../a", "a/../b", "a//b", "a/./b", "a\\b", "a\nb", "a/"] {
            assert!(!is_valid_package_path(bad), "{bad:?}");
        }
    }

    #[test]
    fn env_filter_passes_only_allowed_vars() {
        let g: BTreeMap<String, String> = [
            ("KORU_NTFY_URL", "https://ntfy.sample.test/k"),
            ("KORU_SIGNING_KEY", "secret"),
            ("KORU_SMTP_PASSWORD", "password"),
            ("KORU_HEARTBEAT_URL", "broken\u{1b}[31m"),
            ("PATH", "/usr/bin"),
        ]
        .into_iter()
        .map(|(a, d)| (a.to_string(), d.to_string()))
        .collect();
        let s = filter_env(&g);
        assert_eq!(s, "KORU_NTFY_URL=https://ntfy.sample.test/k\nKORU_SMTP_PASSWORD=password\n");
    }
}
