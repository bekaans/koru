//! Shared helpers: a temp environment, a tree snapshot, template-package writing, external commands.

use std::collections::BTreeMap;
use std::fs::{self, File, FileTimes};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use koru_decoy::{InstallReport, InstallSettings, Package, install, read_package};

/// The repository root.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The decoy templates in the repo (`packages/decoys/`).
pub fn package_dir() -> PathBuf {
    repo_root().join("packages/decoys")
}

/// The decoy package in the repo; it must validate.
pub fn package() -> Package {
    read_package(&package_dir()).unwrap_or_else(|e| panic!("packages/decoys could not be read: {e}"))
}

/// A temp directory. The path is canonical (on macOS the `/var` -> `/private/var` link is
/// resolved); Koru accepts no symlink in a root path.
pub struct TempRoot {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
}

pub fn temp_dir() -> TempRoot {
    let dir = tempfile::tempdir().expect("the temp directory could not be created");
    let path = fs::canonicalize(dir.path()).expect("the temp directory canonical path");
    TempRoot { _dir: dir, path }
}

/// An install environment: the root (a fake home) and the state directory's parent are separate
/// temp directories. The state directory is created at install time.
pub struct Env {
    pub root: TempRoot,
    pub parent: TempRoot,
}

impl Env {
    pub fn new() -> Env {
        Env { root: temp_dir(), parent: temp_dir() }
    }

    pub fn root(&self) -> &Path {
        &self.root.path
    }

    pub fn state(&self) -> PathBuf {
        self.parent.path.join("state")
    }

    pub fn settings(&self) -> InstallSettings {
        InstallSettings::new(self.root().to_path_buf(), self.state())
    }

    /// Installs the repo package into this environment; a failure fails the test.
    pub fn install(&self) -> InstallReport {
        install(&package(), &self.settings()).unwrap_or_else(|e| panic!("install failed: {e}"))
    }
}

/// The snapshot of one tree entry (the test counterpart of `lab/scripts/file-digest.sh`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotEntry {
    /// 'd' directory, 'f' regular file, 'l' symlink, 'p' FIFO, '?' other.
    pub kind: char,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Only for a regular file.
    pub content: Option<Vec<u8>>,
    /// Only for a symlink.
    pub target: Option<PathBuf>,
    /// For a file and a directory; absent for a symlink.
    pub mtime_ns: Option<i128>,
}

pub fn mtime_ns(m: &fs::Metadata) -> i128 {
    i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec())
}

pub fn now_ns() -> i128 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("time").as_nanos() as i128
}

/// The snapshot of the whole tree from the root; the key is the root-relative path (root: ".").
pub fn snapshot(root: &Path) -> BTreeMap<PathBuf, SnapshotEntry> {
    let mut result = BTreeMap::new();
    collect_snapshot(root, Path::new("."), &mut result);
    result
}

fn collect_snapshot(root: &Path, relative: &Path, result: &mut BTreeMap<PathBuf, SnapshotEntry>) {
    let path = root.join(relative);
    let m = fs::symlink_metadata(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let ft = m.file_type();
    let kind = if ft.is_dir() {
        'd'
    } else if ft.is_file() {
        'f'
    } else if ft.is_symlink() {
        'l'
    } else if ft.is_fifo() {
        'p'
    } else {
        '?'
    };
    let entry = SnapshotEntry {
        kind,
        mode: m.permissions().mode() & 0o7777,
        uid: m.uid(),
        gid: m.gid(),
        content: ft.is_file().then(|| fs::read(&path).expect("the file could not be read")),
        target: ft.is_symlink().then(|| fs::read_link(&path).expect("the link could not be read")),
        mtime_ns: (ft.is_file() || ft.is_dir()).then(|| mtime_ns(&m)),
    };
    result.insert(relative.to_path_buf(), entry);
    if ft.is_dir() {
        let mut names: Vec<_> = fs::read_dir(&path)
            .expect("the directory could not be read")
            .map(|g| g.expect("entry").file_name())
            .collect();
        names.sort();
        for name in names {
            collect_snapshot(root, &relative.join(name), result);
        }
    }
}

/// The difference of two snapshots (readable): paths present in only one, or changed.
pub fn snapshot_diff(
    before: &BTreeMap<PathBuf, SnapshotEntry>,
    after: &BTreeMap<PathBuf, SnapshotEntry>,
) -> Vec<String> {
    let mut diff = Vec::new();
    for (path, g) in before {
        match after.get(path) {
            None => diff.push(format!("removed: {}", path.display())),
            Some(s) if s != g => diff.push(format!("changed: {} ({g:?} -> {s:?})", path.display())),
            Some(_) => {}
        }
    }
    for path in after.keys() {
        if !before.contains_key(path) {
            diff.push(format!("added: {}", path.display()));
        }
    }
    diff
}

/// The root-relative paths and contents of regular files.
pub fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    snapshot(root).into_iter().filter_map(|(y, g)| g.content.map(|i| (y, i))).collect()
}

/// Sets a file's or directory's access and modification times.
pub fn set_time(path: &Path, unix_sn: u64, ns: u32) {
    let t = UNIX_EPOCH + Duration::new(unix_sn, ns);
    let f = File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    f.set_times(FileTimes::new().set_accessed(t).set_modified(t)).expect("the time could not be set");
}

pub fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("the mode could not be set");
}

/// A fake pre-existing home directory: `.bash_history`, `.ssh/config`, `.ssh/known_hosts`, and
/// one unrelated file; modes and past timestamps hold fixed values.
pub const PREVIOUS_HISTORY: &str = "ls -la\ncd /var/www/html\ngit status\nsudo systemctl status nginx\n";
pub const PREVIOUS_SSH_CONFIG: &str = "Host github.com\n    User git\n    IdentityFile ~/.ssh/id_ed25519\n";
pub const PREVIOUS_KNOWN_HOSTS: &str =
    "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n";

pub fn prepare_existing_home(root: &Path) {
    fs::write(root.join(".bash_history"), PREVIOUS_HISTORY).unwrap();
    set_mode(&root.join(".bash_history"), 0o600);
    set_time(&root.join(".bash_history"), 1_741_000_353, 123_456_789);
    fs::create_dir(root.join(".ssh")).unwrap();
    set_mode(&root.join(".ssh"), 0o700);
    fs::write(root.join(".ssh/config"), PREVIOUS_SSH_CONFIG).unwrap();
    set_mode(&root.join(".ssh/config"), 0o644);
    set_time(&root.join(".ssh/config"), 1_700_000_000, 5);
    fs::write(root.join(".ssh/known_hosts"), PREVIOUS_KNOWN_HOSTS).unwrap();
    set_mode(&root.join(".ssh/known_hosts"), 0o644);
    set_time(&root.join(".ssh/known_hosts"), 1_710_000_000, 999_999_999);
    fs::write(root.join("notes.txt"), "shopping list\n").unwrap();
    set_time(&root.join("notes.txt"), 1_720_000_000, 0);
    set_time(&root.join(".ssh"), 1_710_000_100, 42);
    set_time(root, 1_730_000_000, 7);
}

/// Writes template files into a directory.
pub fn write_package(dir: &Path, templates: &[(&str, &str)]) {
    fs::create_dir_all(dir).unwrap();
    for (name, text) in templates {
        fs::write(dir.join(name), text).unwrap();
    }
}

/// The smallest valid template used in tests (an .env decoy).
pub const SAMPLE_TEMPLATE: &str = r#"schema = 1
id = "example-env"
description = "The smallest valid template for tests."
kind = "decoy"
class = "env"
format = "env"
secret = true
content = """
APP_ENV=production
API_TOKEN={{token}}
"""

[target]
path = "app/.env"
mode = 0o600
placement = "new_file"

[timestamp]
min_days = 3
max_days = 30

[values.token]
kind = "random"
alphabet = "base62"
length = 32
"#;

/// Runs an external command with `HOME` pointed at a temp directory.
pub fn command(name: &str, args: &[&str], home: &Path) -> Output {
    Command::new(name).args(args).env("HOME", home).output().unwrap_or_else(|e| panic!("{name} could not be run: {e}"))
}

/// The RFC 5737 documentation addresses (TEST-NET-1/2/3): not routed, never reach a real target.
pub fn is_test_network(ip: std::net::Ipv4Addr) -> bool {
    matches!(ip.octets(), [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _])
}

/// The IPv4 literals in the text: parts in exactly dotted-decimal form, separated by characters
/// other than letters, digits, and dots (digit-dot runs inside random strings are not addresses).
pub fn ipv4_constants(text: &str) -> Vec<std::net::Ipv4Addr> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
        .filter(|p| p.chars().all(|c| c.is_ascii_digit() || c == '.'))
        .filter(|p| p.split('.').count() == 4 && p.split('.').all(|s| !s.is_empty() && s.len() <= 3))
        .filter_map(|p| p.parse().ok())
        .collect()
}
