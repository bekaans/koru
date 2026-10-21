//! Shared helpers for the koru CLI and distribution tests.
//!
//! A fake root: tests never write to real system directories; every directory in the config lives
//! under a temporary root. Signed version packages use a key generated in the test
//! (`openssl` required); the repo's real public key is used only in default-behavior tests.
//!
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use koru::config::Config;
use koru::distribution::Systemd;
use sha2::{Digest, Sha256};

pub fn store_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn temp() -> tempfile::TempDir {
    let t = tempfile::tempdir().expect("temp directory");
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o755)).unwrap();
    t
}

pub fn canonical(t: &tempfile::TempDir) -> PathBuf {
    fs::canonicalize(t.path()).unwrap()
}

// ---------------------------------------------------------------------------------------------
// Fake root and configuration
// ---------------------------------------------------------------------------------------------

/// Creates a directory (and any missing parents) explicitly at 0755; modes do not depend on `umask`
/// (Linux's default umask 0002 creates group-writable directories and the distribution code rejects those).
pub fn make_dir_chain(dir: &Path) {
    let mut missing_v = Vec::new();
    let mut p = dir;
    while !p.exists() {
        missing_v.push(p);
        match p.parent() {
            Some(u) => p = u,
            None => break,
        }
    }
    for d in missing_v.iter().rev() {
        fs::create_dir(d).unwrap();
        fs::set_permissions(d, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Prepares the fake root: system directories and a home directory with pre-existing files.
pub fn fake_root(root: &Path) {
    make_dir_chain(root);
    for d in [
        "usr/libexec",
        "etc",
        "var/lib",
        "etc/systemd/system",
        "etc/systemd/system/multi-user.target.wants",
        "home/devops/.ssh",
    ] {
        make_dir_chain(&root.join(d));
    }
    fs::write(root.join("etc/hostname"), "lab-server\n").unwrap();
    fs::write(root.join("home/devops/.bash_history"), "ls -la\ncd /srv\n").unwrap();
    fs::write(root.join("home/devops/.ssh/config"), "Host a\n  HostName a.example\n").unwrap();
    fs::write(root.join("home/devops/.ssh/known_hosts"), "a.example ssh-ed25519 AAAAC3\n").unwrap();
    fs::set_permissions(root.join("home/devops"), fs::Permissions::from_mode(0o750)).unwrap();
    fs::set_permissions(root.join("home/devops/.ssh"), fs::Permissions::from_mode(0o700)).unwrap();
}

/// A configuration pointing at directories under the fake root (`name` is the process and service name).
pub fn config(root: &Path, name: &str) -> Config {
    let k = root.display();
    let text = format!(
        "schema_version = 1\n[id]\nprocess_name = \"{name}\"\nservice_name = \"{name}\"\n\
         [directories]\ninstall = \"{k}/usr/libexec/{name}\"\nconfig = \"{k}/etc/{name}\"\n\
         state = \"{k}/var/lib/{name}\"\nunit = \"{k}/etc/systemd/system\"\n\
         [agent]\nsource_tag = \"synthetic\"\n[decoy]\nroot = \"{k}/home/devops\"\n"
    );
    Config::parse(&text).unwrap_or_else(|e| panic!("the fake configuration is invalid: {e}\n{text}"))
}

/// A config file (for the CLI tests, 0600).
pub fn config_file(root: &Path, y: &Config, name: &str) -> PathBuf {
    let path = root.join(format!("{name}-install.toml"));
    fs::write(&path, y.toml()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

// ---------------------------------------------------------------------------------------------
// Keys and signed version packages
// ---------------------------------------------------------------------------------------------

pub struct TestKey {
    pub secret: PathBuf,
    pub public_v: PathBuf,
    pub plain_text: String,
}

fn openssl(args: &[&str]) {
    let o = Command::new("openssl").args(args).output().expect("openssl could not be run (the tests need openssl)");
    assert!(o.status.success(), "openssl {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

pub fn generate_key(dir: &Path, name: &str) -> TestKey {
    let secret = dir.join(format!("{name}.secret.pem"));
    let public_v = dir.join(format!("{name}.public.pem"));
    openssl(&["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", secret.to_str().unwrap()]);
    openssl(&["ec", "-in", secret.to_str().unwrap(), "-pubout", "-out", public_v.to_str().unwrap()]);
    let plain_text = fs::read_to_string(&public_v).unwrap();
    TestKey { secret, public_v, plain_text }
}

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).unwrap();
    for g in fs::read_dir(source).unwrap() {
        let g = g.unwrap();
        let (k, h) = (g.path(), target.join(g.file_name()));
        if g.file_type().unwrap().is_dir() {
            copy_tree(&k, &h);
        } else {
            fs::copy(&k, &h).unwrap();
        }
    }
}

fn list_files(root: &Path, dir: &Path, output: &mut Vec<String>) {
    for g in fs::read_dir(dir).unwrap() {
        let path = g.unwrap().path();
        if fs::symlink_metadata(&path).unwrap().is_dir() {
            list_files(root, &path, output);
        } else {
            output.push(path.strip_prefix(root).unwrap().to_string_lossy().into_owned());
        }
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Regenerates the `SHA256SUMS` file (except the signature file and itself) and signs it with the given key.
pub fn sign_package(package: &Path, key_v: &TestKey) {
    let mut files = Vec::new();
    list_files(package, package, &mut files);
    files.retain(|d| d != "SHA256SUMS" && d != "SHA256SUMS.sig");
    files.sort();
    let mut text = String::new();
    for d in &files {
        text.push_str(&format!("{}  {d}\n", sha256_hex(&fs::read(package.join(d)).unwrap())));
    }
    fs::write(package.join("SHA256SUMS"), text).unwrap();
    let _ = fs::remove_file(package.join("SHA256SUMS.sig"));
    openssl(&[
        "dgst",
        "-sha256",
        "-sign",
        key_v.secret.to_str().unwrap(),
        "-out",
        package.join("SHA256SUMS.sig").to_str().unwrap(),
        package.join("SHA256SUMS").to_str().unwrap(),
    ]);
}

/// Produces a signed version package: the agent binary (fake), `packages/`, `thresholds.toml`, `VERSION`.
pub fn generate_version(dir: &Path, version: &str, key_v: &TestKey) -> PathBuf {
    let package = dir.join(format!("version-{version}"));
    fs::create_dir_all(&package).unwrap();
    let binary_v = package.join("koru-agent");
    fs::write(&binary_v, format!("#!/bin/sh\n# fake agent binary {version}\nexit 0\n")).unwrap();
    fs::set_permissions(&binary_v, fs::Permissions::from_mode(0o755)).unwrap();
    for child in ["rules", "agents", "decoys"] {
        copy_tree(&store_root().join("packages").join(child), &package.join("packages").join(child));
    }
    fs::copy(store_root().join("thresholds.toml"), package.join("thresholds.toml")).unwrap();
    fs::write(package.join("VERSION"), format!("{version}\n")).unwrap();
    sign_package(&package, key_v);
    package
}

// ---------------------------------------------------------------------------------------------
// Tree digests (the Rust counterpart of lab/scripts/file-digest.sh)
// ---------------------------------------------------------------------------------------------

/// For each entry at the root: path, type, mode, size, content digest or link target, mtime (ns).
pub fn digest(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, output: &mut Vec<String>) {
        let mut entries: Vec<PathBuf> = fs::read_dir(dir).unwrap().map(|g| g.unwrap().path()).collect();
        entries.sort();
        for path in entries {
            let m = fs::symlink_metadata(&path).unwrap();
            let relative = path.strip_prefix(root).unwrap().display().to_string();
            let mtime = format!("{}.{:09}", m.mtime(), m.mtime_nsec());
            let mode = m.mode() & 0o7777;
            if m.file_type().is_symlink() {
                output.push(format!("{relative}\tsymlink\t-> {}", fs::read_link(&path).unwrap().display()));
            } else if m.is_dir() {
                output.push(format!("{relative}\tdir\t{mode:o}\t{mtime}"));
                walk(root, &path, output);
            } else {
                output.push(format!(
                    "{relative}\tfile\t{mode:o}\t{}\t{}\t{mtime}",
                    m.len(),
                    sha256_hex(&fs::read(&path).unwrap())
                ));
            }
        }
    }
    let mut output = vec![format!(".\tdir\t{:o}\t{}", fs::metadata(root).unwrap().mode() & 0o7777, {
        let m = fs::metadata(root).unwrap();
        format!("{}.{:09}", m.mtime(), m.mtime_nsec())
    })];
    walk(root, root, &mut output);
    output
}

/// Paths only (type included), without content or timestamps.
pub fn paths(root: &Path) -> Vec<String> {
    digest(root).into_iter().map(|s| s.split('\t').next().unwrap().to_string()).collect()
}

// ---------------------------------------------------------------------------------------------
// Fake systemd
// ---------------------------------------------------------------------------------------------

pub struct FakeSystemd {
    pub calls: Mutex<Vec<String>>,
    /// `is_active` answers are consumed in order; when exhausted, `defaults` is returned.
    pub replies: Mutex<std::collections::VecDeque<bool>>,
    pub defaults: bool,
}

impl FakeSystemd {
    pub fn new() -> FakeSystemd {
        FakeSystemd { calls: Mutex::default(), replies: Mutex::default(), defaults: true }
    }

    pub fn active_replies(replies: &[bool], defaults: bool) -> FakeSystemd {
        FakeSystemd { calls: Mutex::default(), replies: Mutex::new(replies.iter().copied().collect()), defaults }
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    pub fn clean(&self) {
        self.calls.lock().unwrap().clear();
    }

    fn store(&self, c: String) -> Result<(), String> {
        self.calls.lock().unwrap().push(c);
        Ok(())
    }
}

impl Systemd for FakeSystemd {
    fn daemon_reload(&self) -> Result<(), String> {
        self.store("reload".into())
    }

    fn enable_start(&self, service_v: &str) -> Result<(), String> {
        self.store(format!("enable:{service_v}"))
    }

    fn stop_disable(&self, service_v: &str) -> Result<(), String> {
        self.store(format!("stop:{service_v}"))
    }

    fn restart(&self, service_v: &str) -> Result<(), String> {
        self.store(format!("restart:{service_v}"))
    }

    fn is_active(&self, service_v: &str) -> Result<bool, String> {
        self.calls.lock().unwrap().push(format!("is_active:{service_v}"));
        Ok(self.replies.lock().unwrap().pop_front().unwrap_or(self.defaults))
    }
}

pub fn env_file(dir: &Path, lines: &[(&str, &str)], mode: u32) -> PathBuf {
    let path = dir.join("source.env");
    let text: String = lines.iter().map(|(a, d)| format!("{a}={d}\n")).collect();
    fs::write(&path, text).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

pub fn linked_symlink(target: &Path, path: &Path) {
    symlink(target, path).unwrap();
}

pub fn map_of(c: &[(&str, &str)]) -> BTreeMap<String, String> {
    c.iter().map(|(a, d)| ((*a).to_string(), (*d).to_string())).collect()
}
