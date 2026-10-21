//! `distribution/install.sh` (ADR-0008): it does not install without verifying the signature and SHA-256. The script
//! copies the version package into a private temp directory, verifies that copy, and runs `koru install` from
//! the copy (nothing can change between verification and use). The trusted public key is bound by a
//! fingerprint pinned in the script. The tests perform no real install: a fake script that records its
//! arguments stands in for `koru`.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::*;

fn script() -> PathBuf {
    store_root().join("distribution/install.sh")
}

fn sh(args: &[&str]) -> Output {
    Command::new("sh").arg(script()).args(args).output().expect("sh could not be run")
}

fn output(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

struct Harness {
    t: tempfile::TempDir,
    key_v: TestKey,
    fingerprint: String,
    record: PathBuf,
}

impl Harness {
    fn new() -> Harness {
        let t = temp();
        let key_v = generate_key(&canonical(&t), "test");
        let fingerprint = sha256_hex(&fs::read(&key_v.public_v).unwrap());
        let record = canonical(&t).join("koru-arguments.txt");
        Harness { t, key_v, fingerprint, record }
    }

    /// A signed package holding a fake `koru`: when invoked it writes its arguments to the record file.
    fn package(&self, version: &str) -> PathBuf {
        let p = generate_version(&canonical(&self.t), version, &self.key_v);
        let koru = p.join("koru");
        fs::write(
            &koru,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\npwd >> '{}'\nexit 0\n",
                self.record.display(),
                self.record.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&koru, fs::Permissions::from_mode(0o755)).unwrap();
        sign_package(&p, &self.key_v);
        p
    }

    /// If `extra` contains `--`, the items before it are script options; `--` and what follows come AFTER
    /// the package directory (arguments forwarded to koru).
    fn run(&self, extra: &[&str], package: &Path) -> Output {
        let public_v = self.key_v.public_v.to_string_lossy().into_owned();
        let mut args = vec!["--public-key", public_v.as_str(), "--fingerprint", self.fingerprint.as_str()];
        let (before, after) = match extra.iter().position(|a| *a == "--") {
            Some(i) => extra.split_at(i),
            None => (extra, &[][..]),
        };
        args.extend_from_slice(before);
        args.push(package.to_str().unwrap());
        args.extend_from_slice(after);
        sh(&args)
    }
}

#[test]
fn script_exists_and_has_clean_syntax() {
    assert!(script().is_file(), "distribution/install.sh is missing");
    let o = Command::new("sh").arg("-n").arg(script()).output().unwrap();
    assert!(o.status.success(), "{}", output(&o));
    let content = fs::read_to_string(script()).unwrap();
    assert!(content.starts_with("#!/bin/sh"), "must be a POSIX sh script");
    assert!(content.contains("set -eu"));
    // Where shellcheck exists, it must be clean.
    if let Ok(o) = Command::new("shellcheck").arg("-s").arg("sh").arg(script()).output() {
        assert!(o.status.success(), "shellcheck:\n{}", output(&o));
    }
}

#[test]
fn embedded_fingerprint_matches_repo_public_key() {
    let content = fs::read_to_string(script()).unwrap();
    let line = content.lines().find(|s| s.starts_with("EMBEDDED_FINGERPRINT=")).expect("no pinned fingerprint");
    let value = line.trim_start_matches("EMBEDDED_FINGERPRINT=").trim_matches('"');
    let pem = fs::read(store_root().join("distribution/signing-public-key.pem")).unwrap();
    assert_eq!(value, sha256_hex(&pem), "the fingerprint pinned in install.sh must equal the public key's");
}

#[test]
fn signed_package_validates_in_verify_mode() {
    let d = Harness::new();
    let p = d.package("1.0.0");
    let o = d.run(&["--verify-only"], &p);
    assert!(o.status.success(), "{}", output(&o));
    assert!(output(&o).contains("Verified OK"), "{}", output(&o));
    assert!(!d.record.exists(), "verify-only must not run koru");
}

#[test]
fn embedded_key_default_and_rejects_test_signature() {
    let d = Harness::new();
    let p = d.package("1.0.0");
    let o = sh(&["--verify-only", p.to_str().unwrap()]);
    assert!(!o.status.success());
    assert!(output(&o).contains("signature"), "{}", output(&o));
    assert!(!d.record.exists());
}

#[test]
fn mismatched_or_missing_fingerprint_rejected() {
    let d = Harness::new();
    let p = d.package("1.0.0");
    let public_v = d.key_v.public_v.to_string_lossy().into_owned();
    let wrong_v = "0".repeat(64);
    let o = sh(&["--verify-only", "--public-key", &public_v, "--fingerprint", &wrong_v, p.to_str().unwrap()]);
    assert!(!o.status.success());
    assert!(output(&o).contains("fingerprint"), "{}", output(&o));
    // A public key without a fingerprint: usage error (exit 2).
    let o = sh(&["--verify-only", "--public-key", &public_v, p.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", output(&o));
}

#[test]
fn corrupt_packages_rejected_and_koru_does_not_run() {
    let d = Harness::new();
    // One byte changed.
    let p = d.package("1.0.0");
    let mut binary_v = fs::read(p.join("koru-agent")).unwrap();
    binary_v.push(b'#');
    fs::write(p.join("koru-agent"), binary_v).unwrap();
    let o = d.run(&[], &p);
    assert!(!o.status.success() && output(&o).contains("digest"), "{}", output(&o));
    // A file not in the list.
    let p = d.package("1.0.1");
    fs::write(p.join("packages/rules/extra.yml"), "x\n").unwrap();
    let o = d.run(&[], &p);
    assert!(!o.status.success() && output(&o).contains("not in the list"), "{}", output(&o));
    // No signature.
    let p = d.package("1.0.2");
    fs::remove_file(p.join("SHA256SUMS.sig")).unwrap();
    let o = d.run(&[], &p);
    assert!(!o.status.success() && output(&o).contains("signature"), "{}", output(&o));
    // Signed with another key.
    let p = d.package("1.0.3");
    let other_v = generate_key(&canonical(&d.t), "other_v");
    sign_package(&p, &other_v);
    let o = d.run(&[], &p);
    assert!(!o.status.success() && output(&o).contains("signature"), "{}", output(&o));
    // A symlink.
    let p = d.package("1.0.4");
    linked_symlink(Path::new("/etc/passwd"), &p.join("packages/rules/b.yml"));
    sign_package(&p, &d.key_v);
    let o = d.run(&[], &p);
    assert!(!o.status.success() && output(&o).contains("symlink"), "{}", output(&o));
    // No such package directory.
    let o = d.run(&[], &canonical(&d.t).join("nope"));
    assert!(!o.status.success());
    assert!(!d.record.exists(), "koru must not run for any corrupt package");
}

#[test]
fn verified_copy_runs_koru_install_with_args_forwarded() {
    let d = Harness::new();
    let p = d.package("1.0.0");
    let o = d.run(&["--", "--source-tag", "real", "--decoy-root", "/root"], &p);
    assert!(o.status.success(), "{}", output(&o));
    let record = fs::read_to_string(&d.record).unwrap();
    let lines: Vec<&str> = record.lines().collect();
    assert_eq!(lines[0], "install");
    assert_eq!(lines[1], "--version-dir");
    let copy_v = lines[2];
    assert_ne!(Path::new(copy_v), p, "koru must run from the VERIFIED COPY, not the original directory");
    assert!(
        Path::new(copy_v).starts_with(std::env::temp_dir()) || copy_v.contains("tmp") || copy_v.contains("T/"),
        "{copy_v}"
    );
    assert_eq!(lines[3], "--public-key");
    assert_eq!(lines[5..9], ["--source-tag", "real", "--decoy-root", "/root"], "{lines:?}");
    // A `--` that is not a script option is not forwarded.
    assert!(!lines.contains(&"--"), "{lines:?}");
    // The temp copy is deleted when the work ends.
    assert!(!Path::new(copy_v).exists(), "the temp copy must be cleaned: {copy_v}");
}

#[test]
fn exit_code_is_propagated_when_koru_fails() {
    let d = Harness::new();
    let p = d.package("1.0.0");
    fs::write(p.join("koru"), "#!/bin/sh\nexit 7\n").unwrap();
    fs::set_permissions(p.join("koru"), fs::Permissions::from_mode(0o755)).unwrap();
    sign_package(&p, &d.key_v);
    let o = d.run(&[], &p);
    assert_eq!(o.status.code(), Some(7), "{}", output(&o));
}
