//! `distribution/sign.sh` (ADR-0008): produces the version package's SHA256SUMS file
//! and signs it with the key. The private key and passphrase are read only from two lines of `.env`
//! (or environment variables of the same names); other lines of `.env` are not looked at; no value is
//! written to output. The tests do not use the real key: a key generated in the test is used.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::*;

const PASSWORD: &str = "test-password-SECRET-9f3a";
const CANARY: &str = "OTHER_LINE_CANARY-2c71";

fn script() -> PathBuf {
    store_root().join("distribution/sign.sh")
}

fn encrypted_key_b64(dir: &Path) -> String {
    let path = dir.join("encrypted.pem");
    let o = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-aes-256-cbc",
            "-pass",
            "env:PW",
            "-out",
        ])
        .arg(&path)
        .env("PW", PASSWORD)
        .output()
        .unwrap();
    assert!(o.status.success());
    let o = Command::new("openssl").args(["base64", "-A", "-in"]).arg(&path).output().unwrap();
    String::from_utf8(o.stdout).unwrap()
}

fn public_key(dir: &Path, b64: &str) -> PathBuf {
    // Decode the base64, unlock with the passphrase, extract the public key.
    let encrypted = dir.join("encrypted2.pem");
    let mut c = Command::new("openssl")
        .args(["base64", "-d", "-A", "-out"])
        .arg(&encrypted)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(c.stdin.as_mut().unwrap(), b64.as_bytes()).unwrap();
    assert!(c.wait().unwrap().success());
    let public_v = dir.join("public.pem");
    let o = Command::new("openssl")
        .args(["pkey", "-passin", "env:PW", "-pubout", "-in"])
        .arg(&encrypted)
        .arg("-out")
        .arg(&public_v)
        .env("PW", PASSWORD)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    public_v
}

fn package(dir: &Path) -> PathBuf {
    let p = dir.join("package");
    fs::create_dir_all(p.join("packages/rules")).unwrap();
    fs::write(p.join("koru-agent"), b"binary").unwrap();
    fs::write(p.join("koru"), b"cli").unwrap();
    fs::write(p.join("VERSION"), b"1.0.0\n").unwrap();
    fs::write(p.join("packages/rules/a.yml"), b"x: 1\n").unwrap();
    p
}

fn output(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn env_file(dir: &Path, b64: &str, mode: u32) -> PathBuf {
    let path = dir.join(".env");
    fs::write(
        &path,
        format!(
            "KORU_NTFY_URL=https://ntfy.sample.test/k\nKORU_BEFORE={CANARY}\nKORU_SIGNING_KEY={b64}\n\
             KORU_SIGNING_KEY_PASSWORD={PASSWORD}\nKORU_AFTER=other-secret-value\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn run(package: &Path, env: &Path, extra_env: &[(&str, &str)]) -> Output {
    let mut c = Command::new("sh");
    c.arg(script()).arg(package).arg("--env-file").arg(env);
    for (a, d) in extra_env {
        c.env(a, d);
    }
    c.env_remove("KORU_SIGNING_KEY").env_remove("KORU_SIGNING_KEY_PASSWORD");
    for (a, d) in extra_env {
        c.env(a, d);
    }
    c.output().unwrap()
}

#[test]
fn script_exists_and_has_clean_syntax() {
    assert!(script().is_file(), "distribution/sign.sh is missing");
    let o = Command::new("sh").arg("-n").arg(script()).output().unwrap();
    assert!(o.status.success(), "{}", output(&o));
    let content = fs::read_to_string(script()).unwrap();
    assert!(content.starts_with("#!/bin/sh") && content.contains("set -eu"));
    assert!(
        !content.contains("set -x") && !content.contains("set -eux") && !content.contains("xtrace"),
        "key leak risk"
    );
    if let Ok(o) = Command::new("shellcheck").arg("-s").arg("sh").arg(script()).output() {
        assert!(o.status.success(), "shellcheck:\n{}", output(&o));
    }
}

#[test]
fn signs_with_env_file_key_and_verification_ok() {
    let t = temp();
    let d = canonical(&t);
    let b64 = encrypted_key_b64(&d);
    let p = package(&d);
    let env = env_file(&d, &b64, 0o600);
    let o = run(&p, &env, &[]);
    assert!(o.status.success(), "{}", output(&o));
    let sums = fs::read_to_string(p.join("SHA256SUMS")).unwrap();
    assert_eq!(sums.lines().count(), 4, "{sums}");
    assert!(sums.contains(&format!("{}  koru-agent", sha256_hex(b"binary"))));
    assert!(
        sums.lines().map(|s| s.split("  ").nth(1).unwrap()).collect::<Vec<_>>().windows(2).all(|w| w[0] < w[1]),
        "must be sorted: {sums}"
    );
    assert!(!sums.contains("SHA256SUMS"), "must not list itself");
    // Verification: with the public key, "Verified OK".
    let public_v = public_key(&d, &b64);
    let v = Command::new("openssl")
        .args(["dgst", "-sha256", "-verify"])
        .arg(&public_v)
        .arg("-signature")
        .arg(p.join("SHA256SUMS.sig"))
        .arg(p.join("SHA256SUMS"))
        .output()
        .unwrap();
    assert!(v.status.success() && output(&v).contains("Verified OK"), "{}", output(&v));
}

#[test]
fn secret_values_never_written_and_other_lines_not_read() {
    let t = temp();
    let d = canonical(&t);
    let b64 = encrypted_key_b64(&d);
    let p = package(&d);
    let env = env_file(&d, &b64, 0o600);
    let o = run(&p, &env, &[]);
    let everything = output(&o);
    for secret in [PASSWORD, CANARY, "other-secret-value", "ntfy.sample.test", &b64[..40]] {
        assert!(!everything.contains(secret), "leaked into the output: {secret}\n{everything}");
    }
    let sums = fs::read_to_string(p.join("SHA256SUMS")).unwrap();
    assert!(!sums.contains(PASSWORD));
    // After signing, no key trace remains in the package directory.
    for g in walk(&p) {
        let content = fs::read(&g).unwrap();
        assert!(!String::from_utf8_lossy(&content).contains("ENCRYPTED PRIVATE KEY"), "{}", g.display());
    }
    // Temporary files are cleaned (no key remains in an ordinary temp directory).
    assert!(!everything.contains("PRIVATE KEY"));
}

fn walk(d: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for g in fs::read_dir(d).unwrap() {
        let y = g.unwrap().path();
        if y.is_dir() { v.extend(walk(&y)) } else { v.push(y) }
    }
    v
}

#[test]
fn env_vars_take_precedence_over_env_file() {
    let t = temp();
    let d = canonical(&t);
    let b64 = encrypted_key_b64(&d);
    let p = package(&d);
    let missing_env = d.join("missing.env");
    let o = run(&p, &missing_env, &[("KORU_SIGNING_KEY", &b64), ("KORU_SIGNING_KEY_PASSWORD", PASSWORD)]);
    assert!(o.status.success(), "{}", output(&o));
    assert!(p.join("SHA256SUMS.sig").is_file());
}

#[test]
fn no_signing_for_unsafe_or_missing_inputs() {
    let t = temp();
    let d = canonical(&t);
    let b64 = encrypted_key_b64(&d);
    // .env with wide permissions.
    let p = package(&d);
    let env = env_file(&d, &b64, 0o644);
    let o = run(&p, &env, &[]);
    assert!(!o.status.success() && output(&o).contains("0600"), "{}", output(&o));
    assert!(!p.join("SHA256SUMS.sig").exists());
    // Wrong passphrase.
    fs::write(&env, format!("KORU_SIGNING_KEY={b64}\nKORU_SIGNING_KEY_PASSWORD=wrong\n")).unwrap();
    fs::set_permissions(&env, fs::Permissions::from_mode(0o600)).unwrap();
    let o = run(&p, &env, &[]);
    assert!(!o.status.success());
    assert!(!output(&o).contains("wrong") && !p.join("SHA256SUMS.sig").exists(), "{}", output(&o));
    // Empty key line.
    fs::write(&env, "KORU_SIGNING_KEY=\nKORU_SIGNING_KEY_PASSWORD=\n").unwrap();
    let o = run(&p, &env, &[]);
    assert!(!o.status.success() && output(&o).contains("KORU_SIGNING_KEY"), "{}", output(&o));
    // The package directory is missing.
    let o = run(&d.join("missing-package"), &env, &[]);
    assert!(!o.status.success());
}
