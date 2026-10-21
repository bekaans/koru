//! `distribution/prepare-release.sh` (ADR-0008): assembles the version package (CLI, agent binary, data packages,
//! thresholds, SBOM, VERSION) and signs it with `sign.sh`. The produced package must be verifiable
//! by `install.sh`. The tests use fake binaries and a test key.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::*;

const PASSPHRASE: &str = "prepare-test-password";

fn output(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn encrypted_key(dir: &Path) -> (String, PathBuf) {
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
        .env("PW", PASSPHRASE)
        .output()
        .unwrap();
    assert!(o.status.success());
    let b64 = Command::new("openssl").args(["base64", "-A", "-in"]).arg(&path).output().unwrap();
    let public_v = dir.join("public.pem");
    let o = Command::new("openssl")
        .args(["pkey", "-passin", "env:PW", "-pubout", "-in"])
        .arg(&path)
        .arg("-out")
        .arg(&public_v)
        .env("PW", PASSPHRASE)
        .output()
        .unwrap();
    assert!(o.status.success());
    (String::from_utf8(b64.stdout).unwrap(), public_v)
}

#[test]
fn package_arranged_signed_and_install_sh_verifies() {
    let t = temp();
    let d = canonical(&t);
    let (b64, public_v) = encrypted_key(&d);
    let bin_dir = d.join("bin_dir");
    fs::create_dir_all(&bin_dir).unwrap();
    for name in ["koru", "koru-agent"] {
        fs::write(bin_dir.join(name), format!("#!/bin/sh\n# {name}\n")).unwrap();
        fs::set_permissions(bin_dir.join(name), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let sbom = d.join("sbom.cdx.json");
    fs::write(&sbom, r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#).unwrap();
    let out_dir = d.join("out_dir");
    let o = Command::new("sh")
        .arg(store_root().join("distribution/prepare-release.sh"))
        .arg(&out_dir)
        .args(["--version", "1.2.3", "--binary-dir"])
        .arg(&bin_dir)
        .arg("--sbom-file")
        .arg(&sbom)
        .env("KORU_SIGNING_KEY", b64.trim())
        .env("KORU_SIGNING_KEY_PASSWORD", PASSPHRASE)
        .env("KORU_ROOT", store_root())
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", output(&o));
    for secret in [PASSPHRASE, &b64[..40]] {
        assert!(!output(&o).contains(secret), "a secret value leaked into the output");
    }
    assert_eq!(fs::read_to_string(out_dir.join("VERSION")).unwrap(), "1.2.3\n");
    for var in [
        "koru",
        "koru-agent",
        "thresholds.toml",
        "sbom.cdx.json",
        "SHA256SUMS",
        "SHA256SUMS.sig",
        "packages/rules/decoy_general.yml",
        "packages/agents/claude-code.toml",
        "packages/decoys",
    ] {
        assert!(out_dir.join(var).exists(), "{var} is missing");
    }
    let sums = fs::read_to_string(out_dir.join("SHA256SUMS")).unwrap();
    assert!(sums.contains("  sbom.cdx.json") && sums.contains("  koru-agent"), "{sums}");
    // install.sh verifies the package (with the test key + fingerprint).
    let fingerprint = sha256_hex(&fs::read(&public_v).unwrap());
    let v = Command::new("sh")
        .arg(store_root().join("distribution/install.sh"))
        .args(["--verify-only", "--public-key"])
        .arg(&public_v)
        .args(["--fingerprint", &fingerprint])
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(v.status.success() && output(&v).contains("Verified OK"), "{}", output(&v));
}

#[test]
fn no_package_for_missing_inputs() {
    let t = temp();
    let d = canonical(&t);
    let out_dir = d.join("out_dir");
    // No binary directory.
    let o = Command::new("sh")
        .arg(store_root().join("distribution/prepare-release.sh"))
        .arg(&out_dir)
        .args(["--version", "1.2.3", "--binary-dir"])
        .arg(d.join("nope"))
        .env_remove("KORU_SIGNING_KEY")
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(!out_dir.join("SHA256SUMS.sig").exists());
    // An invalid version.
    let o = Command::new("sh")
        .arg(store_root().join("distribution/prepare-release.sh"))
        .arg(&out_dir)
        .args(["--version", "v\u{fc}rsion-x", "--binary-dir"])
        .arg(&d)
        .output()
        .unwrap();
    assert!(!o.status.success() && output(&o).contains("v\u{fc}rsion"), "{}", output(&o));
}
