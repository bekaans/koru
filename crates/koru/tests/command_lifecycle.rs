//! The `koru install | uninstall | upgrade | rollback` commands (ADR-0008) through the binary. The tests
//! never touch a real system: the config file points the directories at a temporary root and
//! `--no-systemd` keeps systemd out. Usage errors exit 2, runtime errors exit 1.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::*;
use koru::config::DEFAULT_NAME;

fn koru(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_koru")).args(args).output().expect("koru could not be run")
}

fn output(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

struct Harness {
    t: tempfile::TempDir,
    root: PathBuf,
    key_v: TestKey,
    settings_v: PathBuf,
}

impl Harness {
    fn new() -> Harness {
        let t = temp();
        let root = canonical(&t).join("root");
        make_dir_chain(&root);
        fake_root(&root);
        let key_v = generate_key(&canonical(&t), "test");
        let y = config(&root, DEFAULT_NAME);
        let settings_v = config_file(&canonical(&t), &y, "install");
        Harness { t, root, key_v, settings_v }
    }

    fn version(&self, s: &str) -> PathBuf {
        generate_version(&canonical(&self.t), s, &self.key_v)
    }

    fn command(&self, subcommand: &str, package: Option<&Path>, extra: &[&str]) -> Output {
        let public_v = self.key_v.public_v.to_string_lossy().into_owned();
        let settings_v = self.settings_v.to_string_lossy().into_owned();
        let mut args = vec![subcommand, "--config", &settings_v, "--no-systemd"];
        let package_text;
        if let Some(p) = package {
            package_text = p.to_string_lossy().into_owned();
            args.extend(["--version-dir", &package_text, "--public-key", &public_v]);
        }
        args.extend_from_slice(extra);
        koru(&args)
    }
}

#[test]
fn full_cycle_from_cli_and_digests_match() {
    let d = Harness::new();
    let before = digest(&d.root);
    let o = d.command("install", Some(&d.version("1.0.0")), &[]);
    assert!(o.status.success(), "{}", output(&o));
    assert!(output(&o).contains("Install completed: version 1.0.0"), "{}", output(&o));
    assert_ne!(digest(&d.root), before);
    let o = d.command("upgrade", Some(&d.version("1.1.0")), &[]);
    assert!(o.status.success(), "{}", output(&o));
    assert!(output(&o).contains("Upgrade completed: 1.0.0 -> 1.1.0"), "{}", output(&o));
    let o = d.command("rollback", None, &[]);
    assert!(o.status.success(), "{}", output(&o));
    assert!(output(&o).contains("Rollback completed: 1.1.0 -> 1.0.0"), "{}", output(&o));
    let o = d.command("uninstall", None, &[]);
    assert!(o.status.success(), "{}", output(&o));
    assert!(output(&o).contains("Uninstall completed"), "{}", output(&o));
    assert_eq!(digest(&d.root), before, "the file digests must match");
}

#[test]
fn default_public_key_rejects_test_signature() {
    let d = Harness::new();
    let before = digest(&d.root);
    let package = d.version("1.0.0");
    let settings_v = d.settings_v.to_string_lossy().into_owned();
    let o = koru(&["install", "--config", &settings_v, "--no-systemd", "--version-dir", package.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1), "{}", output(&o));
    assert!(output(&o).contains("signature"), "{}", output(&o));
    assert_eq!(digest(&d.root), before);
}

#[test]
fn usage_errors_exit_2() {
    let d = Harness::new();
    let package = d.version("1.0.0");
    let p = package.to_str().unwrap();
    let settings_v = d.settings_v.to_string_lossy().into_owned();
    let cases: &[&[&str]] = &[
        &["install"],
        &["install", "--config", &settings_v],
        &["install", "--version-dir", p],
        &["install", "--version-dir", p, "--source-tag", "real"],
        &["install", "--version-dir", p, "--config", &settings_v, "--source-tag", "real", "--decoy-root", "/root"],
        &["install", "--version-dir", p, "--source-tag", "bogus", "--decoy-root", "/root"],
        &["install", "--version-dir", p, "--config", &settings_v, "--unknown_key", "x"],
        &["uninstall"],
        &["upgrade", "--config", &settings_v],
        &["rollback"],
        &["uninstall", "--config", &settings_v, "--name", "x"],
    ];
    for v in cases {
        let o = koru(v);
        assert_eq!(o.status.code(), Some(2), "{v:?}\n{}", output(&o));
    }
    // The help text describes the new commands.
    let o = koru(&["help"]);
    let y = output(&o);
    for command in ["install ", "uninstall", "upgrade", "rollback", "--version-dir", "--no-systemd"] {
        assert!(y.contains(command), "the help has no {command:?}");
    }
}

#[test]
fn show_plan_writes_default_paths_only() {
    let d = Harness::new();
    let package = d.version("1.0.0");
    let public_v = d.key_v.public_v.to_string_lossy().into_owned();
    let o = koru(&[
        "install",
        "--version-dir",
        package.to_str().unwrap(),
        "--source-tag",
        "real",
        "--decoy-root",
        "/root",
        "--public-key",
        &public_v,
        "--show-plan",
    ]);
    assert!(o.status.success(), "{}", output(&o));
    let c = output(&o);
    for expected_v in [
        "/usr/libexec/system-observer/versions/1.0.0/system-observer",
        "/etc/system-observer/config.toml",
        "/etc/systemd/system/system-observer.service",
        "/var/lib/system-observer",
        "version 1.0.0",
    ] {
        assert!(c.contains(expected_v), "the plan must contain {expected_v:?}:\n{c}");
    }
    assert!(!Path::new("/etc/system-observer").exists() && !Path::new("/usr/libexec/system-observer").exists());
    // A custom name changes the plan.
    let o = koru(&[
        "install",
        "--version-dir",
        package.to_str().unwrap(),
        "--name",
        "backup-logger",
        "--source-tag",
        "legitimate",
        "--decoy-root",
        "/home/a",
        "--public-key",
        &public_v,
        "--show-plan",
    ]);
    assert!(output(&o).contains("/etc/systemd/system/backup-logger.service"), "{}", output(&o));
    // An invalid name (one that would reveal Koru) is rejected.
    let o = koru(&[
        "install",
        "--version-dir",
        package.to_str().unwrap(),
        "--name",
        "koru",
        "--source-tag",
        "legitimate",
        "--decoy-root",
        "/home/a",
        "--public-key",
        &public_v,
        "--show-plan",
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", output(&o));
}

#[test]
fn runtime_errors_exit_1() {
    let d = Harness::new();
    // Uninstall while not installed.
    let o = d.command("uninstall", None, &[]);
    assert_eq!(o.status.code(), Some(1), "{}", output(&o));
    assert!(output(&o).contains("is not installed"), "{}", output(&o));
    // An upgrade to an older version.
    let o = d.command("install", Some(&d.version("2.0.0")), &[]);
    assert!(o.status.success(), "{}", output(&o));
    let o = d.command("upgrade", Some(&d.version("1.0.0")), &[]);
    assert_eq!(o.status.code(), Some(1), "{}", output(&o));
    assert!(output(&o).contains("needs a version newer"), "{}", output(&o));
    // A rollback with no previous version.
    let o = d.command("rollback", None, &[]);
    assert_eq!(o.status.code(), Some(1), "{}", output(&o));
    // A group-writable config file is rejected.
    fs::set_permissions(&d.settings_v, std::os::unix::fs::PermissionsExt::from_mode(0o664)).unwrap();
    let o = d.command("uninstall", None, &[]);
    assert_eq!(o.status.code(), Some(1), "{}", output(&o));
    assert!(output(&o).contains("writable"), "{}", output(&o));
}

#[test]
fn keep_data_flag_works_from_cli() {
    let d = Harness::new();
    let y = config(&d.root, DEFAULT_NAME);
    assert!(d.command("install", Some(&d.version("1.0.0")), &[]).status.success());
    fs::write(y.store_file(), b"SQLite format 3\0").unwrap();
    let o = d.command("uninstall", None, &["--keep-data"]);
    assert!(o.status.success(), "{}", output(&o));
    assert!(y.store_file().is_file());
    assert!(!y.directories.install.exists());
}
