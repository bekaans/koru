//! The `koru-agent` binary (ADR-0003 §7, ADR-0008): `--validate` mode loads and summarizes the config and the
//! data packages (rules, AI agent signatures, thresholds, decoy catalog) without touching eBPF;
//! it also runs on the Mac. Resident mode is Linux only (Pulsar, ADR-0003 §5).

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use common::*;
use koru::config::DEFAULT_NAME;
use koru::distribution::{InstallOptions, LineContext, install_distribution};

fn agent(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_koru-agent")).args(args).output().expect("koru-agent could not be run")
}

fn output(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

/// An installed fake root; gives the config file's path.
fn installed() -> (tempfile::TempDir, PathBuf, koru::config::Config) {
    let t = temp();
    let root = canonical(&t).join("root");
    make_dir_chain(&root);
    fake_root(&root);
    let key_v = generate_key(&canonical(&t), "test");
    let y = config(&root, DEFAULT_NAME);
    let package = generate_version(&canonical(&t), "1.0.0", &key_v);
    let s = FakeSystemd::new();
    install_distribution(
        &LineContext {
            systemd_ctl: &s,
            public_key_pem: key_v.plain_text.clone(),
            health_probe: 1,
            health_wait: std::time::Duration::ZERO,
        },
        &InstallOptions { version_dir: package, config: y.clone(), env_file: None },
    )
    .unwrap();
    let settings_v = y.config_file();
    (t, settings_v, y)
}

#[test]
fn verify_loads_installed_config_and_packages() {
    let (_t, settings_v, y) = installed();
    let o = agent(&["--validate", "--config", settings_v.to_str().unwrap()]);
    assert!(o.status.success(), "{}", output(&o));
    let c = output(&o);
    assert!(c.contains("configuration is valid"), "{c}");
    assert!(c.contains("18 rule") || c.contains("rule: 18"), "{c}");
    assert!(c.contains("AI agent signatures"), "{c}");
    assert!(c.contains("decoy") && c.contains("source tag: synthetic"), "{c}");
    // The output carries no secret values or file contents.
    assert!(!c.contains("KORU_NTFY"), "{c}");
    let _ = y;
}

#[test]
fn verify_exit_codes_for_bad_inputs() {
    let (_t, settings_v, y) = installed();
    // No --config: usage error.
    assert_eq!(agent(&["--validate"]).status.code(), Some(2));
    assert_eq!(agent(&["--unknown_key"]).status.code(), Some(2));
    // No config file: runtime error.
    let missing_config = settings_v.with_file_name("missing.toml");
    let o = agent(&["--validate", "--config", missing_config.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1), "{}", output(&o));
    // Corrupt rule pack: runtime error, and the file name is in the output.
    let rule = y.version_dir("1.0.0").join("data/rules/decoy_general.yml");
    fs::write(&rule, "title: broken\n  : :\n").unwrap();
    let o = agent(&["--validate", "--config", settings_v.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1), "{}", output(&o));
    assert!(output(&o).contains("decoy_general"), "{}", output(&o));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn continuous_run_is_rejected_outside_linux() {
    let (_t, settings_v, _y) = installed();
    let o = agent(&["--config", settings_v.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", output(&o));
    assert!(output(&o).contains("Linux"), "{}", output(&o));
}
