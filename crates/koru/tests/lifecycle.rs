//! Install and lifecycle: install_distribution, uninstall, upgrade, rollback. Install,
//! uninstall, upgrade and rollback work; after an uninstall the file digests match
//! (the Rust counterpart of lab/scripts/file-digest.sh: `common::digest`). Nothing is installed without the
//! signature and SHA-256 verification. The tests run at a fake root (a temp dir) with a fake systemd.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::*;
use koru::config::{Config, DEFAULT_NAME};
use koru::distribution::{
    InstallOptions, LineContext, install_distribution, render_unit, rollback, uninstall, upgrade,
};
use koru_decoy as _;

struct Harness {
    t: tempfile::TempDir,
    root: PathBuf,
    key_v: TestKey,
    systemd_ctl: FakeSystemd,
    y: Config,
}

impl Harness {
    fn new(name: &str) -> Harness {
        let t = temp();
        let root = canonical(&t).join("root");
        make_dir_chain(&root);
        fake_root(&root);
        let key_v = generate_key(&canonical(&t), "test");
        let y = config(&root, name);
        Harness { t, root, key_v, systemd_ctl: FakeSystemd::new(), y }
    }

    fn defaults() -> Harness {
        Harness::new(DEFAULT_NAME)
    }

    fn self_context(&self) -> LineContext<'_> {
        LineContext {
            systemd_ctl: &self.systemd_ctl,
            public_key_pem: self.key_v.plain_text.clone(),
            health_probe: 3,
            health_wait: Duration::from_millis(1),
        }
    }

    fn version(&self, version: &str) -> PathBuf {
        generate_version(&canonical(&self.t), version, &self.key_v)
    }

    fn install_distribution(
        &self,
        version_dir: &Path,
    ) -> Result<koru::distribution::InstallReport, koru::distribution::DistributionError> {
        install_distribution(
            &self.self_context(),
            &InstallOptions { version_dir: version_dir.to_path_buf(), config: self.y.clone(), env_file: None },
        )
    }

    fn valid_version(&self) -> String {
        fs::read_link(self.y.current_link()).unwrap().file_name().unwrap().to_string_lossy().into_owned()
    }
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn install_creates_expected_files_and_modes() {
    let d = Harness::defaults();
    let package = d.version("1.0.0");
    let r = d.install_distribution(&package).unwrap();
    assert_eq!(r.version, "1.0.0");
    let y = &d.y;
    // The version directory and the agent binary (named by the configured process name).
    let binary_v = y.version_dir("1.0.0").join(&y.id.process_name);
    assert_eq!(mode(&binary_v), 0o755);
    assert!(fs::read_to_string(&binary_v).unwrap().contains("fake agent binary 1.0.0"));
    assert!(y.version_dir("1.0.0").join("data/rules").is_dir());
    assert!(y.version_dir("1.0.0").join("data/agents").is_dir());
    assert!(y.version_dir("1.0.0").join("data/decoys").is_dir());
    assert!(y.version_dir("1.0.0").join("data/thresholds.toml").is_file());
    // The active version is a relative symlink.
    assert_eq!(fs::read_link(y.current_link()).unwrap(), PathBuf::from("versions/1.0.0"));
    assert!(y.agent_binary().is_file());
    // The config, env and Pulsar settings are readable only by root (the installer).
    for path in [y.config_file(), y.env_file(), y.pulsar_config()] {
        assert_eq!(mode(&path), 0o600, "{}", path.display());
    }
    assert_eq!(mode(&y.directories.config), 0o700);
    assert_eq!(mode(&y.directories.state), 0o700);
    // The written config reads back identically.
    assert_eq!(&Config::read(&y.config_file()).unwrap(), y);
    // The Pulsar engine API socket lives in the runtime directory (KT-28, KT-29).
    let pulsar = fs::read_to_string(y.pulsar_config()).unwrap();
    assert!(
        pulsar.contains("[pulsar]")
            && pulsar.contains(&format!("api_socket_path = \"{}\"", y.engine_socket().display())),
        "{pulsar}"
    );
    // The unit file.
    assert_eq!(mode(&y.service_file()), 0o644);
    assert_eq!(fs::read_to_string(y.service_file()).unwrap(), render_unit(y));
    // Decoys installed, and the integrity record sits in the state directory.
    assert!(y.decoy_state_dir().is_dir());
    assert!(!koru_decoy::list_entries(&y.decoy_state_dir()).unwrap().is_empty());
    assert!(y.install_record().is_file());
    assert_eq!(mode(&y.install_record()), 0o600);
}

#[test]
fn install_systemd_calls_ordered() {
    let d = Harness::defaults();
    d.install_distribution(&d.version("1.0.0")).unwrap();
    let c = d.systemd_ctl.calls();
    assert_eq!(c[0], "reload");
    assert_eq!(c[1], "enable:system-observer");
    assert!(c[2..].iter().all(|x| x == "is_active:system-observer"), "{c:?}");
}

#[test]
fn install_filters_env_file() {
    let d = Harness::defaults();
    let environment = env_file(
        &canonical(&d.t),
        &[
            ("KORU_NTFY_URL", "https://ntfy.sample.test/secret-topic"),
            ("KORU_NTFY_TOKEN", "tk_probe"),
            ("KORU_HEARTBEAT_URL", "https://hc-ping.example/uuid"),
            ("KORU_SIGNING_KEY", "SIGNING-KEY-MUST-NOT-LEAK"),
            ("KORU_SIGNING_KEY_PASSWORD", "SIGNING-PASSWORD-MUST-NOT-LEAK"),
            ("KORU_LAB_LLM_API_KEY", "LLM-KEY-MUST-NOT-LEAK"),
            ("CLOUDFLARE_API_TOKEN", "CF-MUST-NOT-LEAK"),
            ("OTHER", "x"),
        ],
        0o600,
    );
    let package = d.version("1.0.0");
    install_distribution(
        &d.self_context(),
        &InstallOptions { version_dir: package, config: d.y.clone(), env_file: Some(environment) },
    )
    .unwrap();
    let content = fs::read_to_string(d.y.env_file()).unwrap();
    assert!(content.contains("KORU_NTFY_URL=https://ntfy.sample.test/secret-topic"), "{content}");
    assert!(content.contains("KORU_NTFY_TOKEN=tk_probe") && content.contains("KORU_HEARTBEAT_URL="));
    for must_not_leak in ["SIGNING", "MUST-NOT-LEAK", "CLOUDFLARE", "OTHER", "LAB_LLM"] {
        assert!(!content.contains(must_not_leak), "leaked into the env file: {must_not_leak}\n{content}");
    }
    // A world-readable source env file is rejected and nothing is installed.
    let d2 = Harness::defaults();
    let before = digest(&d2.root);
    let public_v = env_file(&canonical(&d2.t), &[("KORU_NTFY_URL", "https://ntfy.sample.test/k")], 0o644);
    let e = install_distribution(
        &d2.self_context(),
        &InstallOptions { version_dir: d2.version("1.0.0"), config: d2.y.clone(), env_file: Some(public_v) },
    )
    .unwrap_err();
    assert!(e.to_string().contains("0600") || e.to_string().contains("permission"), "{e}");
    assert_eq!(digest(&d2.root), before);
}

#[test]
fn install_rejects_unverifiable_version() {
    let d = Harness::defaults();
    let before = digest(&d.root);
    let extra_key = generate_key(&canonical(&d.t), "other");

    // 1) One byte of a listed file changed.
    let package = d.version("1.0.0");
    let mut binary_v = fs::read(package.join("koru-agent")).unwrap();
    binary_v.push(b'#');
    fs::write(package.join("koru-agent"), binary_v).unwrap();
    let e = d.install_distribution(&package).unwrap_err().to_string();
    assert!(e.contains("digest"), "{e}");
    assert_eq!(digest(&d.root), before, "a rejected install must leave no trace");

    // 2) An extra file not in the list.
    let package = d.version("1.0.1");
    fs::write(package.join("packages/rules/extra.yml"), "title: x\n").unwrap();
    let e = d.install_distribution(&package).unwrap_err().to_string();
    assert!(e.contains("not in the list"), "{e}");

    // 3) A package signed with another key.
    let package = d.version("1.0.2");
    sign_package(&package, &extra_key);
    let e = d.install_distribution(&package).unwrap_err().to_string();
    assert!(e.contains("signature"), "{e}");

    // 4) No signature file.
    let package = d.version("1.0.3");
    fs::remove_file(package.join("SHA256SUMS.sig")).unwrap();
    assert!(d.install_distribution(&package).unwrap_err().to_string().contains("signature"));

    // 5) SHA256SUMS altered (the signature no longer matches).
    let package = d.version("1.0.4");
    let mut sums = fs::read_to_string(package.join("SHA256SUMS")).unwrap();
    sums.push_str(&format!("{}  fabricated\n", "0".repeat(64)));
    fs::write(package.join("SHA256SUMS"), sums).unwrap();
    assert!(d.install_distribution(&package).unwrap_err().to_string().contains("signature"));

    // 6) A symlink in the package.
    let package = d.version("1.0.5");
    linked_symlink(Path::new("/etc/passwd"), &package.join("packages/rules/link.yml"));
    sign_package(&package, &d.key_v);
    assert!(d.install_distribution(&package).unwrap_err().to_string().contains("symlink"));

    // 7) An invalid VERSION file.
    let package = d.version("1.0.6");
    fs::write(package.join("VERSION"), "version-1\n").unwrap();
    sign_package(&package, &d.key_v);
    assert!(d.install_distribution(&package).unwrap_err().to_string().contains("VERSION"));

    // 8) A required file missing (signed, but no agent binary).
    let package = d.version("1.0.7");
    fs::remove_file(package.join("koru-agent")).unwrap();
    sign_package(&package, &d.key_v);
    assert!(d.install_distribution(&package).unwrap_err().to_string().contains("koru-agent"));

    // 9) An entry escaping the path.
    let package = d.version("1.0.8");
    let mut sums = fs::read_to_string(package.join("SHA256SUMS")).unwrap();
    sums.push_str(&format!("{}  ../escape\n", "0".repeat(64)));
    fs::write(package.join("SHA256SUMS"), &sums).unwrap();
    sign_with_openssl_manually(&package, &d.key_v);
    assert!(d.install_distribution(&package).is_err());

    assert_eq!(digest(&d.root), before, "no rejected package may leave a trace");
    assert!(d.systemd_ctl.calls().is_empty(), "a rejected package must not touch systemd");
}

/// Re-signs after `SHA256SUMS` was edited by hand (without regenerating the digest list).
fn sign_with_openssl_manually(package: &Path, a: &TestKey) {
    let o = std::process::Command::new("openssl")
        .args(["dgst", "-sha256", "-sign"])
        .arg(&a.secret)
        .arg("-out")
        .arg(package.join("SHA256SUMS.sig"))
        .arg(package.join("SHA256SUMS"))
        .output()
        .unwrap();
    assert!(o.status.success());
}

#[test]
fn install_uses_repo_real_key_by_default() {
    // A package signed with the test key cannot verify against the embedded (real) public key.
    let d = Harness::defaults();
    let package = d.version("1.0.0");
    let before = digest(&d.root);
    let mut b = d.self_context();
    b.public_key_pem = koru::distribution::EMBEDDED_PUBLIC_KEY.to_string();
    let e = install_distribution(&b, &InstallOptions { version_dir: package, config: d.y.clone(), env_file: None })
        .unwrap_err()
        .to_string();
    assert!(e.contains("signature"), "{e}");
    assert_eq!(digest(&d.root), before);
    assert!(koru::distribution::EMBEDDED_PUBLIC_KEY.starts_with("-----BEGIN PUBLIC KEY-----"));
}

#[test]
fn install_rejected_when_already_installed() {
    let d = Harness::defaults();
    d.install_distribution(&d.version("1.0.0")).unwrap();
    let before = digest(&d.root);
    let e = d.install_distribution(&d.version("1.0.1")).unwrap_err().to_string();
    assert!(e.contains("installed already"), "{e}");
    // Only the second package itself may have been added (test harness); the install tree must not change.
    let after_v = digest(&d.root);
    let install_prefix = d.y.directories.install.strip_prefix(&d.root).unwrap().display().to_string();
    let f = |v: &[String]| v.iter().filter(|s| s.contains(&install_prefix)).cloned().collect::<Vec<_>>();
    assert_eq!(f(&before), f(&after_v));
}

#[test]
fn install_rolls_back_all_if_decoy_setup_fails() {
    let d = Harness::defaults();
    fs::remove_dir_all(d.root.join("home/devops")).unwrap();
    let before = digest(&d.root);
    let e = d.install_distribution(&d.version("1.0.0")).unwrap_err();
    assert!(!e.to_string().is_empty());
    assert_eq!(digest(&d.root), before, "a half install must not remain");
    assert!(d.systemd_ctl.calls().is_empty());
}

#[test]
fn uninstall_rolls_back_everything_and_digests_match() {
    let d = Harness::defaults();
    let before = digest(&d.root);
    let package = d.version("1.0.0");
    d.install_distribution(&package).unwrap();
    assert_ne!(digest(&d.root), before);
    d.systemd_ctl.clean();
    let r = uninstall(&d.self_context(), &d.y, false).unwrap();
    assert!(r.completed, "{r:?}");
    let after_v = digest(&d.root);
    // The package/key files the harness created live outside the root; the root must be exactly as before.
    assert_eq!(after_v, before);
    let c = d.systemd_ctl.calls();
    assert_eq!(c, ["stop:system-observer", "reload"], "{c:?}");
}

#[test]
fn uninstall_keep_data_leaves_store_and_queue() {
    let d = Harness::defaults();
    d.install_distribution(&d.version("1.0.0")).unwrap();
    fs::write(d.y.store_file(), b"SQLite format 3\0").unwrap();
    fs::set_permissions(d.y.store_file(), fs::Permissions::from_mode(0o600)).unwrap();
    fs::create_dir_all(d.y.queue_dir()).unwrap();
    let r = uninstall(&d.self_context(), &d.y, true).unwrap();
    assert!(r.completed);
    assert!(d.y.store_file().is_file() && d.y.queue_dir().is_dir());
    assert!(!d.y.decoy_state_dir().exists() && !d.y.install_record().exists());
    assert!(!d.y.directories.install.exists() && !d.y.directories.config.exists() && !d.y.service_file().exists());
    // The home directory is as it was before the install.
    assert!(!d.root.join("home/devops/.aws").exists());
}

#[test]
fn uninstall_keeps_modified_decoy_and_record() {
    let d = Harness::defaults();
    d.install_distribution(&d.version("1.0.0")).unwrap();
    let entries = koru_decoy::list_entries(&d.y.decoy_state_dir()).unwrap();
    let decoy = entries.iter().find(|g| g.kind == koru_decoy::DecoyKind::Decoy).expect("a decoy must exist");
    fs::write(&decoy.path, b"changed by an attacker\n").unwrap();
    let r = uninstall(&d.self_context(), &d.y, false).unwrap();
    assert!(!r.completed, "{r:?}");
    assert!(!r.warnings.is_empty());
    assert!(Path::new(&decoy.path).exists(), "a modified decoy must not be deleted");
    assert!(
        d.y.install_record().is_file() && d.y.decoy_state_dir().is_dir(),
        "the record must stay; a retry is possible"
    );
}

#[test]
fn uninstall_errors_when_not_installed() {
    let d = Harness::defaults();
    let before = digest(&d.root);
    let e = uninstall(&d.self_context(), &d.y, false).unwrap_err().to_string();
    assert!(e.contains("is not installed"), "{e}");
    assert_eq!(digest(&d.root), before);
}

#[test]
fn upgrade_switches_and_keeps_old_for_downgrade() {
    let d = Harness::defaults();
    d.install_distribution(&d.version("1.0.0")).unwrap();
    d.systemd_ctl.clean();
    let r = upgrade(&d.self_context(), &d.y, &d.version("1.1.0")).unwrap();
    assert_eq!((r.previous.as_str(), r.new.as_str()), ("1.0.0", "1.1.0"));
    assert_eq!(d.valid_version(), "1.1.0");
    assert!(d.y.version_dir("1.0.0").is_dir(), "the old version must stay for a rollback");
    assert!(d.y.version_dir("1.1.0").join(&d.y.id.process_name).is_file());
    let c = d.systemd_ctl.calls();
    assert!(c.contains(&"restart:system-observer".to_string()), "{c:?}");
    assert!(c.contains(&"is_active:system-observer".to_string()));
    // The config, env and store stay untouched.
    assert!(d.y.config_file().is_file() && d.y.decoy_state_dir().is_dir());
}

#[test]
fn upgrade_allows_only_newer_version() {
    let d = Harness::defaults();
    d.install_distribution(&d.version("1.2.0")).unwrap();
    for older in ["1.2.0", "1.1.9", "0.9.0"] {
        let e = upgrade(&d.self_context(), &d.y, &d.version(older)).unwrap_err().to_string();
        assert!(e.contains("needs a version newer"), "{older}: {e}");
    }
    assert_eq!(d.valid_version(), "1.2.0");
    // Numeric comparison: 1.10.0 > 1.9.0.
    let d = Harness::defaults();
    d.install_distribution(&d.version("1.9.0")).unwrap();
    upgrade(&d.self_context(), &d.y, &d.version("1.10.0")).unwrap();
    assert_eq!(d.valid_version(), "1.10.0");
}

#[test]
fn upgrade_rejects_unverifiable_package() {
    let d = Harness::defaults();
    d.install_distribution(&d.version("1.0.0")).unwrap();
    let before = digest(&d.root);
    d.systemd_ctl.clean();
    let package = d.version("2.0.0");
    fs::write(package.join("koru-agent"), b"bad").unwrap();
    let e = upgrade(&d.self_context(), &d.y, &package).unwrap_err().to_string();
    assert!(e.contains("digest"), "{e}");
    assert_eq!(digest(&d.root), before);
    assert!(d.systemd_ctl.calls().is_empty());
}

#[test]
fn upgrade_auto_rollback_on_health_failure() {
    let mut d = Harness::defaults();
    d.install_distribution(&d.version("1.0.0")).unwrap();
    // After the restart the service never goes active; once rolled back it does.
    d.systemd_ctl = FakeSystemd::active_replies(&[false, false, false], true);
    let e = upgrade(&d.self_context(), &d.y, &d.version("1.1.0")).unwrap_err().to_string();
    assert!(e.contains("rolled back to"), "{e}");
    assert_eq!(d.valid_version(), "1.0.0", "the active version must return to the old one");
    let c = d.systemd_ctl.calls();
    assert_eq!(c.iter().filter(|x| x.starts_with("restart:")).count(), 2, "upgrade and rollback both restart: {c:?}");
    assert!(!d.y.version_dir("1.1.0").exists(), "the failed version directory must be cleaned");
}

#[test]
fn upgrade_prunes_oldest_versions() {
    let d = Harness::defaults();
    d.install_distribution(&d.version("1.0.0")).unwrap();
    upgrade(&d.self_context(), &d.y, &d.version("1.1.0")).unwrap();
    upgrade(&d.self_context(), &d.y, &d.version("1.2.0")).unwrap();
    let mut var: Vec<String> = fs::read_dir(d.y.directories.install.join("versions"))
        .unwrap()
        .map(|g| g.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    var.sort();
    assert_eq!(var, ["1.1.0", "1.2.0"], "only the active and previous versions are kept");
}

#[test]
fn downgrade_goes_back_then_forward_again() {
    let d = Harness::defaults();
    d.install_distribution(&d.version("1.0.0")).unwrap();
    upgrade(&d.self_context(), &d.y, &d.version("1.1.0")).unwrap();
    d.systemd_ctl.clean();
    let r = rollback(&d.self_context(), &d.y).unwrap();
    assert_eq!((r.previous.as_str(), r.new.as_str()), ("1.1.0", "1.0.0"));
    assert_eq!(d.valid_version(), "1.0.0");
    assert!(d.systemd_ctl.calls().contains(&"restart:system-observer".to_string()));
    let r = rollback(&d.self_context(), &d.y).unwrap();
    assert_eq!(r.new, "1.1.0");
    assert_eq!(d.valid_version(), "1.1.0");
}

#[test]
fn downgrade_errors_without_previous_version() {
    let d = Harness::defaults();
    d.install_distribution(&d.version("1.0.0")).unwrap();
    let before = digest(&d.root);
    let e = rollback(&d.self_context(), &d.y).unwrap_err().to_string();
    assert!(e.contains("no previous version"), "{e}");
    assert_eq!(digest(&d.root), before);
}

#[test]
fn downgrade_health_failure_restores_state() {
    let mut d = Harness::defaults();
    d.install_distribution(&d.version("1.0.0")).unwrap();
    upgrade(&d.self_context(), &d.y, &d.version("1.1.0")).unwrap();
    d.systemd_ctl = FakeSystemd::active_replies(&[false, false, false], true);
    let e = rollback(&d.self_context(), &d.y).unwrap_err().to_string();
    assert!(e.contains("downgrade failed"), "{e}");
    assert_eq!(d.valid_version(), "1.1.0");
}

#[test]
fn full_cycle_install_upgrade_downgrade_uninstall_restores_start() {
    let d = Harness::defaults();
    let before = digest(&d.root);
    d.install_distribution(&d.version("1.0.0")).unwrap();
    upgrade(&d.self_context(), &d.y, &d.version("1.1.0")).unwrap();
    rollback(&d.self_context(), &d.y).unwrap();
    rollback(&d.self_context(), &d.y).unwrap();
    let r = uninstall(&d.self_context(), &d.y, false).unwrap();
    assert!(r.completed);
    assert_eq!(digest(&d.root), before, "the file digests must match");
}

/// Whether a path is visible to other users: does every parent directory from the root to the path grant
/// "others" the execute (traversal) bit. The install directory is 0700; the file names beneath it (e.g.
/// the rule files' names) are invisible to an unprivileged user.
fn visible_to_others(root: &Path, relative: &str) -> bool {
    let mut path = root.to_path_buf();
    let parts: Vec<&str> = relative.split('/').collect();
    for p in &parts[..parts.len().saturating_sub(1)] {
        path.push(p);
        if fs::symlink_metadata(&path).map_or(true, |m| m.permissions().mode() & 0o001 == 0) {
            return false;
        }
    }
    true
}

#[test]
fn default_names_no_visible_path_reveals_koru() {
    let d = Harness::defaults();
    let before: std::collections::BTreeSet<String> = paths(&d.root).into_iter().collect();
    d.install_distribution(&d.version("1.0.0")).unwrap();
    let appended: Vec<String> = paths(&d.root).into_iter().filter(|y| !before.contains(y)).collect();
    assert!(!appended.is_empty());
    let mut visible = 0;
    for path in &appended {
        if !visible_to_others(&d.root, path) {
            continue;
        }
        visible += 1;
        let lower_v = path.to_lowercase();
        // The decoy files' names (e.g. .aws) come from pre-install names; "koru" and "pulsar" must
        // appear in no path an unprivileged user can see.
        assert!(!lower_v.contains("koru") && !lower_v.contains("pulsar"), "the path gives it away: {path}");
    }
    assert!(visible > 0, "at least one path must be visible to be tested");
    // The install directory is closed to unprivileged users: the names inside (rule files) are invisible.
    assert_eq!(mode(&d.y.directories.install) & 0o077, 0, "the install directory must be open to root only");
    let unit = fs::read_to_string(d.y.service_file()).unwrap().to_lowercase();
    assert!(!unit.contains("koru") && !unit.contains("pulsar"), "the unit file gives it away:\n{unit}");
    // Custom names work too.
    let d = Harness::new("backup-logger");
    d.install_distribution(&d.version("1.0.0")).unwrap();
    assert!(d.y.service_file().ends_with("backup-logger.service"));
    assert!(d.y.version_dir("1.0.0").join("backup-logger").is_file());
}
