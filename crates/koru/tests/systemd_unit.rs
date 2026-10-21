//! The systemd unit (ADR-0008 §1). The unit is written with least privilege:
//! `ProtectSystem=strict`, `NoNewPrivileges` and only the needed capabilities. Target:
//! `systemd-analyze security` ≤ 2.5 (ADR-0008; never loosened). The unit
//! under the default names does not reveal Koru.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use koru::config::{Config, DEFAULT_NAME};
use koru::distribution::render_unit;
use koru_event::SourceTag;

/// ADR-0008 §1: the target written at stage start. It may go DOWN; never UP.
const TARGET_SCORE: f64 = 2.5;

fn defaults() -> Config {
    Config::defaults(DEFAULT_NAME, SourceTag::Real, Path::new("/root")).unwrap()
}

/// Collects `key=value` lines by section (a list for multi-value keys).
fn parse_parts(unit: &str) -> BTreeMap<String, Vec<(String, String)>> {
    let mut sections: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut section = String::new();
    for line in unit.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = name.to_string();
            continue;
        }
        let (a, d) = line.split_once('=').unwrap_or_else(|| panic!("not key=value: {line:?}"));
        sections.entry(section.clone()).or_default().push((a.to_string(), d.to_string()));
    }
    sections
}

fn value<'a>(b: &'a BTreeMap<String, Vec<(String, String)>>, section: &str, key_v: &str) -> Vec<&'a str> {
    b.get(section).map(|v| v.iter().filter(|(a, _)| a == key_v).map(|(_, d)| d.as_str()).collect()).unwrap_or_default()
}

#[test]
fn mandatory_hardening_settings_exact_values() {
    let unit = render_unit(&defaults());
    let b = parse_parts(&unit);
    let expected: &[(&str, &str)] = &[
        ("Type", "exec"),
        ("User", "root"),
        ("UMask", "0077"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", "CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_PTRACE"),
        ("LimitMEMLOCK", "infinity"),
        ("LimitCORE", "0"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "yes"),
        ("PrivateTmp", "yes"),
        ("PrivateDevices", "yes"),
        ("PrivateMounts", "yes"),
        ("ProtectKernelTunables", "yes"),
        ("ProtectKernelModules", "yes"),
        ("ProtectKernelLogs", "yes"),
        ("ProtectControlGroups", "yes"),
        ("ProtectClock", "yes"),
        ("ProtectHostname", "yes"),
        ("RestrictAddressFamilies", "AF_INET AF_INET6 AF_UNIX AF_NETLINK"),
        ("RestrictNamespaces", "yes"),
        ("RestrictRealtime", "yes"),
        ("RestrictSUIDSGID", "yes"),
        ("LockPersonality", "yes"),
        ("MemoryDenyWriteExecute", "yes"),
        ("RemoveIPC", "yes"),
        ("SystemCallArchitectures", "native"),
        ("RuntimeDirectory", "system-observer"),
        ("RuntimeDirectoryMode", "0700"),
        ("ReadWritePaths", "/var/lib/system-observer"),
        ("Restart", "always"),
    ];
    for (key_v, d) in expected {
        assert_eq!(value(&b, "Service", key_v), [*d], "{key_v}\n{unit}");
    }
    // The syscall filter is order-sensitive: the allowlist, then removals, then what is re-added last.
    assert_eq!(
        value(&b, "Service", "SystemCallFilter"),
        [
            "@system-service",
            "~@privileged @resources @mount @swap @reboot @raw-io @module @obsolete @cpu-emulation @debug",
            "bpf perf_event_open fchown",
        ],
        "{unit}"
    );
    assert_eq!(value(&b, "Install", "WantedBy"), ["multi-user.target"]);
    assert_eq!(value(&b, "Service", "ExecStart").len(), 1);
}

#[test]
fn no_relaxing_settings() {
    let unit = render_unit(&defaults());
    let b = parse_parts(&unit);
    let forbidden_keys = [
        "AmbientCapabilities",
        "SupplementaryGroups",
        "DynamicUser",
        "PermissionsStartOnly",
        "ExecStartPre",
        "ExecStartPost",
        "ExecStopPost",
        "EnvironmentFile",
        "SecureBits",
        "NoNewPrivileges=no",
        "DeviceAllow",
        "BindPaths",
        "BindReadOnlyPaths",
        "InaccessiblePaths",
    ];
    for y in forbidden_keys {
        assert!(value(&b, "Service", y).is_empty(), "{y} must not be present:\n{unit}");
    }
    for line in unit.lines() {
        assert!(!line.contains("=no"), "a loosening setting: {line}");
        assert!(!line.contains("ProtectSystem=full") && !line.contains("ProtectSystem=true"), "{line}");
        assert!(!line.contains("CAP_SYS_ADMIN") && !line.contains("CAP_SYS_RESOURCE") && !line.contains("CAP_DAC"));
    }
    // Environment may only be the fixed memory limit ( arbitrary environment injection is forbidden).
    assert_eq!(value(&b, "Service", "Environment"), ["MALLOC_ARENA_MAX=1 MALLOC_TRIM_THRESHOLD_=131072"]);
    // ReadWritePaths is only the state directory; /etc, /usr and home directories are not writable.
    assert_eq!(value(&b, "Service", "ReadWritePaths"), ["/var/lib/system-observer"]);
    // The capability set is exactly the four needed.
    let mut capabilities: Vec<&str> = value(&b, "Service", "CapabilityBoundingSet")[0].split(' ').collect();
    capabilities.sort_unstable();
    assert_eq!(capabilities, ["CAP_BPF", "CAP_NET_ADMIN", "CAP_PERFMON", "CAP_SYS_PTRACE"]);
}

#[test]
fn default_unit_hides_koru_names_from_config() {
    let unit = render_unit(&defaults());
    let lower_v = unit.to_lowercase();
    assert!(!lower_v.contains("koru") && !lower_v.contains("pulsar"), "the unit gives it away:\n{unit}");
    let b = parse_parts(&unit);
    assert_eq!(
        value(&b, "Service", "ExecStart"),
        ["/usr/libexec/system-observer/current/system-observer --config /etc/system-observer/config.toml"]
    );
    let description = value(&b, "Unit", "Description")[0];
    assert!(description.contains("system-observer"), "{description}");

    // A custom name and directories reach the unit.
    let text = "schema_version = 1\n[id]\nprocess_name = \"backup-logger\"\nservice_name = \"backup-service\"\n\
                 [directories]\nstate = \"/srv/backup/state\"\nruntime = \"/run/backup-secret\"\n\
                 [agent]\nsource_tag = \"legitimate\"\n[decoy]\nroot = \"/root\"\n";
    let custom = Config::parse(text).unwrap();
    let b = parse_parts(&render_unit(&custom));
    assert_eq!(
        value(&b, "Service", "ExecStart"),
        ["/usr/libexec/backup-service/current/backup-logger --config /etc/backup-service/config.toml"]
    );
    assert_eq!(value(&b, "Service", "ReadWritePaths"), ["/srv/backup/state"]);
    assert_eq!(value(&b, "Service", "RuntimeDirectory"), ["backup-secret"]);
}

#[test]
fn unit_text_clean_format() {
    let unit = render_unit(&defaults());
    assert!(unit.ends_with('\n'));
    assert!(!unit.contains('\r') && !unit.contains('\t') && !unit.contains('\0'));
    assert!(!unit.contains("  "), "no double spaces");
    // The same configuration always produces the same text (reproducible).
    assert_eq!(unit, render_unit(&defaults()));
    // Sections in order.
    let position = |s: &str| unit.find(s).unwrap_or_else(|| panic!("{s} is missing"));
    assert!(position("[Unit]") < position("[Service]") && position("[Service]") < position("[Install]"));
}

/// ADR-0008 target: `systemd-analyze security --offline` ≤ 2.5. Without the tool (macOS) or when it does not
/// support offline analysis, the test warns and passes; the authoritative measurement runs in the lab VM.
#[test]
fn systemd_analyze_score_within_target() {
    let t = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(t.path()).unwrap().join("system-observer.service");
    fs::write(&path, render_unit(&defaults())).unwrap();
    let output =
        match Command::new("systemd-analyze").args(["security", "--offline=true", "--no-pager"]).arg(&path).output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
            Ok(o) => {
                eprintln!("systemd-analyze ran but failed ({}); measurement skipped", o.status);
                return;
            }
            Err(e) => {
                eprintln!("no systemd-analyze ({e}); the measurement runs in the lab VM");
                return;
            }
        };
    let score: f64 = output
        .lines()
        .find_map(|s| s.split("Overall exposure level for").nth(1))
        .and_then(|s| s.split(':').nth(1))
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("the score could not be read:\n{output}"));
    assert!(score <= TARGET_SCORE, "systemd-analyze score {score} > target {TARGET_SCORE}\n{output}");
}
