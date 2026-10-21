//! A single configuration file (one TOML, validated, safe defaults;
//! ADR-0008 §3). The process name, service name and directories are configurable; the defaults do not
//! reveal Koru. Tests write only to temporary directories.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use koru::config::{Config, DEFAULT_NAME};
use koru_event::SourceTag;

const MINIMAL: &str = "schema_version = 1\n[agent]\nsource_tag = \"real\"\n[decoy]\nroot = \"/root\"\n";

fn parse(text: &str) -> Result<Config, String> {
    Config::parse(text).map_err(|e| e.to_string())
}

/// TOML with `extra` appended to `MINIMAL` (tables start inside `extra`).
fn append(extra: &str) -> String {
    format!("{MINIMAL}{extra}")
}

fn paths(y: &Config) -> Vec<String> {
    let d = &y.directories;
    [&d.install, &d.config, &d.state, &d.runtime].iter().map(|p| p.display().to_string()).collect()
}

#[test]
fn default_names_and_dirs_do_not_reveal_koru() {
    let y = Config::defaults(DEFAULT_NAME, SourceTag::Real, Path::new("/root")).unwrap();
    assert_eq!(y.id.process_name, "system-observer");
    assert_eq!(y.id.service_name, "system-observer");
    assert_eq!(
        paths(&y),
        ["/usr/libexec/system-observer", "/etc/system-observer", "/var/lib/system-observer", "/run/system-observer"]
    );
    let everything = format!("{:?}", (&y.id, &y.directories)).to_lowercase();
    for forbidden in ["koru", "pulsar"] {
        assert!(!everything.contains(forbidden), "a default must not contain {forbidden:?}: {everything}");
    }
    assert_eq!(y.directories.unit, PathBuf::from("/etc/systemd/system"));
    assert_eq!(y.agent.source_tag, SourceTag::Real);
    assert_eq!(y.decoy.root, PathBuf::from("/root"));
}

#[test]
fn safe_default_values() {
    let y = parse(MINIMAL).unwrap();
    assert_eq!(y.store.retention_days, 90);
    assert!(!y.store.store_raw_events, "raw events are not kept by default");
    assert_eq!(y.notify.heartbeat_seconds, 60);
    assert_eq!(y.agent.lineage_depth, 16);
    assert_eq!(y.agent.host, None);
    assert_eq!(y.detection.allowlist, None);
    assert_eq!(y.decoy.allowed_roots, Vec::<PathBuf>::new());
    assert_eq!(y.decoy.owner, None);
    assert_eq!(y.id.process_name, DEFAULT_NAME);
    assert_eq!(y, Config::defaults(DEFAULT_NAME, SourceTag::Real, Path::new("/root")).unwrap());
}

#[test]
fn custom_name_also_determines_dirs() {
    let y = parse(&append("[id]\nprocess_name = \"backup-logger\"\nservice_name = \"backup-logger\"\n")).unwrap();
    assert_eq!(
        paths(&y),
        ["/usr/libexec/backup-logger", "/etc/backup-logger", "/var/lib/backup-logger", "/run/backup-logger"]
    );
    let v = Config::defaults("backup-logger", SourceTag::Legitimate, Path::new("/home/a")).unwrap();
    assert_eq!(v.id.process_name, "backup-logger");
    assert_eq!(v.directories.state, PathBuf::from("/var/lib/backup-logger"));
    // When DirHandle is given explicitly it wins; the rest are derived from the name.
    let y = parse(&append(
        "[id]\nservice_name = \"web-backup\"\nprocess_name = \"web-backup\"\n[directories]\nstate = \"/srv/data/web\"\n",
    ))
    .unwrap();
    assert_eq!(y.directories.state, PathBuf::from("/srv/data/web"));
    assert_eq!(y.directories.config, PathBuf::from("/etc/web-backup"));
}

#[test]
fn rejected_when_required_fields_missing() {
    let e = parse("[agent]\nsource_tag = \"real\"\n[decoy]\nroot = \"/root\"\n").unwrap_err();
    assert!(e.contains("schema_version"), "{e}");
    let e = parse("schema_version = 1\n[decoy]\nroot = \"/root\"\n").unwrap_err();
    assert!(e.contains("source_tag"), "{e}");
    let e = parse("schema_version = 1\n[agent]\nsource_tag = \"real\"\n").unwrap_err();
    assert!(e.contains("root"), "{e}");
    let e = parse("schema_version = 2\n[agent]\nsource_tag = \"real\"\n[decoy]\nroot = \"/root\"\n").unwrap_err();
    assert!(e.contains("schema_version"), "{e}");
    assert!(parse("").is_err());
}

#[test]
fn unknown_field_is_rejected() {
    for extra in ["unknown_key = 1\n", "[agent]\nbogus = true\n", "[id]\nprocess = \"x\"\n", "[store]\nretention = 3\n"]
    {
        // Top-level fields must come before the tables.
        let text = if extra.starts_with('[') { append(extra) } else { format!("{extra}{MINIMAL}") };
        // `[agent]` cannot be defined twice: plant the table again with the required fields.
        let text = if extra.starts_with("[agent]") {
            "schema_version = 1\n[agent]\nsource_tag = \"real\"\nbogus = true\n[decoy]\nroot = \"/root\"\n".to_string()
        } else {
            text
        };
        assert!(parse(&text).is_err(), "{extra:?} must be rejected");
    }
}

#[test]
fn invalid_names_rejected() {
    let bad = [
        "Koru",
        "koru",
        "koru-agent",
        "x-koru-x",
        "PULSAR",
        "pulsar-watcher",
        "ABC",
        "a b",
        "",
        "ad_alt",
        "-x",
        "x-",
        "name/path",
        "..",
        "abcdefghijklmnop", // 16 characters: the kernel's comm limit is 15
        "\u{fc}",
    ];
    for name in bad {
        let extra = format!("[id]\nprocess_name = \"{name}\"\nservice_name = \"valid-name\"\n");
        assert!(parse(&append(&extra)).is_err(), "process name {name:?} must be rejected");
        let extra = format!("[id]\nprocess_name = \"valid-name\"\nservice_name = \"{name}\"\n");
        if name != "abcdefghijklmnop" {
            assert!(parse(&append(&extra)).is_err(), "service name {name:?} must be rejected");
        }
    }
    assert!(Config::defaults("Koru", SourceTag::Real, Path::new("/root")).is_err());
    for good in ["a", "system-observer", "x1", "0abc", "backup-logger", "abcdefghijklmno"] {
        let extra = format!("[id]\nprocess_name = \"{good}\"\nservice_name = \"{good}\"\n");
        assert!(parse(&append(&extra)).is_ok(), "{good:?} must be valid");
    }
}

#[test]
fn invalid_paths_rejected() {
    let bad =
        ["relative/path", "", "/", "/a/../b", "/a/./b", "/a//b", "/a/b/", "/a/b\\u0000c", "/a/b\\nc", "/a/\\u202eb"];
    for path in bad {
        for field in ["install", "config", "state", "runtime", "unit"] {
            let extra = format!("[directories]\n{field} = \"{path}\"\n");
            assert!(parse(&append(&extra)).is_err(), "{field} = {path:?} must be rejected");
        }
        let text = format!("schema_version = 1\n[agent]\nsource_tag = \"real\"\n[decoy]\nroot = \"{path}\"\n");
        assert!(parse(&text).is_err(), "decoy.root = {path:?} must be rejected");
    }
    let e = parse(&append("[detection]\nallowlist = \"relative.toml\"\n")).unwrap_err();
    assert!(e.contains("allowlist"), "{e}");
}

#[test]
fn dirs_cannot_nest() {
    // The state, install, config and runtime directories may not nest or coincide;
    // the state directory may not be inside the decoy roots or their parent (ADR-0004).
    let conflicts = [
        "[directories]\nstate = \"/var/lib/x\"\ninstall = \"/var/lib/x\"\n",
        "[directories]\nstate = \"/var/lib/x\"\nconfig = \"/var/lib/x/etc\"\n",
        "[directories]\ninstall = \"/opt/a\"\nruntime = \"/opt/a/run\"\n",
        "[directories]\nstate = \"/root/state\"\n",
        "[directories]\nstate = \"/\"\n",
        "[decoy]\nallowed_roots = [\"/var/lib/system-observer\"]\n",
    ];
    for extra in conflicts {
        let text = if extra.starts_with("[decoy]") {
            "schema_version = 1\n[agent]\nsource_tag = \"real\"\n[decoy]\nroot = \"/root\"\nallowed_roots = [\"/var/lib/system-observer\"]\n".to_string()
        } else {
            append(extra)
        };
        assert!(parse(&text).is_err(), "{extra:?} must be rejected");
    }
    // decoy.root above the state directory (e.g. root "/var") is also rejected.
    let text = "schema_version = 1\n[agent]\nsource_tag = \"real\"\n[decoy]\nroot = \"/var\"\n";
    assert!(parse(text).is_err());
}

#[test]
fn work_dir_must_be_under_run() {
    // systemd `RuntimeDirectory=` is always under /run; the socket and transient state live there.
    assert!(parse(&append("[directories]\nruntime = \"/run/secret-dir\"\n")).is_ok());
    assert!(parse(&append("[directories]\nruntime = \"/run/a/b\"\n")).is_ok());
    for bad in ["/tmp/x", "/runx/a", "/run", "/var/run/x"] {
        assert!(parse(&append(&format!("[directories]\nruntime = \"{bad}\"\n"))).is_err(), "{bad}");
    }
}

#[test]
fn unit_file_paths_have_no_special_chars() {
    // These paths are written into the systemd unit file: space, quote, '%', '$' and '\\' have special
    // meaning in unit syntax (specifier, variable, escape); rejected to prevent injection.
    for bad in ["/opt/a b", "/opt/%h", "/opt/$HOME", "/opt/\\\"q\\\"", "/opt/a'b", "/opt/a;b", "/opt/\u{15f}"] {
        for field in ["install", "config", "state", "unit"] {
            assert!(parse(&append(&format!("[directories]\n{field} = \"{bad}\"\n"))).is_err(), "{field} = {bad}");
        }
    }
    for good in ["/opt/a-b_c.d", "/srv/Web01/x.y"] {
        assert!(parse(&append(&format!("[directories]\nstate = \"{good}\"\n"))).is_ok(), "{good}");
    }
}

#[test]
fn numeric_bounds() {
    for (field, table, bad, good) in [
        ("retention_days", "store", ["0", "3651"], ["1", "3650"]),
        ("heartbeat_seconds", "notify", ["9", "3601"], ["10", "3600"]),
        ("lineage_depth", "agent", ["0", "65"], ["1", "64"]),
    ] {
        for d in bad {
            let text = if table == "agent" {
                format!(
                    "schema_version = 1\n[agent]\nsource_tag = \"real\"\n{field} = {d}\n[decoy]\nroot = \"/root\"\n"
                )
            } else {
                append(&format!("[{table}]\n{field} = {d}\n"))
            };
            assert!(parse(&text).is_err(), "{field} = {d} must be rejected");
        }
        for d in good {
            let text = if table == "agent" {
                format!(
                    "schema_version = 1\n[agent]\nsource_tag = \"real\"\n{field} = {d}\n[decoy]\nroot = \"/root\"\n"
                )
            } else {
                append(&format!("[{table}]\n{field} = {d}\n"))
            };
            assert!(parse(&text).is_ok(), "{field} = {d} must be valid");
        }
    }
    assert!(parse(&append("[store]\nretention_days = -1\n")).is_err());
    assert!(parse(&append("[store]\nretention_days = \"90\"\n")).is_err());
    assert!(parse(&append("[store]\nstore_raw_events = \"yes\"\n")).is_err());
}

#[test]
fn source_tag_and_other_agent_fields() {
    for (value, expected) in
        [("synthetic", SourceTag::Synthetic), ("legitimate", SourceTag::Legitimate), ("real", SourceTag::Real)]
    {
        let text = format!("schema_version = 1\n[agent]\nsource_tag = \"{value}\"\n[decoy]\nroot = \"/root\"\n");
        assert_eq!(parse(&text).unwrap().agent.source_tag, expected);
    }
    for bad in ["Real", "x", "", "real ", "reeal"] {
        let text = format!("schema_version = 1\n[agent]\nsource_tag = \"{bad}\"\n[decoy]\nroot = \"/root\"\n");
        assert!(parse(&text).is_err(), "{bad:?} must be rejected");
    }
    let entry = |a: &str| {
        parse(&format!(
            "schema_version = 1\n[agent]\nsource_tag = \"real\"\nhost = \"{a}\"\n[decoy]\nroot = \"/root\"\n"
        ))
    };
    assert_eq!(entry("web01.sample.example").unwrap().agent.host.as_deref(), Some("web01.sample.example"));
    for bad in ["10.0.0.1", "password=x", "a b", ""] {
        assert!(entry(bad).is_err(), "host {bad:?} must be rejected");
    }
}

#[test]
fn decoy_owner() {
    let owner = |s: &str| parse(&format!("{MINIMAL}owner = \"{s}\"\n"));
    assert_eq!(owner("0:0").unwrap().decoy.owner, Some((0, 0)));
    assert_eq!(owner("1000:1001").unwrap().decoy.owner, Some((1000, 1001)));
    for bad in ["x:y", "1:2:3", "-1:0", "1000", ":", "1:", ":1", "4294967296:0"] {
        assert!(owner(bad).is_err(), "{bad:?} must be rejected");
    }
}

#[test]
fn toml_roundtrip_gives_same_config() {
    let y = parse(&append("[id]\nprocess_name = \"web-backup\"\nservice_name = \"web-backup\"\n")).unwrap();
    assert_eq!(parse(&y.toml()).unwrap(), y);
    // Unusual but valid paths: quote, backslash, space and Unicode are escaped.
    let mut y =
        Config::defaults(DEFAULT_NAME, SourceTag::Legitimate, Path::new("/home/alice bob/\"x\"\\\u{15f}")).unwrap();
    y.detection.allowlist = Some(PathBuf::from("/etc/allow list.toml"));
    y.decoy.allowed_roots = vec![PathBuf::from("/opt/a"), PathBuf::from("/srv/b c")];
    y.decoy.owner = Some((1000, 1000));
    y.agent.host = Some("web01".to_string());
    y.store.store_raw_events = true;
    assert_eq!(parse(&y.toml()).unwrap(), y, "{}", y.toml());
}

#[test]
fn derived_paths() {
    let y = parse(MINIMAL).unwrap();
    assert_eq!(y.config_file(), PathBuf::from("/etc/system-observer/config.toml"));
    assert_eq!(y.env_file(), PathBuf::from("/etc/system-observer/environment"));
    assert_eq!(y.pulsar_config(), PathBuf::from("/etc/system-observer/sensor.toml"));
    assert_eq!(y.engine_socket(), PathBuf::from("/run/system-observer/api.sock"));
    assert_eq!(y.store_file(), PathBuf::from("/var/lib/system-observer/event.db"));
    assert_eq!(y.queue_dir(), PathBuf::from("/var/lib/system-observer/queue"));
    assert_eq!(y.decoy_state_dir(), PathBuf::from("/var/lib/system-observer/decoy"));
    assert_eq!(y.install_record(), PathBuf::from("/var/lib/system-observer/install.toml"));
    assert_eq!(y.service_file(), PathBuf::from("/etc/systemd/system/system-observer.service"));
    let custom = parse(&append("[directories]\nunit = \"/usr/lib/systemd/system\"\n")).unwrap();
    assert_eq!(custom.service_file(), PathBuf::from("/usr/lib/systemd/system/system-observer.service"));
    assert_eq!(y.version_dir("1.2.3"), PathBuf::from("/usr/libexec/system-observer/versions/1.2.3"));
    assert_eq!(y.current_link(), PathBuf::from("/usr/libexec/system-observer/current"));
    assert_eq!(y.agent_binary(), PathBuf::from("/usr/libexec/system-observer/current/system-observer"));
}

#[test]
fn self_protection_paths_derived_from_config() {
    let y = parse(MINIMAL).unwrap();
    let k = y.self_protection();
    assert_eq!(k.config, ["/etc/system-observer"]);
    assert_eq!(k.secret, ["/etc/system-observer/environment"]);
    assert_eq!(
        k.store,
        [
            "/var/lib/system-observer/event.db",
            "/var/lib/system-observer/event.db-wal",
            "/var/lib/system-observer/event.db-shm"
        ]
    );
    assert_eq!(k.state, ["/var/lib/system-observer"]);
    assert_eq!(k.binaries, ["/usr/libexec/system-observer"]);
    assert_eq!(
        k.service_files,
        ["/etc/systemd/system/system-observer.service", "/etc/systemd/system/system-observer.service.d"]
    );
    assert_eq!(k.service_names, ["system-observer"]);
    assert_eq!(k.process_names, ["system-observer"]);
}

// ---------------------------------------------------------------------------------------------
// Safe reading from a file
// ---------------------------------------------------------------------------------------------

fn file(t: &tempfile::TempDir, name: &str, content: &[u8], mode: u32) -> PathBuf {
    let path = fs::canonicalize(t.path()).unwrap().join(name);
    fs::write(&path, content).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn file_read_security_checks() {
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let good = file(&t, "good.toml", MINIMAL.as_bytes(), 0o600);
    assert!(Config::read(&good).is_ok());
    let readable_v = file(&t, "readable_v.toml", MINIMAL.as_bytes(), 0o644);
    assert!(Config::read(&readable_v).is_ok(), "carries no secrets; 0644 is accepted");
    // If group or others can write, someone else can change the config: rejected.
    for mode in [0o664, 0o666, 0o620, 0o602] {
        let public_v = file(&t, "public_v.toml", MINIMAL.as_bytes(), mode);
        let e = Config::read(&public_v).unwrap_err().to_string();
        assert!(e.contains("writable"), "{mode:o}: {e}");
    }
    let link_v = fs::canonicalize(t.path()).unwrap().join("link_v.toml");
    symlink(&good, &link_v).unwrap();
    assert!(Config::read(&link_v).unwrap_err().to_string().contains("symlink"));
    let big_v = file(&t, "big_v.toml", &vec![b'#'; 70 * 1024], 0o600);
    assert!(Config::read(&big_v).unwrap_err().to_string().contains("too large"));
    let broken = file(&t, "broken.toml", b"\xff\xfe", 0o600);
    assert!(Config::read(&broken).is_err());
    let missing_config = fs::canonicalize(t.path()).unwrap().join("missing.toml");
    assert!(Config::read(&missing_config).is_err());
    assert!(Config::read(Path::new("relative.toml")).is_err(), "a relative path is rejected");
}
