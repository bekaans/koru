//! Golden data replay: the `data/golden/{synthetic,legitimate}` events run
//! through koru-detect in CI without a VM. Every synthetic record must produce at least one
//! finding; no legitimate record may produce one. The catalog comes from
//! `data/golden/catalog.txt` (the `koru decoy list` output of a VM run); the rules,
//! signatures, and thresholds are the real packages in the repo.

use std::path::PathBuf;

use koru_detect::{
    Allowlist, DetectorSettings, FileIdentity, IdentitySource, RuleDetector, SelfProtection, read_agent_signatures,
    read_rule_pack, read_thresholds,
};
use koru_event::{DecoyCatalog, Event, WatchedPath, WatchedPathKind};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[derive(Default)]
struct Catalog(Vec<WatchedPath>);

impl DecoyCatalog for Catalog {
    fn watched_paths(&self) -> Vec<WatchedPath> {
        self.0.clone()
    }
    fn find(&self, path: &str) -> Option<WatchedPath> {
        self.0.iter().find(|y| y.path == path).cloned()
    }
}

struct RuleSource;
impl IdentitySource for RuleSource {
    fn process_exe_id(&self, _pid: u32) -> Option<FileIdentity> {
        None
    }
    fn path_id(&self, _path: &str) -> Option<FileIdentity> {
        None
    }
}

fn read_catalog() -> Catalog {
    let path = root().join("data/golden/catalog.txt");
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{} could not be read: {e}", path.display()));
    let mut k = Catalog::default();
    // A listing line: id, kind (1-2 words), class, placement, path (the path is last).
    const CLASSES: [&str; 10] = [
        "cloud_credentials",
        "ssh_key",
        "env",
        "llm_keys",
        "mcp_config",
        "database_dump",
        "ai_note",
        "bash_history",
        "known_hosts",
        "ssh_config",
    ];
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let Some(class) = fields.iter().find(|a| CLASSES.contains(a)) else { continue };
        let kind = if line.contains("breadcrumb") { WatchedPathKind::Breadcrumb } else { WatchedPathKind::Decoy };
        k.0.push(WatchedPath {
            path: fields[fields.len() - 1].to_string(),
            decoy_id: fields[0].to_string(),
            kind,
            class: (*class).to_string(),
        });
    }
    assert!(!k.0.is_empty(), "the catalog is empty: {}", path.display());
    k
}

fn a_detector() -> RuleDetector {
    let root = root();
    let settings = DetectorSettings {
        rules: read_rule_pack(&root.join("packages/rules")).expect("rules"),
        agents: read_agent_signatures(&root.join("packages/agents")).expect("agents"),
        thresholds: read_thresholds(&root.join("thresholds.toml")).expect("the thresholds"),
        allowlist: Allowlist::empty(),
        self_protection: SelfProtection {
            config: vec!["/etc/koru".to_string()],
            secret: vec!["/etc/koru/.env".to_string()],
            store: vec!["/var/lib/koru/store".to_string()],
            state: vec!["/var/lib/koru/status".to_string()],
            binaries: vec!["/usr/local/bin/koru-agent".to_string()],
            service_files: vec!["/etc/systemd/system/koru.service".to_string()],
            service_names: vec!["koru".to_string()],
            process_names: vec!["koru-agent".to_string()],
        },
        identity: None,
        host_namespaces: None,
    };
    RuleDetector::new(settings, Box::new(read_catalog()), Box::new(RuleSource)).expect("the detector")
}

fn read_events(directory: &str) -> Vec<Event> {
    let path = root().join(directory);
    let mut events = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&path)
        .unwrap_or_else(|e| panic!("{} could not be read: {e}", path.display()))
        .filter_map(|g| g.ok().map(|g| g.path()))
        .filter(|p| p.extension().is_some_and(|u| u == "jsonl"))
        .collect();
    entries.sort();
    for file in entries {
        for line in std::fs::read_to_string(&file).expect("jsonl").lines() {
            if line.trim().is_empty() {
                continue;
            }
            let event: Event =
                serde_json::from_str(line).unwrap_or_else(|e| panic!("the event could not be parsed: {e}"));
            events.push(event);
        }
    }
    events
}

#[test]
fn golden_synthetic_every_event_produces_a_finding() {
    let events = read_events("data/golden/synthetic");
    assert!(events.len() >= 100, "the synthetic golden data must hold at least 100 events, has: {}", events.len());
    let mut t = a_detector();
    let without_finding: Vec<String> =
        events.iter().filter(|o| t.process(o).is_empty()).map(|o| o.event_id.to_string()).collect();
    assert!(without_finding.is_empty(), "synthetic events producing no finding: {without_finding:?}");
}

#[test]
fn golden_legitimate_produces_no_finding() {
    let events = read_events("data/golden/legitimate");
    assert!(!events.is_empty(), "the legitimate golden data must not be empty");
    let mut t = a_detector();
    for o in &events {
        let b = t.process(o);
        assert!(b.is_empty(), "a legitimate event produced a finding: {} -> {:?}", o.event_id, b.len());
    }
}
