//! Shared helpers: repo paths, a fake sensor, a fake decoy catalog, a fake identity source,
//! event builders, and the scenario environment.
//!
//! The scenario environment: decoys and breadcrumbs installed under `/home/devops` (a fake
//! catalog), Koru's own process (pid 4242, `/usr/local/bin/koru-agent`), and its protected
//! paths (`/etc/koru`, `/var/lib/koru/...`, the systemd unit). Tests never touch the file
//! system; inode information comes from the fake identity source.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use koru_detect::{
    AgentSignatures, Allowlist, DetectorSettings, FileIdentity, Finding, IdentitySource, KoruIdentity, RuleDetector,
    RulePack, SelfProtection, Thresholds, read_agent_signatures, read_rule_pack, read_thresholds,
};
use koru_event::{
    Actor, AncestorProcess, Container, DecoyCatalog, Event, EventId, EventType, FileFlag, InterfaceError, Namespaces,
    Process, SchemaVersion, Sensor, SensorInfo, SourceTag, Tags, Target, Timestamp, Untrusted, User, WatchedPath,
    WatchedPathKind,
};

// ---------------------------------------------------------------------------------------------
// Repo paths and the real packages
// ---------------------------------------------------------------------------------------------

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn rules_directory() -> PathBuf {
    repo_root().join("packages/rules")
}

pub fn agent_directory() -> PathBuf {
    repo_root().join("packages/agents")
}

pub fn rules() -> RulePack {
    read_rule_pack(&rules_directory()).unwrap_or_else(|e| panic!("packages/rules could not be read: {e}"))
}

pub fn agents() -> AgentSignatures {
    read_agent_signatures(&agent_directory()).unwrap_or_else(|e| panic!("packages/agents could not be read: {e}"))
}

pub fn thresholds() -> Thresholds {
    read_thresholds(&repo_root().join("thresholds.toml"))
        .unwrap_or_else(|e| panic!("thresholds.toml could not be read: {e}"))
}

/// Files with the given extension in a directory (sorted by name).
pub fn files(directory: &Path, extension: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(directory)
        .unwrap()
        .map(|g| g.unwrap().path())
        .filter(|p| p.extension().is_some_and(|u| u == extension))
        .collect();
    v.sort();
    v
}

/// A temporary directory (canonical path).
pub struct Transient {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
}

pub fn temporary() -> Transient {
    let directory = tempfile::tempdir().expect("a temporary directory could not be opened");
    let path = std::fs::canonicalize(directory.path()).expect("canonical path");
    Transient { _dir: directory, path }
}

// ---------------------------------------------------------------------------------------------
// The fake sensor, catalog, and identity source
// ---------------------------------------------------------------------------------------------

/// A fake sensor feeding the given events to the sink in order (`koru_event::Sensor`).
pub struct FakeSensor {
    events: Vec<Event>,
}

impl FakeSensor {
    pub fn new(events: Vec<Event>) -> FakeSensor {
        FakeSensor { events }
    }
}

impl Sensor for FakeSensor {
    fn info(&self) -> SensorInfo {
        sensor_info()
    }

    fn run(&mut self, sink: &mut dyn FnMut(Event)) -> Result<(), InterfaceError> {
        for event in self.events.drain(..) {
            sink(event);
        }
        Ok(())
    }
}

/// A fake decoy catalog (`koru_event::DecoyCatalog`).
#[derive(Debug, Clone, Default)]
pub struct FakeCatalog {
    paths: Vec<WatchedPath>,
}

impl FakeCatalog {
    pub fn append(mut self, path: &str, id: &str, class: &str, kind: WatchedPathKind) -> FakeCatalog {
        self.paths.push(WatchedPath {
            path: path.to_string(),
            decoy_id: id.to_string(),
            kind,
            class: class.to_string(),
        });
        self
    }
}

impl DecoyCatalog for FakeCatalog {
    fn watched_paths(&self) -> Vec<WatchedPath> {
        self.paths.clone()
    }

    fn find(&self, path: &str) -> Option<WatchedPath> {
        self.paths.iter().find(|y| y.path == path).cloned()
    }
}

/// A fake identity source: pid → exe identity, path → file identity.
#[derive(Debug, Clone, Default)]
pub struct FakeIdentity {
    pub processes: HashMap<u32, FileIdentity>,
    pub paths: HashMap<String, FileIdentity>,
}

impl FakeIdentity {
    pub fn process(mut self, pid: u32, id: FileIdentity) -> FakeIdentity {
        self.processes.insert(pid, id);
        self
    }

    pub fn path(mut self, path: &str, id: FileIdentity) -> FakeIdentity {
        self.paths.insert(path.to_string(), id);
        self
    }
}

impl IdentitySource for FakeIdentity {
    fn process_exe_id(&self, pid: u32) -> Option<FileIdentity> {
        self.processes.get(&pid).copied()
    }

    fn path_id(&self, path: &str) -> Option<FileIdentity> {
        self.paths.get(path).copied()
    }
}

// ---------------------------------------------------------------------------------------------
// The scenario environment
// ---------------------------------------------------------------------------------------------

pub const AWS: &str = "/home/devops/.aws/credentials";
pub const SSH_PATH: &str = "/home/devops/.ssh/id_ed25519_prod";
pub const ENV: &str = "/home/devops/apps/invoice-service/.env";
pub const LLM_ENV: &str = "/home/devops/apps/support-assistant/.env";
pub const MCP: &str = "/home/devops/.config/Claude/claude_desktop_config.json";
pub const DUMP: &str = "/home/devops/backups/mysql/billing_prod_2026-08-30.sql";
pub const NOTE: &str = "/home/devops/notes/prod-access.md";
pub const NEW_DECOY: &str = "/home/devops/.local/share/reports/custom.txt";
pub const HISTORY: &str = "/home/devops/.bash_history";
pub const SSH_CONFIG: &str = "/home/devops/.ssh/config";
pub const KNOWN_HOSTS: &str = "/home/devops/.ssh/known_hosts";
pub const NEW_BREADCRUMB: &str = "/home/devops/.cache/session-note";

pub fn decoy_catalog() -> FakeCatalog {
    use WatchedPathKind::{Breadcrumb, Decoy};
    FakeCatalog::default()
        .append(AWS, "decoy-aws", "cloud_credentials", Decoy)
        .append(SSH_PATH, "decoy-ssh", "ssh_key", Decoy)
        .append(ENV, "decoy-env", "env", Decoy)
        .append(LLM_ENV, "decoy-llm", "llm_keys", Decoy)
        .append(MCP, "decoy-mcp", "mcp_config", Decoy)
        .append(DUMP, "decoy-dump", "database_dump", Decoy)
        .append(NOTE, "decoy-not", "ai_note", Decoy)
        .append(NEW_DECOY, "decoy-new", "report_archive", Decoy)
        .append(HISTORY, "breadcrumb-history", "bash_history", Breadcrumb)
        .append(SSH_CONFIG, "iz-ssh-config", "ssh_config", Breadcrumb)
        .append(KNOWN_HOSTS, "iz-known-hosts", "known_hosts", Breadcrumb)
        .append(NEW_BREADCRUMB, "breadcrumb-new", "session_note", Breadcrumb)
}

pub const KORU_PID: u32 = 4242;
pub const KORU_EXE: &str = "/usr/local/bin/koru-agent";
pub const KORU_FILE: FileIdentity = FileIdentity { device: 64769, inode: 1001 };
pub const OTHER_FILE: FileIdentity = FileIdentity { device: 64769, inode: 2002 };

pub fn koru_identity() -> KoruIdentity {
    KoruIdentity {
        pid: KORU_PID,
        ppid: 1,
        exe: KORU_EXE.to_string(),
        command_line: vec![KORU_EXE.to_string(), "agent".to_string()],
        file: KORU_FILE,
    }
}

pub fn self_protection_settings() -> SelfProtection {
    let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    SelfProtection {
        config: v(&["/etc/koru"]),
        secret: v(&["/etc/koru/.env"]),
        store: v(&["/var/lib/koru/store"]),
        state: v(&["/var/lib/koru/status"]),
        binaries: v(&[KORU_EXE]),
        service_files: v(&["/etc/systemd/system/koru.service", "/etc/systemd/system/koru.service.d"]),
        service_names: v(&["koru"]),
        process_names: v(&["koru-agent"]),
    }
}

/// The host's namespaces.
pub fn host_namespaces() -> Namespaces {
    Namespaces {
        uts: 4026531838,
        ipc: 4026531839,
        mnt: 4026531841,
        pid: 4026531836,
        net: 4026531840,
        time: 4026531834,
        cgroup: 4026531835,
    }
}

/// All namespaces different (a container).
pub fn container_ns() -> Namespaces {
    Namespaces {
        uts: 4026532300,
        ipc: 4026532301,
        mnt: 4026532299,
        pid: 4026532302,
        net: 4026532304,
        time: 4026531834,
        cgroup: 4026532303,
    }
}

pub fn settings() -> DetectorSettings {
    DetectorSettings {
        rules: rules(),
        agents: agents(),
        thresholds: thresholds(),
        allowlist: Allowlist::empty(),
        self_protection: self_protection_settings(),
        identity: Some(koru_identity()),
        host_namespaces: Some(host_namespaces()),
    }
}

pub fn identity_source() -> FakeIdentity {
    FakeIdentity::default().process(KORU_PID, KORU_FILE)
}

pub fn with_a_detector(settings: DetectorSettings, source: FakeIdentity) -> RuleDetector {
    RuleDetector::new(settings, Box::new(decoy_catalog()), Box::new(source))
        .unwrap_or_else(|e| panic!("the detector could not be built: {e}"))
}

pub fn a_detector() -> RuleDetector {
    with_a_detector(settings(), identity_source())
}

/// Feeds events from the fake sensor to the detector; returns all findings in order.
pub fn run(t: &mut RuleDetector, events: Vec<Event>) -> Vec<Finding> {
    let mut sensor = FakeSensor::new(events);
    let mut findings_of = Vec::new();
    sensor.run(&mut |o: Event| findings_of.extend(t.process(&o))).unwrap();
    findings_of
}

/// Runs the events through a fresh detector.
pub fn findings_of(events: Vec<Event>) -> Vec<Finding> {
    run(&mut a_detector(), events)
}

pub fn rule_names(b: &[Finding]) -> Vec<String> {
    b.iter().map(|b| b.event.detection.as_ref().unwrap().rule.clone()).collect()
}

// ---------------------------------------------------------------------------------------------
// Event builders
// ---------------------------------------------------------------------------------------------

/// 2026-10-10 09:00:00 UTC, in seconds.
pub const T0_SN: i128 = 1_791_622_800;

pub fn time_ms(ms: i64) -> Timestamp {
    Timestamp::from_unix_nanos(T0_SN * 1_000_000_000 + i128::from(ms) * 1_000_000).unwrap()
}

pub fn sensor_info() -> SensorInfo {
    SensorInfo { name: "fake".to_string(), version: "0".to_string(), platform: "linux-aarch64".to_string() }
}

pub fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

pub fn ancestor(pid: u32, exe: &str, command: &[&str]) -> AncestorProcess {
    AncestorProcess { pid, exe: Untrusted::new(exe.to_string()), command_line: Untrusted::new(argv(command)) }
}

/// A process description.
#[derive(Debug, Clone)]
pub struct S {
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
    pub command: Vec<String>,
    pub uid: u32,
    pub lineage: Vec<AncestorProcess>,
    pub container: Container,
}

/// A process builder; default: uid 1001 (devops), outside a container (host namespaces).
pub fn s(pid: u32, ppid: u32, exe: &str, command: &[&str]) -> S {
    S {
        pid,
        ppid,
        exe: exe.to_string(),
        command: argv(command),
        uid: 1001,
        lineage: Vec::new(),
        container: Container { namespaces: Some(host_namespaces()), ..Container::default() },
    }
}

impl S {
    pub fn lineage(mut self, lineage: Vec<AncestorProcess>) -> S {
        self.lineage = lineage;
        self
    }

    pub fn uid(mut self, uid: u32) -> S {
        self.uid = uid;
        self
    }

    pub fn container(mut self, k: Container) -> S {
        self.container = k;
        self
    }
}

pub fn event(s: &S, kind: EventType, target: Target, ms: i64) -> Event {
    Event {
        schema_version: SchemaVersion::V1,
        event_id: EventId::new(),
        timestamp: time_ms(ms),
        timestamp_trusted: true,
        source_tag: SourceTag::Synthetic,
        sensor: sensor_info(),
        host: "koru-lab".to_string(),
        process: Process {
            pid: s.pid,
            ppid: s.ppid,
            start_time: None,
            exe: Untrusted::new(s.exe.clone()),
            command_line: Untrusted::new(s.command.clone()),
            environment: Untrusted::new(Vec::new()),
            user: User { uid: s.uid, gid: s.uid },
            lineage: s.lineage.clone(),
        },
        container: s.container.clone(),
        event_type: kind,
        target,
        actor: Actor::unknown(),
        detection: None,
        tags: Tags::default(),
        session_id: None,
        response: None,
    }
}

fn path(y: &str) -> Option<Untrusted<String>> {
    Some(Untrusted::new(y.to_string()))
}

/// A file open (read-only).
pub fn read_text(s: &S, target_path: &str, ms: i64) -> Event {
    open_file(s, target_path, &[FileFlag::Rdonly], ms)
}

/// A file open (with the given flags).
pub fn open_file(s: &S, target_path: &str, flags: &[FileFlag], ms: i64) -> Event {
    event(s, EventType::FileOpened, Target { path: path(target_path), flags: flags.to_vec(), ..Target::default() }, ms)
}

/// A write-mode open (O_WRONLY | O_TRUNC).
pub fn write_text(s: &S, target_path: &str, ms: i64) -> Event {
    open_file(s, target_path, &[FileFlag::Wronly, FileFlag::Trunc], ms)
}

pub fn process_creation(s: &S, target_path: &str, ms: i64) -> Event {
    event(s, EventType::FileCreated, Target { path: path(target_path), ..Target::default() }, ms)
}

pub fn file_deletion(s: &S, target_path: &str, ms: i64) -> Event {
    event(s, EventType::FileDeleted, Target { path: path(target_path), ..Target::default() }, ms)
}

pub fn file_rename(s: &S, old: &str, new: &str, ms: i64) -> Event {
    event(s, EventType::FileRenamed, Target { path: path(old), new_path: path(new), ..Target::default() }, ms)
}

/// exec: the process is its post-exec self; the target is the executed file.
pub fn exec(s: &S, ms: i64) -> Event {
    event(s, EventType::ProcessExecuted, Target { path: path(&s.exe), ..Target::default() }, ms)
}

// ---------------------------------------------------------------------------------------------
// Frequently used processes
// ---------------------------------------------------------------------------------------------

/// `cat` under the non-interactive shell of an SSH session.
pub fn cat(pid: u32, ppid: u32, target: &str) -> S {
    s(pid, ppid, "/usr/bin/cat", &["cat", target]).lineage(vec![
        ancestor(ppid, "/usr/bin/bash", &["bash", "-c", "cat file"]),
        ancestor(700, "/usr/sbin/sshd", &["sshd: devops"]),
    ])
}

/// `cat` run via `bash -c` under Claude Code (a local install).
pub fn cat_under_claude(pid: u32, target: &str) -> S {
    s(pid, 1500, "/usr/bin/cat", &["cat", target]).lineage(vec![
        ancestor(1500, "/usr/bin/bash", &["/bin/bash", "-c", "cat file"]),
        ancestor(1400, "/home/devops/.local/share/claude/versions/2.1.3", &["claude"]),
        ancestor(1300, "/usr/bin/bash", &["-bash"]),
        ancestor(1200, "/usr/sbin/sshd", &["sshd: devops@pts/0"]),
    ])
}
