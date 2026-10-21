//! The detector: enrichment, rule evaluation, classification, actor-kind estimation, the
//! allowlist, and self-protection.
//!
//! Flow (`RuleDetector::process`): events failing schema validation, and events that are
//! already findings, are dropped (KT-30); Koru's own process is excluded by pid, exe path,
//! and exe inode (KT-01); the event's fields are enriched (normalized paths, the decoy
//! catalog, AI-agent lineage, container, protected paths, stop attempts); rules are
//! evaluated; the allowlist (exe path and inode only) applies; a finding is completed with an
//! actor-kind estimate and a threat class.
//!
//! No decision rests on `process.user.uid`: Pulsar can show 0 for privilege-dropped
//! processes (KT-43). Process name, exe path, and command line are under attacker control
//! (KT-02); decoy access therefore produces a finding regardless of actor kind.

use std::collections::{BTreeMap, HashMap, VecDeque};

use koru_event::{
    Actor, ActorKind, Confidence, Container, DecoyCatalog, Detection, Detector, Event, EventId, EventType, Namespaces,
    Process, SchemaVersion, SensorInfo, SourceTag, Tags, Target, ThreatClass, Timestamp, Untrusted, User, WatchedPath,
    WatchedPathKind,
};

use crate::protection::ProtectedPaths;
use crate::{
    AgentSignatures, Allowlist, FieldSet, IdentitySource, KoruIdentity, Level, Rule, RulePack, SelfProtection,
    Thresholds, normalize_path,
};

/// A detector construction error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectorError {
    /// Invalid settings (e.g. a non-absolute protected path).
    #[error("detector setting: {0}")]
    Settings(String),
}

/// The detector's settings. The composition is built in the `koru` crate.
#[derive(Debug, Clone)]
pub struct DetectorSettings {
    /// Rule pack.
    pub rules: RulePack,
    /// AI-agent signatures.
    pub agents: AgentSignatures,
    /// Actor-kind thresholds.
    pub thresholds: Thresholds,
    /// The allowlist.
    pub allowlist: Allowlist,
    /// Self-protection paths and names.
    pub self_protection: SelfProtection,
    /// Koru's own process (exclusion and stop detection); `None` if unknown.
    pub identity: Option<KoruIdentity>,
    /// The host's namespaces (for container suspicion); `None` if unknown.
    pub host_namespaces: Option<Namespaces>,
}

/// A finding: an event (schema v1) with a new id and detection, actor, and ATT&CK tags filled.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// The finding event: `detection`, `actor`, and `tags.mitre_techniques` are present; the
    /// other fields come from the source event.
    pub event: Event,
    /// The rule's title.
    pub title: String,
    /// The severity (critical for a suspected hijacked agent).
    pub severity: Level,
}

/// Context for events Koru itself produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfEventContext {
    /// The event time.
    pub timestamp: Timestamp,
    /// Whether the clock is NTP-synced.
    pub timestamp_trusted: bool,
    /// The installation's source tag.
    pub source_tag: SourceTag,
    /// The host name.
    pub host: String,
}

// ---------------------------------------------------------------------------------------------
// Actor state: per-session command history (memory bounded)
// ---------------------------------------------------------------------------------------------

#[derive(Debug)]
struct Command {
    time_ns: i128,
    name: String,
}

#[derive(Debug)]
struct Session {
    order: u64,
    commands: VecDeque<Command>,
}

/// Recent commands per parent process (session). Session count and commands per session are
/// bounded by `thresholds.toml [memory]`; when full, the oldest (longest inactive) session
/// is dropped (KT-31).
#[derive(Debug, Default)]
struct Sessions {
    map: HashMap<u32, Session>,
    /// Activity order → parent process; the first item is the oldest session.
    order: BTreeMap<u64, u32>,
    counter: u64,
}

impl Sessions {
    fn store(&mut self, upper: u32, time_ns: i128, name: String, max_sessions: usize, max_commands: usize) {
        self.counter += 1;
        let order = self.counter;
        if let Some(o) = self.map.get_mut(&upper) {
            self.order.remove(&o.order);
            o.order = order;
            o.commands.push_back(Command { time_ns, name });
            if o.commands.len() > max_commands {
                o.commands.pop_front();
            }
        } else {
            while self.map.len() >= max_sessions.max(1) {
                let Some((_, oldest)) = self.order.pop_first() else {
                    break;
                };
                self.map.remove(&oldest);
            }
            let mut commands = VecDeque::new();
            commands.push_back(Command { time_ns, name });
            self.map.insert(upper, Session { order, commands });
        }
        self.order.insert(order, upper);
    }
}

/// One session's state at event time.
struct SessionSummary {
    /// Median (ms) and count of command intervals; present if the machine-speed threshold is met.
    machine_speed: Option<(u64, usize)>,
    /// Median (ms) and count if the human-speed threshold is met.
    human_speed: Option<(u64, usize)>,
    /// Distinct discovery commands in the window; present if the threshold is met.
    discovery: Vec<String>,
}

fn median(mut intervals: Vec<u64>) -> u64 {
    intervals.sort_unstable();
    let n = intervals.len();
    if n == 0 {
        0
    } else if n % 2 == 1 {
        intervals[n / 2]
    } else {
        (intervals[n / 2 - 1] + intervals[n / 2]) / 2
    }
}

// ---------------------------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------------------------

/// The result of event enrichment: rule fields and information carried into a finding.
struct Enriched {
    fields: FieldSet,
    exe_normal: String,
    decoy: Option<WatchedPath>,
    agent: Option<AgentInfo>,
}

struct AgentInfo {
    id: String,
    name: String,
    kind: &'static str,
}

/// The detector.
pub struct RuleDetector {
    rules: RulePack,
    agents: AgentSignatures,
    thresholds: Thresholds,
    allow: Allowlist,
    protected: ProtectedPaths,
    identity: Option<KoruIdentity>,
    identity_exe: Option<String>,
    host_ns: Option<Namespaces>,
    catalog: Box<dyn DecoyCatalog + Send>,
    source: Box<dyn IdentitySource + Send>,
    sessions: Sessions,
    suppressed_count: u64,
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The path normalized if possible, otherwise as given.
fn normal_or_raw(path: &str) -> String {
    normalize_path(path).unwrap_or_else(|| path.to_string())
}

/// Whether `argv` holds `-c` (a `c` among single-dash flags counts).
fn runs_command(args: &[String]) -> bool {
    args.iter().any(|a| a.starts_with('-') && !a.starts_with("--") && a[1..].contains('c'))
}

/// An interactive shell: the exe's base name is in the shell list, no `-c`, and a session
/// shell (`argv[0]` starts with `-`), `-i`, `-l`, `--login`, or `--interactive` is present, or
/// there are no arguments. With an unknown (empty) command line the shell kind is
/// undecidable.
fn interactive_shell(exe: &str, command: &[String], shells: &[String]) -> Option<String> {
    let name = base_name(&normal_or_raw(exe)).to_string();
    // Unknown command line (a process started before Koru): the shell kind is undecidable.
    if !shells.contains(&name) || command.is_empty() {
        return None;
    }
    let args = command.get(1..).unwrap_or(&[]);
    if runs_command(args) {
        return None;
    }
    let session_shell = command.first().is_some_and(|a0| a0.starts_with('-'));
    let option = args.iter().any(|a| matches!(a.as_str(), "-i" | "-l" | "--login" | "--interactive"));
    (session_shell || option || args.is_empty()).then_some(name)
}

impl RuleDetector {
    /// Builds the detector; validates the settings.
    pub fn new(
        settings: DetectorSettings,
        catalog: Box<dyn DecoyCatalog + Send>,
        source: Box<dyn IdentitySource + Send>,
    ) -> Result<RuleDetector, DetectorError> {
        let protected = settings.self_protection.prepare().map_err(DetectorError::Settings)?;
        let identity_exe = match &settings.identity {
            Some(k) => Some(
                normalize_path(&k.exe)
                    .ok_or_else(|| DetectorError::Settings("koru.exe must be an absolute path".to_string()))?,
            ),
            None => None,
        };
        Ok(RuleDetector {
            rules: settings.rules,
            agents: settings.agents,
            thresholds: settings.thresholds,
            allow: settings.allowlist,
            protected,
            identity: settings.identity,
            identity_exe,
            host_ns: settings.host_namespaces,
            catalog,
            source,
            sessions: Sessions::default(),
            suppressed_count: 0,
        })
    }

    /// Whether the event is Koru's own process: the pid must match; the event's (normalized)
    /// exe must match Koru's exe path AND the process's real exe (`/proc` path and inode) must
    /// match Koru's (KT-01). Both are required: the real exe alone can be bypassed by exec.
    fn is_koru_process(&self, event: &Event, exe_normal: &str) -> bool {
        let (Some(k), Some(identity_exe)) = (&self.identity, &self.identity_exe) else {
            return false;
        };
        event.process.pid == k.pid
            && exe_normal == identity_exe
            && self.source.verify_process_exe(event.process.pid, identity_exe, k.file)
    }

    /// Processes an event: updates actor state, filters Koru's own events, evaluates rules,
    /// and returns findings. An event failing schema validation is not processed.
    pub fn process(&mut self, event: &Event) -> Vec<Finding> {
        // KT-30: finding events (e.g. bus feedback) are not re-processed.
        if event.detection.is_some() || event.validate().is_err() {
            return Vec::new();
        }
        let exe_normal = normal_or_raw(event.process.exe.untrusted_value());
        if self.is_koru_process(event, &exe_normal) {
            return Vec::new();
        }
        if event.event_type == EventType::ProcessExecuted && event.process.ppid != 0 {
            self.sessions.store(
                event.process.ppid,
                event.timestamp.unix_nanos(),
                base_name(&exe_normal).to_string(),
                self.thresholds.memory.max_sessions,
                self.thresholds.memory.max_commands_per_session,
            );
        }
        let enriched = self.enrich(event, None);
        let mut findings = Vec::new();
        let mut actor: Option<Actor> = None;
        for rule in self.rules.rules() {
            if !rule.is_evaluated()
                || !rule.matches_source(event.event_type, false)
                || !rule.matches_pattern(&enriched.fields)
            {
                continue;
            }
            // Allowlist: the event's exe must match the entry AND the process's real exe
            // (/proc path and inode) must match the entry. If /proc is unreadable, no
            // suppression (fail-closed).
            if let Some(file) = self.allow.candidate_file(&enriched.exe_normal, rule)
                && self.source.verify_process_exe(event.process.pid, &enriched.exe_normal, file)
            {
                self.suppressed_count += 1;
                continue;
            }
            let a = actor.get_or_insert_with(|| self.actor_estimate(event, &enriched)).clone();
            findings.push(create_finding(rule, event, &enriched, a));
        }
        findings
    }

    /// The count of findings silenced by the allowlist (exe path and inode); for auditing and reports.
    pub fn suppressed_count(&self) -> u64 {
        self.suppressed_count
    }

    /// The event's rule fields (the enrichment result).
    pub fn fields(&self, event: &Event) -> FieldSet {
        self.enrich(event, None).fields
    }

    /// On clean shutdown (SIGTERM, SIGINT, SIGHUP), produces and evaluates the "stopped"
    /// event. Empty if Koru's identity is unknown.
    pub fn stopped(&mut self, context: &SelfEventContext) -> Vec<Finding> {
        let Some(k) = &self.identity else {
            return Vec::new();
        };
        let (uid, gid) = own_user();
        let event = Event {
            schema_version: SchemaVersion::V1,
            event_id: EventId::new(),
            timestamp: context.timestamp,
            timestamp_trusted: context.timestamp_trusted,
            source_tag: context.source_tag,
            sensor: SensorInfo {
                name: "koru".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            },
            host: context.host.clone(),
            process: Process {
                pid: k.pid,
                ppid: k.ppid,
                start_time: None,
                exe: Untrusted::new(k.exe.clone()),
                command_line: Untrusted::new(k.command_line.clone()),
                environment: Untrusted::new(Vec::new()),
                user: User { uid, gid },
                lineage: Vec::new(),
            },
            container: Container::default(),
            event_type: EventType::ProcessExited,
            target: Target { exit_code: Some(0), ..Target::default() },
            actor: Actor::unknown(),
            detection: None,
            tags: Tags::default(),
            session_id: None,
            response: None,
        };
        let enriched = self.enrich(&event, Some("stopped"));
        let mut findings = Vec::new();
        for rule in self.rules.rules() {
            if rule.is_evaluated()
                && rule.matches_source(event.event_type, true)
                && rule.matches_pattern(&enriched.fields)
            {
                findings.push(create_finding(rule, &event, &enriched, Actor::unknown()));
            }
        }
        findings
    }

    // -----------------------------------------------------------------------------------------
    // Enrichment
    // -----------------------------------------------------------------------------------------

    /// The first AI-agent signature matched by the process or an ancestor (nearest first).
    fn find_agent(&self, event: &Event) -> Option<AgentInfo> {
        let s = &event.process;
        let own_match = self.agents.match_pattern(s.exe.untrusted_value(), s.command_line.untrusted_value());
        let signature = own_match.or_else(|| {
            s.lineage
                .iter()
                .find_map(|a| self.agents.match_pattern(a.exe.untrusted_value(), a.command_line.untrusted_value()))
        })?;
        Some(AgentInfo { id: signature.id.clone(), name: signature.name.clone(), kind: signature.kind.name() })
    }

    /// Whether inside a container, and (with no id) suspected. Container suspicion: a
    /// different pid namespace, or at least four of the uts, ipc, mount, network, and cgroup
    /// namespaces differ. A mount-only (or few-namespace) difference also comes from systemd
    /// hardening settings (KT-45).
    fn container_state(&self, k: &Container) -> (bool, bool) {
        let has_id = k.id.as_ref().is_some_and(|c| !c.untrusted_value().is_empty());
        let suspected = match (&k.namespaces, &self.host_ns) {
            (Some(s), Some(a)) => {
                let differing = [s.uts != a.uts, s.ipc != a.ipc, s.mnt != a.mnt, s.net != a.net, s.cgroup != a.cgroup]
                    .iter()
                    .filter(|f| **f)
                    .count();
                s.pid != a.pid || differing >= 4
            }
            _ => false,
        };
        (has_id || suspected, !has_id && suspected)
    }

    fn enrich(&self, event: &Event, own_event: Option<&str>) -> Enriched {
        let s = &event.process;
        let exe_normal = normal_or_raw(s.exe.untrusted_value());
        let command = s.command_line.untrusted_value();
        let mut a = FieldSet::new()
            .number("ProcessId", i64::from(s.pid))
            .number("ParentProcessId", i64::from(s.ppid))
            .text("koru.event_type", &event.event_type.to_string());
        if !exe_normal.is_empty() {
            a = a.text("Image", &exe_normal);
        }
        if !command.is_empty() {
            a = a.text("CommandLine", &command.join(" "));
        }
        if let Some(ancestor) = s.lineage.first() {
            if !ancestor.exe.untrusted_value().is_empty() {
                a = a.text("ParentImage", &normal_or_raw(ancestor.exe.untrusted_value()));
            }
            if !ancestor.command_line.untrusted_value().is_empty() {
                a = a.text("ParentCommandLine", &ancestor.command_line.untrusted_value().join(" "));
            }
        }
        if let Some(u) = &event.target.remote {
            a = a.text("DestinationIp", &u.ip.to_string()).number("DestinationPort", i64::from(u.port));
        }
        if let Some(u) = &event.target.local {
            a = a.text("SourceIp", &u.ip.to_string()).number("SourcePort", i64::from(u.port));
        }

        // AI-agent lineage.
        let agent = self.find_agent(event);
        a = a.boolean("koru.ai_agent_ancestor", agent.is_some());
        if let Some(j) = &agent {
            a = a.text("koru.ai_agent", &j.id).text("koru.ai_agent_kind", j.kind);
        }

        // Container.
        let (container, suspected) = self.container_state(&event.container);
        a = a.boolean("koru.container", container).boolean("koru.container_suspected", suspected);

        // File events: target paths, the decoy catalog, protected paths, change.
        let mut modified = false;
        let mut read_access = false;
        let mut decoy = None;
        if let Some(path) = &event.target.path {
            use EventType::{
                DirectoryCreated, DirectoryDeleted, FileCreated, FileDeleted, FileLink, FileOpened, FileRenamed,
            };
            let file_event = matches!(
                event.event_type,
                FileOpened | FileCreated | FileDeleted | FileRenamed | FileLink | DirectoryCreated | DirectoryDeleted
            );
            if file_event {
                use koru_event::FileFlag::{Append, Creat, Rdwr, Trunc, Wronly};
                let primary = normal_or_raw(path.untrusted_value());
                let second = event.target.new_path.as_ref().map(|y| normal_or_raw(y.untrusted_value()));
                modified = match event.event_type {
                    FileOpened => {
                        event.target.flags.iter().any(|b| matches!(b, Wronly | Rdwr | Creat | Trunc | Append))
                    }
                    _ => true,
                };
                // Read capability: O_RDONLY (0; flags may be empty) or O_RDWR. A write-only
                // open (O_WRONLY, e.g. a shell appending to .bash_history) is not a read.
                read_access = event.event_type == FileOpened
                    && (event.target.flags.contains(&Rdwr) || !event.target.flags.contains(&Wronly));
                // In a rename, target is the new name, source the old one; in a link, target
                // is the link, source the path it points to.
                let (target, source) = match (event.event_type, &second) {
                    (FileRenamed, Some(new)) => (new.clone(), Some(primary.clone())),
                    (_, Some(second)) => (primary.clone(), Some(second.clone())),
                    (_, None) => (primary.clone(), None),
                };
                a = a.text("TargetFilename", &target).boolean("koru.modified", modified);
                if let Some(k) = &source {
                    a = a.text("SourceFilename", k);
                }
                let candidates: Vec<&str> = std::iter::once(primary.as_str()).chain(second.as_deref()).collect();
                decoy = candidates.iter().find_map(|y| self.catalog.find(y));
                if let Some(t) = candidates.iter().find_map(|y| self.protected.kind(y)) {
                    a = a.text("koru.protected_kind", t);
                }
            }
        }
        if !a_var(&a, "koru.modified") {
            a = a.boolean("koru.modified", modified);
        }
        a = a.boolean("koru.read", read_access);
        if let Some(t) = &decoy {
            a = a
                .text("koru.decoy_id", &t.decoy_id)
                .text("koru.decoy_class", &t.class)
                .boolean("koru.breadcrumb", t.kind == WatchedPathKind::Breadcrumb);
        }

        // Attempts to stop Koru (in exec events).
        if event.event_type == EventType::ProcessExecuted
            && let Some(d) = self.protected.stopping(&exe_normal, command, self.identity.as_ref())
        {
            a = a.text("koru.stop_attempt", d);
        }
        if let Some(k) = own_event {
            a = a.text("koru.self_event", k);
        }
        Enriched { fields: a, exe_normal, decoy, agent }
    }

    // -----------------------------------------------------------------------------------------
    // Actor-kind estimation
    // -----------------------------------------------------------------------------------------

    /// A summary of one parent process's (session's) command history at event time.
    fn session_summary(&self, upper: u32, now_ns: i128) -> Option<SessionSummary> {
        let o = self.sessions.map.get(&upper)?;
        let a = &self.thresholds.actor;
        let window = |sn: u64| now_ns - i128::from(sn) * 1_000_000_000;
        let machine_window_start = window(a.machine_speed.window_secs);
        let times: Vec<i128> =
            o.commands.iter().filter(|k| k.time_ns >= machine_window_start).map(|k| k.time_ns).collect();
        let intervals: Vec<u64> =
            times.windows(2).map(|w| u64::try_from(((w[1] - w[0]).max(0)) / 1_000_000).unwrap_or(u64::MAX)).collect();
        let median_ms = median(intervals.clone());
        let machine_speed = (intervals.len() >= a.machine_speed.min_intervals as usize
            && median_ms < a.machine_speed.command_interval_median_ms)
            .then_some((median_ms, intervals.len()));
        let human_speed = (intervals.len() >= a.human_speed.min_intervals as usize
            && median_ms > a.human_speed.command_interval_median_ms)
            .then_some((median_ms, intervals.len()));
        let discovery_start = window(a.discovery.window_secs);
        let mut discovery: Vec<String> = o
            .commands
            .iter()
            .filter(|k| k.time_ns >= discovery_start && a.discovery.commands.contains(&k.name))
            .map(|k| k.name.clone())
            .collect();
        discovery.sort();
        discovery.dedup();
        if discovery.len() < a.discovery.min_distinct_commands as usize {
            discovery.clear();
        }
        Some(SessionSummary { machine_speed, human_speed, discovery })
    }

    fn actor_estimate(&self, event: &Event, enriched: &Enriched) -> Actor {
        let a = &self.thresholds.actor;
        let now = event.timestamp.unix_nanos();
        // The process, its parent, or ancestors may have run the commands: sessions are
        // checked near to far, and the first session that can decide by speed (machine or
        // human) is chosen. A distant ancestor's (e.g. a script's) fast commands must not
        // drown out the nearby interactive shell's human-speed commands.
        let mut candidates: Vec<u32> = vec![event.process.pid, event.process.ppid];
        candidates.extend(event.process.lineage.iter().map(|x| x.pid));
        let mut seen = Vec::new();
        let selected = candidates
            .into_iter()
            .filter(|p| {
                *p != 0 && !seen.contains(p) && {
                    seen.push(*p);
                    true
                }
            })
            .filter_map(|p| self.session_summary(p, now))
            .find(|o| o.machine_speed.is_some() || o.human_speed.is_some());
        let machine = selected.as_ref().filter(|o| o.machine_speed.is_some());
        let human = selected.as_ref().and_then(|o| o.human_speed);
        let discovery = machine.map(|m| m.discovery.clone()).unwrap_or_default();

        let s = &event.process;
        let shell = std::iter::once((s.exe.untrusted_value(), s.command_line.untrusted_value()))
            .chain(s.lineage.iter().map(|x| (x.exe.untrusted_value(), x.command_line.untrusted_value())))
            .find_map(|(e, k)| interactive_shell(e, k, &a.shell.names));

        let mut rationale = Vec::new();
        let agent_reason = enriched
            .agent
            .as_ref()
            .map(|j| format!("AI-agent signature: {} ({}; kind {}) in the process lineage", j.id, j.name, j.kind));
        let machine_reason = machine.and_then(|m| m.machine_speed).map(|(ms, n)| {
            format!(
                "machine speed: median of {n} command intervals in the last {} s is {ms} ms (threshold {} ms)",
                a.machine_speed.window_secs, a.machine_speed.command_interval_median_ms
            )
        });
        let discovery_reason = (!discovery.is_empty()).then(|| {
            format!("discovery pattern: {} distinct discovery commands ({})", discovery.len(), discovery.join(", "))
        });
        let shell_reason = shell.as_ref().map(|k| format!("interactive shell: {k} (session shell)"));
        let human_reason = human.map(|(ms, n)| {
            format!(
                "human speed: median of {n} command intervals is {ms} ms (threshold {} ms)",
                a.human_speed.command_interval_median_ms
            )
        });

        let (kind, confidence) = if enriched.agent.is_some() {
            rationale.extend(agent_reason);
            if machine_reason.is_some() {
                rationale.extend(machine_reason);
                (ActorKind::AiAgent, a.agent_signature_and_machine_speed_confidence)
            } else {
                (ActorKind::AiAgent, a.agent_signature_confidence)
            }
        } else if machine_reason.is_some() && discovery_reason.is_some() {
            rationale.extend(machine_reason);
            rationale.extend(discovery_reason);
            (ActorKind::AiAgent, a.machine_speed_and_discovery_confidence)
        } else if shell_reason.is_some() && machine_reason.is_none() {
            rationale.extend(shell_reason);
            if human_reason.is_some() {
                rationale.extend(human_reason);
                (ActorKind::Human, a.interactive_shell_and_human_speed_confidence)
            } else {
                (ActorKind::Human, a.interactive_shell_confidence)
            }
        } else {
            // Undecided: observed signals are still recorded as reasons.
            let in_conflict = machine_reason.is_some() && shell_reason.is_some();
            rationale.extend(machine_reason);
            rationale.extend(discovery_reason);
            if in_conflict {
                rationale.extend(shell_reason);
                rationale.push("signals conflict (machine speed in an interactive shell); kind undecided".to_string());
            }
            (ActorKind::Unknown, 0.0)
        };
        let confidence = Confidence::new(confidence).unwrap_or(Confidence::ZERO);
        Actor { kind, rationale, confidence }
    }
}

fn a_var(a: &FieldSet, name: &str) -> bool {
    a.get(name).is_some()
}

/// Koru's own user (the `/proc/self` owner); (0, 0) if unreadable.
fn own_user() -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map_or((0, 0), |m| (m.uid(), m.gid()))
}

fn create_finding(rule: &Rule, event: &Event, enriched: &Enriched, actor: Actor) -> Finding {
    let mut class = rule.threat_class();
    let mut severity = rule.severity();
    // Decoy access in an AI agent's lineage is "suspected hijacked agent"; breadcrumb
    // access stays a separate (low-priority) signal.
    if class == ThreatClass::DecoyAccess && enriched.agent.is_some() {
        class = ThreatClass::SuspectedHijackedAgent;
        severity = Level::Critical;
    }
    let mut o = event.clone();
    o.event_id = EventId::new();
    o.actor = actor;
    o.detection = Some(Detection {
        rule: rule.name().to_string(),
        decoy_id: enriched.decoy.as_ref().map(|t| t.decoy_id.clone()),
        threat_class: class,
        attack: rule.attack().to_vec(),
    });
    o.tags.mitre_techniques = rule.attack().to_vec();
    Finding { event: o, title: rule.title().to_string(), severity }
}

impl Detector for RuleDetector {
    fn inspect(&mut self, event: &Event) -> Vec<Detection> {
        self.process(event).into_iter().filter_map(|b| b.event.detection).collect()
    }
}
