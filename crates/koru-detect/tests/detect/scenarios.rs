//! Scenarios with a fake sensor: decoys, breadcrumbs,
//! AI-agent lineage, actor kind, allowlist, self-protection, containers, and exe
//! normalization. The rule and signature packages are the repo's real packages
//! (`packages/rules/`, `packages/agents/`).

use std::collections::BTreeSet;
use std::time::Instant;

use koru_detect::{
    FieldSet, FieldValue, FileIdentity, Finding, Level, RuleDetector, SelfEventContext, SelfProtection, parse_allowlist,
};
use koru_event::{
    Actor, ActorKind, Confidence, Container, Detection, Detector, Event, EventType, FileFlag, MitreTechnique,
    Namespaces, NetworkEndpoint, NetworkProtocol, SourceTag, Target, ThreatClass, Untrusted,
};

use crate::common::*;

fn mt(s: &str) -> MitreTechnique {
    MitreTechnique::new(s).unwrap()
}

fn single(b: &[Finding]) -> &Finding {
    assert_eq!(b.len(), 1, "a single finding was expected: {:?}", rule_names(b));
    &b[0]
}

fn detection(b: &Finding) -> &Detection {
    b.event.detection.as_ref().expect("detection is missing from the finding")
}

fn rationale(b: &Finding) -> String {
    b.event.actor.rationale.join(" | ")
}

fn text(a: &FieldSet, name: &str) -> Option<String> {
    match a.get(name) {
        Some(FieldValue::Text(m)) => Some(m.clone()),
        None => None,
        other => panic!("{name} is not text: {other:?}"),
    }
}

fn boolean(a: &FieldSet, name: &str) -> Option<bool> {
    match a.get(name) {
        Some(FieldValue::Bool(m)) => Some(*m),
        None => None,
        other => panic!("{name} is not a boolean: {other:?}"),
    }
}

fn confidence(b: &Finding) -> f64 {
    b.event.actor.confidence.value()
}

// ---------------------------------------------------------------------------------------------
// Decoys and breadcrumbs
// ---------------------------------------------------------------------------------------------

#[test]
fn reading_a_decoy_produces_a_decoy_finding() {
    let source = read_text(&cat(5000, 4999, AWS), AWS, 0);
    let b = findings_of(vec![source.clone()]);
    let b = single(&b);
    let t = detection(b);
    assert_eq!(t.rule, "decoy_credential_file");
    assert_eq!(t.decoy_id.as_deref(), Some("decoy-aws"));
    assert_eq!(t.threat_class, ThreatClass::DecoyAccess);
    assert_eq!(t.attack, vec![mt("T1552.001")]);
    assert_eq!(b.event.tags.mitre_techniques, t.attack);
    assert_eq!(b.severity, Level::High);
    assert_eq!(b.title, "Read of a decoy credential file");
    // A finding is a new event; the source event's process, target, timestamp, and container info are kept.
    assert_ne!(b.event.event_id, source.event_id);
    assert_eq!(b.event.process, source.process);
    assert_eq!(b.event.target, source.target);
    assert_eq!(b.event.timestamp, source.timestamp);
    assert_eq!(b.event.container, source.container);
    assert_eq!(b.event.source_tag, source.source_tag);
    b.event.validate().unwrap();
}

#[test]
fn every_decoy_class_goes_to_its_own_rule() {
    let examples = [
        (AWS, "decoy_credential_file", "decoy-aws"),
        (ENV, "decoy_credential_file", "decoy-env"),
        (LLM_ENV, "decoy_credential_file", "decoy-llm"),
        (MCP, "decoy_credential_file", "decoy-mcp"),
        (SSH_PATH, "decoy_ssh_key", "decoy-ssh"),
        (DUMP, "decoy_database_dump", "decoy-dump"),
        (NOTE, "decoy_ai_note", "decoy-not"),
        (NEW_DECOY, "decoy_report_archive", "decoy-new"),
    ];
    for (path, rule, id) in examples {
        let b = findings_of(vec![read_text(&cat(5000, 4999, path), path, 0)]);
        let b = single(&b);
        assert_eq!(detection(b).rule, rule, "{path}");
        assert_eq!(detection(b).decoy_id.as_deref(), Some(id), "{path}");
        assert_eq!(detection(b).threat_class, ThreatClass::DecoyAccess, "{path}");
    }
}

#[test]
fn a_breadcrumb_is_a_separate_low_priority_signal() {
    let examples = [
        (HISTORY, "breadcrumb_shell_history", vec![mt("T1552.003")]),
        (SSH_CONFIG, "breadcrumb_ssh", vec![mt("T1018")]),
        (KNOWN_HOSTS, "breadcrumb_ssh", vec![mt("T1018")]),
        (NEW_BREADCRUMB, "breadcrumb_general", vec![mt("T1083")]),
    ];
    for (path, rule, attack) in examples {
        let b = findings_of(vec![read_text(&cat(5000, 4999, path), path, 0)]);
        let b = single(&b);
        assert_eq!(detection(b).rule, rule, "{path}");
        assert_eq!(detection(b).threat_class, ThreatClass::BreadcrumbAccess, "{path}");
        assert!(detection(b).decoy_id.is_some());
        assert_eq!(detection(b).attack, attack);
        assert_eq!(b.severity, Level::Low, "{path}");
    }
}

#[test]
fn non_decoy_files_and_other_event_kinds_produce_no_finding() {
    let mut t = a_detector();
    let c = cat(5000, 4999, "/etc/hostname");
    assert!(run(&mut t, vec![read_text(&c, "/etc/hostname", 0)]).is_empty());
    assert!(run(&mut t, vec![read_text(&c, "/home/devops/.aws/config", 0)]).is_empty());
    assert!(run(&mut t, vec![read_text(&c, "/home/devops/.aws/credentials.bak", 0)]).is_empty());
    // Executing a decoy (process_creation) is not a file-access rule matter; opening it is a
    // separate file_opened event.
    let executed = s(5001, 4999, AWS, &[AWS]);
    assert!(run(&mut t, vec![exec(&executed, 0)]).is_empty());
    // A network event.
    let ag = event(
        &c,
        EventType::NetworkConnection,
        Target {
            remote: Some(NetworkEndpoint { ip: "192.0.2.10".parse().unwrap(), port: 22 }),
            protocol: Some(NetworkProtocol::Tcp),
            ..Target::default()
        },
        0,
    );
    assert!(run(&mut t, vec![ag]).is_empty());
}

// ---------------------------------------------------------------------------------------------
// AI-agent lineage and classification
// ---------------------------------------------------------------------------------------------

#[test]
fn decoy_access_in_ai_agent_lineage_is_a_compromised_suspect() {
    let b = findings_of(vec![read_text(&cat_under_claude(5100, SSH_PATH), SSH_PATH, 0)]);
    let b = single(&b);
    assert_eq!(detection(b).rule, "decoy_ssh_key");
    assert_eq!(detection(b).threat_class, ThreatClass::SuspectedHijackedAgent);
    assert_eq!(detection(b).attack, vec![mt("T1552.004")]);
    assert_eq!(b.severity, Level::Critical);
    assert_eq!(b.event.actor.kind, ActorKind::AiAgent);
    assert_eq!(confidence(b), thresholds().actor.agent_signature_confidence);
    assert!(rationale(b).contains("claude-code"), "{}", rationale(b));
    b.event.validate().unwrap();
}

#[test]
fn an_mcp_server_script_reading_a_decoy_is_a_compromised_agent_suspect() {
    let script = s(5200, 5199, "/usr/bin/python3.12", &["python3", "/opt/koru-scenario/mcp-server-notes.py"])
        .lineage(vec![ancestor(5199, "/usr/bin/bash", &["bash", "-c", "python3 mcp-server-notes.py"])]);
    let b = findings_of(vec![read_text(&script, AWS, 0)]);
    let b = single(&b);
    assert_eq!(detection(b).rule, "decoy_credential_file");
    assert_eq!(detection(b).threat_class, ThreatClass::SuspectedHijackedAgent);
    assert_eq!(b.event.actor.kind, ActorKind::AiAgent);
    assert!(rationale(b).contains("mcp-server"), "{}", rationale(b));
}

#[test]
fn an_mcp_servers_child_is_also_a_compromised_agent_suspect() {
    let c = s(5300, 5299, "/usr/bin/cat", &["cat", MCP]).lineage(vec![
        ancestor(
            5299,
            "/usr/bin/node",
            &["node", "/root/.npm/_npx/4f1c/node_modules/.bin/mcp-server-filesystem", "/home"],
        ),
        ancestor(5298, "/usr/bin/node", &["node", "/usr/local/bin/gemini"]),
        ancestor(5297, "/usr/bin/bash", &["-bash"]),
    ]);
    let b = findings_of(vec![read_text(&c, MCP, 0)]);
    let b = single(&b);
    assert_eq!(detection(b).threat_class, ThreatClass::SuspectedHijackedAgent);
    // The nearest ancestor is checked first.
    let a = a_detector().fields(&read_text(&c, MCP, 0));
    assert_eq!(text(&a, "koru.ai_agent").as_deref(), Some("mcp-server"));
    assert_eq!(text(&a, "koru.ai_agent_kind").as_deref(), Some("mcp_server"));
}

#[test]
fn ai_agent_fields() {
    let t = a_detector();
    let a = t.fields(&read_text(&cat_under_claude(5100, AWS), AWS, 0));
    assert_eq!(boolean(&a, "koru.ai_agent_ancestor"), Some(true));
    assert_eq!(text(&a, "koru.ai_agent").as_deref(), Some("claude-code"));
    assert_eq!(text(&a, "koru.ai_agent_kind").as_deref(), Some("coding_assistant"));
    let a = t.fields(&read_text(&cat(5000, 4999, AWS), AWS, 0));
    assert_eq!(boolean(&a, "koru.ai_agent_ancestor"), Some(false));
    assert_eq!(text(&a, "koru.ai_agent"), None);
}

#[test]
fn an_agent_name_as_an_argument_is_not_an_ai_agent() {
    let c = s(5400, 4999, "/usr/bin/cat", &["cat", AWS, "/tmp/claude", "/tmp/mcp-server-x"]).lineage(vec![ancestor(
        4999,
        "/usr/bin/bash",
        &["bash", "-c", "cat claude"],
    )]);
    let b = findings_of(vec![read_text(&c, AWS, 0)]);
    assert_eq!(detection(single(&b)).threat_class, ThreatClass::DecoyAccess);
    assert_ne!(single(&b).event.actor.kind, ActorKind::AiAgent);
}

#[test]
fn a_breadcrumb_stays_in_its_class_even_read_by_an_ai_agent() {
    let b = findings_of(vec![read_text(&cat_under_claude(5100, HISTORY), HISTORY, 0)]);
    let b = single(&b);
    assert_eq!(detection(b).threat_class, ThreatClass::BreadcrumbAccess);
    assert_eq!(b.event.actor.kind, ActorKind::AiAgent);
    assert_eq!(b.severity, Level::Low);
}

// ---------------------------------------------------------------------------------------------
// Actor-kind estimation
// ---------------------------------------------------------------------------------------------

const CLAUDE_EXE: &str = "/home/devops/.local/share/claude/versions/2.1.3";

fn claude_lineage() -> Vec<koru_event::AncestorProcess> {
    vec![
        ancestor(1400, CLAUDE_EXE, &["claude"]),
        ancestor(1300, "/usr/bin/bash", &["-bash"]),
        ancestor(1200, "/usr/sbin/sshd", &["sshd: devops@pts/0"]),
    ]
}

#[test]
fn actor_signature_and_machine_speed() {
    let mut events = Vec::new();
    // The agent runs commands via bash -c every 200 ms (the parent: the agent, pid 1400).
    for (i, ms) in [0, 200, 400, 600, 800].iter().enumerate() {
        let pid = 1501 + i as u32;
        events
            .push(exec(&s(pid, 1400, "/usr/bin/bash", &["/bin/bash", "-c", "ls -la"]).lineage(claude_lineage()), *ms));
    }
    // The last bash -c runs the cat that reads the decoy.
    let mut lineage = vec![ancestor(1505, "/usr/bin/bash", &["/bin/bash", "-c", "cat key"])];
    lineage.extend(claude_lineage());
    let c = s(1506, 1505, "/usr/bin/cat", &["cat", SSH_PATH]).lineage(lineage);
    events.push(exec(&c, 850));
    events.push(read_text(&c, SSH_PATH, 900));
    let b = findings_of(events);
    let b = single(&b);
    assert_eq!(b.event.actor.kind, ActorKind::AiAgent);
    assert_eq!(confidence(b), thresholds().actor.agent_signature_and_machine_speed_confidence);
    assert!(rationale(b).contains("claude-code"), "{}", rationale(b));
    assert!(rationale(b).contains("machine speed"), "{}", rationale(b));
}

/// A signature-less automation (pid 800) runs commands every 150 ms, then reads the decoy.
fn signatureless_automation(commands: &[&str], last_ms: i64) -> Vec<Event> {
    let upper = vec![
        ancestor(800, "/usr/bin/python3.12", &["python3", "/opt/application/task.py"]),
        ancestor(700, "/usr/sbin/cron", &["/usr/sbin/CRON", "-f"]),
    ];
    let mut events = Vec::new();
    for (i, k) in commands.iter().enumerate() {
        let pid = 801 + i as u32;
        events.push(exec(&s(pid, 800, &format!("/usr/bin/{k}"), &[k]).lineage(upper.clone()), 150 * i as i64));
    }
    let c = s(899, 800, "/usr/bin/cat", &["cat", AWS]).lineage(upper);
    events.push(exec(&c, last_ms));
    events.push(read_text(&c, AWS, last_ms + 50));
    events
}

#[test]
fn actor_machine_speed_and_discovery_without_signature() {
    let b = findings_of(signatureless_automation(&["whoami", "id", "uname", "hostname", "ls"], 750));
    let b = single(&b);
    assert_eq!(b.event.actor.kind, ActorKind::AiAgent);
    assert_eq!(confidence(b), thresholds().actor.machine_speed_and_discovery_confidence);
    assert!(rationale(b).contains("machine speed"), "{}", rationale(b));
    assert!(rationale(b).contains("discovery pattern"), "{}", rationale(b));
    // No signature: the class is not raised.
    assert_eq!(detection(b).threat_class, ThreatClass::DecoyAccess);
}

#[test]
fn actor_machine_speed_alone_is_unknown() {
    let b = findings_of(signatureless_automation(&["gcc", "as", "ld", "gcc", "as"], 750));
    let b = single(&b);
    assert_eq!(b.event.actor.kind, ActorKind::Unknown);
    assert_eq!(confidence(b), 0.0);
    assert!(rationale(b).contains("machine speed"), "a rationale must be recorded: {}", rationale(b));
}

#[test]
fn actor_commands_outside_the_window_do_not_count() {
    // Discovery commands ran 400 s ago; the window is 300 s.
    let b = findings_of(signatureless_automation(&["whoami", "id", "uname", "hostname", "ls"], 400_000));
    let b = single(&b);
    assert_eq!(b.event.actor.kind, ActorKind::Unknown);
    assert!(!rationale(b).contains("machine speed"), "{}", rationale(b));
}

/// An SSH session shell (pid 900, "-bash") runs commands at human speed.
fn human_session(uid: u32) -> Vec<Event> {
    let upper =
        vec![ancestor(900, "/usr/bin/bash", &["-bash"]), ancestor(899, "/usr/sbin/sshd", &["sshd: devops@pts/1"])];
    let mut events = Vec::new();
    for (i, (k, ms)) in [("ls", 0), ("id", 4_000), ("df", 9_000)].iter().enumerate() {
        let pid = 901 + i as u32;
        events.push(exec(&s(pid, 900, &format!("/usr/bin/{k}"), &[k]).lineage(upper.clone()).uid(uid), *ms));
    }
    let c = s(904, 900, "/usr/bin/cat", &["cat", AWS]).lineage(upper).uid(uid);
    events.push(exec(&c, 15_000));
    events.push(read_text(&c, AWS, 15_050));
    events
}

#[test]
fn actor_interactive_shell_and_human_speed() {
    let b = findings_of(human_session(1001));
    let b = single(&b);
    assert_eq!(b.event.actor.kind, ActorKind::Human);
    assert_eq!(confidence(b), thresholds().actor.interactive_shell_and_human_speed_confidence);
    assert!(rationale(b).contains("interactive shell"), "{}", rationale(b));
    assert!(rationale(b).contains("human speed"), "{}", rationale(b));
    assert_eq!(detection(b).threat_class, ThreatClass::DecoyAccess);
}

#[test]
fn actor_kt43_uid_does_not_change_the_decision() {
    // Pulsar can show uid 0 for privilege-dropped processes (KT-43): the decision ignores uid.
    let root = findings_of(human_session(0));
    let user = findings_of(human_session(1001));
    let (a, b) = (&single(&root).event.actor, &single(&user).event.actor);
    assert_eq!((a.kind, a.confidence, &a.rationale), (b.kind, b.confidence, &b.rationale));
    assert!(!a.rationale.iter().any(|g| g.contains("uid")), "the rationale must not rest on uid: {:?}", a.rationale);
}

#[test]
fn actor_interactive_shell_without_measurement() {
    for shell in [&["-bash"][..], &["bash", "-i"][..], &["/usr/bin/zsh"][..]] {
        let c = s(950, 949, "/usr/bin/cat", &["cat", AWS])
            .lineage(vec![ancestor(949, "/usr/bin/bash", shell), ancestor(948, "/usr/sbin/sshd", &["sshd: devops"])]);
        let b = findings_of(vec![read_text(&c, AWS, 0)]);
        let b = single(&b);
        assert_eq!(b.event.actor.kind, ActorKind::Human, "{shell:?}");
        assert_eq!(confidence(b), thresholds().actor.interactive_shell_confidence, "{shell:?}");
    }
}

#[test]
fn actor_noninteractive_shell_is_unknown() {
    let b = findings_of(vec![read_text(&cat(5000, 4999, AWS), AWS, 0)]);
    let b = single(&b);
    assert_eq!(b.event.actor.kind, ActorKind::Unknown);
    assert_eq!(confidence(b), 0.0);
}

// ---------------------------------------------------------------------------------------------
// The allowlist and Koru's own process
// ---------------------------------------------------------------------------------------------

fn koru_process(exe: &str) -> S {
    s(KORU_PID, 1, exe, &["koru-agent", "agent"])
}

#[test]
fn korus_own_process_is_excluded_by_pid_exe_and_inode() {
    let mut t = a_detector();
    for exe in [KORU_EXE, "/usr/local/bin/../bin//./koru-agent"] {
        let k = koru_process(exe);
        let events = vec![
            read_text(&k, AWS, 0),
            write_text(&k, "/var/lib/koru/store/events.db", 10),
            write_text(&k, "/var/lib/koru/status/record.json", 20),
            read_text(&k, "/etc/koru/.env", 30),
        ];
        assert!(run(&mut t, events).is_empty(), "{exe}");
    }
}

#[test]
fn same_pid_different_inode_or_exe_is_not_excluded() {
    // Same pid but a different exe identity (e.g. an old event replayed, pid reuse) or the
    // process is gone: no exclusion.
    for source in [FakeIdentity::default().process(KORU_PID, OTHER_FILE), FakeIdentity::default()] {
        let mut t = with_a_detector(settings(), source);
        let b = run(&mut t, vec![read_text(&koru_process(KORU_EXE), AWS, 0)]);
        assert_eq!(rule_names(&b), ["decoy_credential_file"]);
    }
    // Same pid and inode but a different exe path.
    let b = findings_of(vec![read_text(&koru_process("/tmp/koru-agent"), AWS, 0)]);
    assert_eq!(rule_names(&b), ["decoy_credential_file"]);
}

#[test]
fn an_imitated_name_and_command_line_cannot_evade() {
    // The attacker mimics Koru's name and command line; the pid differs.
    let impostor = s(6000, 5999, "/tmp/.x/koru-agent", &["koru-agent", "agent"]);
    assert_eq!(rule_names(&findings_of(vec![read_text(&impostor, AWS, 0)])), ["decoy_credential_file"]);
    // The real binary run a second time (same exe and inode, different pid).
    let second = s(6001, 5999, KORU_EXE, &["koru-agent", "agent"]);
    let mut t = with_a_detector(settings(), identity_source().process(6001, KORU_FILE));
    assert_eq!(rule_names(&run(&mut t, vec![read_text(&second, AWS, 0)])), ["decoy_credential_file"]);
}

const BACKUP: FileIdentity = FileIdentity { device: 64769, inode: 3003 };

fn allow_backed_up(rules: &str) -> (RuleDetector, FakeIdentity) {
    let definition = parse_allowlist(&format!(
        "version = 1\n[[input]]\nexe = \"/usr/local/bin/backup\"\nrules = {rules}\nrationale = \"nightly backup\"\n"
    ))
    .unwrap();
    let source = identity_source()
        .path("/usr/local/bin/backup", BACKUP)
        .process(3000, BACKUP)
        .process(3001, BACKUP)
        .process(3002, OTHER_FILE);
    let mut settings = settings();
    settings.allowlist = definition.resolve(&source, &settings.rules).unwrap();
    assert_eq!(settings.allowlist.len(), 1);
    (with_a_detector(settings, source.clone()), source)
}

#[test]
fn the_allowlist_works_by_exe_path_and_inode() {
    let (mut t, _) = allow_backed_up("[\"decoy_credential_file\"]");
    let read = |t: &mut RuleDetector, pid: u32, exe: &str, target: &str| {
        rule_names(&run(t, vec![read_text(&s(pid, 1, exe, &["backup", "--all_values"]), target, 0)]))
    };
    // Correct path and inode: silenced (normalized path included).
    assert!(read(&mut t, 3000, "/usr/local/bin/backup", AWS).is_empty());
    assert!(read(&mut t, 3000, "/usr/local//bin/./backup", AWS).is_empty());
    // Same inode, different path (hard link or a mimicked name): not silenced.
    assert_eq!(read(&mut t, 3001, "/tmp/backup", AWS), ["decoy_credential_file"]);
    // Correct path, different inode (a replaced binary): not silenced.
    assert_eq!(read(&mut t, 3002, "/usr/local/bin/backup", AWS), ["decoy_credential_file"]);
    // Correct path, process gone (identity unreadable): not silenced.
    assert_eq!(read(&mut t, 3003, "/usr/local/bin/backup", AWS), ["decoy_credential_file"]);
    // A rule outside the allowlisted set: not silenced.
    assert_eq!(read(&mut t, 3000, "/usr/local/bin/backup", SSH_PATH), ["decoy_ssh_key"]);
}

#[test]
fn the_allowlist_cannot_silence_self_protection() {
    let (mut t, _) = allow_backed_up("[]");
    let y = s(3000, 1, "/usr/local/bin/backup", &["backup"]);
    // An empty rule list: all rules except self-protection.
    assert!(run(&mut t, vec![read_text(&y, AWS, 0), read_text(&y, SSH_PATH, 1), read_text(&y, HISTORY, 2)]).is_empty());
    assert_eq!(rule_names(&run(&mut t, vec![write_text(&y, "/etc/koru/koru.toml", 3)])), ["koru_config_modified"]);
    assert_eq!(rule_names(&run(&mut t, vec![read_text(&y, "/etc/koru/.env", 4)])), ["koru_secret_read"]);
    assert_eq!(rule_names(&run(&mut t, vec![write_text(&y, AWS, 5)])), ["koru_decoy_modified"]);
    // The self-protection rule cannot be listed.
    let definition = parse_allowlist(
        "version = 1\n[[input]]\nexe = \"/usr/local/bin/backup\"\nrules = [\"koru_config_modified\"]\nrationale = \"x\"\n",
    )
    .unwrap();
    let source = identity_source().path("/usr/local/bin/backup", BACKUP);
    assert!(definition.resolve(&source, &rules()).is_err());
}

#[test]
fn the_allowlist_cannot_rest_on_a_name_or_command_line() {
    let invalid = [
        ("name only", "version = 1\n[[input]]\nname = \"backup\"\nrationale = \"x\"\n"),
        (
            "a command line",
            "version = 1\n[[input]]\nexe = \"/usr/local/bin/backup\"\ncommand_line = \"backup --all_values\"\nrationale = \"x\"\n",
        ),
        ("a user", "version = 1\n[[input]]\nexe = \"/usr/local/bin/backup\"\nuid = 0\nrationale = \"x\"\n"),
        ("a relative exe", "version = 1\n[[input]]\nexe = \"backup\"\nrationale = \"x\"\n"),
        ("wildcard exe", "version = 1\n[[input]]\nexe = \"/usr/local/bin/*\"\nrationale = \"x\"\n"),
        ("an unnormalized exe", "version = 1\n[[input]]\nexe = \"/usr/local/bin/../bin/backup\"\nrationale = \"x\"\n"),
        ("no rationale", "version = 1\n[[input]]\nexe = \"/usr/local/bin/backup\"\n"),
        ("an empty rationale", "version = 1\n[[input]]\nexe = \"/usr/local/bin/backup\"\nrationale = \" \"\n"),
        ("version", "version = 2\n[[input]]\nexe = \"/usr/local/bin/backup\"\nrationale = \"x\"\n"),
    ];
    for (name, text) in invalid {
        assert!(parse_allowlist(text).is_err(), "{name}: was accepted");
    }
    let source = identity_source().path("/usr/local/bin/backup", BACKUP);
    let definition = parse_allowlist(
        "version = 1\n[[input]]\nexe = \"/usr/local/bin/backup\"\nrules = [\"no_such_rule\"]\nrationale = \"x\"\n",
    )
    .unwrap();
    assert!(definition.resolve(&source, &rules()).is_err(), "an undefined rule");
    let definition =
        parse_allowlist("version = 1\n[[input]]\nexe = \"/usr/bin/nonexistent\"\nrationale = \"x\"\n").unwrap();
    assert!(definition.resolve(&source, &rules()).is_err(), "file is missing: inode cannot be read");
    let empty = parse_allowlist("version = 1\n").unwrap();
    assert!(empty.resolve(&source, &rules()).unwrap().is_empty());
}

// ---------------------------------------------------------------------------------------------
// Self-protection
// ---------------------------------------------------------------------------------------------

fn vim() -> S {
    s(3100, 3099, "/usr/bin/vim", &["vim"]).lineage(vec![ancestor(3099, "/usr/bin/bash", &["-bash"])])
}

fn single_rule(event: Event) -> Option<String> {
    let b = findings_of(vec![event]);
    assert!(b.len() <= 1, "at most one finding was expected: {:?}", rule_names(&b));
    b.first().map(|b| detection(b).rule.clone())
}

#[test]
fn config_and_secret_value_files() {
    assert_eq!(single_rule(write_text(&vim(), "/etc/koru/koru.toml", 0)).as_deref(), Some("koru_config_modified"));
    assert_eq!(
        single_rule(read_text(&vim(), "/etc/koru/koru.toml", 0)),
        None,
        "reading the configuration is not a finding"
    );
    assert_eq!(single_rule(read_text(&vim(), "/etc/koru/.env", 0)).as_deref(), Some("koru_secret_read"));
    assert_eq!(single_rule(write_text(&vim(), "/etc/koru/.env", 0)).as_deref(), Some("koru_config_modified"));
    assert_eq!(single_rule(file_deletion(&vim(), "/etc/koru/koru.toml", 0)).as_deref(), Some("koru_config_modified"));
    let b = findings_of(vec![write_text(&vim(), "/etc/koru/koru.toml", 0)]);
    let b = single(&b);
    assert_eq!(detection(b).threat_class, ThreatClass::SelfProtection);
    assert_eq!(detection(b).attack, vec![mt("T1685")]);
    assert_eq!(detection(b).decoy_id, None);
    b.event.validate().unwrap();
}

#[test]
fn store_state_binary_and_service_unit_change() {
    let v = vim();
    let examples: Vec<(Event, Option<&str>)> = vec![
        (file_deletion(&v, "/var/lib/koru/store/events.db", 0), Some("koru_store_modified")),
        (write_text(&v, "/var/lib/koru/store/events.db-wal", 0), Some("koru_store_modified")),
        (file_rename(&v, "/tmp/fake.json", "/var/lib/koru/status/record.json", 0), Some("koru_store_modified")),
        (process_creation(&v, "/var/lib/koru/status/new", 0), Some("koru_store_modified")),
        (read_text(&v, "/var/lib/koru/store/events.db", 0), None),
        (write_text(&v, KORU_EXE, 0), Some("koru_binary_modified")),
        (file_rename(&v, "/tmp/bad", KORU_EXE, 0), Some("koru_binary_modified")),
        (
            process_creation(&v, "/etc/systemd/system/koru.service.d/override.conf", 0),
            Some("koru_service_unit_modified"),
        ),
        (write_text(&v, "/etc/systemd/system/koru.service", 0), Some("koru_service_unit_modified")),
        (write_text(&v, "/etc/systemd/system/nginx.service", 0), None),
    ];
    for (event, expected) in examples {
        let description = format!("{:?} {:?}", event.event_type, event.target.path);
        assert_eq!(single_rule(event).as_deref(), expected, "{description}");
    }
    let b = findings_of(vec![file_deletion(&v, "/var/lib/koru/store/events.db", 0)]);
    assert_eq!(detection(single(&b)).attack, vec![mt("T1070"), mt("T1565.001")]);
    let b = findings_of(vec![write_text(&v, KORU_EXE, 0)]);
    assert_eq!(single(&b).severity, Level::Critical);
}

#[test]
fn a_decoy_change_is_a_self_protection_finding() {
    let v = vim();
    assert_eq!(single_rule(write_text(&v, AWS, 0)).as_deref(), Some("koru_decoy_modified"));
    // Hardening (KT-58): O_RDWR also reads, so it produces two findings.
    let mut rdwr = rule_names(&findings_of(vec![open_file(&v, AWS, &[FileFlag::Rdwr], 0)]));
    rdwr.sort();
    assert_eq!(rdwr, ["decoy_credential_file", "koru_decoy_modified"]);
    assert_eq!(single_rule(file_deletion(&v, SSH_PATH, 0)).as_deref(), Some("koru_decoy_modified"));
    assert_eq!(single_rule(file_rename(&v, NOTE, "/tmp/not", 0)).as_deref(), Some("koru_decoy_modified"));
    let b = findings_of(vec![write_text(&v, AWS, 0)]);
    assert_eq!(detection(single(&b)).decoy_id.as_deref(), Some("decoy-aws"));
    assert_eq!(detection(single(&b)).threat_class, ThreatClass::SelfProtection);
    // A shell appending to its history file (a breadcrumb): legitimate, not a finding.
    let shell = s(3200, 3199, "/usr/bin/bash", &["-bash"]);
    assert_eq!(single_rule(open_file(&shell, HISTORY, &[FileFlag::Wronly, FileFlag::Append], 0)), None);
}

#[test]
fn path_tricks_are_caught_by_normalization() {
    let v = vim();
    assert_eq!(single_rule(write_text(&v, "/etc/koru/../koru/koru.toml", 0)).as_deref(), Some("koru_config_modified"));
    assert_eq!(single_rule(write_text(&v, "/etc//koru/./koru.toml", 0)).as_deref(), Some("koru_config_modified"));
    assert_eq!(
        single_rule(write_text(&v, "/etc/koru-backup/koru.toml", 0)),
        None,
        "the prefix must end at a directory boundary"
    );
    assert_eq!(single_rule(read_text(&v, "/etc//koru/./.env", 0)).as_deref(), Some("koru_secret_read"));
    let b = findings_of(vec![read_text(&cat(5000, 4999, AWS), "/home/devops/./.aws//credentials", 0)]);
    assert_eq!(detection(single(&b)).decoy_id.as_deref(), Some("decoy-aws"));
}

#[test]
fn service_stop_attempts() {
    let examples: &[(&str, &[&str], bool)] = &[
        ("/usr/bin/systemctl", &["systemctl", "stop", "koru"], true),
        ("/usr/bin/systemctl", &["systemctl", "stop", "koru.service"], true),
        ("/usr/bin/systemctl", &["systemctl", "--no-block", "stop", "koru.service"], true),
        ("/usr/bin/systemctl", &["systemctl", "disable", "--now", "koru"], true),
        ("/usr/bin/systemctl", &["systemctl", "mask", "koru.service"], true),
        ("/usr/bin/systemctl", &["systemctl", "kill", "koru"], true),
        ("/usr/bin/systemctl", &["systemctl", "restart", "koru"], true),
        ("/usr/bin/systemctl", &["systemctl", "stop", "nginx", "koru"], true),
        ("/usr/bin/systemctl", &["systemctl", "stop", "kor*"], true),
        ("/usr/sbin/service", &["service", "koru", "stop"], true),
        ("/usr/bin/systemctl", &["systemctl", "status", "koru"], false),
        ("/usr/bin/systemctl", &["systemctl", "start", "koru"], false),
        ("/usr/bin/systemctl", &["systemctl", "stop", "nginx"], false),
        ("/usr/bin/systemctl", &["systemctl", "restart", "nginx.service"], false),
        ("/usr/bin/systemctl", &["systemctl", "stop", "protected-backup"], false),
        ("/usr/sbin/service", &["service", "nginx", "stop"], false),
        ("/usr/sbin/service", &["service", "koru", "status"], false),
        ("/usr/bin/echo", &["echo", "systemctl", "stop", "koru"], false),
    ];
    for (exe, command, expected) in examples {
        let p = s(7000, 6999, exe, command).lineage(vec![ancestor(6999, "/usr/bin/bash", &["-bash"])]);
        let outcome = single_rule(exec(&p, 0));
        let expected_rule = expected.then_some("koru_service_stop");
        assert_eq!(outcome.as_deref(), expected_rule, "{command:?}");
    }
    let p = s(7000, 6999, "/usr/bin/systemctl", &["systemctl", "stop", "koru"]);
    let b = findings_of(vec![exec(&p, 0)]);
    assert_eq!(detection(single(&b)).attack, vec![mt("T1489"), mt("T1685")]);
    assert_eq!(detection(single(&b)).threat_class, ThreatClass::SelfProtection);
}

#[test]
fn process_kill_attempts() {
    let examples: &[(&str, &[&str], bool)] = &[
        ("/usr/bin/kill", &["kill", "-TERM", "4242"], true),
        ("/usr/bin/kill", &["kill", "-9", "4242"], true),
        ("/usr/bin/kill", &["kill", "-s", "KILL", "4242"], true),
        ("/usr/bin/kill", &["/bin/kill", "4242"], true),
        ("/usr/bin/pkill", &["pkill", "koru-agent"], true),
        ("/usr/bin/pkill", &["pkill", "-f", "koru"], true),
        ("/usr/bin/pkill", &["pkill", "-9", "koru"], true),
        ("/usr/bin/killall", &["killall", "koru-agent"], true),
        ("/usr/bin/killall", &["killall", "-9", "/usr/local/bin/koru-agent"], true),
        ("/usr/bin/busybox", &["kill", "4242"], true),
        ("/usr/bin/kill", &["kill", "1234"], false),
        ("/usr/bin/kill", &["kill", "-l"], false),
        ("/usr/bin/kill", &["kill", "-9", "42420"], false),
        ("/usr/bin/pkill", &["pkill", "nginx"], false),
        ("/usr/bin/killall", &["killall", "sshd"], false),
        ("/usr/bin/cat", &["cat", "4242"], false),
    ];
    for (exe, command, expected) in examples {
        let p = s(7100, 6999, exe, command).lineage(vec![ancestor(6999, "/usr/bin/bash", &["-bash"])]);
        let outcome = single_rule(exec(&p, 0));
        assert_eq!(outcome.as_deref(), expected.then_some("koru_process_kill"), "{command:?}");
    }
}

fn make_context() -> SelfEventContext {
    SelfEventContext {
        timestamp: time_ms(60_000),
        timestamp_trusted: true,
        source_tag: SourceTag::Synthetic,
        host: "koru-lab".to_string(),
    }
}

#[test]
fn the_stopped_event_is_a_self_protection_finding() {
    let mut t = a_detector();
    let b = t.stopped(&make_context());
    let b = single(&b);
    assert_eq!(detection(b).rule, "koru_stopped");
    assert_eq!(detection(b).threat_class, ThreatClass::SelfProtection);
    assert_eq!(detection(b).attack, vec![mt("T1489"), mt("T1685")]);
    assert_eq!(b.event.event_type, EventType::ProcessExited);
    assert!(b.event.target.exit_code.is_some());
    assert_eq!(b.event.process.pid, KORU_PID);
    assert_eq!(b.event.process.exe.untrusted_value(), KORU_EXE);
    assert_eq!(b.event.sensor.name, "koru");
    assert_eq!(b.event.timestamp, make_context().timestamp);
    assert_eq!(b.event.source_tag, SourceTag::Synthetic);
    assert_eq!(b.event.host, "koru-lab");
    b.event.validate().unwrap();
    // Without Koru's identity, no event is produced.
    let mut settings = settings();
    settings.identity = None;
    assert!(with_a_detector(settings, identity_source()).stopped(&make_context()).is_empty());
}

#[test]
fn a_sensor_event_cannot_carry_the_self_event_field() {
    // No sensor event counts as "stopped"; an attacker cannot fake it.
    let t = a_detector();
    let events = vec![
        event(&koru_process(KORU_EXE), EventType::ProcessExited, Target { exit_code: Some(0), ..Target::default() }, 0),
        read_text(&cat(5000, 4999, AWS), AWS, 0),
    ];
    for o in &events {
        assert_eq!(t.fields(o).get("koru.self_event"), None);
    }
}

// ---------------------------------------------------------------------------------------------
// Container
// ---------------------------------------------------------------------------------------------

fn with_container_id() -> Container {
    Container {
        id: Some(Untrusted::new("4f1c2d3e5a6b".to_string())),
        name: Some(Untrusted::new("web".to_string())),
        image: Some(Untrusted::new("docker.io/library/alpine:3.22".to_string())),
        image_digest: None,
        namespaces: Some(container_ns()),
    }
}

#[test]
fn decoy_access_inside_a_container_is_caught() {
    let c = s(8000, 7999, "/bin/cat", &["cat", AWS]).container(with_container_id());
    let source = read_text(&c, AWS, 0);
    let b = findings_of(vec![source.clone()]);
    let b = single(&b);
    assert_eq!(detection(b).rule, "decoy_credential_file");
    assert_eq!(b.event.container, source.container);
    let a = a_detector().fields(&source);
    assert_eq!(boolean(&a, "koru.container"), Some(true));
    assert_eq!(boolean(&a, "koru.container_suspected"), Some(false));
}

#[test]
fn without_a_container_id_a_namespace_gap_is_suspicion() {
    // KT-45: main's Pulsar cannot read podman's SQLite container identity; namespaces are present.
    let k = Container { namespaces: Some(container_ns()), ..Container::default() };
    let source = read_text(&s(8100, 8099, "/bin/cat", &["cat", AWS]).container(k), AWS, 0);
    assert_eq!(rule_names(&findings_of(vec![source.clone()])), ["decoy_credential_file"]);
    let a = a_detector().fields(&source);
    assert_eq!(boolean(&a, "koru.container"), Some(true));
    assert_eq!(boolean(&a, "koru.container_suspected"), Some(true));
}

#[test]
fn a_mount_only_namespace_gap_is_not_a_container() {
    // systemd settings like PrivateTmp/ProtectSystem split only the mount namespace.
    let ns = Namespaces { mnt: 4026532500, ..host_namespaces() };
    let t = a_detector();
    for k in [Container { namespaces: Some(ns), ..Container::default() }, Container::default()] {
        let a = t.fields(&read_text(&s(8200, 8199, "/usr/sbin/nginx", &["nginx"]).container(k), AWS, 0));
        assert_eq!(boolean(&a, "koru.container"), Some(false));
        assert_eq!(boolean(&a, "koru.container_suspected"), Some(false));
    }
}

// ---------------------------------------------------------------------------------------------
// Fields and exe normalization
// ---------------------------------------------------------------------------------------------

#[test]
fn fields_and_path_normalization() {
    let t = a_detector();
    let c = s(5000, 4999, "/usr/bin/../bin//./cat", &["cat", "/home/devops/./.aws//credentials"])
        .lineage(vec![ancestor(4999, "/usr//bin/bash", &["bash", "-c", "x"])]);
    let a = t.fields(&read_text(&c, "/home/devops/./.aws//credentials", 0));
    assert_eq!(text(&a, "Image").as_deref(), Some("/usr/bin/cat"));
    assert_eq!(text(&a, "ParentImage").as_deref(), Some("/usr/bin/bash"));
    assert_eq!(text(&a, "TargetFilename").as_deref(), Some(AWS));
    assert_eq!(text(&a, "CommandLine").as_deref(), Some("cat /home/devops/./.aws//credentials"));
    assert_eq!(text(&a, "ParentCommandLine").as_deref(), Some("bash -c x"));
    assert_eq!(a.get("ProcessId"), Some(&FieldValue::Number(5000)));
    assert_eq!(a.get("ParentProcessId"), Some(&FieldValue::Number(4999)));
    assert_eq!(text(&a, "koru.event_type").as_deref(), Some("file_opened"));
    assert_eq!(text(&a, "koru.decoy_id").as_deref(), Some("decoy-aws"));
    assert_eq!(text(&a, "koru.decoy_class").as_deref(), Some("cloud_credentials"));
    assert_eq!(boolean(&a, "koru.breadcrumb"), Some(false));
    assert_eq!(boolean(&a, "koru.modified"), Some(false));
    assert_eq!(text(&a, "koru.protected_kind"), None);
    assert_eq!(text(&a, "koru.stop_attempt"), None);
    let a = t.fields(&write_text(&c, "/var/lib/koru/status/record.json", 0));
    assert_eq!(boolean(&a, "koru.modified"), Some(true));
    assert_eq!(text(&a, "koru.protected_kind").as_deref(), Some("state"));
    assert_eq!(text(&a, "koru.decoy_id"), None);
    let a = t.fields(&read_text(&c, HISTORY, 0));
    assert_eq!(boolean(&a, "koru.breadcrumb"), Some(true));
    let a = t.fields(&file_rename(&c, "/tmp/a", "/tmp/b", 0));
    assert_eq!(text(&a, "SourceFilename").as_deref(), Some("/tmp/a"));
    assert_eq!(text(&a, "TargetFilename").as_deref(), Some("/tmp/b"));
    let p = s(7000, 6999, "/usr/bin/systemctl", &["systemctl", "stop", "koru"]);
    assert_eq!(text(&t.fields(&exec(&p, 0)), "koru.stop_attempt").as_deref(), Some("service"));
    let p = s(7000, 6999, "/usr/bin/pkill", &["pkill", "koru-agent"]);
    assert_eq!(text(&t.fields(&exec(&p, 0)), "koru.stop_attempt").as_deref(), Some("process"));
    // Boolean derived fields appear on every file event (absence must not read as false).
    let a = t.fields(&read_text(&c, "/etc/hostname", 0));
    for name in ["koru.ai_agent_ancestor", "koru.modified", "koru.container", "koru.container_suspected"] {
        assert_eq!(boolean(&a, name), Some(false), "{name}");
        assert!(koru_detect::SUPPORTED_FIELDS.contains(&name), "{name}");
    }
    assert_eq!(boolean(&a, "koru.breadcrumb"), None, "no breadcrumb field on a non-decoy path");
}

#[test]
fn settings_validation() {
    let mut s = settings();
    s.self_protection = SelfProtection { config: vec!["etc/koru".to_string()], ..self_protection_settings() };
    assert!(RuleDetector::new(s, Box::new(decoy_catalog()), Box::new(identity_source())).is_err(), "a relative path");
    let mut s = settings();
    s.self_protection = SelfProtection { service_names: vec![String::new()], ..self_protection_settings() };
    assert!(
        RuleDetector::new(s, Box::new(decoy_catalog()), Box::new(identity_source())).is_err(),
        "an empty service name"
    );
}

// ---------------------------------------------------------------------------------------------
// The finding shape (event schema v1) and the Detector interface
// ---------------------------------------------------------------------------------------------

#[test]
fn findings_fit_the_event_schema_v1() {
    let mut t = a_detector();
    let v = vim();
    let events = vec![
        read_text(&cat(5000, 4999, AWS), AWS, 0),
        read_text(&cat(5001, 4999, HISTORY), HISTORY, 10),
        read_text(&cat_under_claude(5100, SSH_PATH), SSH_PATH, 20),
        write_text(&v, "/etc/koru/koru.toml", 30),
        exec(&s(7000, 6999, "/usr/bin/systemctl", &["systemctl", "stop", "koru"]), 40),
    ];
    let mut all_values = run(&mut t, events);
    all_values.extend(t.stopped(&make_context()));
    assert_eq!(all_values.len(), 6, "{:?}", rule_names(&all_values));
    let mut ids = BTreeSet::new();
    for b in &all_values {
        b.event.validate().unwrap_or_else(|e| panic!("{:?}: {e}", detection(b).rule));
        let json = serde_json::to_string(&b.event).unwrap();
        let fed_back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(fed_back, b.event);
        let t = detection(b);
        assert!(!t.attack.is_empty());
        assert_eq!(b.event.tags.mitre_techniques, t.attack);
        assert!(!b.event.tags.verified);
        if b.event.actor.kind != ActorKind::Unknown {
            assert!(!b.event.actor.rationale.is_empty());
        }
        assert!(b.event.session_id.is_none() && b.event.response.is_none());
        assert!(ids.insert(b.event.event_id), "event ids must be unique");
        assert!(!b.title.is_empty());
    }
}

#[test]
fn the_detector_trait_yields_detections() {
    let mut t = a_detector();
    let event = read_text(&cat(5000, 4999, AWS), AWS, 0);
    let detections = Detector::inspect(&mut t, &event);
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].rule, "decoy_credential_file");
    assert_eq!(detections[0].decoy_id.as_deref(), Some("decoy-aws"));
}

#[test]
fn an_event_failing_schema_validation_is_skipped() {
    let mut invalid = read_text(&cat(5000, 4999, AWS), AWS, 0);
    invalid.process.pid = 0;
    assert!(findings_of(vec![invalid]).is_empty());
    let mut unjustified = read_text(&cat(5000, 4999, AWS), AWS, 0);
    unjustified.actor =
        Actor { kind: ActorKind::Human, rationale: Vec::new(), confidence: Confidence::new(0.5).unwrap() };
    assert!(findings_of(vec![unjustified]).is_empty());
}

// ---------------------------------------------------------------------------------------------
// Feedback (KT-30) and memory bounds (KT-31; thresholds.toml [memory])
// ---------------------------------------------------------------------------------------------

#[test]
fn finding_events_are_not_reprocessed_kt30() {
    // A finding event fed back into the sensor stream (bus feedback) produces no new finding; no loop.
    let mut t = a_detector();
    let first =
        run(&mut t, vec![read_text(&cat(5000, 4999, AWS), AWS, 0), write_text(&vim(), "/etc/koru/koru.toml", 10)]);
    assert_eq!(rule_names(&first), ["decoy_credential_file", "koru_config_modified"]);
    let mut fed_back: Vec<Event> = first.into_iter().map(|b| b.event).collect();
    fed_back.extend(t.stopped(&make_context()).into_iter().map(|b| b.event));
    assert_eq!(fed_back.len(), 3);
    assert!(fed_back.iter().all(|o| o.detection.is_some()));
    assert!(run(&mut t, fed_back).is_empty(), "finding events must not be reprocessed");
}

fn automation_parent() -> Vec<koru_event::AncestorProcess> {
    vec![
        ancestor(800, "/usr/bin/python3.12", &["python3", "/opt/application/task.py"]),
        ancestor(700, "/usr/sbin/cron", &["/usr/sbin/CRON", "-f"]),
    ]
}

/// A signature-less automation (parent 800) runs 5 discovery commands at 150 ms intervals;
/// then `count` distinct parents each run one command (an event flood); last, the automation's
/// child reads the decoy.
fn finding_after_a_flood(count: u32) -> Finding {
    let upper = automation_parent();
    let mut events = Vec::new();
    for (i, k) in ["whoami", "id", "uname", "hostname", "ls"].iter().enumerate() {
        events
            .push(exec(&s(801 + i as u32, 800, &format!("/usr/bin/{k}"), &[k]).lineage(upper.clone()), 150 * i as i64));
    }
    for j in 0..count {
        let ancestor_pid = 100_000 + j;
        let lineage = vec![ancestor(ancestor_pid, "/usr/bin/bash", &["-bash"])];
        // Every 50 events in the same millisecond: the flood is after the session's command times and inside the window.
        events.push(exec(
            &s(200_000 + j, ancestor_pid, "/usr/bin/ls", &["ls"]).lineage(lineage),
            600 + i64::from(j / 50),
        ));
    }
    let c = s(899, 800, "/usr/bin/cat", &["cat", AWS]).lineage(upper);
    events.push(exec(&c, 750));
    events.push(read_text(&c, AWS, 800));
    let b = findings_of(events);
    assert_eq!(b.len(), 1, "a single finding was expected: {:?}", rule_names(&b));
    b.into_iter().next().unwrap()
}

#[test]
fn tracked_sessions_are_bounded_oldest_drops() {
    let limit = thresholds().memory.max_sessions as u32;
    // Control: a flood far below the limit does not erase the session's command history.
    let b = finding_after_a_flood(100);
    assert!(rationale(&b).contains("machine speed"), "{}", rationale(&b));
    // A flood past the limit drops the oldest session: memory stays bounded (KT-31); decoy
    // access still produces a finding, only the actor estimate loses its history.
    let b = finding_after_a_flood(limit + 100);
    assert_eq!(detection(&b).rule, "decoy_credential_file");
    assert_eq!(b.event.actor.kind, ActorKind::Unknown);
    assert!(!rationale(&b).contains("machine speed"), "{}", rationale(&b));
}

#[test]
fn a_command_flood_in_one_session_is_fast_and_bounded() {
    // One parent runs 20 000 commands within a few hundred milliseconds; all inside the window.
    // The command history must be capped per session: an unbounded history inflates both
    // memory and per-event work (KT-31).
    let upper = automation_parent();
    let mut events = Vec::new();
    for i in 0..20_000u32 {
        let c = s(10_000 + i, 800, "/usr/bin/gcc", &["gcc"]).lineage(upper.clone());
        events.push(exec(&c, i64::from(i / 100)));
    }
    let c = s(899, 800, "/usr/bin/cat", &["cat", AWS]).lineage(upper);
    events.push(exec(&c, 250));
    events.push(read_text(&c, AWS, 300));
    let start = Instant::now();
    let b = findings_of(events);
    assert!(start.elapsed().as_secs() < 30, "the event flood was processed too slowly: {:?}", start.elapsed());
    let b = single(&b);
    assert_eq!(detection(b).rule, "decoy_credential_file");
    assert_eq!(b.event.actor.kind, ActorKind::Unknown, "no signature and no discovery pattern");
    assert!(rationale(b).contains("machine speed"), "{}", rationale(b));
}
