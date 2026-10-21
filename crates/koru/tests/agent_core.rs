//! The agent's core loop (ADR-0003 §7, ADR-0008): sensor events pass through the detector, finding
//! events are written to the store and notified; when the sensor stops (the Pulsar agent returns on SIGTERM)
//! Koru emits the "stopped" event. The notification network never waits for event processing. The tests use a fake
//! sensor, a fake notify channel and a local fake server; no real network or eBPF.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use koru::agent::{Agent, AgentSettings, BackgroundNotifier, build_notification, run};
use koru_detect::{
    Allowlist, DetectorSettings, FileIdentity, IdentitySource, KoruIdentity, RuleDetector, read_agent_signatures,
    read_rule_pack, read_thresholds,
};
use koru_event::{
    DecoyCatalog, Event, InterfaceError, Notification, NotificationChannel, Sensor, SensorInfo, Severity, SourceTag,
    WatchedPath, WatchedPathKind,
};
use koru_notify::{ChannelSettings, Dispatcher, HealthchecksHeartbeat, HeartbeatLoop, HttpsAddress};
use koru_pulsar::{TranslationCounters, TranslationError, count_translation};
use koru_store::{Store, StoreSettings};
use serde_json::{Value, json};

const AWS: &str = "/home/devops/.aws/credentials";
const KORU_PID: u32 = 4242;
const KORU_EXE: &str = "/usr/libexec/system-observer/versions/1.0.0/system-observer";

fn store_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// ---------------------------------------------------------------------------------------------
// Fake components
// ---------------------------------------------------------------------------------------------

struct FakeSensor {
    events: Vec<Event>,
    result: Result<(), InterfaceError>,
}

impl Sensor for FakeSensor {
    fn info(&self) -> SensorInfo {
        SensorInfo { name: "pulsar".into(), version: "0.11.0-alpha.1".into(), platform: "linux-aarch64".into() }
    }

    fn run(&mut self, receiver: &mut dyn FnMut(Event)) -> Result<(), InterfaceError> {
        for o in self.events.drain(..) {
            receiver(o);
        }
        self.result.clone()
    }
}

struct FakeCatalog;

impl DecoyCatalog for FakeCatalog {
    fn watched_paths(&self) -> Vec<WatchedPath> {
        vec![WatchedPath {
            path: AWS.into(),
            decoy_id: "decoy-aws".into(),
            kind: WatchedPathKind::Decoy,
            class: "cloud_credentials".into(),
        }]
    }

    fn find(&self, path: &str) -> Option<WatchedPath> {
        self.watched_paths().into_iter().find(|y| y.path == path)
    }
}

struct FakeIdentity;

impl IdentitySource for FakeIdentity {
    fn process_exe_id(&self, pid: u32) -> Option<FileIdentity> {
        (pid == KORU_PID).then_some(FileIdentity { device: 1, inode: 1 })
    }

    fn path_id(&self, _path: &str) -> Option<FileIdentity> {
        None
    }
}

fn detector() -> RuleDetector {
    let root = store_root();
    let config =
        koru::config::Config::defaults(koru::config::DEFAULT_NAME, SourceTag::Synthetic, Path::new("/root")).unwrap();
    let settings = DetectorSettings {
        rules: read_rule_pack(&root.join("packages/rules")).unwrap(),
        agents: read_agent_signatures(&root.join("packages/agents")).unwrap(),
        thresholds: read_thresholds(&root.join("thresholds.toml")).unwrap(),
        allowlist: Allowlist::empty(),
        self_protection: config.self_protection(),
        identity: Some(KoruIdentity {
            pid: KORU_PID,
            ppid: 1,
            exe: KORU_EXE.to_string(),
            command_line: vec![KORU_EXE.to_string(), "--config".to_string()],
            file: FileIdentity { device: 1, inode: 1 },
        }),
        host_namespaces: None,
    };
    RuleDetector::new(settings, Box::new(FakeCatalog), Box::new(FakeIdentity)).unwrap()
}

/// Collects sent notifications; with an optional delay (a slow network simulation).
#[derive(Clone)]
struct Collector {
    received: Arc<Mutex<Vec<Notification>>>,
    delay: Duration,
}

impl NotificationChannel for Collector {
    fn name(&self) -> &str {
        "fake"
    }

    fn send(&mut self, b: &Notification) -> Result<(), InterfaceError> {
        std::thread::sleep(self.delay);
        self.received.lock().unwrap().push(b.clone());
        Ok(())
    }
}

fn make_dispatcher(t: &tempfile::TempDir, collector: &Collector) -> Dispatcher {
    let mut d = Dispatcher::new(std::fs::canonicalize(t.path()).unwrap().join("queue"));
    d.add_channel(Box::new(collector.clone()), ChannelSettings::default(), 0).unwrap();
    d
}

fn open_store(t: &tempfile::TempDir) -> Store {
    let dir = std::fs::canonicalize(t.path()).unwrap().join("store");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    Store::open(StoreSettings::new(dir.join("event.db"))).unwrap()
}

fn temp() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    std::fs::set_permissions(t.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    t
}

const BASE_NS: i128 = 1_791_560_874_000_000_000;

/// The process opening the decoy file with `cat`; `command` is attacker-controlled.
fn open_event(n: u32, path: &str, command: &[&str]) -> Event {
    let v: Value = json!({
        "schema_version": 1,
        "event_id": koru_event::EventId::new().to_string(),
        "timestamp": koru_event::Timestamp::from_unix_nanos(BASE_NS + i128::from(n) * 1_000_000_000).unwrap().text(),
        "timestamp_trusted": true,
        "source_tag": "synthetic",
        "sensor": {"name": "pulsar", "version": "0.11.0-alpha.1", "platform": "linux-aarch64"},
        "host": "lab-server",
        "process": {
            "pid": 5000 + n, "ppid": 4999, "start_time": null, "exe": "/usr/bin/cat",
            "command_line": command, "environment": [], "user": {"uid": 1000, "gid": 1000},
            "lineage": [
                {"pid": 4999, "exe": "/usr/bin/bash", "command_line": ["bash", "-c", "cat file"]},
                {"pid": 700, "exe": "/usr/sbin/sshd", "command_line": ["sshd: devops"]}
            ]
        },
        "container": {"id": null, "name": null, "image": null, "image_digest": null, "namespaces": null},
        "event_type": "file_opened",
        "target": {
            "path": path, "new_path": null, "flags": ["O_RDONLY"], "hard_link": null, "protocol": null,
            "local": null, "remote": null, "exit_code": null
        },
        "actor": {"kind": "unknown", "rationale": [], "confidence": 0.0},
        "detection": null,
        "tags": {"intent": null, "mitre_techniques": [], "verified": false},
        "session_id": null,
        "response": null
    });
    let o: Event = serde_json::from_value(v).unwrap();
    o.validate().unwrap();
    o
}

fn settings(raw: bool) -> AgentSettings {
    AgentSettings {
        source_tag: SourceTag::Synthetic,
        host: "lab-server".to_string(),
        timestamp_trusted: true,
        store_raw_events: raw,
    }
}

struct Harness {
    t: tempfile::TempDir,
    collector: Collector,
    store: Store,
    detector: RuleDetector,
}

impl Harness {
    fn new(delay: Duration) -> Harness {
        let t = temp();
        let collector = Collector { received: Arc::default(), delay };
        let store = open_store(&t);
        Harness { t, collector, store, detector: detector() }
    }

    fn notifier(&self, capacity: usize) -> BackgroundNotifier {
        BackgroundNotifier::start(make_dispatcher(&self.t, &self.collector), capacity)
    }

    fn run(
        &mut self,
        events: Vec<Event>,
        result: Result<(), InterfaceError>,
        raw: bool,
        heartbeat: Option<HeartbeatLoop>,
    ) -> koru::agent::AgentOutcome {
        let mut sensor = FakeSensor { events, result };
        let notifier = self.notifier(1000);
        run(Agent {
            sensor: &mut sensor,
            detector: &mut self.detector,
            store: &mut self.store,
            notifier,
            heartbeat,
            translation_counters: None,
            settings: settings(raw),
        })
    }

    fn notifications(&self) -> Vec<Notification> {
        self.collector.received.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[test]
fn finding_stored_and_notified_raw_event_not_kept() {
    let mut d = Harness::new(Duration::ZERO);
    let harmless = open_event(1, "/etc/hostname", &["cat", "/etc/hostname"]);
    let decoy = open_event(2, AWS, &["cat", AWS]);
    let s = d.run(vec![harmless.clone(), decoy.clone()], Ok(()), false, None);
    assert_eq!(s.processed, 2);
    assert_eq!(s.finding, 2, "decoy access + stopped: {s:?}");
    assert_eq!(s.sensor_error, None);
    // The store holds only finding events; raw events are not kept.
    assert_eq!(d.store.record_count().unwrap(), 2);
    assert!(d.store.get_event(&harmless.event_id).unwrap().is_none());
    assert!(d.store.get_event(&decoy.event_id).unwrap().is_none());
    let notifications = d.notifications();
    assert_eq!(notifications.len(), 2, "{notifications:?}");
    assert!(
        notifications[0].title.contains("decoy") || notifications[0].body.contains("decoy-aws"),
        "{:?}",
        notifications[0]
    );
    assert_eq!(notifications[0].severity, Severity::Critical);
}

#[test]
fn raw_events_written_when_keep_raw_on() {
    let mut d = Harness::new(Duration::ZERO);
    let harmless = open_event(1, "/etc/hostname", &["cat", "/etc/hostname"]);
    let s = d.run(vec![harmless.clone()], Ok(()), true, None);
    assert_eq!(s.processed, 1);
    assert_eq!(s.stored, 2, "raw event + stopped finding: {s:?}");
    assert!(d.store.get_event(&harmless.event_id).unwrap().is_some());
}

#[test]
fn sensor_stop_event_produced_stored_notified() {
    let mut d = Harness::new(Duration::ZERO);
    let s = d.run(Vec::new(), Ok(()), false, None);
    assert_eq!(s.finding, 1);
    assert_eq!(d.store.record_count().unwrap(), 1);
    let b = d.notifications();
    assert_eq!(b.len(), 1);
    let event = d.store.get_event(&b[0].event_id).unwrap().expect("the stopped event is in the store");
    let t = event.detection.as_ref().unwrap();
    assert_eq!(t.rule, "koru_stopped");
    assert_eq!(event.source_tag, SourceTag::Synthetic);
    assert_eq!(event.host, "lab-server");
    event.validate().unwrap();
}

#[test]
fn sensor_error_also_produces_stop_event() {
    let mut d = Harness::new(Duration::ZERO);
    let s =
        d.run(Vec::new(), Err(InterfaceError::Permanent("Pulsar agent: bpf could not be loaded".into())), false, None);
    assert!(s.sensor_error.as_deref().is_some_and(|h| h.contains("bpf")), "{s:?}");
    assert_eq!(s.finding, 1, "the stopped event is still produced");
    assert_eq!(d.store.record_count().unwrap(), 1);
}

#[test]
fn notification_carries_attacker_fields_sanitized() {
    let mut d = Harness::new(Duration::ZERO);
    let bad = open_event(1, AWS, &["cat", "\u{1b}[31mRED\u{1b}[0m", "line\ninjection: Authorization: x", AWS]);
    d.run(vec![bad], Ok(()), false, None);
    for b in d.notifications() {
        for text in [&b.title, &b.body] {
            assert!(!text.contains('\u{1b}'), "an escape sequence leaked: {text:?}");
            assert!(!text.contains("\ninjection"), "a line injection leaked: {text:?}");
            assert!(text.chars().all(|c| !c.is_control() || c == '\n'), "control character: {text:?}");
        }
        assert!(!b.title.contains('\n'), "the title must be a single line: {:?}", b.title);
    }
}

#[test]
fn build_notification_maps_severity_to_priority() {
    let mut t = detector();
    let b = t.process(&open_event(1, AWS, &["cat", AWS]));
    assert_eq!(b.len(), 1);
    let notify = build_notification(&b[0]);
    assert_eq!(notify.event_id, b[0].event.event_id);
    assert_eq!(notify.severity, Severity::Critical);
    assert!(notify.body.contains("decoy-aws"), "{}", notify.body);
    assert!(!notify.title.is_empty() && notify.title.len() <= 200);
    let d = t.stopped(&koru_detect::SelfEventContext {
        timestamp: koru_event::Timestamp::now(),
        timestamp_trusted: true,
        source_tag: SourceTag::Synthetic,
        host: "lab-server".into(),
    });
    assert_eq!(d.len(), 1);
    assert_eq!(build_notification(&d[0]).event_id, d[0].event.event_id);
}

#[test]
fn slow_notification_network_does_not_stall_events() {
    // Each send takes 300 ms; capacity 4. 200 findings must process fast; overflowing notifications drop and are counted.
    let mut d = Harness::new(Duration::from_millis(300));
    let events: Vec<Event> = (1..=200).map(|n| open_event(n, AWS, &["cat", AWS])).collect();
    let mut sensor = FakeSensor { events, result: Ok(()) };
    let notifier = d.notifier(4);
    let start_v = Instant::now();
    let s = run(Agent {
        sensor: &mut sensor,
        detector: &mut d.detector,
        store: &mut d.store,
        notifier,
        heartbeat: None,
        translation_counters: None,
        settings: settings(false),
    });
    assert!(
        start_v.elapsed() < Duration::from_secs(30),
        "the loop must not wait on the notify network: {:?}",
        start_v.elapsed()
    );
    assert_eq!(s.processed, 200);
    assert!(s.finding >= 200, "{s:?}");
    assert!(s.notifications_dropped > 0, "on capacity overflow the notification must drop and be counted: {s:?}");
    assert_eq!(d.store.record_count().unwrap(), s.finding, "a dropped notification does not affect the finding record");
}

#[test]
fn background_notifier_delivers_pending_on_shutdown() {
    let t = temp();
    let collector = Collector { received: Arc::default(), delay: Duration::from_millis(20) };
    let b = BackgroundNotifier::start(make_dispatcher(&t, &collector), 100);
    let mut detector = detector();
    let finding = detector.process(&open_event(1, AWS, &["cat", AWS])).remove(0);
    for _ in 0..5 {
        b.send(build_notification(&finding));
    }
    assert_eq!(b.dropped(), 0);
    let _ = b.close(Duration::from_secs(10));
    assert!(!collector.received.lock().unwrap().is_empty(), "on shutdown, pending notifications must be delivered");
}

#[test]
fn translation_rejections_are_added_to_the_store_counters() {
    let mut d = Harness::new(Duration::ZERO);
    let counters = Arc::new(TranslationCounters::default());
    for _ in 0..3 {
        let error = TranslationError::Validation(koru_event::ValidationError::Empty { field: "host" });
        assert!(count_translation(Err(error), &counters).is_none());
    }
    let mut sensor = FakeSensor { events: Vec::new(), result: Ok(()) };
    let notifier = d.notifier(10);
    run(Agent {
        sensor: &mut sensor,
        detector: &mut d.detector,
        store: &mut d.store,
        notifier,
        heartbeat: None,
        translation_counters: Some(counters),
        settings: settings(false),
    });
    let red = d.store.rejected().unwrap();
    assert!(red.contains(&(koru_store::RejectReason::TranslationValidation, 3)), "{red:?}");
}

#[test]
fn failed_health_signal_sent_on_stop() {
    // A local fake Healthchecks: records the incoming request lines.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let dur = Arc::new(AtomicBool::new(false));
    let (i2, d2) = (Arc::clone(&requests), Arc::clone(&dur));
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        while !d2.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let mut title = String::new();
                    while reader.read_line(&mut title).unwrap() > 2 {
                        title.clear();
                    }
                    i2.lock().unwrap().push(line.trim_end().to_string());
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                }
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    });
    let address = HttpsAddress::parse_parts(&format!("http://127.0.0.1:{port}/ping")).unwrap();
    let heartbeat = HeartbeatLoop::start(HealthchecksHeartbeat::new(address), Duration::from_millis(50));
    let mut d = Harness::new(Duration::ZERO);
    d.run(Vec::new(), Ok(()), false, Some(heartbeat));
    dur.store(true, Ordering::Relaxed);
    handle.join().unwrap();
    let requests = requests.lock().unwrap().clone();
    assert!(requests.iter().any(|i| i == "GET /ping HTTP/1.1"), "a heartbeat must be sent: {requests:?}");
    assert_eq!(requests.last().map(String::as_str), Some("GET /ping/fail HTTP/1.1"), "{requests:?}");
}
