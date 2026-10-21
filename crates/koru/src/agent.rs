//! The agent's core loop (ADR-0003 §7, ADR-0008): the Pulsar bridge, detection, store and notify
//! meet in one process. The composition lives only here; the layers do not know each other.
//!
//! Flow: sensor event → detector → finding events are written to the store and notified. Raw events
//! are kept only when `store_raw_events` is on. The notification network never waits for event processing: notifications
//! go through a bounded channel to a separate thread; when the channel is full the notification is dropped and counted,
//! and the finding is still in the store. When the sensor stops (the Pulsar agent returns on SIGTERM) Koru emits its own
//! "stopped" event, stores it, notifies it and ends the heartbeat with `/fail`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use koru_detect::{Finding, Level, RuleDetector, SelfEventContext};
use koru_event::{ActorKind, Event, Notification, Sensor, Severity, SourceTag, ThreatClass, Timestamp};
use koru_notify::{Dispatcher, HeartbeatLoop};
use koru_pulsar::TranslationCounters;
use koru_store::{IngestOutcome, RejectReason, Store};

/// Store rotation (retention and record limit) interval; applied while the sensor is active.
const ROTATION_INTERVAL: Duration = Duration::from_secs(6 * 3600);
/// Maximum length of the notification title (characters).
const MAX_TITLE: usize = 120;
/// Maximum length of each line in the notification body (characters).
const MAX_LINE: usize = 240;

/// Core loop settings.
#[derive(Debug, Clone)]
pub struct AgentSettings {
    /// The install's source tag.
    pub source_tag: SourceTag,
    /// Host name.
    pub host: String,
    /// Whether the clock is NTP-synced (determined once as the agent starts).
    pub timestamp_trusted: bool,
    /// Keep raw events alongside findings.
    pub store_raw_events: bool,
}

/// The loop's outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentOutcome {
    /// Number of events from the sensor.
    pub processed: u64,
    /// Number of findings produced ("stopped" included).
    pub finding: u64,
    /// Number of records newly written to the store.
    pub stored: u64,
    /// Number of records that could not be written to the store (full disk, permissions, …).
    pub store_errors: u64,
    /// Number of notifications dropped because the channel was full.
    pub notifications_dropped: u64,
    /// When the sensor stopped with an error, the error text.
    pub sensor_error: Option<String>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
}

/// Distributes notifications on a separate thread; event processing never waits on the network.
pub struct BackgroundNotifier {
    sender: Option<SyncSender<Notification>>,
    dropped: Arc<AtomicU64>,
    shutdown_wait_ms: Arc<AtomicU64>,
    handle: Option<JoinHandle<Dispatcher>>,
}

impl BackgroundNotifier {
    /// Starts the thread; `capacity` bounds the number of pending notifications.
    pub fn start(mut dispatcher: Dispatcher, capacity: usize) -> BackgroundNotifier {
        let (sender, receiver) = mpsc::sync_channel::<Notification>(capacity.max(1));
        let shutdown_wait_ms = Arc::new(AtomicU64::new(0));
        let wait = Arc::clone(&shutdown_wait_ms);
        let handle = std::thread::spawn(move || {
            let mut last_moment: Option<Instant> = None;
            loop {
                // If shutdown was requested, the total time for the remaining notifications is bounded.
                let requested = wait.load(Ordering::Relaxed);
                if requested > 0 {
                    let deadline =
                        *last_moment.get_or_insert_with(|| Instant::now() + Duration::from_millis(requested));
                    if Instant::now() >= deadline {
                        break;
                    }
                }
                match receiver.recv_timeout(Duration::from_millis(250)) {
                    Ok(b) => dispatcher.notify(&b, now_ms()),
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
                // Rate-limit digests and due queue records (delivered when the network returns).
                dispatcher.process(now_ms());
            }
            dispatcher.process(now_ms());
            dispatcher
        });
        BackgroundNotifier {
            sender: Some(sender),
            dropped: Arc::new(AtomicU64::new(0)),
            shutdown_wait_ms,
            handle: Some(handle),
        }
    }

    /// Hands a notification to the queue; never blocks. A full channel drops it, and the drop is counted.
    pub fn send(&self, notify: Notification) {
        let Some(g) = &self.sender else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match g.try_send(notify) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The number of dropped notifications.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Delivers pending notifications (at most `wait`) and ends the thread.
    pub fn close(mut self, wait: Duration) -> Dispatcher {
        let ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX).max(1);
        self.shutdown_wait_ms.store(ms, Ordering::Relaxed);
        self.sender = None;
        let handle = self.handle.take().expect("the thread is awaited once");
        handle.join().unwrap_or_else(|_| panic!("the notify thread panicked"))
    }
}

fn truncate_line(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut s: String = text.chars().take(max.saturating_sub(1)).collect();
    s.push('…');
    s
}

fn class_name(s: ThreatClass) -> &'static str {
    match s {
        ThreatClass::DecoyAccess => "decoy access",
        ThreatClass::BreadcrumbAccess => "breadcrumb access",
        ThreatClass::SuspectedHijackedAgent => "suspected hijacked agent",
        ThreatClass::SelfProtection => "self-protection",
    }
}

fn actor_name(a: ActorKind) -> &'static str {
    match a {
        ActorKind::Human => "human",
        ActorKind::AiAgent => "AI agent",
        ActorKind::Unknown => "unknown",
    }
}

/// Turns newlines and control characters into spaces (the title and lines stay single-line).
fn single_line(m: &str) -> String {
    m.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

/// Builds a notification from a finding. Attacker-controlled fields (path, command line) enter only via
/// [`koru_event::Untrusted::safe_display`]: control and direction characters are neutralized,
/// no newlines (KT-15, KT-25).
pub fn build_notification(finding: &Finding) -> Notification {
    let o: &Event = &finding.event;
    let severity = match finding.severity {
        Level::Critical | Level::High => Severity::Critical,
        Level::Medium => Severity::Warning,
        Level::Low | Level::Info => Severity::Info,
    };
    let title =
        truncate_line(&format!("[{}] {}", finding.severity.sigma_name(), single_line(&finding.title)), MAX_TITLE);
    let mut body = Vec::new();
    if let Some(t) = &o.detection {
        body.push(format!("Rule: {}", t.rule));
        body.push(format!("Class: {}", class_name(t.threat_class)));
        if let Some(k) = &t.decoy_id {
            body.push(format!("Decoy: {k}"));
        }
    }
    body.push(format!("Actor: {} (confidence {:.2})", actor_name(o.actor.kind), o.actor.confidence.value()));
    body.push(format!("Host: {}", o.host));
    body.push(format!("Process: {} (pid {})", o.process.exe.safe_display(), o.process.pid));
    body.push(format!("Command: {}", o.process.command_line.safe_display()));
    if let Some(y) = &o.target.path {
        body.push(format!("Target: {}", y.safe_display()));
    }
    body.push(format!("Timestamp: {}", o.timestamp.text()));
    body.push(format!("Event: {}", o.event_id));
    let body = body.iter().map(|s| truncate_line(&single_line(s), MAX_LINE)).collect::<Vec<_>>().join("\n");
    Notification { severity, title, body, event_id: o.event_id }
}

/// The agent's components.
pub struct Agent<'a> {
    /// The event source (the Pulsar bridge on Linux).
    pub sensor: &'a mut dyn Sensor,
    /// The detection layer.
    pub detector: &'a mut RuleDetector,
    /// The event store.
    pub store: &'a mut Store,
    /// The notification output (consumed).
    pub notifier: BackgroundNotifier,
    /// The heartbeat loop (consumed); on stop, `/fail` is sent.
    pub heartbeat: Option<HeartbeatLoop>,
    /// Translation rejection counters; appended to the data-quality report at the end.
    pub translation_counters: Option<Arc<TranslationCounters>>,
    /// Settings.
    pub settings: AgentSettings,
}

fn persist(store: &mut Store, event: &Event, result: &mut AgentOutcome) {
    match store.store_event(event) {
        Ok(IngestOutcome::Stored) => result.stored += 1,
        Ok(IngestOutcome::Duplicate | IngestOutcome::Rejected(_)) => {}
        Err(_) => result.store_errors += 1,
    }
}

fn process_finding(b: &Finding, store: &mut Store, notifier: &BackgroundNotifier, result: &mut AgentOutcome) {
    result.finding += 1;
    persist(store, &b.event, result);
    notifier.send(build_notification(b));
}

/// Runs until the sensor stops; on a clean shutdown emits the "stopped" event.
pub fn run(agent: Agent<'_>) -> AgentOutcome {
    let Agent { sensor, detector, store, notifier, heartbeat, translation_counters, settings } = agent;
    let mut result = AgentOutcome::default();
    let mut last_rotation = Instant::now();
    let outcome = sensor.run(&mut |event: Event| {
        result.processed += 1;
        if last_rotation.elapsed() >= ROTATION_INTERVAL {
            last_rotation = Instant::now();
            if store.freeze(Timestamp::now()).is_err() {
                result.store_errors += 1;
            }
        }
        if settings.store_raw_events {
            persist(store, &event, &mut result);
        }
        for b in detector.process(&event) {
            process_finding(&b, store, &notifier, &mut result);
        }
    });
    if let Err(e) = outcome {
        result.sensor_error = Some(e.to_string());
    }
    // Clean shutdown: the Pulsar agent returned on SIGINT/SIGTERM; Koru emits its own "stopped" event.
    let self_context = SelfEventContext {
        timestamp: Timestamp::now(),
        timestamp_trusted: settings.timestamp_trusted,
        source_tag: settings.source_tag,
        host: settings.host.clone(),
    };
    for b in detector.stopped(&self_context) {
        process_finding(&b, store, &notifier, &mut result);
    }
    // Translation rejections: the counters join the data-quality report.
    if let Some(s) = translation_counters {
        let g = s.snapshot();
        for (reason, count) in [
            (RejectReason::TranslationInvalidField, g.rejected_invalid_field),
            (RejectReason::TranslationValidation, g.rejected_validation),
        ] {
            if count > 0 && store.count_rejected(reason, count).is_err() {
                result.store_errors += 1;
            }
        }
    }
    result.notifications_dropped = notifier.dropped();
    let _ = notifier.close(Duration::from_secs(5));
    if let Some(k) = heartbeat {
        // Makes Healthchecks go "down" immediately on a clean shutdown (ADR-0007 "Heartbeat").
        let _ = k.stop(true);
    }
    result
}
