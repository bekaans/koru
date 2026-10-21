#![forbid(unsafe_code)]
//! Live ntfy trial (lab).
//!
//! It reads `.env` via `read_dotenv` (must be 0600) and prints only results: the HTTP status,
//! queue counters, the time. The topic address, tokens and variable values never reach the output.
//! The notification is built from a koru-event schema example event, starts with "[Koru
//! live trial]"; IP masking is on (the default).
//!
//! ```text
//! live_ntfy send       <env-file> <queue-dir>   send one notification to the real ntfy
//! live_ntfy outage-one <env-file> <queue-dir>   the target is unreachable: the notification is queued, the process exits
//! live_ntfy outage-two <env-file> <queue-dir>   a new process, the real target: the queue is loaded and delivered
//! ```

use std::net::{IpAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use koru_event::{Event, InterfaceError, NetworkEndpoint, Notification, NotificationChannel, Severity, Timestamp};
use koru_notify::{ChannelSet, ChannelSettings, Dispatcher, HttpsAddress, NtfyChannel, NtfySettings, read_dotenv};

/// Wraps the channel and hands out its last HTTP status (the dispatcher owns the channel).
struct StatusRecorder {
    inner: NtfyChannel,
    last: Arc<Mutex<Option<u16>>>,
}

impl NotificationChannel for StatusRecorder {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn send(&mut self, b: &Notification) -> Result<(), InterfaceError> {
        let result = self.inner.send(b);
        if let Ok(mut k) = self.last.lock() {
            *k = self.inner.last_status();
        }
        result
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
}

fn timestamp() -> String {
    Timestamp::now().to_string()
}

/// Builds a finding notification from a koru-event schema example (raw attacker fields via their safe displays).
fn finding_notification() -> Result<Notification, String> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../koru-event/tests/data/valid/network-connection-ipv6.json");
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("the event example could not be read: {}", e.kind()))?;
    let mut event: Event =
        serde_json::from_str(&text).map_err(|_| "the event example could not be parsed".to_string())?;
    // A documentation-range (TEST-NET-3) IPv4 remote address, to show masking.
    let ip: IpAddr = "203.0.113.77".parse().map_err(|_| "ip".to_string())?;
    event.target.remote = Some(NetworkEndpoint { ip, port: 443 });
    event.validate().map_err(|_| "the event did not validate".to_string())?;
    let remote = event.target.remote.map_or_else(String::new, |u| format!("{}:{}", u.ip, u.port));
    Ok(Notification {
        severity: Severity::Warning,
        title: format!("[Koru live trial] A suspicious network connection ({})", event.sensor.name),
        body: format!(
            "Finding: the process {} connected to {}.\nCommand: {}\nThis is a live trial notification (event: a schema example, source tag {:?}).",
            event.process.exe.safe_display(),
            remote,
            event.process.command_line.safe_display(),
            event.source_tag,
        ),
        event_id: event.event_id,
    })
}

fn real_ntfy_settings(env: &Path) -> Result<NtfySettings, String> {
    let values = read_dotenv(env).map_err(|e| e.to_string())?;
    let set = ChannelSet::from_env(&|name| values.get(name).cloned()).map_err(|e| e.to_string())?;
    if !set.mask_ip {
        return Err("IP masking is off; the live trial must run masked".to_string());
    }
    set.ntfy.ok_or_else(|| "KORU_NTFY_URL is empty".to_string())
}

fn build_dispatcher(queue: &Path, ntfy: NtfySettings, last: Arc<Mutex<Option<u16>>>) -> Result<Dispatcher, String> {
    let mut d = Dispatcher::new(queue);
    let channel = StatusRecorder { inner: NtfyChannel::new(ntfy), last };
    d.add_channel(Box::new(channel), ChannelSettings::default(), now_ms()).map_err(|e| e.to_string())?;
    Ok(d)
}

fn status_text(last: &Arc<Mutex<Option<u16>>>) -> String {
    match last.lock().ok().and_then(|k| *k) {
        Some(d) => format!("HTTP {d}"),
        None => "no response (no connection, or it was severed)".to_string(),
    }
}

fn counters(d: &Dispatcher) -> String {
    d.stats("ntfy").map_or_else(String::new, |s| {
        format!(
            "sent={} queued={} in_queue={} suppressed={} permanent_errors={} dropped_overflow={} dropped_retries={}",
            s.sent, s.queued, s.in_queue, s.suppressed_count, s.permanent_errors, s.dropped_overflow, s.dropped_retries
        )
    })
}

fn queue_file_path(queue: &Path) -> PathBuf {
    queue.join("ntfy.queue")
}

fn queue_summary(queue: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let file = queue_file_path(queue);
    let mode = std::fs::metadata(&file).map(|m| m.permissions().mode() & 0o777);
    let dir_mode = std::fs::metadata(queue).map(|m| m.permissions().mode() & 0o777);
    let content = std::fs::read_to_string(&file).unwrap_or_default();
    println!(
        "  queue file: mode {:?}, dir mode {:?}, {} bytes; contains the full IP (203.0.113.77): {}; contains the masked IP (203.0.113.0): {}",
        mode.map(|k| format!("{k:o}")).ok(),
        dir_mode.map(|k| format!("{k:o}")).ok(),
        content.len(),
        content.contains("203.0.113.77"),
        content.contains("203.0.113.0")
    );
}

fn send(env: &Path, queue: &Path) -> Result<(), String> {
    let ntfy = real_ntfy_settings(env)?;
    let last = Arc::new(Mutex::new(None));
    let mut d = build_dispatcher(queue, ntfy, last.clone())?;
    let b = finding_notification()?;
    println!("{} | ntfy.sh/<secret topic> | sending: {:?} (event {})", timestamp(), b.title, b.event_id);
    d.notify(&b, now_ms());
    println!("{} | result: {} | {}", timestamp(), status_text(&last), counters(&d));
    Ok(())
}

fn outage_one(env: &Path, queue: &Path) -> Result<(), String> {
    // The real settings are read (for the masking check) but the target is replaced by an unreachable local address.
    real_ntfy_settings(env)?;
    let scratch = TcpListener::bind("127.0.0.1:0").map_err(|e| e.kind().to_string())?;
    let port = scratch.local_addr().map_err(|e| e.kind().to_string())?.port();
    drop(scratch);
    let url = HttpsAddress::parse_parts(&format!("http://127.0.0.1:{port}/outage")).map_err(|e| e.to_string())?;
    let mut settings = NtfySettings::new(url);
    settings.timeout = Duration::from_secs(2);
    let last = Arc::new(Mutex::new(None));
    let mut d = build_dispatcher(queue, settings, last.clone())?;
    let b = finding_notification()?;
    println!(
        "{} | target: an unreachable local url (a simulated network outage) | sending (event {})",
        timestamp(),
        b.event_id
    );
    d.notify(&b, now_ms());
    println!("{} | result: {} | {}", timestamp(), status_text(&last), counters(&d));
    queue_summary(queue);
    println!("{} | the process ends (no shutdown calls; the queue lives only on disk)", timestamp());
    Ok(())
}

fn outage_two(env: &Path, queue: &Path) -> Result<(), String> {
    let ntfy = real_ntfy_settings(env)?;
    let last = Arc::new(Mutex::new(None));
    let mut d = build_dispatcher(queue, ntfy, last.clone())?;
    println!(
        "{} | a new process; target: the real ntfy (ntfy.sh/<secret topic>) | at startup {}",
        timestamp(),
        counters(&d)
    );
    queue_summary(queue);
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        d.process(now_ms());
        if d.stats("ntfy").is_some_and(|s| s.in_queue == 0) {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("{} | result: {} | {}", timestamp(), status_text(&last), counters(&d));
    queue_summary(queue);
    match d.stats("ntfy") {
        Some(s) if s.in_queue == 0 && s.sent >= 1 => Ok(()),
        _ => Err("the queue could not be delivered".to_string()),
    }
}

fn main() -> ExitCode {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 4 {
        eprintln!("usage: live_ntfy <send|outage-one|outage-two> <env-file> <queue-dir>");
        return ExitCode::from(2);
    }
    let (env, queue) = (Path::new(&a[2]), Path::new(&a[3]));
    let result = match a[1].as_str() {
        "send" => send(env, queue),
        "outage-one" => outage_one(env, queue),
        "outage-two" => outage_two(env, queue),
        _ => Err("an unknown command".to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::FAILURE
        }
    }
}
