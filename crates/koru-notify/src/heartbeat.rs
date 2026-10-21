//! Healthchecks.io heartbeats (`KORU_HEARTBEAT_URL`).
//!
//! Koru sends a regular `GET` to the ping address; when the pings stop, Healthchecks flips
//! to "down" after the period plus grace and raises an alarm. The ping address counts as a
//! secret: it never enters `Debug` output, error messages or logs.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use koru_event::{Heartbeat, InterfaceError};

use crate::HttpsAddress;
use crate::http::{self, Request};

/// Healthchecks.io heartbeat.
#[derive(Debug, Clone)]
pub struct HealthchecksHeartbeat {
    url: HttpsAddress,
    timeout: Duration,
    last_status: Option<u16>,
}

impl HealthchecksHeartbeat {
    /// Builds it from the ping address (no network). Default deadline: 10 s.
    pub fn new(url: HttpsAddress) -> HealthchecksHeartbeat {
        HealthchecksHeartbeat { url, timeout: Duration::from_secs(10), last_status: None }
    }

    /// The HTTP status code from the last ping (a failed response's code too); `None` when no
    /// response was received or nothing was pinged yet.
    pub fn last_status(&self) -> Option<u16> {
        self.last_status
    }

    /// Sets the connect, write and read deadline.
    pub fn set_timeout(mut self, dur: Duration) -> HealthchecksHeartbeat {
        self.timeout = dur;
        self
    }

    fn ping(&mut self, suffix: Option<&str>) -> Result<(), InterfaceError> {
        let url = match suffix {
            Some(e) => self
                .url
                .join_path(e)
                .map_err(|_| InterfaceError::Permanent("could not build the ping address".to_string()))?,
            None => self.url.clone(),
        };
        let request = Request { method: "GET", url: &url, headers: &[], body: &[], timeout: self.timeout };
        self.last_status = None;
        let state = http::send(&request)?;
        self.last_status = Some(state);
        http::classify_status(state)
    }

    /// Start signal: `GET <url>/start`.
    pub fn begin(&mut self) -> Result<(), InterfaceError> {
        self.ping(Some("start"))
    }

    /// Failure signal: `GET <url>/fail`; Healthchecks flips to "down" at once.
    pub fn failed(&mut self) -> Result<(), InterfaceError> {
        self.ping(Some("fail"))
    }
}

impl Heartbeat for HealthchecksHeartbeat {
    /// `GET <url>`: the "still alive" signal.
    fn beat(&mut self) -> Result<(), InterfaceError> {
        self.ping(None)
    }
}

/// A background loop sending regular heartbeats (its own thread). When dropped without `stop`
/// (the process still running), the thread also stops and the pings end.
#[derive(Debug)]
pub struct HeartbeatLoop {
    stop_tx: Sender<()>,
    thread: JoinHandle<HealthchecksHeartbeat>,
    dropped: Arc<AtomicU64>,
    error: Arc<AtomicU64>,
}

impl HeartbeatLoop {
    /// Starts the loop: first at once, then a `beat()` every interval.
    pub fn start(mut heartbeat: HealthchecksHeartbeat, range: Duration) -> HeartbeatLoop {
        let (stop_tx, al) = mpsc::channel::<()>();
        let dropped = Arc::new(AtomicU64::new(0));
        let error = Arc::new(AtomicU64::new(0));
        let (a, h) = (dropped.clone(), error.clone());
        let is = std::thread::spawn(move || {
            loop {
                match heartbeat.beat() {
                    Ok(()) => a.fetch_add(1, Ordering::Relaxed),
                    Err(_) => h.fetch_add(1, Ordering::Relaxed),
                };
                match al.recv_timeout(range) {
                    Err(RecvTimeoutError::Timeout) => {}
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            heartbeat
        });
        HeartbeatLoop { stop_tx, thread: is, dropped, error }
    }

    /// Heartbeats sent successfully.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Heartbeats that could not be sent.
    pub fn error(&self) -> u64 {
        self.error.load(Ordering::Relaxed)
    }

    /// Stops the loop (the thread is joined). With `send_fail`, a final `/fail` is sent:
    /// on a clean shutdown Healthchecks flips to "down" immediately (ADR-0007 "heartbeat").
    pub fn stop(self, send_fail: bool) -> Result<(), InterfaceError> {
        let _ = self.stop_tx.send(());
        let mut heartbeat =
            self.thread.join().map_err(|_| InterfaceError::Permanent("the heartbeat thread panicked".to_string()))?;
        if send_fail { heartbeat.failed() } else { Ok(()) }
    }
}
