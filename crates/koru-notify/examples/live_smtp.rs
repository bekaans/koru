#![forbid(unsafe_code)]
//! Live SMTP trial (lab). The live_ntfy pattern: .env is read,
//! only the server response (secrets stripped) and the counters are printed.
//!
//! ```text
//! live_smtp <env-file> <queue-dir>
//! ```

use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use koru_event::{EventId, InterfaceError, Notification, NotificationChannel, Severity};
use koru_notify::{ChannelSet, ChannelSettings, Dispatcher, SmtpChannel, read_dotenv};

struct ResponseRecorder {
    inner: SmtpChannel,
    last: Arc<Mutex<Option<String>>>,
}

impl NotificationChannel for ResponseRecorder {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn send(&mut self, b: &Notification) -> Result<(), InterfaceError> {
        let result = self.inner.send(b);
        if let Ok(mut k) = self.last.lock() {
            *k = self.inner.last_response().map(str::to_string);
        }
        result
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
}

fn run_live() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: live_smtp <env-file> <queue-dir>".to_string());
    }
    let values = read_dotenv(Path::new(&args[1])).map_err(|e| e.to_string())?;
    let set = ChannelSet::from_env(&|name| values.get(name).cloned()).map_err(|e| e.to_string())?;
    let settings = set.smtp.ok_or_else(|| "KORU_SMTP_* is empty".to_string())?;
    let last: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let mut d = Dispatcher::new(Path::new(&args[2]));
    d.add_channel(
        Box::new(ResponseRecorder { inner: SmtpChannel::new(settings), last: last.clone() }),
        ChannelSettings::default(),
        now_ms(),
    )
    .map_err(|e| e.to_string())?;
    let notification = Notification {
        severity: Severity::Warning,
        title: "[Koru live trial] A live SMTP notification".to_string(),
        body: "This is a live trial notification (SMTP channel).".to_string(),
        event_id: EventId::new(),
    };
    d.notify(&notification, now_ms());
    d.process(now_ms());
    let response = last.lock().map(|k| k.clone()).ok().flatten();
    let s = d.stats("smtp");
    println!("smtp result: response {:?}; counters: {:?}", response, s);
    match response {
        Some(y) if y.starts_with('2') => Ok(()),
        _ => Err("the expected 2xx SMTP response never arrived".to_string()),
    }
}

fn main() -> ExitCode {
    match run_live() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("live_smtp: {e}");
            ExitCode::FAILURE
        }
    }
}
