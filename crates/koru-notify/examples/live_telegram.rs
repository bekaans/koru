#![forbid(unsafe_code)]
//! Live Telegram trial (lab). The live_ntfy pattern: .env is
//! read; only the HTTP status and counters are printed, and the token never reaches the output.
//!
//! ```text
//! live_telegram <env-file> <queue-dir>
//! ```

use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use koru_event::{EventId, InterfaceError, Notification, NotificationChannel, Severity};
use koru_notify::{ChannelSet, ChannelSettings, Dispatcher, TelegramChannel, read_dotenv};

struct StatusRecorder {
    inner: TelegramChannel,
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

fn run_live() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: live_telegram <env-file> <queue-dir>".to_string());
    }
    let values = read_dotenv(Path::new(&args[1])).map_err(|e| e.to_string())?;
    let set = ChannelSet::from_env(&|name| values.get(name).cloned()).map_err(|e| e.to_string())?;
    let settings = set.telegram.ok_or_else(|| "KORU_TELEGRAM_BOT_TOKEN/CHAT_ID is empty".to_string())?;
    let last: Arc<Mutex<Option<u16>>> = Arc::new(Mutex::new(None));
    let mut d = Dispatcher::new(Path::new(&args[2]));
    d.add_channel(
        Box::new(StatusRecorder { inner: TelegramChannel::new(settings), last: last.clone() }),
        ChannelSettings::default(),
        now_ms(),
    )
    .map_err(|e| e.to_string())?;
    let notification = Notification {
        severity: Severity::Warning,
        title: "[Koru live trial] A live Telegram notification".to_string(),
        body: "This is a live trial notification (Telegram channel).".to_string(),
        event_id: EventId::new(),
    };
    d.notify(&notification, now_ms());
    d.process(now_ms());
    let state = last.lock().map(|k| *k).ok().flatten();
    let s = d.stats("telegram");
    println!("telegram result: HTTP {:?}; counters: {:?}", state, s);
    if state == Some(200) { Ok(()) } else { Err("the expected HTTP 200 never arrived".to_string()) }
}

fn main() -> ExitCode {
    match run_live() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("live_telegram: {e}");
            ExitCode::FAILURE
        }
    }
}
