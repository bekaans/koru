#![forbid(unsafe_code)]
//! Live heartbeat trial (lab): pings the Healthchecks
//! address and prints the HTTP status. The ping address never reaches the output.
//! The "down" alert after `systemctl stop` is verified from the Healthchecks panel.
//!
//! ```text
//! live_heartbeat <env-file>
//! ```

use std::path::Path;
use std::process::ExitCode;

use koru_event::Heartbeat;
use koru_notify::{ChannelSet, HealthchecksHeartbeat, read_dotenv};

fn run_live() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: live_heartbeat <env-file>".to_string());
    }
    let values = read_dotenv(Path::new(&args[1])).map_err(|e| e.to_string())?;
    let set = ChannelSet::from_env(&|name| values.get(name).cloned()).map_err(|e| e.to_string())?;
    let url = set.heartbeat.ok_or_else(|| "KORU_HEARTBEAT_URL is empty".to_string())?;
    let mut heartbeat = HealthchecksHeartbeat::new(url);
    heartbeat.beat().map_err(|e| e.to_string())?;
    println!("heartbeat beat result: HTTP {:?}", heartbeat.last_status());
    if heartbeat.last_status() == Some(200) { Ok(()) } else { Err("the expected HTTP 200 never arrived".to_string()) }
}

fn main() -> ExitCode {
    match run_live() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("live_heartbeat: {e}");
            ExitCode::FAILURE
        }
    }
}
