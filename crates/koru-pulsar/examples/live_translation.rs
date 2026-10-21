#![forbid(unsafe_code)]
//! Live translation example (lab test, `lab/scripts/live-pulsar-test.sh`).
//!
//! Two modes:
//!
//! - Agent (needs root): starts the Pulsar agent with the Koru bridge module; writes every Koru
//!   event to stdout as one JSON line. Stops with SIGINT/SIGTERM.
//!
//!   ```text
//!   live_translation agent --source-tag synthetic --prefix /tmp/koru-live \
//!       [--pulsar-config <toml>] [--host <name>] [--lineage-depth <n>]
//!   ```
//!
//! - Validate: checks the JSON lines against the Koru event schema (serde + `Event::validate`),
//!   prints the counts; exits 1 if any line is invalid.
//!
//!   ```text
//!   live_translation validate <events.jsonl>
//!   ```

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("live_translation runs only on Linux (Pulsar, ADR-0003)");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, ExitCode};

    use koru_event::{Event, Sensor, SourceTag};
    use koru_pulsar::{BridgeSettings, PulsarSensor};

    const USAGE: &str = "usage:\n  live_translation agent --source-tag <synthetic|legitimate|real> [--prefix <path>]... \
[--pulsar-config <toml>] [--host <name>] [--lineage-depth <n>]\n  live_translation validate <events.jsonl>";

    pub fn run() -> ExitCode {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let result = match args.first().map(String::as_str) {
            Some("agent") => agent(&args[1..]),
            Some("validate") if args.len() == 2 => validate(&args[1]),
            _ => Err(USAGE.to_string()),
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("[live] ERROR: {e}");
                ExitCode::FAILURE
            }
        }
    }

    fn agent(args: &[String]) -> Result<(), String> {
        let mut source_tag = None;
        let mut path_prefixes = Vec::new();
        let mut pulsar_config = None;
        let mut host = None;
        let mut lineage_depth = 16;
        let mut i = 0;
        while i < args.len() {
            let value = args.get(i + 1).ok_or_else(|| format!("no value for {}\n{USAGE}", args[i]))?;
            match args[i].as_str() {
                "--source-tag" => {
                    source_tag = Some(match value.as_str() {
                        "synthetic" => SourceTag::Synthetic,
                        "legitimate" => SourceTag::Legitimate,
                        "real" => SourceTag::Real,
                        _ => return Err(format!("invalid source tag: {value}")),
                    })
                }
                "--prefix" => path_prefixes.push(value.clone()),
                "--pulsar-config" => pulsar_config = Some(value.clone()),
                "--host" => host = Some(value.clone()),
                "--lineage-depth" => {
                    lineage_depth = value.parse().map_err(|_| format!("invalid lineage depth: {value}"))?
                }
                other => return Err(format!("unknown option: {other}\n{USAGE}")),
            }
            i += 2;
        }
        let source_tag = source_tag.ok_or_else(|| format!("--source-tag is required\n{USAGE}"))?;
        let host = match host {
            Some(a) => a,
            None => std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map_err(|e| format!("the host name could not be read: {e}"))?
                .trim()
                .to_string(),
        };
        // NTP sync is read once at agent start (no continuous watching).
        let timestamp_trusted = Command::new("timedatectl")
            .args(["show", "-p", "NTPSynchronized", "--value"])
            .output()
            .is_ok_and(|c| c.status.success() && String::from_utf8_lossy(&c.stdout).trim() == "yes");
        let settings =
            BridgeSettings { source_tag, host, timestamp_trusted, path_prefixes, lineage_depth, pulsar_config };
        // Pulsar's logs (RUST_LOG; otherwise info level) go to stderr.
        pulsar::init_logger(None);
        eprintln!("[live] starting the Pulsar agent with the Koru bridge module: {settings:?}");
        let mut sensor = PulsarSensor::new(settings);
        let mut output = std::io::stdout().lock();
        let mut number = 0u64;
        let mut write_error = None;
        let result = sensor.run(&mut |event: Event| match serde_json::to_string(&event) {
            Ok(line) => {
                if let Err(e) = writeln!(output, "{line}").and_then(|()| output.flush()) {
                    write_error.get_or_insert(e.to_string());
                }
                number += 1;
            }
            Err(e) => {
                write_error.get_or_insert(e.to_string());
            }
        });
        eprintln!("[live] the agent stopped; Koru events written: {number}");
        if let Some(e) = write_error {
            return Err(format!("the output could not be written: {e}"));
        }
        result.map_err(|e| e.to_string())
    }

    fn validate(path: &str) -> Result<(), String> {
        let file = std::fs::File::open(path).map_err(|e| format!("{path} could not be opened: {e}"))?;
        let mut valid = 0u64;
        let mut invalid = 0u64;
        for (no, line) in BufReader::new(file).lines().enumerate() {
            let line = line.map_err(|e| format!("{path} could not be read: {e}"))?;
            if line.trim().is_empty() {
                continue;
            }
            let result = serde_json::from_str::<Event>(&line)
                .map_err(|e| e.to_string())
                .and_then(|o| o.validate().map_err(|e| e.to_string()));
            match result {
                Ok(()) => valid += 1,
                Err(e) => {
                    invalid += 1;
                    eprintln!("[live] line {}: invalid: {e}", no + 1);
                }
            }
        }
        println!("schema v1 validation: valid {valid}, invalid {invalid}");
        if invalid == 0 && valid > 0 { Ok(()) } else { Err("invalid events present, or no events at all".to_string()) }
    }
}
