#![forbid(unsafe_code)]
//! Live store example (lab test, `lab/scripts/live-store-test.sh`).
//!
//! The composition of Koru's layers: real Pulsar events (the koru-pulsar embedded module) are translated
//! into Koru events and written to koru-store. The composition lives only in this crate: koru-store does not know koru-pulsar, koru-pulsar does not know koru-store. Translation rejection counters
//! (koru-pulsar `TranslationCounters`) are added to the store's rejection counters when the agent stops, so that
//! translation errors appear in the data-quality report.
//!
//! Root is required (eBPF). SIGINT or SIGTERM shuts it down cleanly.
//!
//! ```text
//! live_store agent --source-tag <synthetic|legitimate|real> --store <path>
//!     [--pulsar-config <toml>] [--host <name>] [--lineage-depth <n>] [--path-prefix <path>]...
//! ```

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::entry()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("live_store runs only on Linux (Pulsar, ADR-0003)");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::process::{Command, ExitCode};

    use koru_event::{Event, Sensor, SourceTag};
    use koru_pulsar::{BridgeSettings, PulsarSensor, init_logging};
    use koru_store::{IngestOutcome, RejectReason, Store, StoreSettings};

    const USAGE: &str = "usage:\n  live_store agent --source-tag <synthetic|legitimate|real> --store <path> \
[--pulsar-config <toml>] [--host <name>] [--lineage-depth <n>] [--path-prefix <path>]...";

    pub fn entry() -> ExitCode {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let result = match args.first().map(String::as_str) {
            Some("agent") => agent(&args[1..]),
            _ => Err(USAGE.to_string()),
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("[store] ERROR: {e}");
                ExitCode::FAILURE
            }
        }
    }

    fn read_options(args: &[String]) -> Result<BTreeMap<String, Vec<String>>, String> {
        let single_flags = ["--source-tag", "--store", "--pulsar-config", "--host", "--lineage-depth"];
        let mut result: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut i = 0;
        while i < args.len() {
            let name = args[i].as_str();
            if !single_flags.contains(&name) && name != "--path-prefix" {
                return Err(format!("unknown option: {name}\n{USAGE}"));
            }
            let value = args.get(i + 1).ok_or_else(|| format!("{name} has no value\n{USAGE}"))?;
            let values = result.entry(name.to_string()).or_default();
            if !values.is_empty() && name != "--path-prefix" {
                return Err(format!("{name} may be given only once"));
            }
            values.push(value.clone());
            i += 2;
        }
        Ok(result)
    }

    fn required_arg<'a>(s: &'a BTreeMap<String, Vec<String>>, name: &str) -> Result<&'a str, String> {
        s.get(name).and_then(|d| d.first()).map(String::as_str).ok_or_else(|| format!("{name} required_arg\n{USAGE}"))
    }

    fn agent(args: &[String]) -> Result<(), String> {
        let s = read_options(args)?;
        let source_tag = match required_arg(&s, "--source-tag")? {
            "synthetic" => SourceTag::Synthetic,
            "legitimate" => SourceTag::Legitimate,
            "real" => SourceTag::Real,
            other => return Err(format!("invalid source tag: {other}")),
        };
        let mut store =
            Store::open(StoreSettings::new(PathBuf::from(required_arg(&s, "--store")?))).map_err(|e| e.to_string())?;
        let host = match s.get("--host").and_then(|d| d.first()) {
            Some(a) => a.clone(),
            None => std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map_err(|e| format!("the host name could not be read: {e}"))?
                .trim()
                .to_string(),
        };
        let lineage_depth = match s.get("--lineage-depth").and_then(|d| d.first()) {
            Some(d) => d.parse().map_err(|_| format!("invalid lineage depth: {d}"))?,
            None => 16,
        };
        let timestamp_trusted = Command::new("timedatectl")
            .args(["show", "-p", "NTPSynchronized", "--value"])
            .output()
            .is_ok_and(|c| c.status.success() && String::from_utf8_lossy(&c.stdout).trim() == "yes");
        let sensor_settings = BridgeSettings {
            source_tag,
            host,
            timestamp_trusted,
            path_prefixes: s.get("--path-prefix").cloned().unwrap_or_default(),
            lineage_depth,
            pulsar_config: s.get("--pulsar-config").and_then(|d| d.first()).cloned(),
        };
        init_logging();
        eprintln!(
            "[store] starting the Pulsar agent with the Koru bridge module; store: {}",
            store.settings().path.display()
        );
        let mut sensor = PulsarSensor::new(sensor_settings);
        let counters = sensor.translation_counters();
        let (mut stored, mut duplicates, mut rejected) = (0u64, 0u64, 0u64);
        let mut store_errors: Option<String> = None;
        let result = sensor.run(&mut |event: Event| match store.store_event(&event) {
            Ok(IngestOutcome::Stored) => stored += 1,
            Ok(IngestOutcome::Duplicate) => duplicates += 1,
            Ok(IngestOutcome::Rejected(_)) => rejected += 1,
            Err(e) => {
                store_errors.get_or_insert(e.to_string());
            }
        });
        // Translation rejections: the counters join the data-quality report.
        let g = counters.snapshot();
        store
            .count_rejected(RejectReason::TranslationInvalidField, g.rejected_invalid_field)
            .map_err(|e| e.to_string())?;
        store.count_rejected(RejectReason::TranslationValidation, g.rejected_validation).map_err(|e| e.to_string())?;
        eprintln!(
            "[store] agent stopped; stored {stored}, duplicates {duplicates}, rejected {rejected}; \
translation: translated {}, rejected {} (invalid fields {}, validation {}), skipped THREAT copies {}, unsupported types {}",
            g.translated,
            g.rejected_total(),
            g.rejected_invalid_field,
            g.rejected_validation,
            g.skipped_threat_duplicate,
            g.skipped_unsupported_kind
        );
        if let Some(sample) = counters.first_rejection_sample() {
            eprintln!("[store] first translation rejection: {sample}");
        }
        if let Some(e) = store_errors {
            return Err(e);
        }
        result.map_err(|e| e.to_string())
    }
}
