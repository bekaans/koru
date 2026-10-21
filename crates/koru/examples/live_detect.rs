#![forbid(unsafe_code)]
//! Live detection example (lab test, `lab/scripts/live-detect-test.sh`).
//!
//! The composition of Koru's layers: real Pulsar events (the koru-pulsar embedded module) are translated
//! into Koru events, run through koru-detect, and findings are written to stdout as JSON lines.
//! The composition lives only in this crate: koru-detect knows neither koru-pulsar
//! nor koru-decoy; the decoy catalog is supplied through the `DecoyCatalog` trait.
//!
//! Root is required (eBPF). On a clean SIGINT or SIGTERM shutdown Koru also emits the "stopped" event
//! (a self-protection finding).
//!
//! Validation mode: checks the finding lines against event schema v1 (serde + `Event::validate`).
//!
//! ```text
//! live_detect validate <findings.jsonl>
//! live_detect agent --source-tag <synthetic|legitimate|real> --rules <dir> --agents <dir>
//!     --thresholds <file> --decoy-state <dir> [--allowlist <toml>]
//!     [--koru-config <path>]... [--koru-secret <path>]... [--koru-store <path>]...
//!     [--koru-state <path>]... [--koru-binary <path>]... [--koru-service-file <path>]...
//!     [--koru-service <name>]... [--koru-process <name>]...
//!     [--pulsar-config <toml>] [--host <name>] [--lineage-depth <n>] [--event-output <jsonl>]
//! ```

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::entry()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("live_detect runs only on Linux (Pulsar, ADR-0003)");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::path::Path;
    use std::process::{Command, ExitCode};

    use koru_decoy::Catalog;
    use koru_detect::{
        Allowlist, DetectorSettings, Finding, KoruIdentity, RuleDetector, SelfEventContext, SelfProtection,
        SystemIdentitySource, read_agent_signatures, read_allowlist, read_rule_pack, read_thresholds,
    };
    use koru_event::{Event, Namespaces, Sensor, SourceTag, Timestamp};
    use koru_pulsar::{BridgeSettings, PulsarSensor, init_logging};

    const USAGE: &str = "usage:\n  live_detect validate <findings.jsonl>\n  live_detect agent --source-tag <synthetic|legitimate|real> --rules <dir> \
--agents <dir> --thresholds <file> --decoy-state <dir> [--allowlist <toml>] [--koru-config <path>]... \
[--koru-secret <path>]... [--koru-store <path>]... [--koru-state <path>]... [--koru-binary <path>]... \
[--koru-service-file <path>]... [--koru-service <name>]... [--koru-process <name>]... \
[--pulsar-config <toml>] [--host <name>] [--lineage-depth <n>] [--event-output <jsonl>]";

    const REPEATABLE: [&str; 8] = [
        "--koru-config",
        "--koru-secret",
        "--koru-store",
        "--koru-state",
        "--koru-binary",
        "--koru-service-file",
        "--koru-service",
        "--koru-process",
    ];
    const SINGLE: [&str; 10] = [
        "--source-tag",
        "--rules",
        "--agents",
        "--thresholds",
        "--decoy-state",
        "--allowlist",
        "--pulsar-config",
        "--host",
        "--lineage-depth",
        "--event-output",
    ];

    pub fn entry() -> ExitCode {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let result = match args.first().map(String::as_str) {
            Some("agent") => agent(&args[1..]),
            Some("validate") if args.len() == 2 => validate(&args[1]),
            _ => Err(USAGE.to_string()),
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("[detection] ERROR: {e}");
                ExitCode::FAILURE
            }
        }
    }

    /// `--name value` pairs; repeatable options take several values.
    fn read_options(args: &[String]) -> Result<BTreeMap<String, Vec<String>>, String> {
        let mut result: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut i = 0;
        while i < args.len() {
            let name = args[i].as_str();
            if !SINGLE.contains(&name) && !REPEATABLE.contains(&name) {
                return Err(format!("unknown option: {name}\n{USAGE}"));
            }
            let value = args.get(i + 1).ok_or_else(|| format!("{name} has no value\n{USAGE}"))?;
            let values = result.entry(name.to_string()).or_default();
            if !values.is_empty() && !REPEATABLE.contains(&name) {
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

    /// The host's (pid 1's) namespaces; when unreadable, the process's own.
    fn host_namespaces() -> Result<Namespaces, String> {
        let read = |name: &str| -> Result<u32, String> {
            let path = std::fs::read_link(format!("/proc/1/ns/{name}"))
                .or_else(|_| std::fs::read_link(format!("/proc/self/ns/{name}")))
                .map_err(|e| format!("namespace {name} could not be read: {e}"))?;
            let text = path.to_string_lossy().into_owned();
            text.split_once('[')
                .and_then(|(_, remaining)| remaining.strip_suffix(']'))
                .and_then(|number| number.parse().ok())
                .ok_or_else(|| format!("namespace {name} could not be parsed: {text}"))
        };
        Ok(Namespaces {
            uts: read("uts")?,
            ipc: read("ipc")?,
            mnt: read("mnt")?,
            pid: read("pid")?,
            net: read("net")?,
            time: read("time")?,
            cgroup: read("cgroup")?,
        })
    }

    fn write(b: &Finding) -> Result<(), String> {
        let line = serde_json::json!({ "title": b.title, "severity": b.severity.sigma_name(), "event": b.event });
        let mut output = std::io::stdout().lock();
        writeln!(output, "{line}")
            .and_then(|()| output.flush())
            .map_err(|e| format!("the output could not be written: {e}"))?;
        if let Some(t) = &b.event.detection {
            eprintln!(
                "[detection] {} | class {:?} | level {} | actor {:?} ({:.2}) | decoy {}",
                t.rule,
                t.threat_class,
                b.severity.sigma_name(),
                b.event.actor.kind,
                b.event.actor.confidence.value(),
                t.decoy_id.as_deref().unwrap_or("-")
            );
        }
        Ok(())
    }

    /// Schema-v1 validation of the finding lines (`{title, level, event}`).
    fn validate(path: &str) -> Result<(), String> {
        let file = std::fs::File::open(path).map_err(|e| format!("{path} could not be opened: {e}"))?;
        let (mut valid, mut invalid) = (0u64, 0u64);
        for (no, line) in BufReader::new(file).lines().enumerate() {
            let line = line.map_err(|e| format!("{path} could not be read: {e}"))?;
            if line.trim().is_empty() {
                continue;
            }
            let result = serde_json::from_str::<serde_json::Value>(&line)
                .map_err(|e| e.to_string())
                .and_then(|v| v.get("event").cloned().ok_or_else(|| "the event field is missing".to_string()))
                .and_then(|o| serde_json::from_value::<Event>(o).map_err(|e| e.to_string()))
                .and_then(|o| {
                    o.validate().map_err(|e| e.to_string())?;
                    match &o.detection {
                        Some(t) if !t.attack.is_empty() && o.tags.mitre_techniques == t.attack => Ok(()),
                        Some(_) => {
                            Err("detection.attack and tags.mitre_techniques are inconsistent or empty".to_string())
                        }
                        None => Err("detection is missing from the finding".to_string()),
                    }
                });
            match result {
                Ok(()) => valid += 1,
                Err(e) => {
                    invalid += 1;
                    eprintln!("[detection] line {}: invalid: {e}", no + 1);
                }
            }
        }
        println!("schema v1 validation: valid {valid}, invalid {invalid}");
        if invalid == 0 && valid > 0 {
            Ok(())
        } else {
            Err("there is an invalid finding, or no findings at all".to_string())
        }
    }

    fn agent(args: &[String]) -> Result<(), String> {
        let s = read_options(args)?;
        let source_tag = match required_arg(&s, "--source-tag")? {
            "synthetic" => SourceTag::Synthetic,
            "legitimate" => SourceTag::Legitimate,
            "real" => SourceTag::Real,
            other => return Err(format!("invalid source tag: {other}")),
        };
        let rules = read_rule_pack(Path::new(required_arg(&s, "--rules")?)).map_err(|e| e.to_string())?;
        let agents = read_agent_signatures(Path::new(required_arg(&s, "--agents")?)).map_err(|e| e.to_string())?;
        let thresholds = read_thresholds(Path::new(required_arg(&s, "--thresholds")?)).map_err(|e| e.to_string())?;
        let catalog = Catalog::read(Path::new(required_arg(&s, "--decoy-state")?)).map_err(|e| e.to_string())?;
        let allowlist = match s.get("--allowlist").and_then(|d| d.first()) {
            Some(path) => read_allowlist(Path::new(path))
                .and_then(|t| t.resolve(&SystemIdentitySource, &rules))
                .map_err(|e| e.to_string())?,
            None => Allowlist::empty(),
        };
        let list = |name: &str| s.get(name).cloned().unwrap_or_default();
        let self_protection = SelfProtection {
            config: list("--koru-config"),
            secret: list("--koru-secret"),
            store: list("--koru-store"),
            state: list("--koru-state"),
            binaries: list("--koru-binary"),
            service_files: list("--koru-service-file"),
            service_names: list("--koru-service"),
            process_names: list("--koru-process"),
        };
        let koru = KoruIdentity::this_process().map_err(|e| format!("own process identity could not be read: {e}"))?;
        eprintln!("[detection] Koru process: pid {}, exe {}", koru.pid, koru.exe);
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
        // The NTP sync state is read once when the agent starts (no continuous watching).
        let timestamp_trusted = Command::new("timedatectl")
            .args(["show", "-p", "NTPSynchronized", "--value"])
            .output()
            .is_ok_and(|c| c.status.success() && String::from_utf8_lossy(&c.stdout).trim() == "yes");

        let settings = DetectorSettings {
            rules,
            agents,
            thresholds,
            allowlist,
            self_protection,
            identity: Some(koru),
            host_namespaces: Some(host_namespaces()?),
        };
        eprintln!(
            "[detection] {} rules, {} agent signatures, {} allowlist entries, {} decoys and breadcrumbs",
            settings.rules.rules().len(),
            settings.agents.signatures().len(),
            settings.allowlist.len(),
            koru_event::DecoyCatalog::watched_paths(&catalog).len()
        );
        let mut detector = RuleDetector::new(settings, Box::new(catalog), Box::new(SystemIdentitySource))
            .map_err(|e| e.to_string())?;

        let sensor_settings = BridgeSettings {
            source_tag,
            host: host.clone(),
            timestamp_trusted,
            path_prefixes: Vec::new(),
            lineage_depth,
            pulsar_config: s.get("--pulsar-config").and_then(|d| d.first()).cloned(),
        };
        init_logging();
        eprintln!("[detection] starting the Pulsar agent with the Koru bridge module");
        // Dump of the source events for golden data (when given, each event is one JSON line).
        let mut event_output: Option<std::io::BufWriter<std::fs::File>> =
            match s.get("--event-output").and_then(|d| d.first()) {
                Some(path) => Some(std::io::BufWriter::new(
                    std::fs::File::create(path).map_err(|e| format!("the event output could not be opened: {e}"))?,
                )),
                None => None,
            };
        let (mut processed, mut finding_count) = (0u64, 0u64);
        let mut write_error: Option<String> = None;
        let mut sensor = PulsarSensor::new(sensor_settings);
        let result = sensor.run(&mut |event: Event| {
            processed += 1;
            if let Some(c) = event_output.as_mut() {
                let line = serde_json::to_string(&event).unwrap_or_default();
                use std::io::Write as _;
                let _ = writeln!(c, "{line}").and_then(|()| c.flush());
            }
            for b in detector.process(&event) {
                finding_count += 1;
                if let Err(e) = write(&b) {
                    write_error.get_or_insert(e);
                }
            }
        });
        // Clean shutdown: the Pulsar agent stopped on SIGINT/SIGTERM; Koru emits its own "stopped" event.
        let self_context = SelfEventContext { timestamp: Timestamp::now(), timestamp_trusted, source_tag, host };
        for b in detector.stopped(&self_context) {
            finding_count += 1;
            if let Err(e) = write(&b) {
                write_error.get_or_insert(e);
            }
        }
        eprintln!(
            "[detection] agent stopped; events processed: {processed}, findings: {finding_count}, muted by the allowlist: {}",
            detector.suppressed_count()
        );
        if let Some(e) = write_error {
            return Err(e);
        }
        result.map_err(|e| e.to_string())
    }
}
