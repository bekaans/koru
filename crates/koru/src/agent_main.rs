#![forbid(unsafe_code)]
//! koru-agent: the resident agent (ADR-0003 §7, ADR-0008). The Pulsar bridge, detection, store and
//! notify meet in one process; the composition is in `koru::agent`.
//!
//! ```text
//! koru-agent --config <config.toml>             runs indefinitely (Linux only, root)
//! koru-agent --validate --config <config.toml>   loads the config and the data packages,
//!                                                  summarizes and exits (does not touch eBPF)
//! ```
//!
//! Exit codes: 0 success, 1 runtime error, 2 usage error or unsupported platform.
//! At install the binary is copied under the configured process name (ADR-0008 §3); `systemctl stop` /
//! SIGTERM shuts it down cleanly and Koru emits the "stopped" event.

use std::path::PathBuf;
use std::process::ExitCode;

use koru::config::Config;
use koru_decoy::Catalog;
use koru_detect::{
    AgentSignatures, Allowlist, RulePack, SystemIdentitySource, Thresholds, read_agent_signatures, read_allowlist,
    read_rule_pack, read_thresholds,
};
use koru_event::DecoyCatalog;

const USAGE: &str = "usage:\n  koru-agent --config <config.toml>\n  koru-agent --validate --config <config.toml>";

/// Loaded data packages.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Packages {
    rules: RulePack,
    agents: AgentSignatures,
    thresholds: Thresholds,
    allowlist: Allowlist,
    catalog: Catalog,
}

fn load_packages(y: &Config) -> Result<Packages, String> {
    let data = y.current_link().join("data");
    let rules = read_rule_pack(&data.join("rules")).map_err(|e| format!("rule pack: {e}"))?;
    let agents = read_agent_signatures(&data.join("agents")).map_err(|e| format!("AI agent signatures: {e}"))?;
    let thresholds = read_thresholds(&data.join("thresholds.toml")).map_err(|e| format!("thresholds: {e}"))?;
    let catalog = Catalog::read(&y.decoy_state_dir()).map_err(|e| format!("decoy catalog: {e}"))?;
    let allowlist = match &y.detection.allowlist {
        Some(path) => read_allowlist(path)
            .and_then(|t| t.resolve(&SystemIdentitySource, &rules))
            .map_err(|e| format!("allowlist: {e}"))?,
        None => Allowlist::empty(),
    };
    Ok(Packages { rules, agents, thresholds, allowlist, catalog })
}

fn validate(y: &Config) -> Result<(), String> {
    let p = load_packages(y)?;
    println!("configuration is valid");
    println!("source tag: {}", format!("{:?}", y.agent.source_tag).to_lowercase());
    println!("{} rule", p.rules.rules().len());
    println!("{} AI agent signatures", p.agents.signatures().len());
    println!("{} allowlist entries", p.allowlist.len());
    println!("{} decoys and breadcrumbs watched", p.catalog.watched_paths().len());
    println!("raw event retention: {}", if y.store.store_raw_events { "on" } else { "off" });
    Ok(())
}

fn read_args() -> Result<(bool, PathBuf), String> {
    let mut validate = false;
    let mut settings_v: Option<PathBuf> = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--validate" => validate = true,
            "--config" => {
                if settings_v.is_some() {
                    return Err("--config may be given only once".into());
                }
                settings_v = Some(PathBuf::from(it.next().ok_or("--config needs a value")?));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok((validate, settings_v.ok_or("--config is required")?))
}

fn main() -> ExitCode {
    let (verify_mode, settings_path) = match read_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("koru-agent: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let y = match Config::read(&settings_path) {
        Ok(y) => y,
        Err(e) => {
            eprintln!("koru-agent: error: {e}");
            return ExitCode::from(1);
        }
    };
    if verify_mode {
        return match validate(&y) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("koru-agent: error: {e}");
                ExitCode::from(1)
            }
        };
    }
    continuous(&y)
}

#[cfg(not(target_os = "linux"))]
fn continuous(_y: &Config) -> ExitCode {
    eprintln!("koru-agent: resident operation is supported only on Linux (Pulsar, ADR-0003); --validate is usable");
    ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn continuous(y: &Config) -> ExitCode {
    match linux::run(y) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("koru-agent: error: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::process::Command;
    use std::time::Duration;

    use koru::agent::{Agent, AgentSettings, BackgroundNotifier, run as run_agent};
    use koru_detect::{DetectorSettings, KoruIdentity, RuleDetector, SystemIdentitySource};
    use koru_event::{Namespaces, is_valid_host};
    use koru_notify::{
        ChannelSet, ChannelSettings, Dispatcher, HealthchecksHeartbeat, HeartbeatLoop, NtfyChannel, SmtpChannel,
        TelegramChannel, read_dotenv,
    };
    use koru_pulsar::{BridgeSettings, PulsarSensor, init_logging};
    use koru_store::{Store, StoreSettings};

    use super::{Config, load_packages};

    /// The notification channel's pending-notification bound.
    const NOTIFICATION_CAPACITY: usize = 256;

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

    fn is_time_trusted() -> bool {
        Command::new("timedatectl")
            .args(["show", "-p", "NTPSynchronized", "--value"])
            .output()
            .is_ok_and(|c| c.status.success() && String::from_utf8_lossy(&c.stdout).trim() == "yes")
    }

    fn setup_distributor(y: &Config) -> Result<(Dispatcher, Option<HealthchecksHeartbeat>), String> {
        let values = read_dotenv(&y.env_file()).map_err(|e| format!("environment file: {e}"))?;
        let channels =
            ChannelSet::from_env(&|name| values.get(name).cloned()).map_err(|e| format!("environment file: {e}"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0));
        let mut d = Dispatcher::new(y.queue_dir());
        d.set_masking(channels.mask_ip);
        let settings_v = ChannelSettings::default();
        if let Some(n) = channels.ntfy {
            d.add_channel(Box::new(NtfyChannel::new(n)), settings_v, now).map_err(|e| format!("ntfy channel: {e}"))?;
        }
        if let Some(t) = channels.telegram {
            d.add_channel(Box::new(TelegramChannel::new(t)), settings_v, now)
                .map_err(|e| format!("telegram channel: {e}"))?;
        }
        if let Some(s) = channels.smtp {
            d.add_channel(Box::new(SmtpChannel::new(s)), settings_v, now).map_err(|e| format!("smtp channel: {e}"))?;
        }
        let heartbeat = channels.heartbeat.map(HealthchecksHeartbeat::new);
        Ok((d, heartbeat))
    }

    pub(super) fn run(y: &Config) -> Result<(), String> {
        let p = load_packages(y)?;
        let own = KoruIdentity::this_process().map_err(|e| format!("own process identity could not be read: {e}"))?;
        let host = match &y.agent.host {
            Some(a) => a.clone(),
            None => std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map_err(|e| format!("the host name could not be read: {e}"))?
                .trim()
                .to_string(),
        };
        if !is_valid_host(&host) {
            return Err("the host name does not match RFC 1123; set agent.host in the config".to_string());
        }
        let timestamp_trusted = is_time_trusted();
        let mut store = Store::open(StoreSettings::new(y.store_file()).retention_days(y.store.retention_days))
            .map_err(|e| format!("store: {e}"))?;
        // At start, expired records are deleted and the record limit is enforced.
        store.freeze(koru_event::Timestamp::now()).map_err(|e| format!("store rotation: {e}"))?;
        let (dispatcher, heartbeat) = setup_distributor(y)?;
        let notifier = BackgroundNotifier::start(dispatcher, NOTIFICATION_CAPACITY);
        let heartbeat = heartbeat.map(|k| HeartbeatLoop::start(k, Duration::from_secs(y.notify.heartbeat_seconds)));

        let mut detector = RuleDetector::new(
            DetectorSettings {
                rules: p.rules,
                agents: p.agents,
                thresholds: p.thresholds,
                allowlist: p.allowlist,
                self_protection: y.self_protection(),
                identity: Some(own),
                host_namespaces: Some(host_namespaces()?),
            },
            Box::new(p.catalog),
            Box::new(SystemIdentitySource),
        )
        .map_err(|e| e.to_string())?;

        let sensor_settings = BridgeSettings {
            source_tag: y.agent.source_tag,
            host: host.clone(),
            timestamp_trusted,
            path_prefixes: Vec::new(),
            lineage_depth: y.agent.lineage_depth,
            pulsar_config: Some(y.pulsar_config().display().to_string()),
        };
        init_logging();
        let mut sensor = PulsarSensor::new(sensor_settings);
        let counters = sensor.translation_counters();
        let result = run_agent(Agent {
            sensor: &mut sensor,
            detector: &mut detector,
            store: &mut store,
            notifier,
            heartbeat,
            translation_counters: Some(counters),
            settings: AgentSettings {
                source_tag: y.agent.source_tag,
                host,
                timestamp_trusted,
                store_raw_events: y.store.store_raw_events,
            },
        });
        eprintln!(
            "agent stopped; events processed {}, findings {}, stored {}, store errors {}, notifications dropped {}",
            result.processed, result.finding, result.stored, result.store_errors, result.notifications_dropped
        );
        match result.sensor_error {
            Some(h) => Err(format!("sensor: {h}")),
            None => Ok(()),
        }
    }
}
