//! Embedded module (ADR-0001): the Koru bridge module runs inside the Pulsar agent, in the same
//! process as Pulsar's built-in modules; it enriches bus events with the process tracker, translates
//! them into Koru events and hands them out through the [`koru_event::Sensor`] interface.
//!
//! The bridge module never writes events to the bus; it filters THREAT events before translating (KT-30).

use std::sync::Arc;
use std::time::SystemTime;

use koru_event::{AncestorProcess, InterfaceError, Namespaces, Sensor, SensorInfo, SourceTag, Untrusted};
use pulsar_core::pdk::process_tracker::ProcessTrackerHandle;
use pulsar_core::pdk::{Event, ModuleContext, ModuleError, NoConfig, Payload, SimplePulsarModule};
use pulsar_core::{Pid, Timestamp};
use tokio::sync::mpsc;

use crate::{
    KORU_MODULE_NAME, ProcessAttachment, TranslationContext, TranslationCounters, count_translation, translate,
};

/// Pulsar version: a pinned commit on main (Cargo.toml `rev`, ADR-0003).
pub const PULSAR_VERSION: &str = "0.11.0-alpha.1+0bb7bc20";

/// Capacity of the channel carrying translated events from the bridge module. If it fills up the
/// module waits; the Pulsar bus then leaves the module behind and logs the lost events (measured in the end-to-end suite).
const CHANNEL_CAPACITY: usize = 10_000;

/// Bridge and agent settings.
#[derive(Debug, Clone)]
pub struct BridgeSettings {
    /// The install's source tag.
    pub source_tag: SourceTag,
    /// Host name.
    pub host: String,
    /// Whether the clock is NTP-synchronized. Determined once at agent start; there is no continuous watching.
    pub timestamp_trusted: bool,
    /// If non-empty, only events about paths starting with these prefixes (a file path, the exec'd
    /// file or argv, the process binary) are translated. If empty, all supported events are translated.
    pub path_prefixes: Vec<String>,
    /// How many ancestor processes at most to collect in the lineage.
    pub lineage_depth: usize,
    /// The Pulsar config file (Pulsar main: TOML); `None` means Pulsar's default.
    pub pulsar_config: Option<String>,
}

/// Starts writing Pulsar's logs (`RUST_LOG`; otherwise info level) to stderr. Lets composition code
/// that does not depend on Pulsar directly (the `koru` crate) turn logging on.
pub fn init_logging() {
    pulsar::init_logger(None);
}

/// The Pulsar sensor's info: name, version and the platform it runs on.
pub fn pulsar_sensor_info() -> SensorInfo {
    SensorInfo {
        name: "pulsar".to_string(),
        version: PULSAR_VERSION.to_string(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
    }
}

/// The Pulsar-based Koru sensor. `run` starts the Pulsar agent with the Koru bridge module and
/// hands every Koru event to the receiver until the agent stops (SIGINT/SIGTERM). Needs root.
#[derive(Debug, Clone)]
pub struct PulsarSensor {
    settings: BridgeSettings,
    counters: Arc<TranslationCounters>,
}

impl PulsarSensor {
    /// A new sensor.
    pub fn new(settings: BridgeSettings) -> PulsarSensor {
        PulsarSensor { settings, counters: Arc::new(TranslationCounters::default()) }
    }

    /// Translation counters: the rejected (translation errors) and the deliberately skipped.
    /// The composition forwards them to the data-quality report.
    pub fn translation_counters(&self) -> Arc<TranslationCounters> {
        Arc::clone(&self.counters)
    }
}

impl Sensor for PulsarSensor {
    fn info(&self) -> SensorInfo {
        pulsar_sensor_info()
    }

    fn run(&mut self, receiver: &mut dyn FnMut(koru_event::Event)) -> Result<(), InterfaceError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| InterfaceError::Permanent(format!("could not create the tokio runtime: {e}")))?;
        let settings = self.settings.clone();
        let counters = Arc::clone(&self.counters);
        runtime.block_on(async move {
            let (sender, mut received) = mpsc::channel::<koru_event::Event>(CHANNEL_CAPACITY);
            let module = KoruBridgeModule {
                sender,
                context: Arc::new(TranslationContext {
                    source_tag: settings.source_tag,
                    host: settings.host.clone(),
                    timestamp_trusted: settings.timestamp_trusted,
                    sensor: pulsar_sensor_info(),
                }),
                path_prefixes: Arc::new(settings.path_prefixes.clone()),
                lineage_depth: settings.lineage_depth,
                counters: Arc::clone(&counters),
            };
            let options = pulsar::pulsard::PulsarDaemonOpts { config_file: settings.pulsar_config.clone() };
            let agent = pulsar::pulsard::pulsar_daemon_run(&options, move |builder| {
                builder.add_module(module)?;
                Ok(())
            });
            tokio::pin!(agent);
            loop {
                tokio::select! {
                    result = &mut agent => {
                        // The agent stopped; events remaining in the channel are still delivered.
                        while let Ok(event) = received.try_recv() {
                            receiver(event);
                        }
                        return result.map_err(|e| InterfaceError::Permanent(format!("Pulsar agent: {e:#}")));
                    }
                    Some(event) = received.recv() => receiver(event),
                }
            }
        })
    }
}

/// The Pulsar module.
struct KoruBridgeModule {
    sender: mpsc::Sender<koru_event::Event>,
    context: Arc<TranslationContext>,
    path_prefixes: Arc<Vec<String>>,
    lineage_depth: usize,
    counters: Arc<TranslationCounters>,
}

/// The module's state.
struct BridgeState {
    sender: mpsc::Sender<koru_event::Event>,
    context: Arc<TranslationContext>,
    path_prefixes: Arc<Vec<String>>,
    lineage_depth: usize,
    counters: Arc<TranslationCounters>,
    tracker: ProcessTrackerHandle,
    own_pid: i32,
}

impl SimplePulsarModule for KoruBridgeModule {
    type Config = NoConfig;
    type State = BridgeState;

    const MODULE_NAME: &'static str = KORU_MODULE_NAME;
    const DEFAULT_ENABLED: bool = true;

    async fn init_state(&self, _config: &Self::Config, ctx: &ModuleContext) -> Result<Self::State, ModuleError> {
        Ok(BridgeState {
            sender: self.sender.clone(),
            context: Arc::clone(&self.context),
            path_prefixes: Arc::clone(&self.path_prefixes),
            lineage_depth: self.lineage_depth,
            counters: Arc::clone(&self.counters),
            tracker: ctx.get_process_tracker(),
            own_pid: i32::try_from(std::process::id()).unwrap_or(i32::MAX),
        })
    }

    async fn on_event(
        event: &Event,
        _config: &Self::Config,
        state: &mut Self::State,
        _ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        let h = event.header();
        // KT-30: THREAT copies (including Koru's own) are dropped without any processing.
        // The agent's own process is not translated either (its output's events must not feed back).
        if h.threat.is_some() || h.pid == state.own_pid || !is_relevant(event, &state.path_prefixes) {
            return Ok(());
        }
        let attachment = process_attachment(&state.tracker, event, state.lineage_depth).await;
        // A translation error is never dropped silently: it is counted.
        if let Some(koru_event) = count_translation(translate(event, &attachment, &state.context), &state.counters) {
            // If the receiver is closed (the agent is stopping) the event is dropped.
            let _ = state.sender.send(*koru_event).await;
        }
        Ok(())
    }
}

/// Whether the event matches the path-prefix filter.
fn is_relevant(event: &Event, prefixes: &[String]) -> bool {
    if prefixes.is_empty() {
        return true;
    }
    let matches = |s: &str| prefixes.iter().any(|o| s.starts_with(o.as_str()));
    if matches(&event.header().image) {
        return true;
    }
    match event.payload() {
        Payload::FileOpened { filename, .. }
        | Payload::FileCreated { filename }
        | Payload::FileDeleted { filename } => matches(filename),
        Payload::DirCreated { dirname } | Payload::DirDeleted { dirname } => matches(dirname),
        Payload::FileRename { source, destination } | Payload::FileLink { source, destination, .. } => {
            matches(source) || matches(destination)
        }
        Payload::Exec { filename, argv, .. } => {
            matches(filename) || Vec::<String>::from(argv.clone()).iter().any(|a| matches(a))
        }
        _ => false,
    }
}

/// Converts the event's time to the monotonic clock the process tracker uses (ns since boot).
/// For short-lived processes, querying with `Timestamp::now()` races (ADR-0001, KT-20).
fn event_time(timestamp: SystemTime) -> Timestamp {
    let elapsed = SystemTime::now().duration_since(timestamp).unwrap_or_default();
    let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
    Timestamp::from(Timestamp::now().raw().saturating_sub(elapsed_ns))
}

/// The command line, namespaces and lineage from the process tracker.
async fn process_attachment(tracker: &ProcessTrackerHandle, event: &Event, depth: usize) -> ProcessAttachment {
    let timestamp = event_time(event.header().timestamp);
    let mut attachment = ProcessAttachment::default();
    let Ok(info) = tracker.get(Pid::from_raw(event.header().pid), timestamp).await else {
        return attachment;
    };
    attachment.command_line = Some(info.argv.clone());
    let ns = info.namespaces;
    attachment.namespaces = Some(Namespaces {
        uts: ns.uts,
        ipc: ns.ipc,
        mnt: ns.mnt,
        pid: ns.pid,
        net: ns.net,
        time: ns.time,
        cgroup: ns.cgroup,
    });
    let mut parent_pid = info.ppid;
    for _ in 0..depth {
        let Ok(raw_pid) = u32::try_from(parent_pid.as_raw()) else { break };
        if raw_pid == 0 {
            break;
        }
        let Ok(parent) = tracker.get(parent_pid, timestamp).await else { break };
        attachment.lineage.push(AncestorProcess {
            pid: raw_pid,
            exe: Untrusted::new(parent.image.clone()),
            command_line: Untrusted::new(parent.argv.clone()),
        });
        if raw_pid == 1 {
            break;
        }
        parent_pid = parent.ppid;
    }
    attachment
}
