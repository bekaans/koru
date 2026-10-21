//! `thresholds.toml`: thresholds for actor-kind estimation (a protected set).

use std::path::Path;

use serde::Deserialize;

/// A threshold-file error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ThresholdError {
    /// A schema or semantic violation.
    #[error("thresholds.toml: {0}")]
    Invalid(String),
    /// The file could not be read.
    #[error("{path}: {reason}")]
    Unreadable {
        /// The path.
        path: String,
        /// The reason.
        reason: String,
    },
}

/// Thresholds (version 1).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    /// The file format version (1).
    pub version: u32,
    /// Actor-kind estimation.
    pub actor: ActorThresholds,
    /// Memory bounds.
    pub memory: MemoryThresholds,
}

/// Confidence values and signal thresholds for actor-kind estimation.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorThresholds {
    /// A signature.
    pub agent_signature_confidence: f64,
    /// A signature and machine speed.
    pub agent_signature_and_machine_speed_confidence: f64,
    /// Machine speed and a discovery pattern (no signature).
    pub machine_speed_and_discovery_confidence: f64,
    /// An interactive shell.
    pub interactive_shell_confidence: f64,
    /// An interactive shell and measured human speed.
    pub interactive_shell_and_human_speed_confidence: f64,
    /// Machine speed.
    pub machine_speed: MachineSpeedThreshold,
    /// Human speed.
    pub human_speed: HumanSpeedThreshold,
    /// A discovery pattern.
    pub discovery: DiscoveryThreshold,
    /// What counts as an interactive shell.
    pub shell: ShellDefinition,
}

/// The machine-speed threshold.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSpeedThreshold {
    /// Machine speed when the median inter-command interval is below this (ms).
    pub command_interval_median_ms: u64,
    /// The minimum number of command intervals.
    pub min_intervals: u32,
    /// Window (s).
    pub window_secs: u64,
}

/// The human-speed threshold.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanSpeedThreshold {
    /// Human speed when the median inter-command interval is above this (ms).
    pub command_interval_median_ms: u64,
    /// The minimum number of command intervals.
    pub min_intervals: u32,
}

/// The discovery-pattern threshold.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryThreshold {
    /// The minimum number of distinct discovery commands in the window.
    pub min_distinct_commands: u32,
    /// Window (s).
    pub window_secs: u64,
    /// Discovery commands (exe base names).
    pub commands: Vec<String>,
}

/// Programs counted as interactive shells.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellDefinition {
    /// Exe base names.
    pub names: Vec<String>,
}

/// Memory bounds for actor state.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryThresholds {
    /// The most tracked sessions (parent processes).
    pub max_sessions: usize,
    /// The most command records per session.
    pub max_commands_per_session: usize,
}

/// The largest threshold file (bytes).
const MAX_FILES: u64 = 64 * 1024;

fn invalid<T>(message: impl Into<String>) -> Result<T, ThresholdError> {
    Err(ThresholdError::Invalid(message.into()))
}

fn valid_confidence(name: &str, g: f64) -> Result<(), ThresholdError> {
    if g.is_finite() && g > 0.0 && g <= 1.0 {
        Ok(())
    } else {
        invalid(format!("{name} must be between 0 and 1 (0 exclusive, 1 inclusive): {g}"))
    }
}

fn greater_than_zero(name: &str, value: u64) -> Result<(), ThresholdError> {
    if value > 0 { Ok(()) } else { invalid(format!("{name} must be greater than zero")) }
}

fn name_list(name: &str, string_list: &[String]) -> Result<(), ThresholdError> {
    if string_list.is_empty() {
        return invalid(format!("{name} cannot be empty"));
    }
    for a in string_list {
        if a.is_empty() || a.contains('/') || a.contains('\0') || a.chars().any(char::is_whitespace) {
            return invalid(format!("{name}: an invalid program name: {}", crate::file::sanitize(a)));
        }
    }
    Ok(())
}

/// Parses and validates threshold text: confidences between 0 and 1 in a consistent order,
/// the human-speed threshold above the machine-speed one, numbers above zero, lists
/// non-empty.
pub fn parse_thresholds(text: &str) -> Result<Thresholds, ThresholdError> {
    let e: Thresholds = toml::from_str(text).map_err(|e| ThresholdError::Invalid(e.message().to_string()))?;
    if e.version != 1 {
        return invalid(format!("unsupported version {} (expected 1)", e.version));
    }
    let a = &e.actor;
    valid_confidence("agent_signature_confidence", a.agent_signature_confidence)?;
    valid_confidence("agent_signature_and_machine_speed_confidence", a.agent_signature_and_machine_speed_confidence)?;
    valid_confidence("machine_speed_and_discovery_confidence", a.machine_speed_and_discovery_confidence)?;
    valid_confidence("interactive_shell_confidence", a.interactive_shell_confidence)?;
    valid_confidence("interactive_shell_and_human_speed_confidence", a.interactive_shell_and_human_speed_confidence)?;
    if a.agent_signature_and_machine_speed_confidence < a.agent_signature_confidence {
        return invalid(
            "agent_signature_and_machine_speed_confidence cannot be below agent_signature_confidence (two signals are stronger than one)",
        );
    }
    if a.interactive_shell_and_human_speed_confidence < a.interactive_shell_confidence {
        return invalid("interactive_shell_and_human_speed_confidence cannot be below interactive_shell_confidence");
    }
    greater_than_zero("machine_speed.command_interval_median_ms", a.machine_speed.command_interval_median_ms)?;
    greater_than_zero("machine_speed.min_intervals", u64::from(a.machine_speed.min_intervals))?;
    greater_than_zero("machine_speed.window_secs", a.machine_speed.window_secs)?;
    greater_than_zero("human_speed.min_intervals", u64::from(a.human_speed.min_intervals))?;
    if a.human_speed.command_interval_median_ms <= a.machine_speed.command_interval_median_ms {
        return invalid(
            "human_speed.command_interval_median_ms must be greater than machine_speed.command_interval_median_ms",
        );
    }
    greater_than_zero("discovery.min_distinct_commands", u64::from(a.discovery.min_distinct_commands))?;
    greater_than_zero("discovery.window_secs", a.discovery.window_secs)?;
    name_list("discovery.commands", &a.discovery.commands)?;
    name_list("shell.names", &a.shell.names)?;
    greater_than_zero("memory.max_sessions", e.memory.max_sessions as u64)?;
    greater_than_zero("memory.max_commands_per_session", e.memory.max_commands_per_session as u64)?;
    Ok(e)
}

/// Reads a threshold file.
pub fn read_thresholds(file: &Path) -> Result<Thresholds, ThresholdError> {
    let text = crate::file::read_regular_file(file, MAX_FILES)
        .map_err(|reason| ThresholdError::Unreadable { path: file.display().to_string(), reason })?;
    parse_thresholds(&text)
}
