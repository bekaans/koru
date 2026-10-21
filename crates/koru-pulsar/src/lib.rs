#![forbid(unsafe_code)]
//! # koru-pulsar
//!
//! Koru's Pulsar (Rust + eBPF) sensor. This is the **only** Koru crate that depends on the Pulsar crates (`dependency-rules.toml`).
//!
//! - Embedded module path (ADR-0001): the Koru bridge module runs inside the Pulsar agent
//!   via `pulsar_daemon_run` + `add_module` ([`PulsarSensor`]).
//! - Translation: [`translate`] maps a Pulsar event to a Koru event (schema v1); the command line,
//!   namespaces and lineage from the process tracker come via [`ProcessAttachment`]. Mapping rules: ADR-0003.
//! - KT-30: events with `header.threat` present (including Koru's own THREATs) are not translated.
//!
//! Pulsar compiles only on Linux. The Pulsar-dependent parts (`translate`, [`PulsarSensor`])
//! sit behind `cfg(target_os = "linux")`; on other platforms this crate holds only the translation
//! types and the workspace keeps building (ADR-0003).

#[cfg(target_os = "linux")]
mod bridge;
#[cfg(target_os = "linux")]
mod pulsar_translation;
mod translation;

#[cfg(target_os = "linux")]
pub use bridge::{BridgeSettings, PULSAR_VERSION, PulsarSensor, init_logging, pulsar_sensor_info};
#[cfg(target_os = "linux")]
pub use pulsar_translation::translate;
pub use translation::{
    KORU_MODULE_NAME, ProcessAttachment, SkipReason, Translation, TranslationContext, TranslationCounters,
    TranslationCountersSnapshot, TranslationError, count_translation,
};
