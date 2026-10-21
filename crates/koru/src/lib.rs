#![forbid(unsafe_code)]
//! # koru (library)
//!
//! Shared code of the `koru` CLI and the `koru-agent` binary. The layers are composed only in this crate
//! (ADR-0003 §7, ADR-0008).

pub mod agent;
pub mod config;
pub mod distribution;
pub mod input;
mod safe_read;
