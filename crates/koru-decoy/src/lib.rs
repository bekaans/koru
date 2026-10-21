#![forbid(unsafe_code)]
//! # koru-decoy
//!
//! Koru decoys and breadcrumbs (ADR-0004).
//!
//! - Decoy definitions are data, not code: the `packages/decoys/*.toml` templates
//!   (`schemas/decoy-template.v1.json`; [`Template`]). Templates hold only placeholders; values
//!   are generated with a CSPRNG at install time ([`generate`]). Someone without Rust knowledge
//!   can add a new decoy kind by writing only a template; [`read_package`] and
//!   [`validate_directory`] validate a template against the schema, the safety rules, and trial
//!   generations.
//! - [`install`] writes the decoys safely (symlinks are not followed, existing files are not
//!   overwritten, a backup is taken before appending), gives every decoy a UUIDv7 id, and writes
//!   the integrity record (SHA-256, path, owner, mode, timestamp) to the state directory.
//! - [`uninstall`] touches only the recorded files and restores everything exactly; it does not
//!   blindly delete a decoy that changed after installation.
//! - [`integrity`] catches changes; [`Catalog`] implements `koru_event::DecoyCatalog`.
//!
//! This layer depends only on koru-event; it knows neither Pulsar, nor the other layers, nor
//! the sensor.

mod catalog;
mod error;
mod format;
mod generation;
mod generator;
mod install;
mod package;
mod placeholder;
mod random;
mod record;
mod safe_file;
mod template;

pub use catalog::Catalog;
pub use error::InstallError;
pub use generation::{Generation, GenerationError, generate};
pub use install::{
    InstallReport, InstallSettings, IntegrityReport, IntegrityResult, IntegrityStatus, RemovalReport, RemovalResult,
    RemovalStatus, install, integrity, list_entries, uninstall,
};
pub use package::{FileResult, Package, PackageError, ValidationReport, read_package, validate_directory};
pub use random::RandomError;
pub use record::{AppendInfo, PreviousFile, RecordEntry};
pub use template::{
    Alphabet, DecoyKind, Format, Placement, TEMPLATE_SCHEMA_VERSION, Target, Template, TemplateError, TimeRange, Value,
    parse_template,
};
