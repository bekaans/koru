#![forbid(unsafe_code)]
//! # koru-detect
//!
//! The Koru detection layer (ADR-0005).
//!
//! - **Rules are data:** `packages/rules/*.yml`, Sigma v2.1.0-compatible YAML
//!   (`schemas/rule-pack.v1.json`; [`Rule`], [`parse_rule`], [`read_rule_pack`]). Someone with
//!   no Rust can add a detection just by writing a rule file.
//! - **Evaluator:** `selection`, `condition` (and, or, not, parentheses, `1 of`, `all of`,
//!   `them`), and modifiers (contains, startswith, endswith, all, exists, cased). Wildcard
//!   characters (`*`, `?`) run on a linear bounded matcher instead of a regex engine.
//! - **Enrichment:** process lineage, AI-agent signatures (`packages/agents/*.toml`;
//!   [`AgentSignatures`]), decoy matching (`koru_event::DecoyCatalog`; koru-decoy is not
//!   known directly), container and self-protection fields. Koru-specific derived fields carry
//!   the `koru.` prefix ([`SUPPORTED_FIELDS`]).
//! - **Classification and actor kind:** decoy access in an AI agent's lineage is "suspected
//!   hijacked agent"; the actor kind (human, ai_agent, unknown) is estimated with a reason
//!   and a confidence, thresholds live in `thresholds.toml` ([`Thresholds`]).
//! - **Allowlist and self-protection:** Koru's own process is excluded only by the (exe path,
//!   inode, pid) triple ([`KoruIdentity`]); other entries need an exe path and inode, never a
//!   process name or command line ([`Allowlist`]). Changes to Koru's config, store, state,
//!   binary, and service files, and stop attempts, produce findings ([`SelfProtection`]).
//! - **ATT&CK:** every rule links to at least one valid ATT&CK v20.0 technique; a coverage
//!   table and a Navigator layer are generated ([`Coverage`]).
//!
//! This layer depends only on koru-event; it knows neither Pulsar, the other layers, nor the
//! sensor. It talks to other layers through
//! `koru_event::Detector` and `koru_event::DecoyCatalog`.

mod agent;
mod allowlist;
mod attack;
mod detector;
mod fields;
mod file;
mod file_id;
mod path;
mod pattern;
mod protection;
mod rule;
mod shell;
mod sigma;
mod threshold;
mod yaml;

pub use agent::{AgentError, AgentKind, AgentSignature, AgentSignatures, parse_agent_signature, read_agent_signatures};
pub use allowlist::{Allowlist, AllowlistDefinition, AllowlistError, parse_allowlist, read_allowlist};
pub use attack::{
    ATTACK_VERSION, AttackStatus, AttackTactic, AttackTechnique, Coverage, RuleCoverage, TechniqueCoverage,
    attack_tactic, attack_technique, coverage, coverage_markdown, navigator_layer,
};
pub use detector::{DetectorError, DetectorSettings, Finding, RuleDetector, SelfEventContext};
pub use fields::{FieldSet, FieldValue, SUPPORTED_FIELDS};
pub use file_id::{FileIdentity, IdentitySource, KoruIdentity, SystemIdentitySource};
pub use path::normalize_path;
pub use protection::SelfProtection;
pub use rule::{
    Level, Rule, RuleError, RuleFileResult, RulePack, RuleStatus, RuleValidationReport, parse_rule, read_rule_file,
    read_rule_pack, validate_rule_dir,
};
pub use sigma::export_sigma;
pub use threshold::{
    ActorThresholds, DiscoveryThreshold, HumanSpeedThreshold, MachineSpeedThreshold, MemoryThresholds, ShellDefinition,
    ThresholdError, Thresholds, parse_thresholds, read_thresholds,
};
pub use yaml::yaml_json;
