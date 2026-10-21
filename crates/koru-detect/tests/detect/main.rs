//! koru-detect integration tests (the protected set).
//!
//! Covered:
//! - `json_schema`: `schemas/rule-pack.v1.json` and `schemas/agent-signature.v1.json`; a small
//!   JSON Schema validator.
//! - `yaml`: the YAML → JSON data model; anchor, alias, tag, duplicate key, depth, and size
//!   bounds.
//! - `rule_schema`: the rule schema applies the same rules in two places (JSON schema and Rust
//!   types); a rule without ATT&CK, with a revoked technique, or with an unsupported
//!   field/modifier is rejected; the repo's rules pass.
//! - `evaluator`: Sigma meaning (selections, value lists, modifiers, wildcards, escaping,
//!   condition).
//! - `agent_signatures`: the AI-agent signature schema and match examples.
//! - `stop_gaps`: glob patterns, init scripts, and abbreviated long options in stop detection.
//! - `thresholds`: `thresholds.toml`.
//! - `path`: lexical path normalization.
//! - `file_id`: the file-identity (device and inode) source; real files in a temporary
//!   directory, `/proc` on Linux.
//!   `/proc`.
//! - `breadcrumb_read_mode`: a read-capable (O_RDONLY, O_RDWR) open produces a breadcrumb
//!   finding; a write-only open does not (KT-58).
//! - `file_id_validation`: `verify_process_exe` (real exe path and inode; fail-closed on the real source).
//! - `allow_exec_bypass`: the allowlist and Koru's self-exclusion require the event's and the
//!   real exe together, against exec bypass.
//! - `allow_real_path`: the allowlist uses the process's real exe path (`/proc/<pid>/exe`).
//! - `scenarios`: decoy, breadcrumb, AI-agent lineage, actor kind, allowlist, self-protection,
//!   container, and exe-normalization scenarios with a fake sensor; findings comply with the
//!   event schema v1; finding events are not reprocessed (KT-30) and memory bounds hold
//!   (KT-31).
//! - `decoy_o_rdwr_ai_agent`: decoy access by a process whose lineage holds an AI agent, opened
//!   with `O_RDWR`, lands in the "suspected hijacked agent" class (KT-58).
//! - `attack`: the ATT&CK v20.0 catalog, the coverage table, and the Navigator layer.
//!
//! Tests do not write to the real file system (only `tempfile` directories) and spawn no
//! processes; process and inode information comes from fake sources.

mod agent_signatures;
mod allow_exec_bypass;
mod allow_real_path;
mod attack;
mod breadcrumb_read_mode;
mod common;
mod decoy_o_rdwr_ai_agent;
mod evaluator;
mod file_id;
mod file_id_validation;
mod json_schema;
mod path;
mod rule_schema;
mod scenarios;
mod stop_gaps;
mod thresholds;
mod yaml;
