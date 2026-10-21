//! The koru-decoy integration tests (a protected set).
//!
//! What is checked:
//! - `template_schema`: the template schema applies the same rules in two places (the JSON
//!   schema and the Rust types); malformed, incomplete, or unknown-field templates are
//!   rejected; template safety rules.
//! - `format`: generated decoys parsed by real tools (ssh-keygen, ssh -G, JSON,
//!   INI, .env, SQL).
//! - `uniqueness`: no generated value shared between two installs, no "koru" string, ids
//!   unique and invisible in content, timestamps natural.
//! - `integrity`: the integrity record and change detection; the `DecoyCatalog` implementation.
//! - `rollback`: the pre-install snapshot = the post-removal snapshot; existing files coming
//!   back from backup byte for byte.
//! - `safe_write`: symbolic links, `..`, targets outside the root, and unsafe file kinds.
//! - `removal_safety`: removal does not rewrite a hard-linked or re-owned file
//!   (it is reported and left in place).
//! - `catalog_class`: `DecoyCatalog` gives the decoy class of each path.
//!
//! A HARD RULE: these tests never write to a real home directory or system paths. The root and
//! the state directory are always temporary directories opened with `tempfile`; external
//! commands (`ssh`, `ssh-keygen`, `mkfifo`) run with `HOME` pointed at the temporary directory.

mod catalog_class;
mod common;
mod format;
mod integrity;
mod removal_safety;
mod rollback;
mod safe_write;
mod template_schema;
mod uniqueness;
