# Configuration (TOML)

The agent takes a single TOML configuration (ADR-0008); see `crates/koru/src/config.rs` and `distribution/` for the install layout. Secret values come from `.env`, never from committed files.
