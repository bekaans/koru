# koru-decoy

Decoys and breadcrumbs. Decoy definitions are TOML templates (`packages/decoys/`), not code, so a
new decoy kind needs no Rust.

## Layer and dependencies

Layer: core. Allowed Koru dependency: `koru-event`. External dependencies (in
`dependency-rules.toml`): `serde`, `toml`, `serde_json`, `thiserror`, `uuid`, `getrandom`,
`sha2`, `ed25519-dalek` and `rustix`; `tempfile` for tests. It knows neither Pulsar nor the other
core crates.

## Main modules and types

- `template`, `package`: `Template`, `read_package` and `validate_directory`, which validate
  templates against `schemas/decoy-template.v1.json`.
- `generation`, `generator`, `random`: per-host generation of decoy content with a CSPRNG.
- `install`: `install` and `uninstall`; symlinks are not followed, existing files are not
  overwritten silently, and removal touches only recorded files.
- `record`: the integrity record (SHA-256, path, owner, mode, timestamp) and the integrity check.
- `catalog`: `Catalog`, the `koru_event::DecoyCatalog` implementation used by detection.

## Testing

`crates/koru-decoy/tests/decoy/` covers template schema, uniqueness, integrity, safe writes,
removal safety and rollback. Run `cargo test -p koru-decoy`.

## Further reading

- [Crates and layers](../../docs/architecture.md#crates-and-layers) and [layer independence](../../docs/architecture.md#layer-independence).
- [ADR-0004](../../docs/adr/0004-koru-decoy.md) and [decoys and breadcrumbs](../../docs/architecture.md#decoys-and-breadcrumbs).
- Workspace overview: [README](../../README.md).
