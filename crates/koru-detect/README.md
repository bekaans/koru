# koru-detect

The detection layer: Sigma-compatible rule packs, an evaluator, process-lineage and AI-agent
enrichment, actor-kind estimation and self-protection events.

## Layer and dependencies

Layer: core. Allowed Koru dependency: `koru-event`. External dependencies (in
`dependency-rules.toml`): `serde`, `serde_json`, `toml`, `thiserror` and `yaml-rust2`; `tempfile`
for tests. It knows neither Pulsar nor the other core crates; decoys are reached through the
`DecoyCatalog` trait.

## Main modules and types

- `rule`, `yaml`, `sigma`: `Rule`, `parse_rule` and Sigma export (rule packs in `packages/rules/`).
- `detector`, `pattern`, `fields`: the evaluator; wildcards run on a bounded linear matcher, not
  a regular expression engine.
- `agent`: `AgentSignatures`, the AI-agent signatures from `packages/agents/`.
- `threshold`: `Thresholds`, loaded from `thresholds.toml`.
- `allowlist`, `file_id`: `Allowlist` and `KoruIdentity` for excluding Koru's own process.
- `protection`: self-protection findings.
- `attack`: ATT&CK mapping and the `Coverage` table and Navigator layer.

## Testing

`crates/koru-detect/tests/` has the `detect/` suite (evaluator, rule schema, agent signatures,
allowlist bypass cases, scenarios) and `golden_data.rs`, which replays datasets from `data/`.
Run `cargo test -p koru-detect`.

## Further reading

- [Crates and layers](../../docs/architecture.md#crates-and-layers) and [layer independence](../../docs/architecture.md#layer-independence).
- [ADR-0005](../../docs/adr/0005-koru-detect.md) and [detection quality and measurement](../../docs/architecture.md#detection-quality-and-measurement).
- Workspace overview: [README](../../README.md).
