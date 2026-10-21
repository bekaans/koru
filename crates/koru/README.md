# koru

The `koru` command-line tool and the `koru-agent` binary. This is the only crate that composes
the layers.

## Layer and dependencies

Layer: composition. Allowed Koru dependencies: all other Koru crates (`koru-event`,
`koru-pulsar`, `koru-decoy`, `koru-detect`, `koru-store`, `koru-notify`). It does not depend on
Pulsar directly. External dependencies (in `dependency-rules.toml`) include `serde`, `serde_json`,
`toml`, `rustix` and `sha2`.

## Main modules and commands

- `main.rs`: the CLI. `decoy` commands come from `koru-decoy`, `rule` commands from
  `koru-detect`, and `event ingest`, `report data-quality`, `export` and `store freeze` from
  `koru-store`. `install`, `uninstall`, `upgrade`, `rollback` and `report threat` are handled
  here.
- `agent`, `agent_main.rs`: the `koru-agent` binary, which wires sensor, detection, store and
  notification.
- `config`, `distribution`, `input`, `safe_read`: configuration, the signed install flow, input
  validation and safe file reading.

## Testing

`crates/koru/tests/` runs the CLI and agent end to end: decoy, rule, store and threat commands,
the install, release and signing scripts, the systemd unit and the distribution layout.
Run `cargo test -p koru`.

## Further reading

- [Crates and layers](../../docs/architecture.md#crates-and-layers) and [layer independence](../../docs/architecture.md#layer-independence).
- [ADR-0003](../../docs/adr/0003-koru-pulsar.md), [ADR-0008](../../docs/adr/0008-distribution-hardening-signing.md), [ADR-0009](../../docs/adr/0009-end-to-end-scenarios.md) and [ADR-0010](../../docs/adr/0010-standard-path-and-global.md).
- Workspace overview: [README](../../README.md).
