# koru-pulsar

The sensor layer. It runs inside the Pulsar (Rust and eBPF) agent and translates Pulsar events
into Koru events.

## Layer and dependencies

Layer: sensor. Allowed Koru dependency: `koru-event`. This is the only crate allowed to depend on
Pulsar (`pulsar`, `pulsar-core`, pinned to a git revision) and on `tokio` and `thiserror`;
`serde_json` is for tests only (`dependency-rules.toml`). Pulsar compiles only on Linux, so the
Pulsar-dependent code sits behind `cfg(target_os = "linux")` and the workspace still builds
elsewhere.

## Main modules and types

- `bridge`: `PulsarSensor` and `BridgeSettings`, the module that runs inside the Pulsar agent.
- `pulsar_translation`: `translate`, which maps a Pulsar event to a Koru event (Linux only).
- `translation`: the platform-independent translation types, including `ProcessAttachment`
  (command line, namespaces and lineage from the process tracker).

Events that already carry a `header.threat` value, including Koru's own threat events, are not
translated again.

## Testing

`crates/koru-pulsar/tests/` has `translation.rs` and `translation_counter.rs`, which replay
recorded Pulsar events from `tests/data/`. The `live_translation` example reads real events on a
Linux host. Run `cargo test -p koru-pulsar`.

## Further reading

- [Crates and layers](../../docs/architecture.md#crates-and-layers) and [layer independence](../../docs/architecture.md#layer-independence).
- [ADR-0001](../../docs/adr/0001-pulsar-integration.md) (Pulsar integration) and [ADR-0003](../../docs/adr/0003-koru-pulsar.md) (this crate).
- Workspace overview: [README](../../README.md).
