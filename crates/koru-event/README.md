# koru-event

The shared event format and the interfaces between layers. Every other Koru crate talks to its
neighbours only through the types and traits defined here.

## Layer and dependencies

Layer: shared format. Allowed Koru dependencies: none. Allowed external dependencies (in
`dependency-rules.toml`): `serde`, `thiserror`, `uuid`, `time`; `serde_json` for tests only. The
crate does not depend on Pulsar.

## Main modules and types

- `event`: `Event`, event schema v1 (`schemas/event.v1.json`). Unknown, missing or out-of-rule
  fields are rejected.
- `untrusted`: `Untrusted<T>`, the marker for fields an attacker can control.
- `mask`: `mask_ip` and `mask_ip_in_text`, the IP masking shared by the store and the notifier.
- `id`, `time`, `identity_fields`: UUIDv7 event ids, UTC nanosecond timestamps and host validation.
- `interfaces`: the cross-layer traits `Sensor`, `Detector`, `DecoyCatalog`, `EventStore`,
  `NotificationChannel` and `Heartbeat`, plus the placeholders `Router`, `ResponseAction` and
  `IntentClassifier` for later releases.

## Testing

`crates/koru-event/tests/` holds `schema.rs` (the Rust types against the JSON schema) and
`ip_mask.rs`, with fixtures in `tests/data/`. Run `cargo test -p koru-event`.

## Further reading

- [Crates and layers](../../docs/architecture.md#crates-and-layers) and [layer independence](../../docs/architecture.md#layer-independence).
- [Event model and data quality](../../docs/architecture.md#event-model-and-data-quality) and [timestamps](../../docs/architecture.md#timestamps).
- Workspace overview: [README](../../README.md).
