# koru-store

The event store: SQLite in WAL mode with schema validation on entry, deduplication, export,
IP masking, retention and a data quality report.

## Layer and dependencies

Layer: core. Allowed Koru dependency: `koru-event`. External dependencies (in
`dependency-rules.toml`): `rusqlite`, `sha2`, `serde`, `serde_json`, `thiserror` and `rustix`;
`tempfile` for tests. It knows neither Pulsar nor the other core crates and implements
`koru_event::EventStore`. All SQL is parameterized.

## Main modules and types

- `store`, `schema`, `raw`: the store itself and validation of events on entry.
- `key`: `event_key`, the deduplication key.
- `export`, `ocsf`: JSONL and OCSF export (`ExportFormat`, `ExportOptions`).
- `mask`: IP masking, using the shared function from `koru-event`.
- `retention`, `settings`: retention, rotation and store settings.
- `report`: the data quality report.
- `error`: `StoreError` and `RejectReason`.

## Testing

`crates/koru-store/tests/` covers basic storage, deduplication, export, OCSF, masking, file
permissions, retention, schema validation and SQL safety, with fixtures in `tests/data/`.
Run `cargo test -p koru-store`.

## Further reading

- [Crates and layers](../../docs/architecture.md#crates-and-layers) and [layer independence](../../docs/architecture.md#layer-independence).
- [ADR-0006](../../docs/adr/0006-koru-store.md) and [event model and data quality](../../docs/architecture.md#event-model-and-data-quality).
- Workspace overview: [README](../../README.md).
