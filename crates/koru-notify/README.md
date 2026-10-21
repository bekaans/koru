# koru-notify

Notification channels (ntfy, Telegram, SMTP), rate limiting, a disk-persistent retry queue and
Healthchecks.io heartbeats.

## Layer and dependencies

Layer: output. Allowed Koru dependency: `koru-event`. External dependencies (in
`dependency-rules.toml`): `rustls`, `rustls-native-certs`, `serde`, `serde_json`, `thiserror`,
`rustix` and `getrandom`; `tempfile` and `rcgen` for tests. It knows neither Pulsar nor the other
core crates and talks to them through `NotificationChannel` and `Heartbeat`.

## Main modules and types

- `ntfy`, `telegram`, `smtp`: the three channels.
- `dispatcher`: routing, rate limiting (`rate`) and summaries.
- `queue`, `backoff`: the persistent queue with exponential-backoff retries.
- `heartbeat`: Healthchecks.io pings.
- `text`, `secret`, `address`: sanitizing of notification text, the `Secret` wrapper that keeps
  tokens out of logs, and address validation (`https` only, except local test servers).

TLS uses rustls only, and the server certificate and host name are verified.

## Testing

`crates/koru-notify/tests/` covers each channel, the dispatcher, queue, rate limiting, masking,
injection, TLS validation and client safety. The `live_*` examples send real notifications and
need credentials from the environment. Run `cargo test -p koru-notify`.

## Further reading

- [Crates and layers](../../docs/architecture.md#crates-and-layers) and [layer independence](../../docs/architecture.md#layer-independence).
- [ADR-0007](../../docs/adr/0007-koru-notify.md) and [security](../../docs/architecture.md#security).
- Workspace overview: [README](../../README.md).
