# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The version
number is `workspace.package.version` in `Cargo.toml`. Release packages are signed
(`SHA256SUMS.sig`) and include an SBOM.

## [Unreleased]

## [0.1.0] - 2026-10-21

### Added

- Seven workspace crates arranged in layers that know only the shared event format:
  `koru-event`, `koru-pulsar` (eBPF sensor bridge), `koru-decoy`, `koru-detect`, `koru-store`,
  `koru-notify` and the `koru` crate, which builds the `koru` command-line tool and the
  `koru-agent` binary. See [docs/architecture.md](docs/architecture.md).
- `koru-agent`: the Pulsar bridge, detection, store and notification in one process, driven by a
  single TOML configuration, with a clean shutdown and a "stopped" event on `SIGTERM`.
- `koru` commands: `decoy validate|plant|list|integrity|uninstall`,
  `rule validate|export|coverage`, `event ingest`, `report data-quality|threat`,
  `export`, `store freeze`, `install`, `uninstall`, `upgrade`, `rollback` and `version`.
- Event schema v1 (`schemas/event.v1.json`), together with schemas for decoy templates
  (`schemas/decoy-template.v1.json`), rule packs (`schemas/rule-pack.v1.json`) and agent
  signatures (`schemas/agent-signature.v1.json`). Events that are corrupt, untagged or duplicated
  are rejected and counted by reason.
- Decoy and breadcrumb packages as data files: 13 decoy and breadcrumb templates in
  `packages/decoys/` (SSH keys, `.env` files, cloud credentials, database dumps, LLM API keys,
  MCP configuration files, AI-bait notes, shell history, SSH configuration and `known_hosts`
  entries). Decoys are generated uniquely per host, integrity-checked and removed cleanly.
- AI-agent attribution through process lineage, with 14 agent signatures in `packages/agents/`
  and a "suspected hijacked agent" class.
- 18 Sigma-compatible detection rules in `packages/rules/`, including self-protection rules for
  stopping Koru or modifying its binary, configuration, decoys, service unit or event store.
  The rules cover 12 MITRE ATT&CK Enterprise v20.0 techniques; the coverage table and the
  ATT&CK Navigator layer are generated into
  [docs/reports/attack-coverage.md](docs/reports/attack-coverage.md) and
  `docs/reports/attack-layer.json`.
- Event store on SQLite with a data-quality report, JSONL and OCSF 1.9.0 export, IP address
  masking (`--mask`) and retention (`koru store freeze`, 90 days by default).
- Notification channels: ntfy, Telegram, SMTP and a heartbeat, with a persistent queue, retry
  back-off and rate limiting.
- Signed distribution in `distribution/`: `install.sh`, `sign.sh`, `prepare-release.sh`, a
  systemd unit template hardened to a `systemd-analyze security` score of 2.5 or lower, an
  nftables egress lock and the release signing public key.
- `koru install`, `koru uninstall`, `koru upgrade` and `koru rollback`: signature and SHA-256
  verified installation, versioned directories, automatic rollback and clean removal. The
  process name, service name and directories are configurable, and the defaults do not reveal
  Koru.
- Lab in `lab/`: a Lima VM, a 100-scenario end-to-end suite (`lab/scenarios/list.toml`) with
  golden data replayed in CI, and performance and resilience measurements. Results are generated
  into [docs/reports/metrics.md](docs/reports/metrics.md).
- Seven cargo-fuzz targets in `fuzz/`: Pulsar event translation, configuration, decoy template,
  rule pack, CLI input, JSONL import and the persistent notification queue.
- Continuous integration with the `test` and `supply-chain` jobs on x86_64 and arm64, an SBOM
  (CycloneDX), a devcontainer, architecture decision records in `docs/adr/` and the threat model
  in `docs/threat-model.md`.
- Community files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `GOVERNANCE.md`, `SECURITY.md`, a
  Developer Certificate of Origin and a documentation site in `docs-site/`.

### Security

- Intermediate path components of `.env` and the queue path are checked for symlinks and writable
  parent directories.
- Stop detection recognizes bracketed globs, init scripts, `invoke-rc.d`, `rc-service` and
  abbreviated long options.
- `koru event ingest` validates the `host` and `sensor.*` fields against strict formats.

[Unreleased]: https://github.com/korusecurity/koru/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/korusecurity/koru/releases/tag/v0.1.0
