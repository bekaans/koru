# ADR-0003: koru-pulsar — Pulsar version and features, platform condition, translation and supply-chain exceptions

- **Status:** Accepted. The two deviations and two exceptions are maintainer decisions.
- **Date:** 2026-10-09
- **Related:** ADR-0001 (embedded module), [architecture](../architecture.md#security),
  [CONTRIBUTING.md](../../CONTRIBUTING.md#protected-files), `deny.toml`, `dependency-rules.toml`,
  [threat model](../threat-model.md) (KT-13, KT-20, KT-28, KT-30, KT-36, KT-43, KT-44)

## Context

ADR-0001 chose the embedded module path: `koru-pulsar` would depend on the `pulsar` and
`pulsar-core` crates at git tag v0.10.1, with `features = ["core", "rules-engine"]`. When
the workspace was set up and `cargo deny check` and `cargo audit` first ran, two security
advisories and one license problem appeared in Pulsar's transitive dependencies. Supply-chain
findings are not relaxed silently, so the maintainers decided each one explicitly.

## Decisions

### 1. Deviation: Pulsar is pinned to a commit on main (instead of the v0.10.1 tag)

- **Dependency:** `rev = "0bb7bc20d454c35be4d662d6a3cd609e47f31c84"` (full 40 characters; no
  branch name is used). Commit date 2026-10-08, version `0.11.0-alpha.1`. `Cargo.lock` records the
  same commit; `dependency-rules.toml` constrains the source prefix to this SHA.
- **Rationale:** v0.10.1 always enables network-monitor's `test-suite` feature in its workspace
  dependency; therefore test dependencies (`dns-mock-server`, `hickory-resolver`) enter the
  production graph and `hickory-proto 0.25.2` arrives: **RUSTSEC-2026-0118** (an infinite loop in
  NSEC3 verification) and **RUSTSEC-2026-0119** (O(n²) CPU consumption in name compression). The
  fix is hickory 0.26.x; it cannot be taken without Pulsar changing, being semver-incompatible. On
  Pulsar main `test-suite` is not the default and hickory 0.26.3 is used: `cargo audit` reports 0
  vulnerabilities.
- **Departure from the default:** the default is to depend on Pulsar's latest stable release;
  this is a deliberate deviation, justified by the two advisories above.
- **Return path:** when Pulsar's next stable tag arrives, Koru moves to it; at the move `cargo deny`,
  `cargo audit`, the translation tests and the live test re-run, and this ADR and the
  [toolchain and versions](../architecture.md#toolchain-and-versions) section are updated.
- **Lab:** the official `pulsard` binary in the lab VM stays v0.10.1 (see
  `lab/scripts/pulsar-setup.sh`). Koru's live test runs not with that binary but with Koru's own
  embedded-module binary (Pulsar main) (`lab/scripts/live-pulsar-test.sh`).
- **Recorded samples:** the Pulsar events in the translation tests were recorded with the v0.10.1
  binary; the tests parse them with main's `pulsar_core` types. The event JSON format is the same
  in both versions.

### 2. Deviation: the `rules-engine` feature is not used (from ADR-0001 outcome 1)

- **Dependency:** `pulsar = { …, default-features = false, features = ["core"] }`. `core`:
  process-monitor, network-monitor, file-system-monitor, threat-logger. `smtp-notifier`,
  `desktop-notifier` and OpenSSL do not arrive (as in ADR-0001).
- **Rationale:** Koru does not translate Pulsar's THREAT events (decision 4, KT-30) and has its
  own rule engine (ADR-0005). Pulsar's default rules produce noise on ordinary operations (ADR-0001
  outcome 7). The rule engine brings extra parsers (lalrpop, serde_yaml) and runtime cost; it was
  removed under the least-dependency principle ([architecture](../architecture.md#security)).
  The rules-engine brings no new security advisory; removing it is a simplicity decision, not a
  security one.

### 3. Exception: RUSTSEC-2021-0139 (ansi_term unmaintained)

- `deny.toml` → `[advisories] ignore`, only this id. `unmaintained = "all"` did not change; no
  other advisory is ignored.
- **Path:** `ansi_term 0.12.1` ← `nut 0.1.4` (the latest version on crates.io; the dependency is
  unconditional) ← `bpf-common` (Pulsar's core; it cannot drop by any feature choice) ←
  `pulsar-core` / `pulsar`.
- **Rationale:** it is an unmaintained-crate notice, not a vulnerability; "no safe upgrade".
  `cargo audit` counts it as a warning (exit 0). Removing it needs a change in Pulsar or nut
  (no upstream issue or pull request has been opened).
- **Review:** when the Pulsar version changes.

### 4. Exception: tiny-keccak (CC0-1.0)

- `deny.toml` → `[licenses] exceptions`, only `{ crate = "tiny-keccak", allow = ["CC0-1.0"] }`.
  CC0-1.0 was not added to the general allow list (that would weaken the license policy for every crate).
- **Path:** `bpf-common` → `rust-ini 0.21.3` → `ordered-multimap 0.7.3` → `dlv-list 0.5.2` →
  `const-random 0.1.18` → `const-random-macro 0.1.16` (proc-macro) → `tiny-keccak 2.0.2`. Every
  link is unconditional. In `dlv-list 0.6.0` `const-random` is optional, but `ordered-multimap
  0.7.x` requires `dlv-list ^0.5` (semver-incompatible).
- **Rationale:** tiny-keccak runs only at build time inside a proc-macro; it does not enter the
  shipped binary (NOTICE).
- **Review:** when the Pulsar version changes.

### 5. Platform condition: Pulsar-dependent code builds only on Linux

- Pulsar does not build on macOS: `pulsar_core::kernel` defines only `linux-{x86_64,aarch64,riscv64}`
  platform modules; the eBPF probes are compiled for a Linux target with `bpf-builder`.
- `koru-pulsar/Cargo.toml`: `pulsar`, `pulsar-core` and `tokio` sit under
  `[target.'cfg(target_os = "linux")'.dependencies]`. `translate`, the bridge module and
  `PulsarSensor` build with `#[cfg(target_os = "linux")]`; the translation types
  (`TranslationContext`, `ProcessAttachment`, `Translation`, `SkipReason`, `TranslationError`,
  `KORU_MODULE_NAME`) exist on every platform. `tests/translation.rs` carries
  `#![cfg(target_os = "linux")]`.
- Result: the workspace builds and tests on the Mac (koru-pulsar's translation tests pass as 0
  tests). The translation tests run in full in the lab VM (aarch64) and in CI (x86_64 and aarch64).
  `cargo xtask dependency-check` and `cargo deny` audit the graph without platform filtering;
  Pulsar is audited on every platform.

### 6. Translation mapping (Pulsar `Event` → Koru event, schema v1)

| Pulsar payload | `event_type` | `target` |
|---|---|---|
| FileOpened | `file_opened` | `path` = filename, `flags` (access mode + O_CREAT…O_DIRECTORY) |
| FileCreated / FileDeleted | `file_created` / `file_deleted` | `path` |
| DirCreated / DirDeleted | `directory_created` / `directory_deleted` | `path` = dirname |
| FileRename | `file_renamed` | `path` = source, `new_path` = destination |
| FileLink | `file_link` | `path` = the link, `new_path` = the pointed-to path, `hard_link` |
| Exec | `process_executed` | `path` = filename; `process.exe` = filename, `process.command_line` = argv |
| Exit | `process_exited` | `exit_code` |
| Connect | `network_connection` | `remote`, `protocol` (is_tcp) |
| Accept | `network_accept` | `remote` = source (the client), `local` = destination, `protocol` = tcp |
| Others (Fork, DnsQuery, Send, …) | — | Skipped: `UnsupportedKind` |

- **THREAT copies:** if `header.threat` is set, the event is skipped before anything else
  (`ThreatDuplicate`; `koru_originated = true` if Koru-sourced). The original event is separately
  on the bus. The bridge module never writes events to the bus and does not translate its own pid's
  events (KT-30).
- **Process:** `pid` must be > 0, `ppid` ≥ 0; otherwise `TranslationError`. `start_time` = fork_time
  (`null` if it is the Unix epoch). In an Exec event Pulsar's header carries the pre-exec binary;
  in the Koru event the process is its post-exec state (the same meaning as Sigma's
  `process_creation`).
- **Process attachment** (from the process tracker in the embedded module, at event time; KT-20):
  command line, namespaces, lineage (at most 16 ancestors).
- **Container:** `id`, `name`, `image`, `image_digest` ← `header.container` (empty text → `null`);
  `namespaces` ← the process tracker.
- **From the context:** `source_tag`, `host`, `timestamp_trusted`, `sensor`. The source tag is
  never taken from the event (KT-19).
- **Flags:** decoded with the constants of the architecture Pulsar was compiled for. `O_DIRECTORY`
  and `O_LARGEFILE` differ between aarch64 and x86_64; the recorded samples therefore contain no
  directory opens.
- **Validation:** every produced event passes through `Event::validate`; on failure an error is returned.

### 7. Agent and CLI separation (ADR-0001 outcome 5)

- The agent (root, eBPF) and the `koru` CLI are separate binaries. The CLI's query and decoy
  commands run unprivileged (KT-36). The composition is still built in `crates/koru`: the agent is
  the second `[[bin]]` of this crate (`koru-agent`). The lab test also uses
  `crates/koru-pulsar/examples/live_translation.rs`.
- `pulsar_daemon_run` always opens the engine API socket. This surface also exists in the Koru
  agent (KT-28, KT-29). The socket path is configurable; disabling it or its permissions are
  addressed in ADR-0008.

## Consequences

- `cargo deny check`: advisories, bans, licenses and sources clean. `cargo audit`: 0
  vulnerabilities (1 allowed warning: RUSTSEC-2021-0139).
- Supply-chain risk: an unreleased commit is used (KT-44). Full-SHA pinning, `--locked` builds,
  the source being only exein-io/pulsar (`deny.toml [sources]`) and the source prefix in
  `dependency-rules.toml` bound this risk.
- Known limits:
  - **The podman SQLite regression on Pulsar main (found in the live test):** when moving from
    diesel to rusqlite, `bpf-common` reads podman's `ContainerConfig.JSON` column as text
    (`row.get::<_, String>`), while podman writes a BLOB. Pulsar's log:
    `error querying podman sqlite database Invalid column type Blob at index: 0, name: JSON`. As a
    result, on systems using podman's SQLite database (the default of Ubuntu 24.04's podman 4.9.3)
    `header.container` stays empty. Therefore in the Koru event `container.id`, `name`, `image`
    and `image_digest` are empty. In-container access is still caught; `container.namespaces`
    differ from the host's and are the "container suspicion" signal (KT-20). v0.10.1 (diesel) gave
    this information: the recorded `container-file-opened.json` sample and the translation test
    cover it. The Docker path was not tested. No upstream issue or pull request has been opened. It is re-tested when moving to
    Pulsar's next stable tag. If a fallback such as deriving the id from cgroups is needed on
    Koru's side, it can be added to the translation.
  - The `uid` value in Pulsar's header shows 0 for processes that changed credentials after fork
    (KT-43).
  - For short-lived processes the process-tracker query can return `ProcessExited`; in that case
    the attachment stays empty and the event is still translated.
  - If the bridge channel is full the module waits; Pulsar's bus drops the events of lagging
    modules. Its measurement is part of the end-to-end suite (ADR-0009).
