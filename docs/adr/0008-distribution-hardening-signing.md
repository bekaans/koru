# ADR-0008: Distribution — systemd hardening, configurable names, signing and lifecycle

- **Status:** Accepted. The target score in §1 was set before the unit was written and is not loosened.
- **Date:** 2026-10-16
- **Related:** [security](../architecture.md#security),
  [installation and lab](../architecture.md#installation-and-lab),
  [crates and layers](../architecture.md#crates-and-layers),
  [toolchain and versions](../architecture.md#toolchain-and-versions); ADR-0001, ADR-0003 §7,
  ADR-0004, ADR-0007; [threat model](../threat-model.md) (KT-07, KT-28, KT-29, KT-36, KT-44)

## Context

The Koru layers (ADR-0003 to ADR-0007) are not a working product on their own. The distribution joins them in a
single agent process (ADR-0003 §7), makes them installable and removable, signs the release and
runs the agent with least privilege. The agent runs as root (eBPF), sits on a server an attacker
can reach and must not give itself away; these three conditions shape every decision.

## Decisions

### 1. The systemd unit and the target score

**Target (set before the unit was written, not loosened): `systemd-analyze security <service>` ≤ 2.5.**
Measurement tool: systemd 255 (Ubuntu 24.04). The lower the score, the better.

The basis for the target was found in two experiments run in the lab VM (Ubuntu 24.04, kernel 6.8,
aarch64) before the unit was written:

- **Function experiment:** Koru's embedded Pulsar module (`live_translation`) ran in a transient
  unit (`systemd-run`) with the target restrictions. Pulsar's three modules started and file
  events were translated. Limits found in the experiment:
  - Capabilities: only `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`.
    `CAP_NET_ADMIN` is required: the network tracker attaches a `cgroup_skb` program
    (`BPF_PROG_ATTACH`); without it the network tracker does not start. `CAP_SYS_PTRACE` is for
    reading the `/proc/<pid>/exe` link of other users' processes (the detection layer verifies
    this in its filter decision). `CAP_SYS_RESOURCE` is not needed: `LimitMEMLOCK=infinity` is
    applied by systemd before privileges drop. `CAP_SYS_ADMIN` and `CAP_DAC_READ_SEARCH` are not
    needed. Ambient capabilities (`AmbientCapabilities`) are not needed: the process is root anyway.
  - Syscall filter: `@system-service`, from which `@privileged @resources @mount @swap @reboot
    @raw-io @module @obsolete @cpu-emulation @debug` are removed, then only `bpf` and
    `perf_event_open` are added back (the filter is order-sensitive; add back after removing).
    Without the add-back, removing `@privileged` and `@debug` kills the process with SIGSYS. A
    second need appeared in the live experiment: `fchown` (SQLite sets the owner of the journal/WAL
    file it opens as root equal to the database file's). The third line is therefore
    `bpf perf_event_open fchown`; since `CAP_CHOWN` is not in the bounding set, the call grants no
    power to change to another owner. The score did not change (`@privileged` was already flagged
    because of `bpf`).
  - Under `ProtectSystem=strict`, `/run` is also read-only: Pulsar's engine API socket must be
    under `RuntimeDirectory` (§2).
  - `ProtectProc=default` and `ProcSubset=all` stay: the agent must see all processes.
    `PrivateNetwork`, `PrivateUsers` and `IPAddressDeny` cannot be used: the agent reaches the
    notification channels (ntfy, Telegram, SMTP, Healthchecks) over the network and must stay in
    the initial user namespace for eBPF.
- **Measured on the running service and unit file: 2.5** (the target was met, not loosened).
- **Offline score (design time):** These restrictions written as a unit file gave **2.5** with
  `systemd-analyze security --offline=true`. Reasons for the remaining score: root (0.4), no
  `PrivateNetwork` (0.5), `CAP_SYS_PTRACE` (0.3), internet sockets (0.3), `CAP_NET_ADMIN` (0.2),
  `bpf` and `perf_event_open` inside `@privileged` and `@debug` (0.2 + 0.2), `ProtectProc` (0.2),
  `PrivateUsers` (0.2), `IPAddressDeny` (0.2) and smaller items.

**Unit principles:** `NoNewPrivileges`, `ProtectSystem=strict` (writing only in the state
directory and `RuntimeDirectory`), `ProtectHome`, `PrivateTmp`, `PrivateDevices`, kernel and
cgroup protection, `RestrictAddressFamilies` (INET, INET6, UNIX, NETLINK), `RestrictNamespaces`,
`MemoryDenyWriteExecute`, `LockPersonality`, `RestrictSUIDSGID`, `UMask=0077`, `LimitCORE=0`.

If the target cannot be reached, the target is not loosened; the change is rejected. If a
later capability addition, filter widening or removal of a protection line raises the score, the
change is invalid ([CONTRIBUTING.md](../../CONTRIBUTING.md#protected-files)).

### 2. The Pulsar engine API socket (KT-28, KT-29)

Pulsar opens its engine API on `/var/run/pulsar.sock`; the socket permission depends on the umask
and the path gives away the "pulsar" name. The Koru agent gives Pulsar `[pulsar] api_socket_path`
in its configuration file: the socket is in the unit's `RuntimeDirectory` (mode 0700, deleted when
the service stops; a stale socket left by a crash does not block the next start). Since the unit
has `UMask=0077`, the socket is 0700 root.

### 3. Configurable names (self-concealment; [security](../architecture.md#security))

The process name, service name and directories come from the single TOML configuration. The
defaults do not give Koru away (`system-observer`: the binary, the service, the directories under
`/usr/libexec/`, `/etc/`, `/var/lib/` and `/run/`; neither "koru" nor "pulsar" appears in a path, a
name or a command line). Name rule: lowercase letters, digits and `-`, at most 15 characters (the
kernel `comm` limit), must not contain "koru" or "pulsar". Changed at install with `--name`.

### 4. The agent binary and configuration (ADR-0003 §7)

- `koru-agent` (`crates/koru/src/agent_main.rs`) is the second `[[bin]]` of the `koru` crate; the
  composition is built only in this crate and follows the dependency matrix (`koru` may already
  depend on all of them). The architecture is unchanged: the layers do not know each other, the
  link is via `koru_event` traits.
- Flow: sensor (the Pulsar bridge) → detector → finding events are written to the store and
  notified. **Raw events are not stored by default** (`store_raw_events = false`): if all file
  events on a server were stored, the store and personal-data burden would grow meaninglessly; what is
  stored is the finding.
- The notification network does not stall event processing: notifications go to a separate thread
  over a bounded channel (256); if the channel is full the notification drops and counts, the
  finding stays in the store (consistent with KT-73). On a slow network (300 ms per notification)
  200 findings are processed without waiting for the network (test `agent_core.rs`).
- Clean shutdown: on SIGTERM/SIGINT the Pulsar agent returns; Koru produces the "stopped" event,
  writes it to the store, notifies it and cuts the heartbeat with `/fail` (Healthchecks is
  immediately "down").
- **Configuration** is a single TOML file (`schemas/config.v1.json`; the Rust types use
  `deny_unknown_fields`). The source tag and decoy root have **no defaults** (no decoy is planted
  into the real home directory by accident, synthetic and real data do not mix). Safe defaults: no
  raw events, IP masking on, 90-day retention. The file is read without following a symlink, with
  owner and mode checks, at most 64 KiB. Paths entering the unit file carry only `[A-Za-z0-9._/-]`.
- The Pulsar settings file is named `sensor.toml` (the path does not contain "pulsar").

### 5. Lifecycle (`koru install | uninstall | upgrade | rollback`)

- **Release package:** `koru`, `koru-agent`, `packages/{rules,agents,decoys}`, `thresholds.toml`,
  `VERSION`, the SBOM, `SHA256SUMS`, `SHA256SUMS.sig`. Before accepting the package, `install.sh`
  and `koru install` verify the signature, that the file set matches the list exactly (a file not
  in the list, a symlink, or an entry escaping the path is rejected) and every SHA-256.
  `install.sh` first copies the package into a private (0700) temp directory and verifies that
  copy; `koru install` uses the same in-memory content for verification and install: nothing can
  change between verification and use.
- **Directory layout** (all derived from the service name): `/usr/libexec/<name>/versions/<version>/<process name>`
  and `.../data/`, `/usr/libexec/<name>/current` (a link to the active version),
  `/etc/<name>/{config.toml, environment, sensor.toml}` (0600),
  `/var/lib/<name>/{event.db, queue/, decoy/, install.toml}` (0700),
  `/etc/systemd/system/<name>.service`. The install directory is 0700: the rule file names
  (`koru_*.yml`) are invisible to unprivileged users. The `koru` CLI is not installed on the
  target machine (its name gives it away); the administrator runs it from the release package.
- **Upgrade:** only a version strictly newer than the active one is accepted (SemVer; a prerelease
  is older than the stable). The new version is written under `versions/<new>`, the `current` link
  is switched atomically (`rename`), the service is restarted and all 5 consecutive health attempts
  (`is-active`) must pass; if they do not, the link, unit and record return to the old state and
  the service restarts on the old version. Only the active and previous versions are kept.
- **Rollback:** the link is turned to the `previous` version; called again, it moves forward.
- **Uninstall:** the service stops, decoys are rolled back per the koru-decoy record (a modified
  decoy is not deleted, the record stays, exit code 1), everything the install created is deleted,
  the timestamps of pre-existing parent directories are restored from the record; `--keep-data`
  leaves the store and queue. The lifecycle test (`lab/scripts/lifecycle-test.sh`) runs on a clean VM and
  `file-digest.sh` matches after uninstall.
- **Environment file:** from the file given with `--environment`, only the notification variables
  (`KORU_NTFY_*`, `KORU_TELEGRAM_*`, `KORU_SMTP_*`, `KORU_HEARTBEAT_URL`, `KORU_NOTIFY_MASK_IP`)
  pass to the target; the signing key, `KORU_LAB_LLM_*` and `CLOUDFLARE_*` never pass.

### 6. Signing (keyed while the repo is private)

- **Algorithm:** ECDSA P-256 (SHA-256). Verification uses `openssl dgst -sha256 -verify` and
  prints "Verified OK"; `install.sh` and `koru install` use the same command (without `openssl`,
  no install happens). Keyless Sigstore is **not used**: because it writes its records to a public
  transparency log, it may be reconsidered later.
- **The key pair** was generated locally. The private key is password-encrypted PKCS#8
  (AES-256-CBC) and lives only in `.env` (`KORU_SIGNING_KEY`, `KORU_SIGNING_KEY_PASSWORD`; the file
  is 0600) as single-line base64. **The public key** is in the repo:
  `distribution/signing-public-key.pem`.
- **Root of trust:** `install.sh` pins the SHA-256 fingerprint of the public key file into the
  script (`EMBEDDED_FINGERPRINT`); if the file changed, the script stops. The `koru` binary embeds
  the same public key at compile time (`EMBEDDED_PUBLIC_KEY`). `--public-key`/`--fingerprint` exist
  only for forks and tests and are given together.
- **Signing process:** `distribution/prepare-release.sh` lays out the package, `distribution/sign.sh`
  produces and signs `SHA256SUMS`. The private key and password are never written to any output,
  log, file or command line (the password travels via an environment variable; there is no command
  trace mode); `.env` must be 0600 and only its two lines are read with `grep`. Tests never use the
  real key.
- Key rotation: a new pair is generated, the public key and the `install.sh` fingerprint change in
  the same commit, and packages signed with the old key cannot be installed with the new
  `install.sh` (deliberately).

### 7. SBOM

`cargo cyclonedx` 0.5.9 ([toolchain and versions](../architecture.md#toolchain-and-versions)), CycloneDX 1.5 JSON, `--target all` (including the Linux-only
Pulsar dependencies), reproducible with `SOURCE_DATE_EPOCH`. It enters the release package as
`sbom.cdx.json` and is signed via `SHA256SUMS`.

### 8. Fuzz (cargo-fuzz)

Seven targets (`fuzz/fuzz_targets/`): `pulsar_event_translation`, `config`, `decoy_template`,
`rule_pack` (rules, AI-agent signatures, thresholds, the allowlist), `cli_input`, `jsonl_import`,
`persistent_queue`. `fuzz/` is a separate workspace (`fuzz/Cargo.lock`): `libfuzzer-sys`
(MIT/Apache-2.0 and NCSA) is only a fuzz tool, never enters the shipped binaries and is outside the
main workspace's `cargo audit` / `cargo deny` / `dependency-check` scope. The properties
(round-trip stability, no line injection into the unit, validation of an accepted event) are the
`assert!`s in the target files. Seed inputs are under `fuzz/corpus/`. Each target runs 600 s.

### 9. devcontainer

`.devcontainer/` pins an Ubuntu 24.04 base by multi-arch digest and reads the Rust version from
`rust-toolchain.toml` (the same toolchain as CI). The container does not run as root and has no
extra capabilities and no Docker socket; `.env` appears empty in the container, bound over with
`/dev/null` (the KT-38 lesson). The container image was built with podman in the lab VM
and `cargo test --workspace --locked` ran inside it.

### 10. Detection and import decisions

- **KT-58 (tightening):** a process opening a decoy with `O_RDWR` produces, in addition to the
  `koru_decoy_modified` finding, a decoy-access finding; if an AI agent is in the lineage, the
  class is "suspected hijacked agent". The `decoy_*` rules require `koru.read: true` instead of
  `koru.modified: false`.
- **KT-66:** in events imported with `koru event ingest`, `host` (RFC 1123, IP-like rejected) and
  `sensor.name`/`version`/`platform` (narrow shapes) are checked; the reject counts as
  `validation`. The locked `masking.rs` and the `RejectReason` set did not change.
- **ATT&CK v20.0:** the catalog was regenerated from the official bundle (SHA-256 verified);
  additions only, the rules' 12 techniques valid.
- **Pulsar:** the latest stable release is v0.10.1; the pinned commit `0bb7bc2` did not change
  (ADR-0003).

### 11. Below-threshold notes from earlier layers

- The intermediate components of the `.env` and queue paths: the path is opened component by
  component with `O_NOFOLLOW`; intermediate directories must belong to the euid/root and be
  non-writable (except the sticky bit); tests `intermediate_component.rs`.
- Parsing gaps in stop commands: fnmatch classes, `sh /etc/init.d/<service>`, `invoke-rc.d`,
  `rc-service`, getopt_long prefix abbreviations; tests `stop_gaps.rs`.
- Re-audit of `arraydeque` maintenance. Result: unmaintained
  (last release 2023-02-05), two open soundness issues, no RustSec advisory; used only via the
  yaml-rust2 scanner's `drain(0..n)` call, only while parsing administrator-controlled rule files.
  It remains an open risk (KT-80).

## Consequences and known limits

- The agent carries root and `CAP_SYS_PTRACE`: the ptrace capability enlarges the impact if the
  service is seized. This capability is required for detection's `/proc/<pid>/exe` verification (§1).
- Journal (journald) lines name Pulsar; a privileged user who can read the journal notices Koru.
  The paths, process name and unit visible to unprivileged users are neutral.
- The `systemd-analyze` score is measured offline and online (`systemd-analyze security`); the target 2.5
  cannot be loosened.
- The `openssl` binary is required at install for signature verification (installed on Ubuntu 24.04).
