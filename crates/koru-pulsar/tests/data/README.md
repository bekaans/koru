# Test data for the koru-pulsar translation tests

This directory is part of the protected set (see CONTRIBUTING.md#protected-files). Existing files are not modified; a new sample is added only as a new file.

## `pulsar/`: recorded Pulsar events

- **Source:** the lab VM (`koru-lab`, Ubuntu 24.04 arm64, kernel 6.8.0-142-generic), the
  official Pulsar v0.10.1 binary (`pulsard`, commit `e79d2eb3771b7ad657c0029ca2c7bbaeac5e61fb`).
- **Date:** 2026-10-09.
- **Method:** `lab/scripts/pulsar-collect-samples.sh` uses `lab/scripts/pulsar-record-event.py`
  to record events from the engine API's `/monitor` WebSocket while running harmless triggers
  under `/tmp/koru-sample`. Each file is one event selected from that recording, in Pulsar's own
  serde JSON form (`pulsar_core::event::Event`), indented for readability; the content is unchanged.
- **Privacy:** The files contain no real secret or personal data. File contents are "fake"
  text; the triggers ran as the `nobody` user (setpriv), the container sample with rootful
  podman; network addresses are `127.0.0.1`, the container image is the public
  `docker.io/library/alpine:3.22`.
  Note: Pulsar's header shows `uid` 0 for these processes (docs/threat-model.md KT-43).
- **Version fit:** Koru's dependency is Pulsar main `0bb7bc20d454c35be4d662d6a3cd609e47f31c84`
  (ADR-0003). The samples were recorded with the official v0.10.1 binary; the tests parse this
  JSON with the dependency's `pulsar_core` types, which also proves the event form is the same
  in both versions. Live translation is additionally exercised in the lab with Koru's own binary
  (Pulsar main) (`lab/scripts/live-pulsar-test.sh`).

| File | Pulsar event | Note |
|---|---|---|
| `file-opened-read.json` | FileOpened | `cat`, `O_RDONLY` |
| `file-opened-write.json` | FileOpened | `sh` redirection, `O_WRONLY|O_CREAT|O_TRUNC` |
| `file-created.json` | FileCreated | |
| `file-deleted.json` | FileDeleted | |
| `directory-created.json` | DirCreated | |
| `directory-deleted.json` | DirDeleted | |
| `file-renamed.json` | FileRename | |
| `file-link-symlink.json` | FileLink | `ln -s /etc/shadow …` |
| `file-link-hard.json` | FileLink | hard link |
| `process-executed.json` | Exec | the header's `image` is the pre-exec binary (`setpriv`) |
| `process-exited.json` | Exit | exit code 1 |
| `network-connection-tcp.json` | Connect | TCP |
| `network-connection-udp.json` | Connect | UDP |
| `network-accepted.json` | Accept | `source` is the remote end, `destination` the local end |
| `threat-rules-engine.json` | FileLink + THREAT | Pulsar's default rule ("Create sensitive files symlink") |
| `unsupported-dns-query.json` | DnsQuery | a type not translated |
| `container-file-opened.json` | FileOpened | inside a rootful podman container; `header.container` set |

**Derived samples** (hand-edited from a recorded event; names start with `derived-`):

| File | Source | Change | Purpose |
|---|---|---|---|
| `derived-threat-koru-originated.json` | `threat-rules-engine.json` | `threat.source` = `koru-bridge`, `description` changed, `extra` = null | Koru's own THREAT is not processed (KT-30, bus feedback loop) |
| `derived-invalid-pid.json` | `file-opened-read.json` | `header.pid` = -5 | An invalid field is rejected as an error |

**Architecture-dependent flags:** Pulsar carries `open` flags as raw integers. The `O_DIRECTORY`
and `O_LARGEFILE` values differ between aarch64 and x86_64 (`pulsar_core::kernel::file::flags`).
The samples deliberately contain no directory open (`O_DIRECTORY`); aarch64's `O_LARGEFILE`
(0x20000) corresponds to none of the flags Koru translates on x86_64. The tests therefore give
the same result on both architectures.

## `expected/`: the expected Koru events (schema v1)

Each file is the translation of the same-named event under `pulsar/` into a Koru event,
excluding `event_id` (a fresh UUIDv7 is produced on every translation; the test also checks
its version). The translation context and the process attachment (`ProcessAttachment`: command
line, namespaces, lineage) are fixed in `tests/translation.rs`.

The expected files were produced, before the Rust implementation was written, by an independent
Python implementation of the mapping rules, and reviewed by hand. The mapping rules are in ADR-0003.
