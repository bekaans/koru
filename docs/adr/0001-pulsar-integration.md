# ADR-0001: Pulsar integration shape

- **Status:** Accepted (verified in the lab)
- **Date:** 2026-10-08
- **Related:** [architecture](../architecture.md#crates-and-layers), [CONTRIBUTING.md](../../CONTRIBUTING.md#protected-files), ADR-0003

## Context

Koru will be written as modules on top of exein-io/pulsar. Only the `koru-pulsar` crate will depend on Pulsar; the other layers will not know Pulsar ([layer independence](../architecture.md#layer-independence)). These questions had to be answered:

1. Can we depend on Pulsar's crates by git tag and, **without forking Pulsar**, build an agent binary containing our own module? (The preferred path.)
2. If not, can events be read from a running `pulsard` via the engine API, the socket or `pulsar monitor`?
3. Do Pulsar events carry container information (container id, namespaces)?
4. Which Pulsar crates fall under GPL-2.0? (The `deny.toml` exception will be scoped by this.)

Discovery environment: the `koru-lab` VM (Ubuntu 24.04.5 LTS arm64, kernel 6.8.0-142-generic, 4 vCPU), Pulsar v0.10.1 (commit `e79d2eb3771b7ad657c0029ca2c7bbaeac5e61fb`), rustc 1.99.0, clang 18.1.3, podman 4.9.3, cargo-deny 0.20.2.

### Findings from the source code

- **How the agent binary is formed:** the `pulsard` binary is a thin wrapper. The real work is in the `pulsar::pulsard::pulsar_daemon_run(&PulsarDaemonOpts, customize_starter)` function in the `pulsar` library crate (`src/pulsard.rs`). This function registers the built-in modules with `starter.add_module(...)` according to cargo features, then runs the caller's `customize_starter` closure. No fork is needed to add a module from outside; the official example does this (`examples/pulsar-extension-module`).
- **Module registration:** a module implements the `pulsar_core::pdk::SimplePulsarModule` (or the more detailed `PulsarModule`) trait: `MODULE_NAME`, `DEFAULT_ENABLED`, `init_state`, `on_event`, `on_config_change`, `graceful_stop`. It is registered with `PulsarDaemonStarter::add_module`. Modules are attached to a shared broadcast bus; **every module receives every event on the bus**.
- **Engine API:** `pulsard` opens an HTTP server on the `/var/run/pulsar.sock` Unix socket (`crates/engine-api`). Endpoints: `/` (modules), `/{module}/start|stop|restart|config`, `/configs` and `/monitor` (WebSocket; sends the event as JSON via serde). There is no authentication; the only protection is the socket permissions (`srwxr-xr-x root root`). `pulsar monitor` is this WebSocket's client; by default it prints only THREAT events, with `--all` all events.
- **Event header:** `Header { image, pid, parent_pid, uid, gid, container: Option<ContainerInfo>, threat, source, timestamp, fork_time }`.

## Options

### A) Embedded module: depend on Pulsar crates by git tag, our own agent binary (preferred)

`koru-pulsar` depends on the `pulsar` and `pulsar-core` crates with `git = "https://github.com/exein-io/pulsar", tag = "v0.10.1"`. Koru's agent binary calls `pulsar_daemon_run` and adds the Koru module with `add_module`. Pulsar is not forked.

**Trial (in the VM, results below):**

```toml
# Cargo.toml (excerpt)
[dependencies]
pulsar = { git = "https://github.com/exein-io/pulsar", tag = "v0.10.1", default-features = false, features = ["core", "rules-engine"] }
pulsar-core = { git = "https://github.com/exein-io/pulsar", tag = "v0.10.1" }
tokio = { version = "1", features = ["full"] }
clap = { version = "4", features = ["derive"] }
```

```rust
// src/main.rs (excerpt)
let result = pulsar::pulsard::pulsar_daemon_run(&options.daemon, |starter| {
    starter.add_module(koru_module::KoruSampleModule)?;
    Ok(())
}).await;
```

The sample module (`koru-sample`), when a watched file is opened, takes the namespace and container information from the process tracker and produces a THREAT event with `ctx.send_threat_derived(...)`.

```sh
sudo apt-get install -y --no-install-recommends rustup clang llvm libsqlite3-dev pkg-config build-essential
rustup toolchain install stable --profile minimal && rustup default stable
cd ~/discovery/koru-sample-agent && cargo clean -q && cargo build --release
#   Finished `release` profile [optimized] target(s) in 57.60s   (no warnings, binary 18.5 MB)
sudo systemctl stop pulsard.service
sudo target/release/koru-sample-agent &
sudo pulsar status        # koru-sample | Running (next to the built-in modules)
cat /tmp/koru-decoy-test
sudo podman run --rm -v /tmp/koru-decoy-test:/tmp/koru-decoy-test:ro docker.io/library/alpine:3.22 cat /tmp/koru-decoy-test
```

Result: the build succeeded. `pulsar status` shows the module `Running`. `pulsar monitor` output:

```text
[2026-10-08T16:12:40Z THREAT /usr/bin/cat (25177)] [koru-sample - Koru sample module: watched file opened] File Opened { filename: /tmp/koru-decoy-test, flags:(O_RDONLY) }
[2026-10-08T16:12:40Z THREAT docker.io/library/alpine:3.22 sha256:5291449c… /bin/cat (25233)] [koru-sample - Koru sample module: watched file opened] File Opened { … }
[2026-10-08T16:12:42Z THREAT /usr/bin/ln (25386)] [rules-engine - Create sensitive files symlink] File Link { source: /tmp/koru-sample-symlink, destination: /etc/shadow, hard_link: false }
```

The default rule engine keeps running in the same binary; the Koru module's THREAT events appear in both `pulsar monitor` and the engine API.

### B) Reading from outside via the engine API / socket / `pulsar monitor` (fallback)

The official `pulsard` runs as-is; Koru, as a separate process, connects to the `/monitor` WebSocket on `/var/run/pulsar.sock` and reads the JSON events.

**Trial:** a client written with only the Python standard library (`~/discovery/ws_read.py`) completed the handshake (`HTTP/1.1 101 Switching Protocols`) and read the in-container THREAT event as JSON. The path works.

Weaknesses:
- No namespace information in the JSON (see below); no access to the process tracker.
- Two processes, two separate crash and restart surfaces; event loss (a WebSocket drop) must be handled separately.
- The JSON format is the serde output of Rust types; it is not a documented, versioned API contract.
- The API is unauthenticated: anyone with root can stop modules with `POST /{module}/stop`. For Koru's self-protection requirement this surface must be watched (it exists in both options; in B, Koru itself becomes dependent on this surface).

### C) Reading the `threat-logger` output (syslog/journald, `output_format=json`)

It yields only THREAT events; there is no raw event stream, process tree or namespaces. Insufficient for Koru-specific detections such as decoy access. Eliminated.

### D) Forking Pulsar

No longer needed: path A works without a fork. It also contradicts the "upstream first" principle.

## Decision

**Option A: embedded module.** Koru's agent binary depends on Pulsar's `pulsar` and `pulsar-core` crates at the v0.10.1 git tag and runs the Koru modules in the same process as Pulsar's built-in modules via `pulsar_daemon_run` + `add_module`. Pulsar is not forked. The engine API (B) remains only a diagnostic and fallback tool.

This decision does not change the architecture: the only crate depending directly on Pulsar is `koru-pulsar`. The `koru` CLI starts the agent through a function offered by `koru-pulsar`; it does not depend on Pulsar directly.

**No stop condition arose:** Pulsar runs in the VM and produces THREAT events; the embedded module path needs no fork; we are not condemned to the engine API alone.

## Consequences

### For the architecture

1. **Dependency:** `koru-pulsar` → `pulsar` (`default-features = false`, `features = ["core", "rules-engine"]`) and `pulsar-core`. This feature choice leaves out `smtp-notifier` and `desktop-notifier`; no OpenSSL dependency arrives.
2. **Version pinning:** with git dependencies, Pulsar's own `Cargo.lock` is not used; our lock file resolves newer semver-compatible versions than Pulsar tested (e.g. tokio 1.53.2). `Cargo.lock` is pinned; the lock records the tag's commit (`#e79d2eb3…`). Even if the tag moves, a `--locked` build uses the same commit.
3. **Build requirements:** Pulsar's eBPF probes are compiled with `clang` at build time (`bpf-builder`, `-mcpu=v3`); `llvm-strip`, `libsqlite3-dev` (or the `sqlite3-vendored` feature) and `pkg-config` are needed. Ubuntu 24.04's clang 18 is sufficient. These packages must be added to the CI images (x86_64 and arm64). Pulsar pins Rust 1.98.1 in its own repo; the sample built warning-free with 1.99.0 stable. A from-scratch release build takes about 1 minute on 4 vCPUs.
4. **Bus feedback loop:** modules receive all events on the bus; a THREAT event published with `send_threat_derived` comes back with the same payload. In the first trial the sample module reprocessed its own event and entered an endless loop (hundreds of thousands of events in a few seconds). Koru modules must not process events with `header.threat` set (at least their own). A test must cover this.
5. **Agent and CLI separation:** the agent loads eBPF as root. The `koru` CLI's query and decoy commands do not want this privilege. Whether the agent is offered as a subcommand of the `koru` CLI or as a separate binary was left open at this point (ADR-0003 settles it). This does not change the composition rule; it is only the binary layout.
6. **Self-concealment:** module names (`pulsar status`) and the process name are visible to root. For Koru's "not giving itself away" requirement, module and binary names are addressed in ADR-0008.
7. **Default rule noise:** Pulsar's default rules also produce THREATs on ordinary operations (e.g. `sudo` → "Open sensitive file", `grep` → "Suspicious command targeting /proc filesystem"). Koru must not carry Pulsar's THREATs into notifications as-is; it must filter with its own rules and allowlist.
8. **BPF LSM:** Ubuntu 24.04's enabled LSM list has no `bpf`; Pulsar uses the `kprobe/security_*` fallback instead of eBPF LSM. Detection works. Enabling LSM (a boot parameter) is a separate decision (ADR-0008).

### Container information

| Information | Event header / JSON (`header.container`) | Process tracker in the embedded module (`ProcessInfo`) |
|---|---|---|
| Container id | Present (`id`) | Present |
| Container name, image, image digest | Present (`name`, `image`, `image_digest`, `layers`) | Present |
| Namespaces (uts, ipc, mnt, pid, net, time, cgroup inodes) | **Absent** (discarded in `module_context.rs` as `namespaces: _`) | **Present** (`ProcessInfo.namespaces`) |

- A container is recognized on the eBPF side from the memory cgroup name; only **Docker** and **Podman** are supported (`ContainerEngineKind { Docker, Podman }`). containerd/nerdctl, CRI-O and Kubernetes are not recognized (Kubernetes support is out of scope for now).
- Podman trial: for the in-container `cat`, the id, name, image and digest arrived; the namespaces differed from the host's (`mnt=4026532418 pid=4026532421 net=4026532346 … cgroup=4026532422`). A process run via `podman exec` was also recognized. In the OCI runtime's (crun, `/dev/fd/3`) setup-phase file opens there are new mnt/pid namespaces but the cgroup is not yet the container's; in those events `container` is empty. Even when `container` is empty, Koru can mark the event a "container suspicion" if the namespaces differ from the host's.
- With the official `pulsard`, the default rule also fired inside a container; in the engine API JSON `header.container` is filled, the namespace field absent.
- Querying the process tracker with `Timestamp::now()` can race for short-lived processes: in one trial a `ProcessExited` error was received for the in-container `cat` (not seen in the last run). The query must use the event time (`header.timestamp` converted to monotonic time).
- Schema mapping: `container.id` ← `header.container.id`; `container.namespaces` ← `ProcessInfo.namespaces`. This is a concrete reason to prefer the embedded path: path B cannot fill the namespace field.

### Licensing: the GPL-2.0 scope

Pulsar's user space is Apache-2.0, its eBPF probes GPL-2.0 (`LICENSE`). But the license field in the `Cargo.toml` of 15 of the 16 Pulsar crates in the sample agent's dependency graph is `"Apache-2.0 WITH BPF probes exception under GPL-2.0"`, which is not a valid SPDX expression (only `validatron-derive` is plain `Apache-2.0`). cargo-deny counts these crates as "unlicensed" and the audit fails.

Crates where eBPF C source is compiled and embedded into (or provided at build time to) the crate's Rust code **are under GPL-2.0**:

| Crate | GPL-2.0 source | Note |
|---|---|---|
| `process-monitor` | `probes.bpf.c` (SPDX: GPL-2.0 OR BSD-3-Clause) + GPL-2.0-only headers | Probe embedded in the binary, `SEC("license") = "GPL v2"` |
| `network-monitor` | `probes.bpf.c` (GPL-2.0 OR BSD-3-Clause) + GPL-2.0-only headers | Same |
| `file-system-monitor` | `probes.bpf.c` (GPL-2.0) | Same |
| `bpf-feature-autodetect` | `test_lsm.bpf.c` (`SEC("license") = "GPL v2"`), `test_bpf_loop.bpf.c` (no SPDX; `vmlinux.h` and libbpf headers) | Feature-detection probes embedded in the binary |
| `bpf-filtering` | `filtering_example.bpf.c` (includes the GPL-2.0-only `interest_tracking.bpf.h`) | `build.rs` always compiles; embedding depends on the `test-suite` feature (on in Pulsar's workspace) |
| `bpf-builder` | `include/*.bpf.h` (GPL-2.0-only), libbpf headers (LGPL-2.1 OR BSD-2-Clause), `vmlinux.h` | Build dependency only; its headers are compiled into the probes |

Crates **outside** the GPL scope, Apache-2.0 user-space code only: `pulsar`, `pulsar-core`, `bpf-common`, `bpf-features`, `bpf-features-macros`, `engine-api`, `rules-engine`, `threat-logger`, `validatron`, `validatron-derive`.

**For `deny.toml`:** a `[[licenses.clarify]]` entry is written for every Pulsar crate: `"Apache-2.0 AND GPL-2.0-only"` for the 6 crates above, `"Apache-2.0"` for the other 9. `GPL-2.0-only` is **not added** to the global `allow` list; it is granted to only these 6 crates via `[[licenses.exceptions]]`. In the VM trial, with this configuration all Pulsar crates passed the audit. One non-Pulsar finding remained: `tiny-keccak 2.0.2` (CC0-1.0; arriving from `bpf-common` via the `rust-ini → ordered-multimap → dlv-list → const-random` chain). Its decision is recorded in ADR-0003. In distribution, a `NOTICE` file must state that the eBPF bytecode embedded in the binary is GPL-2.0 and where the source (the Pulsar v0.10.1 tag) is. This is not a legal opinion.

### Candidates to propose upstream (notes only; nothing has been opened upstream)

1. Converting the crate license fields to valid SPDX expressions (e.g. `Apache-2.0` for user-space crates, `Apache-2.0 AND GPL-2.0-only` for probe-carrying crates). This solves the cargo-deny problem of everyone using Pulsar.
2. Adding namespace information to `Header` (currently discarded in `module_context.rs`).
3. Recognizing the containerd/CRI-O container engines.
4. Updating the stale `rev` pin (`797f6864…`) in `examples/pulsar-extension-module/README.md`.
