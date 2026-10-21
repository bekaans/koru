# ADR-0005: koru-detect — YAML library, rule evaluator, enrichment, actor kind, allowlist and self-protection

- **Status:** Accepted.
- **Date:** 2026-10-14
- **Related:** [detection quality and measurement](../architecture.md#detection-quality-and-measurement),
  [security](../architecture.md#security), [event model and data quality](../architecture.md#event-model-and-data-quality),
  [toolchain and versions](../architecture.md#toolchain-and-versions); `schemas/rule-pack.v1.json`;
  `schemas/agent-signature.v1.json`; `packages/rules/`; `packages/agents/`; `thresholds.toml`;
  `dependency-rules.toml`; [threat model](../threat-model.md) (KT-01, KT-02, KT-12, KT-15, KT-20,
  KT-30, KT-31, KT-43, KT-45, KT-52–KT-57)

## Context

`koru-detect` is Koru's detection layer: it reads and evaluates Sigma-compatible YAML rule packs; enriches
events with the process lineage, AI agent signatures and the decoy catalog; classifies
AI-agent-originated access as "suspected hijacked agent"; estimates the actor kind with rationale
and confidence; enforces the allowlist and self-protection events; links every rule to an ATT&CK
technique.

Rule files come from contributors and Koru runs as root (KT-12, KT-35): the parser and the
evaluator must be robust against attacker input. Most event fields (exe, command line, file name)
are under the attacker's control (KT-02, KT-15); decisions must not rest on these fields being
authentic.

## Decisions

### 1. YAML library: `yaml-rust2` 0.13.0

The detection layer needs a maintained YAML parser. Those evaluated (sources read from crates.io and
RustSec on 2026-10-14):

| Option | Status | Decision |
|---|---|---|
| `serde_yaml` 0.9.34+deprecated | Archived by the repo author, last release 2024-03-25 and the version name `+deprecated`. The `unsafe-libyaml` it depends on has RUSTSEC-2024-0449 ("unmaintained"); the advisory text calls `serde_yaml` "itself deprecated". The old RUSTSEC-2018-0005 (recursion) is patched. | Rejected: unmaintained and built on an unsafe C translation. |
| `serde_yml` 0.0.13 | RUSTSEC-2025-0068: "unsound and unmaintained"; the GitHub repo is archived; the last release is a stub redirecting to another package. Its dependency `libyml` has RUSTSEC-2025-0067 (unsound). | Rejected: not sound. |
| `serde_yaml_ng` 0.10.0, `serde_norway` | `serde_yaml` forks (the RustSec `serde_yml` advisory recommends them); they depend on `unsafe-libyaml` (RUSTSEC-2024-0449) or a fork of it. The last `serde_yaml_ng` release is 2024-05-26. | Rejected: the same unsafe C translation. |
| `saphyr` 0.2.1 | Active, but published on 2026-10-12; its maturity cannot be measured. | Not chosen for now; in the same class as yaml-rust2, to be evaluated later. |
| **`yaml-rust2` 0.13.0** | Pure Rust; no `unsafe` in its own source (`grep unsafe` is empty); MIT or Apache-2.0; last release 2026-09-11, the last six releases published between 2025-06 and 2026-09; 64 million downloads; the fork RustSec recommends for the abandoned `yaml-rust` (RUSTSEC-2024-0320). `cargo audit` 0 vulnerabilities; `cargo deny check` clean on advisories, bans, licenses and sources. | **Chosen.** |

`yaml-rust2`'s default features (`encoding` → `encoding_rs`) are off. The only new transitive
dependency is `arraydeque` (`hashlink` was already in the tree); both are data-structure crates and
they contain `unsafe`, while `#![forbid(unsafe_code)]` still holds in Koru's code. The latest
`arraydeque` release is 2023-02-05 (no advisory); its maintenance status is re-checked at each dependency review.

`yaml-rust2` itself does not enforce anchor/alias and depth limits. These limits are in Koru
(`koru_detect::yaml_json`): the parser's event-based interface (`Parser::next_token`) is used, events
are pulled one by one and parsing is abandoned the moment a limit is exceeded. The rules:

- A single document; an empty document and multiple documents are rejected.
- Anchors, aliases ("billion laughs"), tags (`!!str`, `!custom`), duplicate keys and non-text
  (complex) keys are rejected.
- Depth is limited to 32, node count to 10 000 and input to 1 MiB. The tree is built with an explicit
  stack (no recursion); thanks to the depth limit, dropping `serde_json::Value` does not overflow the
  stack either.
- Quoted scalars are text. In unquoted scalars a subset of the YAML 1.2 core schema:
  `true`/`false`, `null`/`~`/empty, decimal integer; the rest (`yes`, `1.5`, `0x10`, `2026-10-10`)
  is text. This way values like `yes` or a date do not turn into an unexpected type.
- The parser's English error message is wrapped in a Turkish frame and given with line/column.

### 2. Rule format: Sigma v2.1.0 subset + `koru` section

- The YAML document is converted to `serde_json::Value` and read into Rust types carrying
  `deny_unknown_fields`. The schema lives in two places: `schemas/rule-pack.v1.json` and the Rust
  types; the tests feed the same examples to both. Patterns and semantic rules (ATT&CK, field names,
  modifiers, condition, date, uniqueness) live only in Rust and are tested separately.
- Standard Sigma fields (`Image`, `CommandLine`, `ParentImage`, `TargetFilename`, …) and
  Koru-specific derived fields with the `koru.` prefix (`koru.decoy_class`, `koru.ai_agent_ancestor`,
  `koru.protected_kind`, …; the full list is `SUPPORTED_FIELDS`). A rule that refers to a field not
  in the list is rejected: there is never a "junk" rule that cannot match.
- `logsource`: `category` (`file_access`, `file_event`, `process_creation`, …; mapped to Koru event
  kinds) or `service: koru` (only Koru's own events). Koru's events go only to `service: koru`
  rules, sensor events only to `category` rules.
- The `koru: {threat_class}` section is a private field in Sigma; it is stripped in Sigma export.
- The file name is the same as the rule's `name` field (iCloud copies like `name 2.yml` are not loaded
  silently); `id` and `name` are unique in the pack; a `.yaml` extension is not skipped silently, it
  errors.

### 3. Evaluator: no regular expressions

`selection`, `condition` (`and`, `or`, `not`, parentheses, `1 of`, `all of`, `them`) and the
modifiers `contains`, `startswith`, `endswith`, `all`, `exists`, `cased` are supported. Modifiers
like `re` and `base64` are rejected. Wildcards (`*`, `?`) and Sigma escapes (`\*`, `\?`, `\\`) are
enforced by a two-pointer matcher that backtracks to the last `*`: in the worst case it takes
`pattern × value` steps, there is no exponential backtracking (KT-12). The default match is
case-insensitive (case-sensitive with `cased`). A `condition` can be at most 4096 characters and 32
levels nested; if the target of `1 of`/`all of` matches no selection, the rule is rejected.
Evaluation caches the selection results per event.

### 4. ATT&CK v19.2

- The catalog (`crates/koru-detect/data/attack-enterprise-v19.2.tsv`) is generated with
  `tools/attack-catalog-gen.py` from the official STIX bundle at the `v19.2` tag of the
  `mitre-attack/attack-stix-data` repository (the bundle's SHA-256 digest is in the file's header
  and is verified at generation). There is no network at runtime.
- Every rule carries at least one valid technique tag (`attack.t1552.001`); the technique must be
  valid in the catalog and the tactic tags must be consistent with the technique. **A revoked
  technique is rejected and the error names the replacement:** in v19 Defense Evasion split into the
  `stealth` and `defense-impairment` tactics; T1562.001 was revoked and replaced by T1685 ("Disable
  or Modify Tools", `defense-impairment`). Self-protection rules are therefore bound to T1685 (and
  T1489, T1070, T1565.001, T1554, T1543.002).
- `koru rule coverage` deterministically generates the Markdown coverage table and the ATT&CK
  Navigator 4.5 layer (`docs/reports/attack-coverage.md`, `attack-layer.json`).

### 5. Enrichment and classification

- Paths are lexically normalized before comparison (`//`, `/./`, `..`; a finding of the security
  review). `TargetFilename` is the new name in a rename, the link path in a link; `SourceFilename`
  is the old name or the displayed path. Decoy and protected path matching looks at both paths.
- Decoy matching goes only through `koru_event::DecoyCatalog` (`WatchedPath.class` carries the decoy class):
  koru-detect does not know koru-decoy or Pulsar; the composition is in the `koru` crate.
- AI agent signatures (`packages/agents/*.toml`, `schemas/agent-signature.v1.json`): coding
  assistants (Claude Code, Cursor, Codex CLI, Aider, Gemini CLI, Goose, OpenHands, GitHub Copilot
  CLI, opencode, Qwen Code), MCP servers and agent frameworks (LangGraph, CrewAI, AutoGen Studio);
  next to every signature there are official source links and a validation date. The conditions are
  the exe name, exe path, argv[0], script name, argument substring and `python -m` module; all are
  under the attacker's control (KT-02) and they take part only in the actor kind estimate and class
  escalation.
- A decoy access whose process or one of its ancestors matches a signature becomes
  `suspected_hijacked_agent` (severity critical); breadcrumb access stays as a separate,
  lower-priority signal (KT-52).
- Container: if the id is filled it is a container; without an id (KT-45), if the pid namespace
  differs or at least four of the uts, ipc, mount, network and cgroup namespaces differ, it is a
  "container suspicion". A mount-namespace difference alone (systemd hardening) is not a container.

### 6. Actor kind estimate

It is rule-based and always recorded with a rationale and the confidence values in `thresholds.toml`:

| State | Kind | Confidence (thresholds.toml) |
|---|---|---|
| Signature + machine speed | `ai_agent` | `agent_signature_and_machine_speed_confidence` |
| Signature | `ai_agent` | `agent_signature_confidence` |
| Machine speed + discovery pattern (no signature) | `ai_agent` | `machine_speed_and_discovery_confidence` |
| Interactive shell + human speed | `human` | `interactive_shell_and_human_speed_confidence` |
| Interactive shell (no speed signal) | `human` | `interactive_shell_confidence` |
| Other (machine speed alone, conflicting signals) | `unknown` | 0, the observed signals in the rationale |

Speed is the median of the intervals between consecutive commands (execs) run from the same parent
process; the last N commands per session and at most M sessions are kept, and the oldest session
drops when full (`[memory]`, KT-31). The session that decides is the one nearest to the process,
walking from the process toward its ancestors: the fast commands of a distant ancestor (e.g. a
script) do not suppress the human-speed commands of the nearby interactive shell (a live lab
finding). **No decision rests on `process.user.uid`:** Pulsar can show `uid` as 0 in
privilege-dropped processes (KT-43; test `actor_kt43_uid_does_not_change_the_decision`). Interactive
shell definition: the shell name is in the list, there is no `-c` and `argv[0]` starts with `-`,
`-i`/`-l`/`--login` is present or there are no arguments; if the command line is unknown (a process
that started before Koru) the shell kind cannot be determined.

### 7. Allowlist: exe path and inode only

- Input: a normalized absolute exe path (no wildcards), an optional rule list (if empty, all rules
  except self-protection), a mandatory rationale. It cannot be a process name, command line or user
  input (the schema rejects it). Self-protection rules cannot be listed and cannot be silenced by
  the allowlist.
- **Suppression happens only when both conditions hold together:** (1) the (normalized) exe in the
  event matches the input's exe path, and (2) the process's real exe (`/proc/<pid>/exe` path and the
  exe file's identity: device and inode) matches the input. The first version checked only (2); the
  security review (HIGH) found this bypass: the attacker opens the decoy with its own binary,
  immediately execs an allowlisted binary and keeps the process alive (`ptrace(PTRACE_TRACEME)` or
  waiting on stdin); when Koru processed the event, `/proc` showed the allowlisted binary and the
  finding was suppressed. The exe in the event is the image at the moment the event happened; (1)
  closes this bypass.
- **Fail closed:** if `/proc/<pid>/exe` cannot be read (the process has exited, no permission, not
  Linux) or the path is not UTF-8, nothing is suppressed and the code does not fall back to the path
  in the event (`SystemIdentitySource::verify_process_exe`). In fake sources that give no path
  information (tests) the default implementation looks only at the inode; the production source is
  always fail-closed.
- **A deliberate false positive:** the Pulsar process tracker can show the parent process's old
  image in events right after an exec (observed in a live lab test). In that case the exe in the
  event is not allowlisted, so a legitimate allowlisted binary also produces a finding. The safe
  direction was chosen deliberately; the permanent fix is an exec timeline and a
  re-query from the sensor (KT-57).
- An imitated name (`/tmp/backup`), a hard link (same inode, different path), the same path but a
  modified binary (new inode), a different rule and "open then exec" cannot be suppressed; shown
  with the fake sensor (`scenarios`, `allow_exec_bypass`) and in the live lab (KT-53).
- For Koru's own process the same two conditions hold: the pid must match; the exe in the event must
  match Koru's exe path AND the process's real exe (`/proc` path and inode) must match Koru's
  (KT-01). In the first version only the inode of Koru's own pid was read (the real exe of the
  event's process was not verified). If the identity of a short-lived process cannot be read, the
  exclusion and the allowlist do not apply (the safe direction: a false positive).

### 8. Self-protection

These cases are threat events (class `self_protection`, ATT&CK T1685 and related techniques):
configuration, secret, store, state directory, decoy, binary and service unit change (opening in
write mode, creating, deleting, renaming, linking); reading a secret file;
`systemctl stop|kill|disable|mask|restart`, `service <name> stop`, `/etc/init.d/<name> stop`;
`kill`, `pkill`, `killall` (including busybox applets); on a clean shutdown with
SIGTERM/SIGINT/SIGHUP, Koru's own produced "stopped" event (`RuleDetector::stopped`; no event from
the sensor can carry the `koru.self_event` field). Protected paths are chosen at directory
granularity with the most specific match winning (`/etc/koru/.env` is secret, `/etc/koru-backup` is
not protected). `pkill` patterns are resolved with a crude regular-expression matcher; a complex
pattern that cannot be resolved is taken to target Koru (the safe direction).

**Limit (accepted):** `kill -9` kills Koru without producing any event; the external heartbeat
catches this (ADR-0007). The shell's `kill` builtin starts no process, so it produces no exec event; a
program calling `kill(2)` directly is also invisible to these rules (KT-55).

### 9. Finding format, feedback and memory

A finding is a copy of the source event with a new UUIDv7 id; `detection` (rule, decoy id, threat
class, ATT&CK), `actor` and `tags.mitre_techniques` are filled, and it conforms to schema v1 through
`Event::validate`. Events whose `detection` field is filled are not reprocessed (KT-30). An event
that does not pass schema validation is not processed.

### 10. Composition and dependencies

koru-detect depends only on koru-event (`cargo xtask dependency-check` → 0 violations). The added
external dependencies (`dependency-rules.toml`): `serde`, `serde_json`, `toml`, `thiserror` (already
in the tree), `yaml-rust2` (+ `arraydeque`) and `tempfile` for development. The live composition is
in `crates/koru/examples/live_detect.rs`: koru-pulsar → koru-detect, the decoy catalog from
koru-decoy. `koru-pulsar` is only a development dependency of the `koru` crate; the `koru` binary
does not link Pulsar.

## Conclusions and known limits

- Pulsar's process tracker gives no command line for ancestors that started before Koru (in the live
  evidence `process.lineage[*].command_line` is empty); on those ancestors only exe-based signature
  conditions work (KT-57).
- The process tracker can show the old image in events right after an exec; decisions that rest on
  the exe path or argv (signatures, rule fields) can be affected by this. The allowlist and the Koru
  exclusion require both the exe in the event and the real exe; in the old-image case a legitimate
  allowlisted binary also produces a finding (a deliberate false positive; KT-53, KT-57).
- A breadcrumb opened with `O_RDWR` counts as a read: the
  `koru.read` field is true if the open is `O_RDONLY` or `O_RDWR`, and the `breadcrumb_*` rules
  require this; an open in write mode only (`O_WRONLY`, e.g. the shell appending to `.bash_history`)
  produces no finding. **On the decoy side** a process that opens the decoy with
  `O_RDWR` produces `koru_decoy_modified` and also a `decoy_*` finding; in an AI-agent lineage it
  lands in the "suspected hijacked agent" class (KT-58, mitigated; see ADR-0008).
- Decoy matching is done with the path string; a process that reads a decoy through a different
  mount path (e.g. binding another directory into a container) does not match (KT-56). Containers
  bound the same way are caught.
- The allowlist inode can be reused if the file is deleted and a new file with the same inode number
  is created; allowlisted binaries must sit in a directory that is unwritable and root-owned
  (KT-53).
- The YAML parser and the rule/signature/threshold readers have not been fuzzed; fuzz targets for them
  are listed in ADR-0008 (KT-12, KT-35, KT-54).
- The ATT&CK catalog is pinned in code (`ATTACK_VERSION`, currently v20.0). The 12 techniques of
  the rules are valid in v20.0; a version switch is a separate decision (catalog, `ATTACK_VERSION`
  and version-dependent tests).
