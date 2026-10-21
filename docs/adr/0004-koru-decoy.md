# ADR-0004: koru-decoy — decoy model, template format, state directory, safe writing and rollback

- **Status:** Accepted.
- **Date:** 2026-10-10
- **Related:** [architecture](../architecture.md#decoys-and-breadcrumbs),
  [security](../architecture.md#security), [repository layout](../architecture.md#repository-layout);
  `schemas/decoy-template.v1.json`; `packages/decoys/`; `dependency-rules.toml`;
  [threat model](../threat-model.md) (KT-06, KT-07, KT-11, KT-16, KT-17, KT-23, KT-24, KT-46–KT-52)

## Context

`koru-decoy` is Koru's decoy layer: it generates classic and AI-era decoys and breadcrumbs from TOML
templates, plants them, lists them, checks their integrity and removes them cleanly. Koru will
later run as root and write into target users' home directories. These directories are under that
user's control; the user (or an attacker who has hijacked them) may try to redirect the file root
writes somewhere else by swapping path components with symbolic links. Decoys must look real, be
unique at every install and not give Koru away; removal too must return the user's files exactly to
their old state.

## Decisions

### 1. Decoy model

- A template produces a single file. In the `new_file` placement the file is created if it is
  absent, and if it exists the install is rejected (it is never overwritten). In the `append`
  placement the block is appended to the end of an existing file (a backup is taken first); the file
  is created if it is absent.
- Kind: `decoy` (a fake credential or secret value) or `breadcrumb` (a record pointing at fake
  targets). The `Catalog` (`koru_event::DecoyCatalog`) hands this distinction to the detection layer
  as `WatchedPathKind`; `koru-detect` evaluates breadcrumb reading as a separate signal (ADR-0005).
- At every install every decoy is given a UUIDv7 id. The id lives only in the integrity record; it
  is not visible in the content, the file name or the path.
- Values are generated at install time from the operating system's CSPRNG (`getrandom`). The
  templates in the repository hold only placeholders. "Generated value": keys, tokens, passwords,
  password hashes, UUID-like values of at least 16 characters and 64 bits of entropy; there is no
  generated value shared between two installs (test and evidence). Values picked from a list
  (profile name, file name) and narrow-range values (port, documentation network address, date) can
  coincide by chance; that is a diversification and it reduces KT-24.
- Timestamps are natural: each file's modification time is picked within the day range in the
  template, mostly on weekdays and in working hours, with random minute, second and nanosecond; the
  dates in the content (`{{file_time.date}}`) are consistent with it. Files the install creates take
  a time slightly after the newest entry inside the directories it creates; the times of existing
  directories are preserved.
- There is no "koru" string (case-insensitive) in decoy contents or paths: template constants are
  rejected in validation; if one occurs by chance in random values, the whole package is regenerated
  (KT-23).
- The package contains: SSH private key (ed25519), production `.env` file,
  `~/.aws/credentials`, MySQL dump; LLM provider keys (`.env`), `.mcp.json`,
  `~/.config/Claude/claude_desktop_config.json`, `~/.cursor/mcp.json`, a "production access" note;
  breadcrumbs `~/.bash_history`, `~/.ssh/config`, `~/.ssh/known_hosts`.

### 2. Template format (for contributors who do not know Rust)

A template is a TOML file (`packages/decoys/<name>.toml`); the schema lives in two places:
`schemas/decoy-template.v1.json` and the Rust types (`koru_decoy::Template`, `deny_unknown_fields`).
To add a new decoy kind it is enough to write a new template and run
`koru decoy validate packages/decoys/`.

| Field | Meaning |
|---|---|
| `schema` | 1 |
| `id` | Unique id (`[a-z0-9-]`); used in cross-references |
| `description` | A Turkish description; it does not enter the content |
| `kind` | `decoy` or `breadcrumb` |
| `class` | Free label (e.g. `cloud_credentials`); a new label is enough for a new kind |
| `format` | `text`, `env`, `ini`, `json`, `mcp_json`, `sql`, `openssh_private_key`, `ssh_config`, `known_hosts`, `bash_history`, `markdown` |
| `secret` | `true` if it carries a secret value; the mode must be 0o600 |
| `content` | Content with placeholders |
| `[target]` | `path` (relative to the root, or absolute under an allowed root), `mode` (e.g. `0o600`), `placement` |
| `[timestamp]` | `min_days`, `max_days`: the file's natural time range |
| `[values.<name>]` | Value generators (below) |

**Placeholders:** `{{name}}`, `{{name.child}}` (a multi-output value), `{{template:name}}` (another
template's value), `{{template:path}}` (another template's path, in `~/…` form),
`{{file_time.child}}` and the `|lower`, `|upper` filters. There is no logic, loop or condition.

**Value generators:** `random` (alphabet, length, prefix, suffix), `choice`, `number`, `uuid4`,
`bcrypt` (a format; not the hash of a real password), `github_token` (a format with a CRC32 check),
`ssh_ed25519` (sub-fields `private`, `public`, `public_key`), `test_net_ipv4` (RFC 5737),
`timestamp` (sub-fields `date`, `time`, `datetime`, `iso`, `unix`, `year`), `repeat` (a random
number of repetitions of an inner template; like SQL rows).

**Validation** (`koru decoy validate`): the schema; that placeholders are defined; the targets of
cross-references; that no value is unused; 16 trial generations and a format check in each (`.env`,
INI, JSON, MCP, SQL, `ssh_config`, `known_hosts`, shell history, note).

### 3. Template safety (KT-11, KT-16, KT-17)

- The target path cannot contain `..`, `.`, an empty component, a backslash or a control character;
  an absolute path may only be under the allowed roots given at install (`--allowed-root`).
- Mode: no execute bit, no group or other write bit and no special bit; the owner can read. A secret
  file is 0600.
- A constant text written into a template is rejected if it could be a real secret (an AWS key id, a
  GitHub token, a key with the `sk-` prefix, a PEM header, a high-entropy long string).
- MCP decoys define only a remote server (`http`, `sse`, `streamable-http`); the `command`, `args`
  and `env` fields are forbidden. Even if a legitimate AI agent loads this file, it runs no command.
- In all content, IPv4 addresses are only from the RFC 5737 documentation networks and URL hosts
  are only in a documentation network or the `.invalid` domain; the domain of email-shaped addresses
  is a reserved top-level domain (`.invalid`, `.test`, `.example`, `.localhost`, `.internal`).
  Breadcrumbs point at non-routable addresses; a later release is planned to redirect them to a decoy VM (see the roadmap in the README).
- The `~/.ssh/config` block defines only new, wildcard-free aliases; `ProxyCommand`, `LocalCommand`,
  `Match` and `Include` are forbidden. The user's existing connections are not affected.
- Destructive, data-exfiltrating or instruction-changing patterns are rejected in shell history,
  notes and free text (`rm -`, `curl`, `wget`, `| sh`, `scp`, `nc`, `http://`, "ignore previous" and
  the like). The note only points at other decoys. Instruction file names that AI agents load on
  their own (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`) are not used.
- The address, URL and forbidden-pattern checks run on a copy in which random values are masked: an
  "nc " or "://" occurring by chance inside a random password is not a false alarm; every text the
  template author wrote and that is picked from a list is checked.

### 4. State directory and integrity record

- The state directory is given explicitly at every install (`--state`); it has no default. It cannot
  be nested with the root or the allowed roots: backups and the record do not stay in a place the
  target user can reach. The recommended place is a neutrally named system directory that does not
  reveal Koru to the attacker (e.g. `/var/lib/<neutral name>`). It can be set in the
  configuration file (ADR-0008).
- The directory belongs to the user running Koru and is 0700; otherwise the install is rejected.
  Inside it are `record.json` (0600) and `backups/<uuid>` (0600). Backup names are random; they
  carry no original file name and do not look like a decoy.
- The record keeps for every decoy: id, template, kind, class, absolute path, placement, SHA-256,
  size, mode, uid, gid and modification time; for appends, the appended block and the digest, mode,
  owner and time of the previous state; and the previous and new times of the directories touched.
- Install, removal and queries lock the directory with `flock` (install and removal exclusive,
  queries shared). The lock is retried for a short while: a child process inside the same process
  may hold a copy of the handle until the `exec` moment.
- Before the record is written it is written to disk together with the expected digests; if the
  install is cut short, removal proceeds from the state in the record.

### 5. Safe writing (KT-46, KT-47)

- The path is opened from `/` onward component by component with
  `openat(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`; if a component is a symbolic link the operation is
  rejected. The root, the state directory and the allowed roots are also opened this way; these
  paths must not contain symbolic links (a canonical path is given).
- All later operations are relative to the open directory handle (`mkdirat`, `openat`, `renameat`,
  `unlinkat`, `fstatat`). Swapping the path between check and use cannot redirect into another
  directory.
- A new file is created with `O_CREAT | O_EXCL | O_NOFOLLOW`; nothing existing, file or link, is
  overwritten. An existing file is written into a temporary file in the same directory and swapped
  in with `renameat`; a half-written file is never visible.
- Reading uses `O_NOFOLLOW | O_NONBLOCK` (it does not block on a FIFO); type and size are checked
  from the open handle (`fstat`).
- The append target must be a singly linked (`nlink == 1`), regular file owned by the target user. A
  hard link is rejected: otherwise the content of another file (e.g. `/etc/shadow`) could leak into
  the backup and into the new file owned by the target user.
- Mode, owner and time are set through the open handle (`fchmod`, `fchown`, `futimens`). Files are
  created with the mode in the template, directories with 0700; the owner is the root's owner or the
  user given with `--owner`.
- `unsafe` is not used. std has no `*at` calls; that is why `rustix` was chosen. Only `O_NOFOLLOW`
  (std `custom_flags`) protects the last component; it does not prevent intermediate directories
  from being swapped.
- Outside Linux (the development machine), install and removal can only happen under the system
  temporary directory. This technically prevents decoys from being planted by accident into the
  developer's real home directory (KT-51).

### 6. Rollback

- Removal touches only the files in the record.
- New file: it is deleted if its content is identical to the SHA-256 in the record. **If it differs
  it is not deleted, it is reported and it stays in the record** (exit code 1). Reason: the change
  may be a trace left by the attacker or the user, or real data written over it; deleting blindly
  destroys evidence and can lose user data. The administrator inspects the file and deletes or
  restores it himself; when removal is run again the record is cleaned.
- Append: if the file has not changed since the install it is restored from the backup exactly
  (content, mode, owner, modification time). If it changed (e.g. the shell kept writing to history)
  only the appended block is removed; if the block cannot be found as a whole, its lines are removed
  one by one, from the end backwards. The backup is verified against the digest in the record before
  it is restored.
- Created directories are deleted if they are empty; if they are not empty they are left and a
  warning is given.
- The modification time of touched existing directories is restored if nobody else changed it after
  the install; if it changed it is left alone and a warning is given. In a partial removal this
  information is updated in the record; after a second removal the tree is again exactly in its old
  state.
- A failed install is rolled back the same way; the record and the backups are deleted.
- Evidence: in the lab VM, install → remove digests before and after are exactly the same with
  `lab/scripts/file-digest.sh` (path, kind, mode, owner, size, content SHA-256, nanosecond mtime).

### 7. Dependencies

Only additions were made to `dependency-rules.toml`. koru-decoy depends only on koru-event.

| Crate | Version | Reason |
|---|---|---|
| serde, toml, thiserror | in the workspace | Template schema, TOML, error types |
| serde_json | 1.0.151 | Integrity record; validation of JSON/MCP decoys |
| uuid | 1.27.0 | UUIDv7 id (same as koru-event) |
| getrandom | 0.4.3 | CSPRNG (the version uuid uses) |
| sha2 | 0.11.0 | RustCrypto SHA-256 |
| ed25519-dalek | 3.0.0 | ed25519 public key derivation; default features off |
| rustix | 1.1.5 | `*at` calls without `unsafe`, `flock`, `geteuid` (already in the Pulsar tree) |
| tempfile | 3.27.0 | Tests only |

The licenses of the newly arriving transitive crates are in the allow list in `deny.toml` (no new
exception); no OpenSSL arrives; `cargo deny check` and `cargo audit` are clean
(CI job `supply-chain`).

## Alternatives considered

- **std only (`O_NOFOLLOW` + `symlink_metadata` check):** Protects the last component, does not
  close the check-to-use race (TOCTOU) in intermediate directories. Insufficient for root; rejected.
- **Linux `openat2(RESOLVE_NO_SYMLINKS)`:** The most solid path but Linux 5.6+ only; the tests would
  not run on the development machine (macOS). Component-by-component `openat` gives the same
  guarantee on both platforms.
- **RustCrypto `ssh-key`:** Writes the OpenSSH format out of the box, but still brings ed25519-dalek
  for ed25519 plus extra encoding crates. The format is small and well defined, so it was written by
  hand and tested with `ssh-keygen -l/-y`.
- **RSA key:** Requires bignum and prime generation; more dependencies and more risk.
- **Template engine (Tera, Handlebars):** Carries logic and loops; makes template safety hard to
  audit. The placeholder language is deliberately logicless.

## Conclusions and known limits

- A root-privileged attacker can change the record, the backups and the decoys together (KT-07);
  that is the limit of local integrity. A record change is a self-protection event in `koru-detect` (ADR-0005).
- If the shell writes to the same file during an append (after the file has been re-read and its
  digest checked, before `renameat`), a line can be lost; the window is at millisecond level
  (KT-49).
- It is known that the account id can be derived from AWS access key ids; a random id is a
  nonexistent key, and account ids are not counted as secret information. It is recorded as a note.
- Legitimate reading of breadcrumbs (the shell reading its own history, `ssh` reading its
  configuration) is a source of false positives in detection; the distinction is made in `koru-detect` (KT-52).
- Using only remote servers in the desktop AI assistant's configuration is not as realistic as real
  configurations that carry `command`; security (KT-17) comes before realism.
- The state directory and the template path are set in the single configuration file (ADR-0008),
  which also covers the systemd hardening.
- The template and record parsers are fuzzed (`fuzz/`, [security](../architecture.md#security)).
