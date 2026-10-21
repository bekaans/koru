# ADR-0006: koru-store — SQLite WAL store, event key, OCSF mapping, masking, retention and rotation

- **Status:** Accepted.
- **Date:** 2026-10-15
- **Related:** [event model and data quality](../architecture.md#event-model-and-data-quality),
  [repository layout](../architecture.md#repository-layout); `dependency-rules.toml`;
  [threat model](../threat-model.md) (KT-09, KT-15, KT-19, KT-26, KT-59–KT-65); ADR-0003, ADR-0004

## Context

`koru-store` is Koru's event store. The store is evidence and it carries personal data (attacker IPs, user
names, command lines): its integrity, confidentiality and retention period must be handled together.
The architecture requires: every event passes schema validation; a corrupt, incomplete or untagged event
never enters the store, it is rejected and counted; duplicate events are deduplicated; synthetic,
legitimate and real data never mix; export has a masking option; the data quality report says
"schema compliance 100% · duplicates 0 · untagged 0 · rejected N". As the dependency matrix
requires, koru-store depends only on koru-event (rusqlite and the OCSF mapping live here).

## Decisions

### 1. Store design

- **SQLite, `rusqlite` 0.40.2, `bundled`** (SQLite 3.53.2, 2026-06-03, compiled from source; the
  version is independent of the system and pinned. The newest version on sqlite.org is 3.54.0
  (2026-10-09); the latest stable rusqlite still packages 3.53.2, it will be updated in the next
  rusqlite release). Default features are off; no ORM, connection pool, vtab or extension. It brings
  no new dependency tree: `rusqlite` and `libsqlite3-sys` were already in the Pulsar tree
  (`Cargo.lock`); `cc` was added as a build dependency. Evaluated and not chosen: a plain JSONL file
  (concurrent writing, deduplication and deletion are hard), `sled` (maintenance status unclear),
  `sqlx`/`diesel` (unnecessary weight and extra dependency).
- **Connection settings:** `journal_mode = WAL` (concurrent reads, crash-resistant), `synchronous =
  FULL` (evidence must not be lost on power failure), `secure_delete = ON` (deleted personal data is
  zeroed in the page; personal data protection), `trusted_schema = OFF`, `cell_size_check = ON`, busy timeout 5 s. Schema
  version `PRAGMA user_version = 1`; a store written with a newer version is not opened
  (`SchemaVersion`). `application_id` is not set and the word Koru does not appear in the schema
  (test `schema_does_not_contain_the_word_koru`).
- **Schema** (`STRICT` tables): `events(seq, event_id UNIQUE, event_key UNIQUE, timestamp,
  source_tag CHECK, event_type, data)`, `rejected(reason, count)`, `counters(name, value)`. `data` is
  the event's canonical JSON (that is the source of truth); the other columns are for queries and
  consistency checks. `timestamp` is fixed-width canonical text (`koru_event::Timestamp`), so a text
  sort is a time sort.
- **Parameterized SQL:** All queries are constant text; changing values are parameters only. SQL is
  never built with string concatenation. This is tested in two ways: a behavior test
  (`sql_injection_is_neutralized`: a path containing `'; DROP TABLE events; --` is stored and the
  table survives) and a source scan (`tests/sql_safety.rs`).
- **Writing:** every insert is a `BEGIN IMMEDIATE` transaction; two connections can write at the
  same time, and even if the same event arrives from two connections it is stored once (tests
  `two_connections_*`).

### 2. File safety

The safe file principles of ADR-0004 §5 also hold here; since koru-store cannot
depend on koru-decoy, the principles are implemented here with `rustix` (`src/path.rs`, no
`unsafe`):

- The store path must be absolute; `.` and `..` are not accepted. The path is opened from the root
  component by component with `openat(O_DIRECTORY | O_NOFOLLOW)`; if one of the components is a
  symbolic link it is rejected.
- Only the directory immediately above the store file is created if it is missing (0700); a missing
  directory higher up is an error (the chain is not created silently). The directory must belong to
  the user running Koru and be 0700; otherwise the store is not opened (e.g. `/tmp` cannot be used
  directly).
- If the file is absent it is created 0600 with `O_CREAT | O_EXCL | O_NOFOLLOW`. If it exists: a
  symbolic link, a non-regular file (it does not wait on a FIFO; the type is checked with `fstatat`
  before opening), a file owned by another user, a mode open to group or others and multiple hard
  links are rejected (the same reasoning as KT-47). SQLite is additionally opened with
  `SQLITE_OPEN_NOFOLLOW`. The WAL and SHM files take the main file's 0600 mode (test
  `wal_and_shm_files_are_also_0600`).
- **Place:** The path is configurable and has no default (`--store`); a neutral name that does not
  give Koru away is recommended (like the state directory in ADR-0004 §4, `/var/lib/<neutral
  name>/`). It is set in the configuration file (ADR-0008).
- Residual: there is a short window between the path check and SQLite's opening; since the directory
  is 0700 and user-owned, only the same user or root can race (KT-59).

### 3. Validation at ingest and reject reasons

`Store::store_json` classifies a raw line in this order; the first matching reason is counted and
the event does not enter the store. The codes are permanent (they appear in the database and in the
report):

| Order | Code | When |
|---|---|---|
| 1 | `size_limit` | the line is larger than 1 MiB |
| 2 | `json_format` | not JSON or not an object |
| 3 | `untagged` | `source_tag` is absent, `null` or empty |
| 3 | `invalid_source_tag` | a value or kind other than synthetic, legitimate, real |
| 4 | `schema_version` | `schema_version` is not 1 |
| 5 | `unknown_field`, `missing_field`, `schema_violation` | a serde (schema v1) error; the distinction follows the pattern at the start of the message (attacker text inside the message does not change the class) |
| 6 | `validation` | `Event::validate` rejected a cross-field rule |
| 7 | `id_conflict` | the same `event_id` is already recorded with different content (tampering or an error) |
| — | `translation_invalid_field`, `translation_validation` | events rejected during sensor translation (below) |

`untagged` comes first: an event without a tag shows the tag problem even if it is also corrupt for
another reason. `Store::store_event(&Event)` passes a type-level valid event through
`Event::validate` again; `EventStore::store` returns the rejection as
`InterfaceError::Permanent("rejected: <code>")` and counts it.

**Translation rejection.** The `koru-pulsar` bridge module used to
drop translation errors silently. Now `TranslationCounters` (atomic, shared through `Arc`) counts
the rejected ones (`rejected_invalid_field`, `rejected_validation`) and the deliberately skipped ones
(a THREAT duplicate, an unsupported kind; these do not count as rejections);
`PulsarSensor::translation_counters()` exposes them. koru-pulsar does not know koru-store; the
composition in the `koru` crate forwards the counters to the store with `Store::count_rejected`
(example `live_store`). **The dependency matrix and the architecture did not change** (no new
koru-internal dependency; `cargo xtask dependency-check` 0 violations). In the live test two real
Pulsar events were rejected with the reason `target.path is required for file_opened events` and the
report showed `translation_validation: 2` (`crates/koru-pulsar/tests/translation_counter.rs`).

### 4. Event key and deduplication

`event_id` is a UUIDv7: it changes at every production, so a redelivery of the same fact with a new
id cannot be caught by identity alone. The key is the SHA-256 digest of the fields that identify
**the observed fact**. Those that go in (and why):

| Field | Reason |
|---|---|
| `schema_version`, label `koru-event-key-v1` | If the schema or the encoding changes, the keys do not collide |
| `source_tag` | Synthetic, legitimate and real never mix; the same fact is stored under both tags |
| `host`, `timestamp` (ns), `event_type` | Where, when and what the fact is |
| `process.pid`, `process.start_time` | Identifies the process uniquely (pid is reused) |
| `target.*` (path, new_path, flags sorted, hard_link, protocol, local, remote, exit_code) | The target of the event |
| `detection.rule`, `detection.decoy_id` | Findings of two different rules on the same fact are separate records; a raw event and a finding are also separate |

Those that do not go in: `event_id` (above), `timestamp_trusted`, `sensor.*`, `process.exe`,
`command_line`, `environment`, `user`, `lineage`, `ppid`, `container.*`, `actor`, `tags`,
`session_id`, `response`. These are enrichment and estimate fields; the Pulsar process tracker can
give a different command line or an old image for the same event (KT-57) and the actor estimate
changes with the rule version. If these fields were in the key, a redelivery would not count as a
duplicate and the attacker could also forge "different" records with variable fields (command
line).

Encoding (length-prefixed; `a|bc` and `ab|c` do not collide): a field is `0x00` (absent) or
`0x01 || u32 length || bytes`; a list is `u32 count` and the items; a network endpoint is `0x00` or
`0x01 || ip || port`. The order is in the header of `src/key.rs`; an independent reimplementation in
`tests/dedup.rs` verifies the key byte for byte. Behavior: the same key → `Duplicate` (does not
enter the store, the `deduplicated` counter grows, not counted as a rejection); the same id but a
different key → `id_conflict` rejection. Limit: since the key holds ns time, only an event with the
same time is a duplicate; events with close but different times are separate records (a wrong
duplicate is not preferred: losing evidence is worse than redundant copies).

### 5. Export

- **JSONL:** every line is a Koru event (schema v1). **OCSF:** every line is an OCSF 1.9.0 event
  (§6). Order: time, then event id. The output is streamed (not collected in memory).
- **Mixed source tags are rejected** ([architecture](../architecture.md#event-model-and-data-quality)): if `--source` is not given and the store holds
  several tags, a `MixedSources` error is returned before anything is written; `--source <tag>`
  exports a single tag. A record whose tag in the line does not match the column is not written
  (tampering).
- **A corrupt record is not written:** if the line does not pass schema v1 and `Event::validate`, or
  consistency with the columns, it is skipped and counted as `skipped_corrupt` in the result (the
  CLI warns).
- **CLI:** `koru export --store … --format jsonl|ocsf [--mask] [--source …] [--output file]`. The
  output file is created new (`O_EXCL`, 0600): an existing file and a symbolic link are not
  overwritten; on error no half-written file is left. The output carries export data (which may be
  personal data).

### 6. OCSF mapping

**Version.** The target is OCSF **1.9.0**. Verification (2026-10-15): the `ocsf/ocsf-schema` GitHub
releases show 1.9.0 (2026-08-03) as the latest stable (1.8.0 was 2026-03-18);
`schema.ocsf.io/api/versions` shows 1.9.0 as the default version, `1.10.0-dev` is a development
version and is not used. The mapping tests run against a snapshot generated from the official schema
API (`tests/data/ocsf-1.9.0-snapshot.json`, generator `tools/ocsf-snapshot-gen.py`, sources and
commands in `tools/ocsf-snapshot-gen.py`): required attributes, no attribute absent from the schema
(only `unmapped` is free), types, `enum` sets, `at_least_one` constraints and
`type_uid = class_uid * 100 + activity_id`. The snapshot was generated with the `host` profile (for
`actor` and `device`); the osint, cloud etc. profiles are not used.

**Classes.**

| Koru | OCSF class | Activity |
|---|---|---|
| detection present | Detection Finding (2004, category 2) | Create (1) |
| `file_opened` | File System Activity (1001, category 1) | Open (14) |
| `file_created`, `directory_created` | 1001 | Create (1); for a directory `file.type_id` 2 (Folder) |
| `file_deleted`, `directory_deleted` | 1001 | Delete (4) |
| `file_renamed` | 1001 | Rename (5); `file` the old, `file_result` the new name |
| `file_link` | 1001 | Other (99), `activity_name` "Link"; `file` the link, `file_result` the path it points to (OCSF has no link activity) |
| `process_executed` | Process Activity (1007) | Launch (1), `launch_type_id` 3 (Exec) |
| `process_exited` | 1007 | Terminate (2), `exit_code` |
| `network_connection` | Network Activity (4001, category 4) | Open (1); `connection_info.direction_id` 2 |
| `network_accept` | 4001 | Open (1); `direction_id` 1; the initiator is the remote endpoint (`src_endpoint`) |

**Fields.** `time` is in milliseconds (the full ns is in the `metadata.original_time` text);
`metadata`: version 1.9.0, product Koru, `uid` the event id, `labels` `["source:<tag>"]`; `device`
the host name; `actor.process` the process and lineage (`parent_process` chain), `actor.user.uid`.
Detection Finding: `finding_info` (`uid` event id, `title` rule, `types` threat class, `analytic`
rule, `attacks` ATT&CK: `T1552.004` → `technique` T1552 + `sub_technique` T1552.004), `evidences[0]`
(process, file, endpoints), `status_id` 1 (New), `is_alert` true. `severity_id` in a finding by
threat class: decoy access 4 (High), breadcrumb access 2 (Low), suspected hijacked agent 5
(Critical), self-protection 4; in other events 1 (Informational). Koru fields with no counterpart in
the schema (actor estimate, tags, container, sensor, source tag, `timestamp_trusted`, flags, decoy
id, the `untrusted_fields` path list) live under `unmapped.koru`; no other non-standard attribute is
written. Attacker data is carried only as values (test
`attacker_data_only_in_values_in_mapping`).

### 7. Masking (personal data)

`--mask` (in the library `mask_event`) changes **the exported copy**, not the stored data. Format:
in IPv4 the last octet is zeroed (203.0.113.77 → 203.0.113.0, /24); in IPv6 the first 48 bits are
kept (2001:db8:abcd:12::99 → 2001:db8:abcd::, /48); in IPv4-mapped IPv6 the last octet of the IPv4
part is zeroed. This is a design choice (the network prefix is kept so that the attack source can be
analyzed at network level; it is not based on an external standard) and **it is not full
anonymization**: the shortened address still shows a network. If full anonymization is needed, the
option will be added later.

Masked: `target.local` and `target.remote` (as a whole, the port is kept; the event stays valid) and
the addresses in free texts: `process.exe`, `command_line`, `environment`, lineage, container
fields, `target.path`, `new_path`, `actor.rationale`, `tags.intent`, `session_id`,
`response.rationale` and (after the security review) `detection.rule` and `detection.decoy_id`. Since
`finding_info.title`, `analytic.name` and `message` in OCSF derive from these fields, they are
covered when generated from the masked Event. **Not masked:** `host` and `sensor.*` (the protected
server's own identity; `tests/masking.rs` `host_and_sensor_not_masked` fixes this and it is locked).
This means that in events coming from outside with `koru event ingest`, an address written into
these fields can come out unmasked (KT-66); in events from the sensor these fields are Koru's own
install values.

**Scanner** (`src/mask.rs`; no new dependency, no regular expressions). The text is scanned byte by
byte in linear time: at every position at most 45 bytes are looked ahead (the longest IPv6 text),
stopping early on group length, the number of colons and `:::`. At every position IPv6 is tried
first, then IPv4:

- **IPv6:** the longest valid match (the `std` parser validates). It does not start in the middle of
  a word (there must be no letter, digit or `_` before it) but it can start after separators like
  `src:`, `from:`, `x:y:`; there must be no letter, digit or `_` to its right; `:` and `.` are
  accepted only when no address continuation follows (end of sentence, like "address:").
  `fe80::1%eth0` → `fe80::%eth0`.
- **IPv4:** 4 octets, each 1-3 digits and ≤ 255; **octets with leading zeros also count as IPv4**
  (`010.000.000.001` → `010.000.000.0`). The first three octets stay as written, the last octet
  becomes `0`; there is no octal interpretation. To its left there must be no digit or another
  dotted number part (`1.2.3.4.5`, `2026.10.15.4`), to its right no digit or another dotted number
  part.
- **Adjacent writings:** `ssh -L 8080:10.0.0.5:22` → `8080:10.0.0.0:22`;
  `example.com:443:203.0.113.9` → `…:203.0.113.0`; `src:192.0.2.7` → `src:192.0.2.0`;
  `from:2001:db8:1:2::5` → `from:2001:db8:1::`; `10.0.0.5:22->203.0.113.9:443`;
  `[2001:db8::1]:443`.
- **Not counted as addresses:** a clock (`12:30:45`, `12:30:45.123`), a version (`1.2.3`,
  `10.15.7`), a 48-bit MAC (`00:1a:2b:3c:4d:5e`, `00-1a-…`), dates and ISO timestamps, hex digests,
  `std::fs::File`, `Result::Ok`. **MAC decision:** a 48-bit MAC (6 groups) cannot be IPv6 and is not
  masked; an 8-group EUI-64 (`00:1a:2b:ff:fe:3c:4d:5e`) is a valid IPv6 text and cannot be told
  apart from one, so it is treated conservatively and masked like IPv6 (`0:1a:2b::`); since a MAC
  address is an identifier that may count as personal data, this false positive is preferred.

**Known limits (not masked):** (1) in 6to4 (`2002:c000:0204::`) and Teredo (`2001:0:…`) addresses the
IPv4 sits inside the first 48 bits and is **kept** by the IPv6 /48 rule (in 6to4 the whole address
stays); (2) alternative IPv4 encodings (`0x7f000001`, decimal `2130706433`, dotted hex/octal
`0x7f.0.0.1`, `0177.0.0.1` with octal interpretation) are not recognized as addresses; (3) non-IP
personal data (user name, email, MAC); (4) if the address is split by letters (`1.2.3.x4`) or
encoded (URL percent encoding, Base64). These are recorded as a separate threat (KT-67). Masking is
idempotent and the output passes the schema (tests `masking.rs`, `masking_embedded.rs`,
`export.rs`); linear time is tested with `pathological_inputs_processed_in_linear_time`.

### 8. Retention and rotation

- The default retention is **90 days**, changed with `StoreSettings::retention_days` /
  `--retention-days` (at least 1). The period is counted from the event's `timestamp` field: if
  `timestamp < now − retention` it is expired, and a record on the boundary stays. (The event time
  was chosen over the ingest time: an old event that enters the store late is also deleted when it
  expires; the sensor time is not under the attacker's control.)
- **Rotation** (`Store::freeze`, `koru store freeze`): (1) the expired are deleted; (2) if the
  record count exceeds the `max_records` cap, the oldest by time are deleted (against unbounded disk
  growth); (3) after the deletion, `VACUUM` rewrites the file and `wal_checkpoint(TRUNCATE)`
  truncates the WAL. Together with `secure_delete`, deleted personal data does not remain in the
  database file or in the WAL (test `deleted_personal_data_does_not_remain_in_file`). The counters
  (reject and duplicate counts) are not deleted.
- The chosen method is single-file, in-place rotation. The rejected option: multi-file rotation by
  time slices (renaming the file and deleting the old one). Reason: deduplication across files, query
  and report complexity, and the risk of deleted data remaining in the old file; at this scale the
  volume fits in a single file. It will be re-evaluated after measurement if needed.
- The schedule that triggers rotation (daily) is wired to the agent service and a `systemd` timer
  (ADR-0008); the store provides a command and a library function.

### 9. Data quality report

`Store::quality_report` / `koru report data-quality --store`:

> schema compliance 100% · duplicates 0 · untagged 0 · rejected N

- **Schema compliance:** every record in the store is re-validated in the form it would be exported
  (JSON → schema v1 → `Event::validate`) and its consistency with the columns (id, tag, time, kind)
  is checked; the percentage is rounded down (99.5 never shows as 100); with no records it is 100%.
- **Duplicates:** the event key is recomputed from the content (the index is not trusted); the number
  of extra records whose key equals another record's.
- **Untagged:** a record in the store without a valid source tag.
- **Rejected:** the total rejected at ingest and the breakdown by reason (including translation
  rejections); also the number of duplicates deduplicated at ingest. The reject and duplicate
  counters are permanent.
- Exit code: 1 if a record in the store does not fit the schema, or a duplicate or untagged record
  exists; an event rejected at ingest is not an error (counting it is the expected behavior).
- Memory: the duplicate count keeps the first 128 bits of the key (about 160 MB at 10 million
  records).

## Conclusions and residual risks

- The store file is **not encrypted**; the protection is file permissions and directory mode. Root
  or an attacker with disk access reads and changes it (KT-09, KT-59). Tampering is only detected
  (report, export), not prevented; digest chaining and signing remain open (KT-59). A file change is
  a self-protection event (ADR-0005).
- Masking happens at export time; the stored events hold raw addresses (for forensic analysis) and
  are deleted after 90 days.
- The OCSF mapping is a broker format: some Koru fields live under `unmapped.koru` and an OCSF
  consumer does not know them. There is no mark in OCSF for the untrusted fields; the path list is
  in `unmapped.koru`.
- The full-disk behavior (write error `InterfaceError::Transient`) is measured in the resilience
  tests (ADR-0009).
- Moving the store path and the retention period to the configuration file and scheduling rotation
  is covered by ADR-0008.

## Test summary

`crates/koru-store/tests/` (store_basic, permissions, schema_validation, dedup, masking,
masking_embedded, export, ocsf, retention, report, sql_safety), `crates/koru-pulsar/tests/translation_counter.rs`,
`crates/koru/tests/store_cli.rs`. 

## Additional note: where the masking function lives

The `mask_ip_in_text` function and the single-address function `mask_ip` were moved to
`koru-event/src/mask.rs` without any behavior change (koru-notify uses the same masking in
notifications; the dependency matrix does not allow koru-notify to know koru-store). koru-store
re-exports `mask_ip_in_text` under the same name; `mask_event` (which walks the event fields) stays
here. The masking formats and limits in §7 of this document (KT-66, KT-67) hold unchanged; details
are in ADR-0007 §8.
