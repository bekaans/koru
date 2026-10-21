#!/usr/bin/env bash
# Live store test. Runs as root inside the VM; uses the `live_store` example, which writes
# real Pulsar events to koru-store, and the `koru` commands (koru-pulsar -> koru-store):
#   limactl shell koru-lab sudo bash /koru/lab/scripts/live-store-test.sh <target dir>
# <target dir>: the cargo target directory holding the `koru` binary and `examples/live_store`.
# Usually called via `lab/lab.sh live-store` (builds the binaries first).
#
# Method:
# 1. If the official pulsard is running it is stopped (two eBPF agents are not loaded at once);
#    it is restored at the end (including on failure).
# 2. `live_store agent` starts as root; during the scenario (file create, open, rename, delete,
#    process exec, a network connection attempt) real events are written to the store.
# 3. The agent is stopped with SIGTERM. `koru report data-quality` runs.
# 4. Deliberately corrupt lines derived from the real events exported from the store (8 reject
#    reasons) and duplicate lines (the same fact with a new id, and redelivery of the same line)
#    are fed with `koru event ingest`; the report runs again: schema compliance 100%, duplicates 0,
#    untagged 0, rejected N (> 0) with reasons listed.
# 5. Export: JSONL and OCSF, before/after --mask (only masked output is written to evidence: the
#    lab's real IPs are not shown), and rejection of a mixed source tag.
#
# Exit code: 0 if all checks pass, otherwise 1.

# The jq programs are single-quoted; the $variables in them belong to jq (--arg), not the shell.
# shellcheck disable=SC2016
set -euo pipefail

TARGET="${1:?usage: live-store-test.sh <cargo target dir (koru and examples/live_store)>}"
KORU="${TARGET}/koru"
AGENT_BINARY="${TARGET}/examples/live_store"
DEMO_LIB="/var/lib/store-demo"
DB="${DEMO_LIB}/cache.db"
SCENARIO="/var/tmp/store-demo-scenario"
SOCKET="/run/koru-live-store.sock"

info() { printf '[live-store] %s\n' "$*"; }
fail() { printf '[live-store] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must be run as root"
[ -x "$KORU" ] || fail "no koru binary: ${KORU}"
[ -x "$AGENT_BINARY" ] || fail "no live_store binary: ${AGENT_BINARY}"
command -v jq >/dev/null 2>&1 || fail "no jq; run first: lab/scripts/dev-setup.sh"

TMP=$(mktemp -d)
LOG="${TMP}/agent.log"
CONF="${TMP}/pulsar.toml"
AGENT=""
PULSARD_WAS_ON=0
cleanup() {
  if [ -n "$AGENT" ] && kill -0 "$AGENT" 2>/dev/null; then
    kill -TERM "$AGENT" 2>/dev/null || true
    sleep 2
    kill -KILL "$AGENT" 2>/dev/null || true
  fi
  rm -rf "$TMP" "$DEMO_LIB" "$SCENARIO"
  if [ "$PULSARD_WAS_ON" -eq 1 ]; then
    systemctl start pulsard.service || true
  fi
}
trap cleanup EXIT

info "environment: $(uname -srm); NTPSynchronized: $(timedatectl show -p NTPSynchronized --value)"
info "jq: $(jq --version); koru: $("$KORU" --version); live_store sha256 $(sha256sum "$AGENT_BINARY" | cut -d' ' -f1)"

rm -rf "$DEMO_LIB" "$SCENARIO"
install -d -m 700 -o root -g root "$DEMO_LIB"
install -d -m 755 -o root -g root "$SCENARIO"

if systemctl is-active --quiet pulsard.service; then
  PULSARD_WAS_ON=1
  info "stopping the official pulsard for the duration of the test"
  systemctl stop pulsard.service
fi
printf '[pulsar]\napi_socket_path = "%s"\n' "$SOCKET" >"$CONF"

info "starting the Koru agent (source tag: synthetic; store: ${DB})"
"$AGENT_BINARY" agent --source-tag synthetic --store "$DB" --pulsar-config "$CONF" 2>"$LOG" &
AGENT=$!

# Warmup: a file is opened in the scenario directory until the first record lands (at most 60 s).
ready=0
for _ in $(seq 1 120); do
  kill -0 "$AGENT" 2>/dev/null || { cat "$LOG" >&2; fail "the agent exited early"; }
  echo warmup >>"${SCENARIO}/warmup.txt"
  if [ -f "$DB" ] && sqlite_count=$("$KORU" report data-quality --store "$DB" 2>/dev/null | sed -n 's/^records: \([0-9]*\) .*/\1/p') && [ "${sqlite_count:-0}" -gt 0 ]; then
    ready=1
    break
  fi
  sleep 0.5
done
[ "$ready" -eq 1 ] || { cat "$LOG" >&2; fail "the agent wrote no record to the store within 60 s"; }
info "agent ready (pid ${AGENT})"
sleep 1

info "scenario: create, open, rename, delete a file; run processes; try a network connection"
echo not-a-secret-test >"${SCENARIO}/note.txt"
cat "${SCENARIO}/note.txt" >/dev/null
mv "${SCENARIO}/note.txt" "${SCENARIO}/note-new.txt"
mkdir "${SCENARIO}/sub"
rm -r "${SCENARIO}/sub"
rm "${SCENARIO}/note-new.txt"
id >/dev/null
ls /etc >/dev/null
# 203.0.113.9 is a documentation (TEST-NET-3) address; it appears in the command line and the connection event.
timeout 2 bash -c 'exec 3<>/dev/tcp/203.0.113.9/8080' 2>/dev/null || true
timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22' 2>/dev/null || true
sleep 3

info "stopping the agent with SIGTERM"
info "stopping the agent with SIGTERM"
wait "$AGENT" || fail "the agent ended with an error: $(tail -5 "$LOG")"
AGENT=""
grep -E '^\[store\] (agent stopped|first translation rejection)' "$LOG" | sed 's/^/[live-store] /'

echo "--- report 1: real events only ---"
"$KORU" report data-quality --store "$DB" | tee "${TMP}/report1.txt"
REAL_COUNT=$(sed -n 's/^records: \([0-9]*\) .*/\1/p' "${TMP}/report1.txt")
[ "$REAL_COUNT" -ge 5 ] || fail "expected at least 5 real events: ${REAL_COUNT}"
head -1 "${TMP}/report1.txt" | grep -Eq '^schema compliance 100% · duplicates 0 · untagged 0 · rejected [0-9]+$' || fail "report line format"
REJECTED_BEFORE=$(head -1 "${TMP}/report1.txt" | sed -n 's/.*rejected \([0-9]*\)$/\1/p')

"$KORU" export --store "$DB" --format jsonl --output "${TMP}/real.jsonl" 2>/dev/null
[ "$(wc -l <"${TMP}/real.jsonl")" -eq "$REAL_COUNT" ] || fail "the exported line count must equal the record count"
info "real event types: $(jq -r .event_type "${TMP}/real.jsonl" | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}')"

# --- Deliberately corrupt and duplicate events ----------------------------------------------
SAMPLE=$(head -1 "${TMP}/real.jsonl")
INJECTED="${TMP}/corrupt-and-duplicate.jsonl"
{
  { printf '%s' "$SAMPLE" | head -c 80; echo; }                                                         # json_format
  printf '%s\n' "$SAMPLE" | jq -c 'del(.source_tag)'                                                 # untagged
  printf '%s\n' "$SAMPLE" | jq -c '. + {extra_field: 1}'                                                  # unknown_field
  printf '%s\n' "$SAMPLE" | jq -c '.process.pid = 0'                                                       # validation
  printf '%s\n' "$SAMPLE" | jq -c '.schema_version = 2'                                                     # schema_version
  printf '%s\n' "$SAMPLE" | jq -c '.source_tag = "unknown"'                                       # invalid_source_tag
  printf '%s\n' "$SAMPLE" | jq -c 'del(.host)'                                                     # missing_field
  printf '%s\n' "$SAMPLE" | jq -c '.event_id = "550e8400-e29b-41d4-a716-446655440000"'               # schema_violation
} >"$INJECTED"
# 8 corrupt lines, 8 different reject reasons (the comments above).
CORRUPT=8
# 5 duplicates: the same fact, a new event id; 2 duplicates: redelivery of the same line.
head -5 "${TMP}/real.jsonl" | while IFS= read -r line; do
  tail=$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')
  printf '%s\n' "$line" | jq -c --arg k "$tail" '.event_id = (.event_id[0:24] + $k)' >>"$INJECTED"
done
head -2 "${TMP}/real.jsonl" >>"$INJECTED"
DUPLICATE=7
info "injected: ${CORRUPT} corrupt lines, ${DUPLICATE} duplicate lines"

"$KORU" event ingest --store "$DB" --input "$INJECTED" | tee "${TMP}/ingest.txt"
grep -q "Result: stored 0 · duplicates ${DUPLICATE} · rejected ${CORRUPT}$" "${TMP}/ingest.txt" || fail "the event ingest result differs from expected"

echo "--- report 2: after mixing in corrupt and duplicate events ---"
"$KORU" report data-quality --store "$DB" | tee "${TMP}/report2.txt"
EXPECTED="schema compliance 100% · duplicates 0 · untagged 0 · rejected $((REJECTED_BEFORE + CORRUPT))"
[ "$(head -1 "${TMP}/report2.txt")" = "$EXPECTED" ] || fail "the report line is not the expected one: ${EXPECTED}"
[ "$(sed -n 's/^records: \([0-9]*\) .*/\1/p' "${TMP}/report2.txt")" -eq "$REAL_COUNT" ] || fail "corrupt and duplicate lines must not enter the store"
grep -q "^deduplicated on ingest: ${DUPLICATE}$" "${TMP}/report2.txt" || fail "the deduplicated duplicate count"
for code in json_format untagged unknown_field validation schema_version invalid_source_tag missing_field schema_violation; do
  grep -q "^  ${code}: " "${TMP}/report2.txt" || fail "reject reason missing from the report: ${code}"
done

echo "--- 3. export (only masked output is shown) ---"
"$KORU" export --store "$DB" --format jsonl --mask --output "${TMP}/masked.jsonl"
"$KORU" export --store "$DB" --format ocsf --mask --output "${TMP}/masked-ocsf.jsonl"
! grep -q '203\.0\.113\.9[^0-9]' "${TMP}/masked.jsonl" "${TMP}/masked-ocsf.jsonl" || fail "a raw IP remained in masked output"
info "JSONL (masked) sample lines:"
jq -c '{event_id, timestamp, event_type, command: .process.command_line, target: {path: .target.path, remote: .target.remote}}' "${TMP}/masked.jsonl" | sed -n '1,4p' | cut -c1-260
info "OCSF 1.9.0 (masked) sample lines:"
jq -c '{class_uid, activity_id, type_uid, time, version: .metadata.version, file: .file.path, process: (.process.cmd_line // .actor.process.cmd_line), remote: .dst_endpoint}' "${TMP}/masked-ocsf.jsonl" | sed -n '1,4p' | cut -c1-260
info "addresses in the masked lines: $(grep -Eoh '\"ip\":\"[0-9a-f:.]+\"' "${TMP}/masked.jsonl" | sort -u | tr '\n' ' ')"
info "the masked TEST-NET address in command lines: $(grep -Eoh '203\.0\.113\.[0-9]+' "${TMP}/masked.jsonl" | sort -u | tr '\n' ' ')"

echo "--- 4. mixed source tag ---"
printf '%s\n' "$SAMPLE" | jq -c '.source_tag = "legitimate" | .event_id = (.event_id[0:24] + "aabbccddeeff")' >"${TMP}/legitimate.jsonl"
"$KORU" event ingest --store "$DB" --input "${TMP}/legitimate.jsonl"
for fmt in jsonl ocsf; do
  if "$KORU" export --store "$DB" --format "$fmt" >"${TMP}/mixed.out" 2>"${TMP}/mixed.err"; then
    fail "a mixed-tag export should have been rejected (${fmt})"
  fi
  [ ! -s "${TMP}/mixed.out" ] || fail "no output must be written for a rejected export"
  info "${fmt}: rejected: $(cat "${TMP}/mixed.err")"
done
"$KORU" export --store "$DB" --format jsonl --source synthetic >"${TMP}/synthetic.out" 2>/dev/null
[ "$(wc -l <"${TMP}/synthetic.out")" -eq "$REAL_COUNT" ] || fail "--source synthetic must yield only synthetic events"
info "export with --source synthetic succeeded (${REAL_COUNT} lines)"

info "DONE: real events were stored; corrupt and duplicate events did not enter, counted by reason"
