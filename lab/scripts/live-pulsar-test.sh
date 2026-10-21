#!/usr/bin/env bash
# Live Pulsar translation test. Runs as root inside the VM; uses Koru's own binary with
# the embedded module (Pulsar main 0bb7bc2 + the Koru bridge module; ADR-0003):
#   limactl shell koru-lab sudo bash /koru/lab/scripts/live-pulsar-test.sh <live_translation binary>
# Usually called via `lab/lab.sh live-pulsar` (builds the binary first).
#
# Method:
# 1. If the official pulsard (v0.10.1) is running it is stopped; two eBPF agents are not loaded
#    at once. It is restored at the end of the test (including on failure).
# 2. The Koru agent is started with the engine API socket at a separate path and writes, as JSON
#    lines, only events for paths under the /tmp/koru-live prefix.
# 3. Harmless file operations run as the unprivileged `nobody` user, plus one read inside a rootful
#    podman container. The files hold only "fake" content.
# 4. The agent is stopped with SIGINT; the output is validated against schema v1 (live_translation
#    validate) and the expected events are checked one by one with jq.
#
# Exit code: 0 if all checks pass, otherwise 1.
set -euo pipefail

BINARY="${1:?usage: live-pulsar-test.sh <live_translation binary>}"
PREFIX="/tmp/koru-live"
WARMUP="/tmp/koru-live-warmup"
SOCKET="/run/koru-live.sock"
IMAGE="docker.io/library/alpine:3.22"
EXPECTED_VERSION="0.11.0-alpha.1+0bb7bc20"

info() { printf '[live] %s\n' "$*"; }
fail() { printf '[live] ERROR: %s\n' "$*" >&2; exit 1; }
unpriv() { setpriv --reuid=nobody --regid=nogroup --clear-groups -- "$@"; }

[ "$(id -u)" -eq 0 ] || fail "must be run as root"
[ -x "$BINARY" ] || fail "binary missing or not executable: ${BINARY}"
command -v jq >/dev/null 2>&1 || fail "no jq; run first: lab/scripts/dev-setup.sh"
command -v podman >/dev/null 2>&1 || fail "no podman; run first: lab/scripts/dev-setup.sh"

TMP=$(mktemp -d)
OUTPUT="${TMP}/events.jsonl"
LOG="${TMP}/agent.log"
CONF="${TMP}/pulsar.toml"
AGENT=""
PULSARD_WAS_ON=0
cleanup() {
  if [ -n "$AGENT" ] && kill -0 "$AGENT" 2>/dev/null; then
    kill -INT "$AGENT" 2>/dev/null || true
    sleep 2
    kill -KILL "$AGENT" 2>/dev/null || true
  fi
  rm -rf "$PREFIX" "$WARMUP" "$TMP"
  if [ "$PULSARD_WAS_ON" -eq 1 ]; then
    systemctl start pulsard.service || true
  fi
}
trap cleanup EXIT

info "environment: $(uname -srm); active LSMs: $(cat /sys/kernel/security/lsm)"
info "without BPF LSM, Pulsar uses the kprobe fallback (KT-34); this test exercises that path too"
info "NTPSynchronized: $(timedatectl show -p NTPSynchronized --value)"
info "binary: ${BINARY} (sha256 $(sha256sum "$BINARY" | cut -d' ' -f1))"

podman image exists "$IMAGE" || podman pull -q "$IMAGE" >/dev/null
rm -rf "$PREFIX" "$WARMUP"
if systemctl is-active --quiet pulsard.service; then
  PULSARD_WAS_ON=1
  info "stopping the official pulsard (v0.10.1) for the duration of the test"
  systemctl stop pulsard.service
fi

# Pulsar main's configuration file is TOML (it was INI in v0.10.1).
printf '[pulsar]\napi_socket_path = "%s"\n' "$SOCKET" >"$CONF"
info "starting the Koru agent (source tag: synthetic, prefix: ${PREFIX})"
"$BINARY" agent --source-tag synthetic --prefix /tmp/koru-live --pulsar-config "$CONF" \
  >"$OUTPUT" 2>"$LOG" &
AGENT=$!

# Warmup: a prefixed file is opened until the agent starts writing events (at most 60 s).
ready=0
for _ in $(seq 1 120); do
  kill -0 "$AGENT" 2>/dev/null || { cat "$LOG" >&2; fail "the agent exited early"; }
  printf 'fake\n' >"$WARMUP"
  cat "$WARMUP" >/dev/null
  if grep -q "$WARMUP" "$OUTPUT" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 0.5
done
[ "$ready" -eq 1 ] || { cat "$LOG" >&2; fail "the agent produced no event within 60 s"; }
info "agent ready (pid ${AGENT}); engine API socket: $(stat -c '%A %U:%G %n' "$SOCKET" 2>/dev/null || echo none)"
rm -f "$WARMUP"

info "triggers (user nobody)"
unpriv mkdir "$PREFIX"
unpriv sh -c "printf 'fake content\n' > ${PREFIX}/decoy.txt"
unpriv cat "${PREFIX}/decoy.txt" >/dev/null
unpriv mv "${PREFIX}/decoy.txt" "${PREFIX}/decoy2.txt"
unpriv ln -s decoy2.txt "${PREFIX}/link"
info "container trigger (rootful podman, ${IMAGE})"
podman run --rm --network=none -v "${PREFIX}:${PREFIX}:ro" "$IMAGE" cat "${PREFIX}/decoy2.txt" >/dev/null
unpriv rm "${PREFIX}/link" "${PREFIX}/decoy2.txt"
unpriv rmdir "$PREFIX"
sleep 3

info "stopping the agent (SIGINT)"
info "stopping the agent (SIGINT)"
for _ in $(seq 1 60); do kill -0 "$AGENT" 2>/dev/null || break; sleep 0.5; done
if kill -0 "$AGENT" 2>/dev/null; then fail "the agent did not stop within 30 s"; fi
AGENT_OWN_PID="$AGENT"
AGENT_CODE=0
wait "$AGENT" || AGENT_CODE=$?
AGENT=""
info "agent exit code: ${AGENT_CODE}; last log lines:"
tail -n 3 "$LOG" | sed 's/^/[live]   /'
if [ "$PULSARD_WAS_ON" -eq 1 ]; then
  systemctl start pulsard.service
  PULSARD_WAS_ON=0
  info "official pulsard restarted: $(systemctl is-active pulsard.service)"
fi

info "schema v1 validation (live_translation validate):"
"$BINARY" validate "$OUTPUT"

PASSED=0
FAILED=0
check() { # <description> <jq expression; must return true>
  if jq -e -s "$2" "$OUTPUT" >/dev/null; then
    PASSED=$((PASSED + 1)); printf 'PASS  %s\n' "$1"
  else
    FAILED=$((FAILED + 1)); printf 'FAIL  %s\n' "$1"
  fi
}
evt='def evt(kind; path): map(select(.event_type == kind and .target.path == path));'
check "the agent stopped with exit code 0" "${AGENT_CODE} == 0"
check "at least 10 Koru events" 'length >= 10'
check "source_tag synthetic in every event (from context)" 'all(.source_tag == "synthetic")'
check "sensor pulsar ${EXPECTED_VERSION} in every event" \
  "all(.sensor.name == \"pulsar\" and .sensor.version == \"${EXPECTED_VERSION}\" and (.sensor.platform | startswith(\"linux-\")))"
check "every event id is UUIDv7" 'all(.event_id[14:15] == "7")'
check "timestamp_trusted true in every event (NTP synced)" 'all(.timestamp_trusted == true)'
check "the agent's own process was not translated" "all(.process.pid != ${AGENT_OWN_PID})"
check "directory_created ${PREFIX}" "${evt} evt(\"directory_created\"; \"${PREFIX}\") | length >= 1"
check "file_created ${PREFIX}/decoy.txt" "${evt} evt(\"file_created\"; \"${PREFIX}/decoy.txt\") | length >= 1"
check "process_executed: exe /usr/bin/cat, command line [cat, ${PREFIX}/decoy.txt]" \
  "map(select(.event_type == \"process_executed\" and .process.exe == \"/usr/bin/cat\" and .process.command_line == [\"cat\", \"${PREFIX}/decoy.txt\"])) | length >= 1"
check "file_opened ${PREFIX}/decoy.txt: cat, O_RDONLY, outside a container, namespaces and lineage filled" \
  "${evt} evt(\"file_opened\"; \"${PREFIX}/decoy.txt\") | map(select(.process.exe == \"/usr/bin/cat\" and .target.flags == [\"O_RDONLY\"] and .container.id == null and .container.namespaces != null and (.process.lineage | length) >= 1)) | length >= 1"
check "file_renamed decoy.txt -> decoy2.txt" \
  "${evt} evt(\"file_renamed\"; \"${PREFIX}/decoy.txt\") | map(select(.target.new_path == \"${PREFIX}/decoy2.txt\")) | length >= 1"
check "file_link (symbolic)" \
  "${evt} evt(\"file_link\"; \"${PREFIX}/link\") | map(select(.target.hard_link == false and .target.new_path == \"decoy2.txt\")) | length >= 1"
check "file_opened captured inside a container (alpine /bin/cat, ${PREFIX}/decoy2.txt)" \
  "${evt} evt(\"file_opened\"; \"${PREFIX}/decoy2.txt\") | map(select(.process.exe == \"/bin/cat\")) | length >= 1"
check "container namespaces differ from the host's (mnt, pid; the KT-20 container-suspicion signal)" \
  "(${evt} evt(\"file_opened\"; \"${PREFIX}/decoy.txt\") | map(select(.process.exe == \"/usr/bin/cat\")) | .[0].container.namespaces) as \$host | (${evt} evt(\"file_opened\"; \"${PREFIX}/decoy2.txt\") | map(select(.process.exe == \"/bin/cat\")) | .[0].container.namespaces) as \$cont | \$host != null and \$cont != null and \$host.mnt != \$cont.mnt and \$host.pid != \$cont.pid"
check "file_deleted ${PREFIX}/decoy2.txt" "${evt} evt(\"file_deleted\"; \"${PREFIX}/decoy2.txt\") | length >= 1"
check "directory_deleted ${PREFIX}" "${evt} evt(\"directory_deleted\"; \"${PREFIX}\") | length >= 1"

# Known limit (ADR-0003, KT-20): Pulsar main 0bb7bc2 cannot read container info from podman's
# SQLite database ("Invalid column type Blob ... JSON"; the diesel -> rusqlite move). The container
# id, name, and image may therefore stay empty; the state is reported here separately, not a check.
cid=$(jq -s -r "map(select(.event_type == \"file_opened\" and .target.path == \"${PREFIX}/decoy2.txt\" and .process.exe == \"/bin/cat\")) | .[0].container.id // \"null\"" "$OUTPUT")
podman_db=$(podman info --format '{{.Host.DatabaseBackend}}' 2>/dev/null || echo unknown)
if [ "$cid" = "null" ]; then
  info "KNOWN LIMIT: container.id empty in the container event (podman database: ${podman_db}; Pulsar main's podman SQLite regression, ADR-0003)"
else
  info "container.id filled: ${cid} (podman database: ${podman_db})"
fi

info "counts by event type:"
jq -s -r 'group_by(.event_type) | map("\(.[0].event_type): \(length)") | .[]' "$OUTPUT" | sed 's/^/[live]   /'
info "example: cat opening the decoy file on the host (a Koru event, schema v1):"
jq -s "map(select(.event_type == \"file_opened\" and .target.path == \"${PREFIX}/decoy.txt\" and .process.exe == \"/usr/bin/cat\")) | .[0]" "$OUTPUT"
info "example: the same file read inside a container:"
jq -s "map(select(.event_type == \"file_opened\" and .target.path == \"${PREFIX}/decoy2.txt\" and .process.exe == \"/bin/cat\")) | .[0]" "$OUTPUT"

printf 'RESULT: %d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
