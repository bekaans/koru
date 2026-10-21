#!/usr/bin/env bash
# Live detection test. Runs as root inside the VM; uses the `live_detect` example, which
# joins Koru's layers with real Pulsar events (koru-pulsar -> koru-detect):
#   limactl shell koru-lab sudo bash /koru/lab/scripts/live-detect-test.sh <target dir>
# <target dir>: the cargo target directory holding the `koru` binary and `examples/live_detect`.
# Usually called via `lab/lab.sh live-detect` (builds the binaries first).
#
# Method:
# 1. If the official pulsard (v0.10.1) is running it is stopped (two eBPF agents are not loaded
#    at once); it is restored at the end of the test (including on failure).
# 2. Decoys and breadcrumbs are planted into the `devops` test user's home with `koru decoy plant`
#    (VM only; state directory /var/lib/koru-demo/state). For Koru's configuration, store, binary,
#    and service unit, FAKE files are prepared under /etc/koru-demo and /var/lib/koru-demo; there
#    is no real Koru service.
# 3. `live_detect agent` starts as root; each finding is written to stdout as a JSON line.
# 4. Scenarios run with time-window markers:
#    (a) a breadcrumb read, (b) a decoy read from a human shell, (c) reading the same decoy from a
#    process chain matching an AI-agent signature, (d) self-protection (modifying the configuration,
#    state, a decoy, the binary, and the service unit; systemctl stop; kill, pkill, killall; the
#    SIGTERM shutdown), (e) the allowlist (exe path + inode; a mimicked name, a hard link, and a
#    replaced binary), (f) a read from inside a container, (g) the allowlist not being bypassable
#    by 'open the decoy first, then exec the allowed binary', (h) opening a breadcrumb with O_RDWR
#    yields a finding; a write-only open (O_APPEND) does not (KT-58 partial fix). Decoy file
#    contents are never printed or read anywhere (outputs go to /dev/null); the files named
#    'claude' and 'mcp-server' in the scenario scripts are harmless shell scripts that only open a decoy file.
# 5. The agent is stopped with SIGTERM; the output is validated against event schema v1 and the
#    expected findings are checked one by one with jq. At the end the decoys are removed with `koru decoy uninstall`.
#
# Exit code: 0 if all checks pass, otherwise 1.

# The jq programs are single-quoted; the $variables in them belong to jq (--arg), not the shell.
# shellcheck disable=SC2016
set -euo pipefail

TARGET="${1:?usage: live-detect-test.sh <cargo target dir (koru and examples/live_detect)>}"
KORU="${TARGET}/koru"
AGENT_BINARY="${TARGET}/examples/live_detect"
REPO="/koru"
USER="devops"
HOME_DIR="/home/${USER}"
DEMO_ETC="/etc/koru-demo"
DEMO_LIB="/var/lib/koru-demo"
STATE="${DEMO_LIB}/state"
STORE_DIR="${DEMO_LIB}/store"
UNIT="/etc/systemd/system/koru-demo.service"
BACKUP_BINARY="/usr/local/bin/koru-demo"
SOCKET="/run/koru-live-detect.sock"
IMAGE="docker.io/library/alpine:3.22"
SCENARIO="${HOME_DIR}/.local"

info() { printf '[live-detect] %s\n' "$*"; }
# A UTC timestamp for scenario windows (same format as event time; compared as strings).
now() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }
fail() { printf '[live-detect] ERROR: %s\n' "$*" >&2; exit 1; }
devops() { sudo -u "$USER" -- "$@"; }

[ "$(id -u)" -eq 0 ] || fail "must be run as root"
[ -x "$KORU" ] || fail "no koru binary: ${KORU}"
[ -x "$AGENT_BINARY" ] || fail "no live_detect binary: ${AGENT_BINARY}"
command -v jq >/dev/null 2>&1 || fail "no jq; run first: lab/scripts/dev-setup.sh"
command -v podman >/dev/null 2>&1 || fail "no podman; run first: lab/scripts/dev-setup.sh"
id "$USER" >/dev/null 2>&1 || fail "no ${USER} test user"

TMP=$(mktemp -d)
OUTPUT="${TMP}/findings.jsonl"
LOG="${TMP}/agent.log"
CONF="${TMP}/pulsar.toml"
ALLOWLIST="${TMP}/allowlist.toml"
AGENT=""
PULSARD_WAS_ON=0
DECOYS_PLANTED=0
cleanup() {
  if [ -n "$AGENT" ] && kill -0 "$AGENT" 2>/dev/null; then
    kill -TERM "$AGENT" 2>/dev/null || true
    sleep 2
    kill -KILL "$AGENT" 2>/dev/null || true
  fi
  if [ "$DECOYS_PLANTED" -eq 1 ]; then
    "$KORU" decoy uninstall --state "$STATE" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP" "$DEMO_ETC" "$DEMO_LIB" "$UNIT" "$BACKUP_BINARY" /usr/local/bin/backup /usr/local/bin/backup.new \
    /tmp/backup /tmp/backup-hard "${SCENARIO}/lib/node_modules" "${SCENARIO}/bin/claude" "${SCENARIO}/bin/mcp-server-notes"
  rmdir "${SCENARIO}/lib" "${SCENARIO}/bin" "$SCENARIO" 2>/dev/null || true
  if [ "$PULSARD_WAS_ON" -eq 1 ]; then
    systemctl start pulsard.service || true
  fi
}
trap cleanup EXIT

info "environment: $(uname -srm); active LSMs: $(cat /sys/kernel/security/lsm)"
info "NTPSynchronized: $(timedatectl show -p NTPSynchronized --value)"
info "jq: $(jq --version); podman: $(podman --version)"
info "koru: $("$KORU" --version); live_detect sha256 $(sha256sum "$AGENT_BINARY" | cut -d' ' -f1)"
podman image exists "$IMAGE" || podman pull -q "$IMAGE" >/dev/null

# --- Preparation ------------------------------------------------------------------------------
rm -rf "$DEMO_ETC" "$DEMO_LIB"
install -d -m 700 -o root -g root "$DEMO_ETC" "$DEMO_LIB" "$STORE_DIR"
printf '# fake Koru configuration (lab)\nversion = 1\n' >"${DEMO_ETC}/koru.toml"
printf '# fake secret-value file (lab; no real secret)\nKORU_SAMPLE=fake\n' >"${DEMO_ETC}/.env"
chmod 600 "${DEMO_ETC}/koru.toml" "${DEMO_ETC}/.env"
printf '[Unit]\nDescription=Koru lab sample (not a real service)\n' >"$UNIT"
cp "$KORU" "$BACKUP_BINARY"

info "planting decoys and breadcrumbs: root ${HOME_DIR} (VM only; state ${STATE})"
"$KORU" decoy plant --package "${REPO}/packages/decoys" --root "$HOME_DIR" --state "$STATE" >"${TMP}/install.txt"
DECOYS_PLANTED=1
sed 's/^/[live-detect]   /' "${TMP}/install.txt" | cut -c1-200
LIST=$("$KORU" decoy list --state "$STATE")
# A class's path and decoy id (listing row: id, kind, class, placement, path).
class_path() { printf '%s\n' "$LIST" | awk -v s="$1" '{ for (i = 2; i < NF; i++) if ($i == s) { print $NF; exit } }'; }
class_id() { printf '%s\n' "$LIST" | awk -v s="$1" '{ for (i = 2; i < NF; i++) if ($i == s) { print $1; exit } }'; }
AWS=$(class_path cloud_credentials);          AWS_ID=$(class_id cloud_credentials)
SSH=$(class_path ssh_key);           SSH_ID=$(class_id ssh_key)
ENV_FILE=$(class_path env);            ENV_ID=$(class_id env)
HISTORY=$(class_path bash_history);        HISTORY_ID=$(class_id bash_history)
for var in AWS SSH ENV_FILE HISTORY AWS_ID SSH_ID ENV_ID HISTORY_ID; do
  [ -n "${!var}" ] || fail "${var} not found in the decoy list"
done
info "scenario targets: cloud identity ${AWS} (${AWS_ID}), SSH key ${SSH}, .env ${ENV_FILE}, shell history ${HISTORY}"

# Harmless scripts matching an AI-agent signature: the path contains the signature string (any argv form).
CLAUDE="${SCENARIO}/lib/node_modules/@anthropic-ai/claude-code/bin/claude"
MCP="${SCENARIO}/lib/node_modules/@modelcontextprotocol/server-notes/mcp-server-notes"
install -d -m 755 -o "$USER" -g "$USER" "$SCENARIO" "${SCENARIO}/lib" "${SCENARIO}/bin" \
  "${SCENARIO}/lib/node_modules" "${SCENARIO}/lib/node_modules/@anthropic-ai" \
  "${SCENARIO}/lib/node_modules/@anthropic-ai/claude-code" "${SCENARIO}/lib/node_modules/@anthropic-ai/claude-code/bin" \
  "${SCENARIO}/lib/node_modules/@modelcontextprotocol" "${SCENARIO}/lib/node_modules/@modelcontextprotocol/server-notes"
printf '#!/bin/bash\ncat "%s" >/dev/null\n' "$SSH" >"$CLAUDE"
printf '#!/bin/bash\ncat "%s" >/dev/null\n' "$ENV_FILE" >"$MCP"
chown "$USER:$USER" "$CLAUDE" "$MCP"
chmod 755 "$CLAUDE" "$MCP"

# Allowlist: only /usr/local/bin/backup (exe path + inode) and only for decoy_credential_file.
# The allowed binary: a bash copy. It does the read itself 1 s after exec, so Pulsar's process
# tracker's post-exec stale-image race (KT-57) does not affect this scenario. The ':' at the end
# of the script stops bash from exec'ing the last command without forking: otherwise the process
# becomes sleep right after the read and (correctly) is not muted.
cp /usr/bin/bash /usr/local/bin/backup
READ_SCRIPT='sleep 1; exec 3< "$0"; sleep 2; :'
cat >"$ALLOWLIST" <<'TOML'
version = 1

[[input]]
exe = "/usr/local/bin/backup"
rules = ["decoy_credential_file"]
rationale = "lab: the nightly backup script (by exe path and inode only)"
TOML

if systemctl is-active --quiet pulsard.service; then
  PULSARD_WAS_ON=1
  info "stopping the official pulsard (v0.10.1) for the duration of the test"
  systemctl stop pulsard.service
fi
printf '[pulsar]\napi_socket_path = "%s"\n' "$SOCKET" >"$CONF"

info "starting the Koru agent (source tag: synthetic)"
"$AGENT_BINARY" agent --source-tag synthetic \
  --rules "${REPO}/packages/rules" --agents "${REPO}/packages/agents" --thresholds "${REPO}/thresholds.toml" \
  --decoy-state "$STATE" --allowlist "$ALLOWLIST" \
  --koru-config "$DEMO_ETC" --koru-secret "${DEMO_ETC}/.env" --koru-store "$STORE_DIR" --koru-state "$STATE" \
  --koru-binary "$BACKUP_BINARY" --koru-binary "$AGENT_BINARY" --koru-service-file "$UNIT" \
  --koru-service koru-demo --koru-process live_detect \
  --pulsar-config "$CONF" >"$OUTPUT" 2>"$LOG" &
AGENT=$!

# Warmup: a file is appended in the Koru config directory until the agent starts writing findings (at most 60 s).
ready=0
for _ in $(seq 1 120); do
  kill -0 "$AGENT" 2>/dev/null || { cat "$LOG" >&2; fail "the agent exited early"; }
  sh -c "echo warmup >> ${DEMO_ETC}/warmup.conf"
  if grep -q 'warmup.conf' "$OUTPUT" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 0.5
done
[ "$ready" -eq 1 ] || { cat "$LOG" >&2; fail "the agent produced no finding within 60 s"; }
rm -f "${DEMO_ETC}/warmup.conf"
info "agent ready (pid ${AGENT}); engine API socket: $(stat -c '%A %U:%G %n' "$SOCKET" 2>/dev/null || echo none)"
sleep 1

# --- Scenarios -----------------------------------------------------------------------------------
T_A=$(now)
info "(a) breadcrumb read: ${USER} reads the shell history"
devops cat "$HISTORY" >/dev/null
sleep 1

T_B=$(now)
info "(b) decoy read from a human shell: an interactive shell, 3 s between commands"
{
  sleep 1
  echo "ls ${HOME_DIR} >/dev/null"
  sleep 3
  echo "id >/dev/null"
  sleep 3
  echo "cat ${AWS} >/dev/null"
  sleep 1
  echo exit
} | devops bash --noprofile --norc -i >/dev/null 2>&1 || true
sleep 1

T_C1=$(now)
info "(c) AI-agent lineage: the 'claude' script reads the SSH decoy, the 'mcp-server-notes' script reads the .env decoy"
devops "$CLAUDE"
sleep 1
T_C2=$(now)
devops "$MCP"
sleep 1
T_C3=$(now)
info "(c) comparison: a cat with no agent in its lineage reads the same SSH decoy"
devops cat "$SSH" >/dev/null
sleep 1

T_D=$(now)
info "(d) self-protection"
sh -c "echo '# modified' >> ${DEMO_ETC}/koru.toml"
cat "${DEMO_ETC}/.env" >/dev/null
sh -c "echo '# fake' > ${STATE}/fake-file"
rm -f "${STATE}/fake-file"
sh -c ": >> ${AWS}"
sh -c ": >> ${BACKUP_BINARY}"
sh -c ": >> ${UNIT}"
systemctl stop koru-demo 2>/dev/null || true
/usr/bin/kill -0 "$AGENT"
pkill -0 live_detect || true
if command -v killall >/dev/null 2>&1; then killall -0 live_detect || true; fi
sleep 1

info "(e) allowlist: backup (allowed path and inode), the exec bypass, /tmp/backup (mimicked name), a hard link, a different rule, a replaced binary"
T_E1=$(now)
/usr/local/bin/backup -c "$READ_SCRIPT" "$AWS" >/dev/null 2>&1 || true
T_G=$(now)
info "(g) exec bypass: its own shell opens the decoy, then execs the allowed binary (the process stays alive 2 s)"
bash -c 'exec 3< "$1"; exec /usr/local/bin/backup -c "sleep 2; :"' _ "$AWS" >/dev/null 2>&1 || true
T_E2=$(now)
/usr/local/bin/backup -c "$READ_SCRIPT" "$SSH" >/dev/null 2>&1 || true
cp /usr/bin/bash /tmp/backup
T_E3=$(now)
/tmp/backup -c "$READ_SCRIPT" "$AWS" >/dev/null 2>&1 || true
ln /usr/local/bin/backup /tmp/backup-hard
T_E4=$(now)
/tmp/backup-hard -c "$READ_SCRIPT" "$AWS" >/dev/null 2>&1 || true
cp /usr/bin/bash /usr/local/bin/backup.new
mv /usr/local/bin/backup.new /usr/local/bin/backup
T_E5=$(now)
/usr/local/bin/backup -c "$READ_SCRIPT" "$AWS" >/dev/null 2>&1 || true
sleep 1

T_H=$(now)
info "(h) opening a breadcrumb with O_RDWR: a finding must be produced (KT-58 partial fix)"
sh -c 'exec 3<> "$0"; sleep 1' "$HISTORY" >/dev/null 2>&1 || true
sleep 1
T_H2=$(now)
info "(h) comparison: a write-only (O_APPEND) open, the shell appending to history: no finding must be produced"
sh -c 'exec 3>> "$0"; sleep 1' "$HISTORY" >/dev/null 2>&1 || true
sleep 1

T_F=$(now)
info "(f) a read from inside a container (rootful podman, ${IMAGE}; the home directory is bound at the same path)"
AWS_DIR=$(dirname "$AWS")
podman run --rm --network=none -v "${AWS_DIR}:${AWS_DIR}:ro" "$IMAGE" cat "$AWS" >/dev/null
sleep 3
T_END=$(now)

info "stopping the agent (SIGTERM; clean shutdown)"
kill -TERM "$AGENT"
for _ in $(seq 1 60); do kill -0 "$AGENT" 2>/dev/null || break; sleep 0.5; done
if kill -0 "$AGENT" 2>/dev/null; then fail "the agent did not stop within 30 s"; fi
AGENT_OWN_PID="$AGENT"
AGENT_CODE=0
wait "$AGENT" || AGENT_CODE=$?
AGENT=""
info "agent exit code: ${AGENT_CODE}; the log's detection lines:"
grep '^\[detection\]' "$LOG" | cut -c1-230 | sed 's/^/[live-detect]   /'
if [ "$PULSARD_WAS_ON" -eq 1 ]; then
  systemctl start pulsard.service
  PULSARD_WAS_ON=0
  info "official pulsard restarted: $(systemctl is-active pulsard.service)"
fi

# --- Validation ----------------------------------------------------------------------------------
# The last run's findings are left under /tmp in the VM for debugging (no contents written).
cp "$OUTPUT" /tmp/koru-live-detect-findings.jsonl
info "schema v1 validation of the finding events (live_detect validate):"
"$AGENT_BINARY" validate "$OUTPUT"

PASSED=0
FAILED=0
check() { # <description> <jq expression; must return true>
  if jq -e -s --arg awsy "$AWS" --arg ssh "$SSH" --arg envy "$ENV_FILE" --arg hist "$HISTORY" \
      --arg ta "$T_A" --arg tb "$T_B" --arg tc1 "$T_C1" --arg tc2 "$T_C2" --arg tc3 "$T_C3" --arg td "$T_D" \
      --arg te1 "$T_E1" --arg tg "$T_G" --arg th "$T_H" --arg th2 "$T_H2" --arg te2 "$T_E2" --arg te3 "$T_E3" --arg te4 "$T_E4" --arg te5 "$T_E5" --arg tf "$T_F" --arg tend "$T_END" \
      --arg aws_k "$AWS_ID" --arg ssh_k "$SSH_ID" --arg env_k "$ENV_ID" --arg hist_k "$HISTORY_ID" \
      --argjson agent_pid "$AGENT_OWN_PID" "${JQ_PRE}$2" "$OUTPUT" >/dev/null; then
    PASSED=$((PASSED + 1)); printf 'PASS  %s\n' "$1"
  else
    FAILED=$((FAILED + 1)); printf 'FAIL  %s\n' "$1"
  fi
}
JQ_PRE='def b(k): map(select(.event.detection.rule == k)); def g: (.event.actor.rationale | join(" | ")); def t: .event.detection; def w(a; z): map(select(.event.timestamp >= a and .event.timestamp < z)); '
check "the agent stopped with exit code 0" \
check "in every finding the source_tag is synthetic and the sensor is pulsar" \
  'length > 0 and all(.event.source_tag == "synthetic" and (.event.sensor.name == "pulsar" or .event.sensor.name == "koru"))'
check "every finding carries an ATT&CK technique, identical to tags.mitre_techniques" \
  'all((t.attack | length) >= 1 and .event.tags.mitre_techniques == t.attack)'
check "Koru's own process is excluded (only the stopped event comes from Koru)" \
  'all(.event.process.pid != $agent_pid or t.rule == "koru_stopped")'

# (a) breadcrumb
check "(a) breadcrumb: breadcrumb_shell_history, class breadcrumb_access, severity low, T1552.003, correct decoy id" \
  'w($ta; $tb) | b("breadcrumb_shell_history") | map(select(.event.target.path == $hist and t.threat_class == "breadcrumb_access" and .severity == "low" and t.attack == ["T1552.003"] and t.decoy_id == $hist_k)) | length >= 1'
# (b) human
check "(b) decoy from a human shell: decoy_credential_file, class decoy_access, actor human (interactive shell + human speed)" \
  'w($tb; $tc1) | b("decoy_credential_file") | map(select(.event.target.path == $awsy and t.decoy_id == $aws_k and t.threat_class == "decoy_access" and .event.actor.kind == "human" and (g | contains("interactive shell")) and (g | contains("human speed")))) | length >= 1'
# (c) AI agent
check "(c) the claude script reads the SSH decoy: suspected_hijacked_agent, actor ai_agent (claude-code), severity critical, T1552.004" \
  'w($tc1; $tc2) | b("decoy_ssh_key") | map(select(.event.target.path == $ssh and t.threat_class == "suspected_hijacked_agent" and .event.actor.kind == "ai_agent" and (g | contains("claude-code")) and .severity == "critical" and t.attack == ["T1552.004"])) | length >= 1'
check "(c) the mcp-server-notes script reads the .env decoy: suspected_hijacked_agent, agent mcp-server" \
  'w($tc2; $tc3) | b("decoy_credential_file") | map(select(.event.target.path == $envy and t.threat_class == "suspected_hijacked_agent" and .event.actor.kind == "ai_agent" and (g | contains("mcp-server")))) | length >= 1'
check "(c) comparison: in an agent-free lineage the same SSH decoy stays in class decoy_access" \
  'w($tc3; $td) | b("decoy_ssh_key") | map(select(.event.target.path == $ssh and t.threat_class == "decoy_access" and .event.actor.kind != "ai_agent")) | length >= 1'
# (d) self-protection
check "(d) writing the Koru configuration: koru_config_modified (self_protection, T1685)" \
  'b("koru_config_modified") | map(select(.event.target.path == "'"${DEMO_ETC}"'/koru.toml" and t.threat_class == "self_protection" and t.attack == ["T1685"])) | length >= 1'
check "(d) reading the Koru secret-value file: koru_secret_read" \
  'b("koru_secret_read") | map(select(.event.target.path == "'"${DEMO_ETC}"'/.env")) | length >= 1'
check "(d) creating and deleting a file in the state directory: koru_store_modified (T1070, T1565.001)" \
  'b("koru_store_modified") | map(select(.event.target.path == "'"${STATE}"'/fake-file" and t.attack == ["T1070", "T1565.001"])) | length >= 2'
check "(d) opening a decoy file for writing: koru_decoy_modified, decoy id set" \
  'b("koru_decoy_modified") | map(select(.event.target.path == $awsy and t.decoy_id == $aws_k)) | length >= 1'
check "(d) opening the Koru binary for writing: koru_binary_modified (severity critical)" \
  'b("koru_binary_modified") | map(select(.event.target.path == "'"${BACKUP_BINARY}"'" and .severity == "critical")) | length >= 1'
check "(d) opening the service unit for writing: koru_service_unit_modified (T1543.002)" \
  'b("koru_service_unit_modified") | map(select(.event.target.path == "'"${UNIT}"'")) | length >= 1'
check "(d) systemctl stop koru-demo: koru_service_stop (T1489, T1685)" \
  'b("koru_service_stop") | map(select(.event.process.exe == "/usr/bin/systemctl" and t.attack == ["T1489", "T1685"])) | length >= 1'
check "(d) targeting the Koru process with kill: koru_process_kill" \
  'b("koru_process_kill") | map(select(.event.process.exe == "/usr/bin/kill")) | length >= 1'
check "(d) targeting the Koru process with pkill: koru_process_kill" \
  'b("koru_process_kill") | map(select(.event.process.exe == "/usr/bin/pkill")) | length >= 1'
check "(d) clean SIGTERM shutdown: koru_stopped (process_exited, T1489, T1685)" \
  'b("koru_stopped") | map(select(.event.event_type == "process_exited" and .event.sensor.name == "koru" and t.attack == ["T1489", "T1685"])) | length == 1'
# (e) allowlist
check "(e) the allowed /usr/local/bin/backup (path + inode) is muted for decoy_credential_file (no finding in this window)" \
  'w($te1; $tg) | b("decoy_credential_file") | map(select(.event.target.path == $awsy)) | length == 0'
if grep -q 'muted by the allowlist: 1$' "$LOG"; then
  PASSED=$((PASSED + 1)); printf 'PASS  %s\n' "(e) agent log: exactly 1 finding muted by the allowlist (only the allowed first read; the exec bypass and others were not muted)"
else
  FAILED=$((FAILED + 1)); printf 'FAIL  %s\n' "(e) agent log: the count muted by the allowlist is not 1"
fi
# (g) exec bypass
check "(g) exec bypass: a process that opens the decoy with its own shell then execs the allowed binary produced a finding (not muted)" \
  'w($tg; $te2) | b("decoy_credential_file") | map(select(.event.target.path == $awsy and t.decoy_id == $aws_k)) | length >= 1'
check "(e) the same binary is not muted under a different rule (decoy_ssh_key)" \
  'w($te2; $te3) | b("decoy_ssh_key") | map(select(.event.target.path == $ssh)) | length >= 1'
check "(e) a mimicked name (/tmp/backup, same binary content) is not muted" \
  'w($te3; $te4) | b("decoy_credential_file") | map(select(.event.target.path == $awsy)) | length >= 1'
check "(e) a hard link (/tmp/backup-hard, same inode, different path) is not muted" \
  'w($te4; $te5) | b("decoy_credential_file") | map(select(.event.target.path == $awsy)) | length >= 1'
check "(e) same path, replaced binary (new inode) is not muted" \
  'w($te5; $th) | b("decoy_credential_file") | map(select(.event.target.path == $awsy)) | length >= 1'
# (f) container
check "(f) a decoy read from inside a container is caught: decoy_credential_file, decoy id set" \
  'w($tf; $tend) | b("decoy_credential_file") | map(select(.event.target.path == $awsy and t.decoy_id == $aws_k)) | length >= 1'
check "(f) the container's namespaces differ from the host's (the container-suspicion signal)" \
  '(w($tb; $tc1) | b("decoy_credential_file") | map(select(.event.container.namespaces != null)) | .[0].event.container.namespaces) as $host | (w($tf; $tend) | b("decoy_credential_file") | map(select(.event.container.namespaces != null)) | .[0].event.container.namespaces) as $cont | $host != null and $k != null and $host.pid != $cont.pid and $host.mnt != $cont.mnt'
# (h) breadcrumb with O_RDWR (KT-58 partial fix)
check "(h) a breadcrumb opened with O_RDWR produced a finding: breadcrumb_shell_history, class breadcrumb_access, severity low, target flags O_RDWR" \
  'w($th; $th2) | b("breadcrumb_shell_history") | map(select(.event.target.path == $hist and t.threat_class == "breadcrumb_access" and .severity == "low" and t.decoy_id == $hist_k and (.event.target.flags | index("O_RDWR") != null))) | length >= 1'
check "(h) a breadcrumb opened write-only (O_APPEND) produced no finding (the shell appending to history is legitimate)" \
  'w($th2; $tf) | map(select(.event.target.path == $hist)) | length == 0'
cid=$(jq -s -r --arg tf "$T_F" --arg tend "$T_END" 'map(select(.event.detection.rule == "decoy_credential_file" and .event.timestamp >= $tf and .event.timestamp < $tend)) | .[0].event.container.id // "null"' "$OUTPUT")
if [ "$cid" = "null" ]; then
  info "KNOWN LIMITATION: container.id is empty in the container event (Pulsar main's podman SQLite regression, KT-45); detection also runs on the namespace difference (container suspicion)"
else
  info "container.id set: ${cid}"
fi

info "finding breakdown by rule and class:"
jq -s -r 'group_by(.event.detection.rule) | map("\(.[0].event.detection.rule): \(length) findings, class \(.[0].event.detection.threat_class)") | .[]' "$OUTPUT" | sed 's/^/[live-detect]   /'
info "finding list (time, rule, class, actor, process exe, target):"
jq -s -r '.[] | "\(.event.timestamp[11:23]) \(.event.detection.rule) \(.event.detection.threat_class) \(.event.actor.kind) \(.event.process.exe) \(.event.target.path // .event.process.command_line[0:3] | tostring)"' "$OUTPUT" | sed 's/^/[live-detect]   /'
example() { # <description> <jq selector> — a sample finding with shortened fields; writes no contents
  info "sample finding: $1"
  jq -s "map(select($2)) | .[0] | {title, severity, event: {timestamp: .event.timestamp, process: {pid: .event.process.pid, exe: .event.process.exe, command_line: .event.process.command_line, lineage: [.event.process.lineage[:4][] | {pid, exe, command_line}]}, container: {id: .event.container.id, namespaces: .event.container.namespaces}, event_type: .event.event_type, target: {path: .event.target.path, flags: .event.target.flags}, actor: .event.actor, detection: .event.detection, tags: .event.tags}}" "$OUTPUT" | sed 's/^/[live-detect]   /'
}
example "(c) SSH decoy from an AI-agent lineage" ".event.detection.rule == \"decoy_ssh_key\" and .event.detection.threat_class == \"suspected_hijacked_agent\""
example "(b) cloud-credential decoy from a human shell" ".event.detection.rule == \"decoy_credential_file\" and .event.actor.kind == \"human\""
example "(a) breadcrumb" ".event.detection.rule == \"breadcrumb_shell_history\""

printf 'RESULT: %d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
