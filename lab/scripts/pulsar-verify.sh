#!/usr/bin/env bash
# Verifies that Pulsar produces a THREAT event. Runs as root inside the VM:
#   limactl shell koru-lab sudo bash /koru/lab/scripts/pulsar-verify.sh
#
# Method: while pulsard runs, `pulsar monitor` is opened, then a harmless command
# that triggers the "Create sensitive files symlink" rule in Pulsar's DEFAULT
# rule set (rules/credential_access/link_sensitive_file.yaml) is run as the
# unprivileged `nobody` user (setpriv; does not go through PAM):
#   ln -s /etc/shadow /tmp/koru-pulsar-verify.<pid>
# Creating a symlink does not read the target file; the link is deleted at once.
# No rule is added to the rule set.
set -euo pipefail

RULE_FILE="/var/lib/pulsar/rules/credential_access/link_sensitive_file.yaml"
RULE_NAME="Create sensitive files symlink"
LINK="/tmp/koru-pulsar-verify.$$"
WAIT_S=15

info() { printf '[pulsar-verify] %s\n' "$*"; }
# `pulsar monitor` prints the THREAT word with ANSI color codes; the color
# codes are stripped so the evidence files stay readable.
strip_color() { sed 's/\x1b\[[0-9;]*m//g'; }
fail() { printf '[pulsar-verify] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must be run as root"
systemctl is-active --quiet pulsard.service || fail "pulsard is not running"
[ -f "$RULE_FILE" ] || fail "the default rule file is missing: ${RULE_FILE}"
grep -q "^- name: ${RULE_NAME}\$" "$RULE_FILE" \
  || fail "the '${RULE_NAME}' rule was not found in the default set"

info "the default rule used (${RULE_FILE}):"
sed -n "/^- name: ${RULE_NAME}\$/,/^\$/p" "$RULE_FILE"

TMP=$(mktemp -d)
MONITOR_PID=""
cleanup() {
  if [ -n "$MONITOR_PID" ]; then kill "$MONITOR_PID" 2>/dev/null || true; fi
  rm -f "$LINK"
  rm -rf "$TMP"
}
trap cleanup EXIT

start=$(date -u '+%Y-%m-%d %H:%M:%S')
info "starting pulsar monitor"
pulsar monitor >"${TMP}/monitor.txt" 2>&1 &
MONITOR_PID=$!
sleep 2
kill -0 "$MONITOR_PID" 2>/dev/null || { cat "${TMP}/monitor.txt" >&2; fail "pulsar monitor did not start"; }

info "trigger (user nobody): ln -s /etc/shadow ${LINK}"
setpriv --reuid=nobody --regid=nogroup --clear-groups -- ln -s /etc/shadow "$LINK"
rm -f "$LINK"

found=0
for _ in $(seq 1 $((WAIT_S * 2))); do
  if grep -q "$RULE_NAME" "${TMP}/monitor.txt"; then
    found=1
    break
  fi
  sleep 0.5
done
kill "$MONITOR_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true
MONITOR_PID=""

info "pulsar monitor output (all THREAT events triggered by the default rules):"
strip_color <"${TMP}/monitor.txt"
info "the same rule's line in the pulsard log (threat-logger), after ${start} UTC:"
journalctl -u pulsard.service --since "$start" --no-pager -o cat | strip_color | grep -F "$RULE_NAME" || true

[ "$found" -eq 1 ] || fail "no '${RULE_NAME}' THREAT event seen within ${WAIT_S} s"
strip_color <"${TMP}/monitor.txt" | grep -F "$RULE_NAME" | grep -q ' THREAT ' \
  || fail "no THREAT marker in the rule's monitor line"
info "RESULT: a THREAT event was seen (rule: ${RULE_NAME})"
