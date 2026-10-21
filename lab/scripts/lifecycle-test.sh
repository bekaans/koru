#!/usr/bin/env bash
# Lifecycle test: in a clean VM (lab/lima/koru-clean.yaml), with the real systemd service,
# install, run, upgrade, roll back, and uninstall; shows that file digests match after uninstall
# (ADR-0008).
#
# Usage (in the VM, root):
#   sudo bash lifecycle-test.sh <package-1> <package-2> <file-digest.sh> <output-dir>
#
# <package-1>, <package-2>: signed release packages (distribution/prepare-release.sh; the second
# is the newer version). signature.txt, systemd.txt, and lifecycle.txt are written to the output
# directory. There is no secret value: the notification recipient is a fake ntfy server on
# 127.0.0.1. No attack tool or AI agent runs; the trigger is only a harmless `cat` reading a decoy file.
set -uo pipefail
export LC_ALL=C.UTF-8
export HISTFILE=/dev/null

PKG1=${1:?package-1}
PKG1=${1:?package-1}
PKG2=${2:?package-2}
OUTPUT=${4:?output directory}
NAME=system-observer
CONF=/etc/$NAME/config.toml
REPO=/var/lib/$NAME/event.db
NTFY_PORT=18080
NTFY_LOG=/root/ntfy-received.jsonl

mkdir -p "$OUTPUT"
say() { printf '# %s\n' "$*"; }
run() {
  printf '$ %s\n' "$*"
  "$@" 2>&1
  local rc=$?
  printf '(exit code: %s)\n' "$rc"
  return 0
}
guest() {
  printf '$ %s\n' "$1"
  bash -c "$1" 2>&1
  local rc=$?
  printf '(exit code: %s)\n' "$rc"
  return 0
}
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------------------------------------
# Preparation: the test user (decoy root), the fake ntfy, the baseline digest
# --------------------------------------------------------------------------------------------
id devops >/dev/null 2>&1 || useradd --create-home --shell /bin/bash devops
chmod 750 /home/devops
printf 'ls -la\ncd /srv\n' > /home/devops/.bash_history
mkdir -p /home/devops/.ssh && chmod 700 /home/devops/.ssh
printf 'Host a\n  HostName a.example\n' > /home/devops/.ssh/config
printf 'a.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGE=\n' > /home/devops/.ssh/known_hosts
chown -R devops:devops /home/devops
sync

cat > /root/fake-ntfy.py <<'PY'
import http.server, json, sys
log_path = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n).decode("utf-8", "replace")
        with open(log_path, "a") as f:
            f.write(json.dumps({"path": self.path, "title": self.headers.get("Title"), "body": body}) + "\n")
        self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[2])), H).serve_forever()
PY
: > "$NTFY_LOG"
python3 /root/fake-ntfy.py "$NTFY_LOG" "$NTFY_PORT" &
NTFY_PID=$!
trap 'kill $NTFY_PID 2>/dev/null || true' EXIT
printf 'KORU_NTFY_URL=http://127.0.0.1:%s/secret-topic\nKORU_SIGNING_KEY=THIS-VALUE-MUST-NOT-PASS\nKORU_LAB_LLM_API_KEY=THIS-ONE-EITHER\n' "$NTFY_PORT" > /root/environment.env
chmod 600 /root/environment.env

take_digest() { # <file>
  {
    for d in /usr/libexec /etc/systemd/system /home/devops; do
      printf '== %s\n' "$d"
      bash "$DIGEST" "$d"
    done
    for d in / /etc /usr /var /var/lib /home; do
      stat -c 'dir %n mode=%a owner=%U:%G mtime=%.9Y' "$d"
    done
  } > "$1"
}
take_digest /root/digest-before.txt

# --------------------------------------------------------------------------------------------
# signature.txt
# --------------------------------------------------------------------------------------------
{
  say "Evidence: release signature (ADR-0008 section 6)"
  say "Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ); clean VM: $(hostname), $(uname -sr), $(openssl version)"
  say "Public key: distribution/signing-public-key.pem in the repo (verified against the fingerprint pinned in install.sh). The private key and passphrase are in neither this file nor any output."
  echo
  guest "sha256sum $PKG1/../install-scripts/signing-public-key.pem"
  guest "grep EMBEDDED_FINGERPRINT= $PKG1/../install-scripts/install.sh"
  echo
  say "1. A correctly signed package (embedded public key, the default):"
  run sh "$PKG1/../install-scripts/install.sh" --verify-only "$PKG1"
  echo
  say "2. The direct openssl command (SHA256SUMS, public key, signature):"
  run openssl dgst -sha256 -verify "$PKG1/../install-scripts/signing-public-key.pem" -signature "$PKG1/SHA256SUMS.sig" "$PKG1/SHA256SUMS"
  echo
  say "3. A copy with one byte changed is rejected:"
  rm -rf /root/corrupt && cp -R "$PKG1" /root/corrupt
  printf '#' >> /root/corrupt/koru-agent
  run sh "$PKG1/../install-scripts/install.sh" --verify-only /root/corrupt
  echo
  say "4. A copy with the signature file deleted is rejected:"
  rm -f /root/corrupt/SHA256SUMS.sig
  run sh "$PKG1/../install-scripts/install.sh" --verify-only /root/corrupt
  echo
  say "5. A copy with a file not in the list added is rejected:"
  rm -rf /root/corrupt && cp -R "$PKG1" /root/corrupt && printf 'x\n' > /root/corrupt/extra-file
  run sh "$PKG1/../install-scripts/install.sh" --verify-only /root/corrupt
  rm -rf /root/corrupt
} > "$OUTPUT/signature.txt"

# --------------------------------------------------------------------------------------------
# lifecycle.txt
# --------------------------------------------------------------------------------------------
LC="$OUTPUT/lifecycle.txt"
{
  say "Evidence: lifecycle - install, run, upgrade, roll back, uninstall in a clean VM (ADR-0008 section 5)"
  say "Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ); VM: $(hostname); $(uname -a)"
  say "Clean VM: lab/lima/koru-clean.yaml (Ubuntu 24.04 arm64; no Koru, Rust, or Pulsar; this script runs as root)."
  say "Packages: $PKG1 (version $(cat "$PKG1/VERSION")), $PKG2 (version $(cat "$PKG2/VERSION")); test packages with the same binaries, different version numbers."
  echo
  say "A. Before install: nothing belonging to Koru exists"
  guest "ls -d /usr/libexec/$NAME /etc/$NAME /var/lib/$NAME /etc/systemd/system/$NAME.service 2>&1 | head"
  guest "systemctl list-unit-files | grep -c $NAME || true"
  echo
  say "B. Install (install.sh: after signature and SHA-256 verification, koru install from the verified copy)"
  run sh "$PKG1/../install-scripts/install.sh" "$PKG1" -- --source-tag synthetic --decoy-root /home/devops --environment /root/environment.env
  sleep 4
  guest "systemctl is-active $NAME; systemctl is-enabled $NAME"
  guest "ls -la /usr/libexec/$NAME /usr/libexec/$NAME/versions/*/ /etc/$NAME /var/lib/$NAME"
  guest "readlink /usr/libexec/$NAME/current"
  echo
  say "C. Process name, socket permission, and the environment file"
  PID=$(systemctl show -p MainPID --value "$NAME")
  guest "ps -o pid,user,comm,args -p $PID"
  guest "cat /proc/$PID/comm; readlink /proc/$PID/exe"
  guest "ls -la /run/$NAME/"
  guest "stat -c '%a %U %n' /run/$NAME /run/$NAME/api.sock"
  guest "sed -E 's#(KORU_NTFY_URL=http://127.0.0.1:[0-9]+/).*#\\1<secret-topic>#' /etc/$NAME/environment"
  guest "grep -c -E 'SIGNING|LLM' /etc/$NAME/environment || true"
  guest "cat /etc/systemd/system/$NAME.service"
  guest "ps -eo pid,user,comm,args | grep -i -E 'koru|pulsar' | grep -v grep || echo 'no process with koru/pulsar in ps output'"
  echo
  guest "journalctl -u $NAME --no-pager -o cat | grep -c 'loading probe' || true   # eBPF probe load error count (must be 0)"
  say "D. Live detection: a decoy read (the devops user) and an O_RDWR open (KT-58)"
  guest "$PKG1/koru decoy list --state /var/lib/$NAME/decoy | head -20"
  guest "sudo -u devops cat /home/devops/.aws/credentials > /dev/null; echo read"
  guest "sudo -u devops python3 -c \"f=open('/home/devops/.aws/credentials','r+'); f.close(); print('opened with O_RDWR')\""
  sleep 5
  guest "$PKG1/koru report data-quality --store $REPO"
  rm -f /root/findings.jsonl
  guest "$PKG1/koru export --store $REPO --format jsonl --source synthetic --output /root/findings.jsonl; python3 - <<'PY'
import json
for s in open('/root/findings.jsonl'):
    o = json.loads(s)
    t = o['detection']
    print(t['rule'], '|', t['threat_class'], '|', o['actor']['kind'], '|', o['source_tag'], '|', t['decoy_id'])
PY"
  guest "wc -l < $NTFY_LOG; head -c 600 $NTFY_LOG"
  echo
  say "E. systemctl stop (SIGTERM): a clean shutdown and the \"stopped\" event"
  run systemctl stop "$NAME"
  sleep 2
  guest "journalctl -u $NAME --no-pager -n 4 -o cat | cut -c1-200"
  rm -f /root/findings.jsonl
  guest "$PKG1/koru export --store $REPO --format jsonl --source synthetic --output /root/findings.jsonl; python3 - <<'PY'
import json
for s in open('/root/findings.jsonl'):
    o = json.loads(s)
    print(o['detection']['rule'], '|', o['detection']['threat_class'], '|', o['timestamp'])
PY"
  guest "tail -n 1 $NTFY_LOG | head -c 400"
  run systemctl start "$NAME"
  sleep 3
  guest "systemctl is-active $NAME"
  echo
  say "F. Upgrade (the new version's koru; the active version changes after the health check)"
  run "$PKG2/koru" upgrade --version-dir "$PKG2" --config "$CONF"
  guest "readlink /usr/libexec/$NAME/current; ls /usr/libexec/$NAME/versions; systemctl is-active $NAME"
  guest "readlink /proc/\$(systemctl show -p MainPID --value $NAME)/exe"
  guest "grep -E '^(active|previous)' /var/lib/$NAME/install.toml"
  echo
  say "G. Roll back and roll forward"
  run "$PKG2/koru" rollback --config "$CONF"
  guest "readlink /usr/libexec/$NAME/current; systemctl is-active $NAME"
  run "$PKG2/koru" rollback --config "$CONF"
  guest "readlink /usr/libexec/$NAME/current; systemctl is-active $NAME"
  echo
  say "H. Must be rejected: upgrading to an older version and upgrading with a corrupt package"
  run "$PKG1/koru" upgrade --version-dir "$PKG1" --config "$CONF"
  rm -rf /root/corrupt && cp -R "$PKG2" /root/corrupt && printf '#' >> /root/corrupt/koru-agent
  run "$PKG2/koru" upgrade --version-dir /root/corrupt --config "$CONF"
  rm -rf /root/corrupt
  guest "readlink /usr/libexec/$NAME/current; systemctl is-active $NAME"
  echo
  say "I. Uninstall"
  run "$PKG2/koru" uninstall --config "$CONF"
  sleep 1
  guest "ls -d /usr/libexec/$NAME /etc/$NAME /var/lib/$NAME /run/$NAME /etc/systemd/system/$NAME.service 2>&1 | head"
  guest "systemctl list-unit-files | grep -c $NAME || true; systemctl is-active $NAME || true"
  guest "ps -eo pid,comm | grep $NAME | grep -v grep || echo 'no process'"
  take_digest /root/digest-after.txt
  echo
  say "J. File digests (lab/scripts/file-digest.sh: path, type, mode, owner, size, SHA-256, mtime) before install and after uninstall"
  say "Scope: every entry under /usr/libexec, /etc/systemd/system, /home/devops (the decoy root); plus the mode, owner, and mtime of /, /etc, /usr, /var, /var/lib, /home."
  guest "wc -l /root/digest-before.txt /root/digest-after.txt"
  printf '$ diff /root/digest-before.txt /root/digest-after.txt\n'
  if diff /root/digest-before.txt /root/digest-after.txt; then
    printf '(no difference)\nRESULT: file digests matched\n'
  else
    printf '(DIFFERENCES)\nRESULT: file digests DID NOT MATCH\n'
  fi
} > "$LC" 2>&1

# --------------------------------------------------------------------------------------------
# systemd.txt: online and offline measurement in a second install (reinstall after uninstall)
# --------------------------------------------------------------------------------------------
{
  say "Evidence: systemd-analyze security (ADR-0008 section 1)"
  say "Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ); $(systemd-analyze --version | head -1); target (ADR-0008, written at phase start): <= 2.5"
  echo
  run sh "$PKG1/../install-scripts/install.sh" "$PKG1" -- --source-tag synthetic --decoy-root /home/devops --environment /root/environment.env
  sleep 4
  guest "systemctl is-active $NAME"
  say "Online (the running service):"
  guest "systemd-analyze security $NAME.service --no-pager"
  say "Offline (the unit file):"
  guest "systemd-analyze security --offline=true /etc/systemd/system/$NAME.service --no-pager | tail -3"
  SCORE=$(systemd-analyze security "$NAME.service" --no-pager 2>/dev/null | sed -n 's/.*Overall exposure level for [^:]*: \([0-9.]*\).*/\1/p')
  printf 'SCORE=%s TARGET=2.5\n' "$SCORE"
  if awk -v p="$SCORE" 'BEGIN { exit !(p != "" && p <= 2.5) }'; then
    printf 'RESULT: target met (%s <= 2.5)\n' "$SCORE"
  else
    printf 'RESULT: TARGET EXCEEDED (%s)\n' "$SCORE"
  fi
  echo
  say "Does the service run cleanly under hardening (journal, error line count):"
  guest "journalctl -u $NAME --no-pager -o cat | grep -i -c -E 'denied|permission|operation not permitted|failed to|error' || true"
  guest "journalctl -u $NAME --no-pager -o cat | cut -c1-160 | head -20"
  run "$PKG1/koru" uninstall --config "$CONF"
} > "$OUTPUT/systemd.txt" 2>&1

take_digest /root/digest-after2.txt
if diff -q /root/digest-before.txt /root/digest-after2.txt >/dev/null; then
  printf 'Digests also matched after the second install-uninstall round\n' >> "$OUTPUT/systemd.txt"
else
  printf 'Digests DID NOT MATCH after the second round\n' >> "$OUTPUT/systemd.txt"
fi
echo "done"
