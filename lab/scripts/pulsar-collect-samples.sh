#!/usr/bin/env bash
# Collects real Pulsar event samples for the koru-pulsar translation tests.
# Runs as root inside the VM; pulsard (the official v0.10.1 binary) must be running:
#   limactl shell koru-lab sudo bash /koru/lab/scripts/pulsar-collect-samples.sh /tmp/koru-samples.jsonl
#
# Method: while pulsar-record-event.py records events from the engine API, harmless triggers
# are run under /tmp/koru-sample. The triggers run as the unprivileged `nobody` user
# (setpriv; does not go through PAM); the container sample is taken with rootful podman. The files
# contain only "fake" content; there is no real secret or personal data.
#
# Event kinds produced: DirCreated, FileCreated, FileOpened (write and read), Exec, ElfOpened,
# Exit, FileRename, FileLink (symlink and hard link), FileDeleted, DirDeleted, Connect (TCP and UDP),
# Accept, DnsQuery, the rules-engine THREAT (symlink -> /etc/shadow), and the in-container
# FileOpened. Directory opens (O_DIRECTORY) are deliberately absent: this flag's value differs
# between aarch64 and x86_64 (crates/koru-pulsar/tests/data/README.md).
set -euo pipefail

OUTPUT="${1:?usage: pulsar-collect-samples.sh <output.jsonl>}"
DIR="/tmp/koru-sample"
PORT=18080
IMAGE="docker.io/library/alpine:3.22"
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)

info() { printf '[collect-samples] %s\n' "$*" >&2; }
fail() { printf '[collect-samples] ERROR: %s\n' "$*" >&2; exit 1; }
unpriv() { setpriv --reuid=nobody --regid=nogroup --clear-groups -- "$@"; }

[ "$(id -u)" -eq 0 ] || fail "must be run as root"
systemctl is-active --quiet pulsard.service || fail "pulsard is not running"
command -v podman >/dev/null 2>&1 || fail "podman missing; first: lab/scripts/dev-setup.sh"

# The image is pulled before recording (so download events do not mix into the recording).
podman image exists "$IMAGE" || podman pull -q "$IMAGE" >/dev/null
info "image: ${IMAGE} $(podman image inspect --format '{{.Digest}}' "$IMAGE")"

rm -rf "$DIR"
LOG=$(mktemp)
LISTENER=""
cleanup() {
  if [ -n "$LISTENER" ]; then kill "$LISTENER" 2>/dev/null || true; fi
  rm -rf "$DIR" "$LOG"
}
trap cleanup EXIT

python3 "${SCRIPT_DIR}/pulsar-record-event.py" --duration 45 --output "$OUTPUT" \
  --filter koru-sample --filter "\"port\":${PORT}" 2>"$LOG" &
RECORDER=$!
for _ in $(seq 1 50); do grep -q 'ready' "$LOG" && break; sleep 0.1; done
grep -q 'ready' "$LOG" || { cat "$LOG" >&2; fail "the recorder did not start"; }
sleep 1

info "filesystem triggers (user nobody)"
unpriv mkdir "$DIR"
unpriv sh -c "printf 'fake content\n' > ${DIR}/decoy.txt"
unpriv cat "${DIR}/decoy.txt" >/dev/null
unpriv cp /usr/bin/false "${DIR}/sample-binary"
unpriv "${DIR}/sample-binary" || true
unpriv mv "${DIR}/decoy.txt" "${DIR}/decoy2.txt"
unpriv ln -s /etc/shadow "${DIR}/link"
unpriv ln "${DIR}/decoy2.txt" "${DIR}/hardlink"
unpriv rm "${DIR}/decoy2.txt" "${DIR}/hardlink" "${DIR}/link" "${DIR}/sample-binary"

info "network triggers (127.0.0.1:${PORT})"
python3 -c "
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', ${PORT})); s.listen(1); s.settimeout(10)
c, _ = s.accept(); c.close(); s.close()
" &
LISTENER=$!
sleep 1
unpriv python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', ${PORT}), timeout=5); s.close()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.connect(('127.0.0.1', ${PORT})); u.close()
"
wait "$LISTENER" || true
LISTENER=""
unpriv getent hosts koru-sample.invalid >/dev/null || true

info "container trigger (rootful podman, ${IMAGE})"
unpriv sh -c "printf 'fake content\n' > ${DIR}/container.txt"
podman run --rm --network=none -v "${DIR}:${DIR}:ro" "$IMAGE" cat "${DIR}/container.txt" >/dev/null
unpriv rm "${DIR}/container.txt"
unpriv rmdir "$DIR"

info "waiting for the recorder to finish"
wait "$RECORDER"
cat "$LOG" >&2
line=$(wc -l <"$OUTPUT" | tr -d ' ')
[ "$line" -gt 0 ] || fail "no event was recorded"
info "RESULT: ${line} events -> ${OUTPUT}"
