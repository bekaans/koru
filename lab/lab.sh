#!/usr/bin/env bash
# Koru lab VM: one-command setup and management (macOS + Lima).
#
#   lab/lab.sh setup     Creates/starts the VM, verifies the security settings,
#                      copies the repo into the VM, waits for NTP sync, installs Pulsar,
#                      and verifies it with a THREAT event. Idempotent; safe to
#                      run again.
#   lab/lab.sh sync  Copies the repo, except `.env`, `.git`, and build outputs, to
#                      /koru in the VM (rsync, Mac to VM only; KT-38).
#   lab/lab.sh status   Shows VM, NTP, and Pulsar status.
#   lab/lab.sh test    Copies the repo, sets up the Rust environment, and runs
#                      `cargo test --workspace --locked` in the VM (Linux).
#   lab/lab.sh live-pulsar
#                      Runs the live Pulsar translation test with Koru's own binary with
#                      embedded modules (lab/scripts/live-pulsar-test.sh).
#   lab/lab.sh live-detect
#                      Feeds real Pulsar events through koru-detect: decoy, breadcrumb, AI
#                      agent lineage, human shell, self-protection, allowlist, and container
#                      scenarios (lab/scripts/live-detect-test.sh).
#   lab/lab.sh live-store
#                      Writes real Pulsar events to koru-store; corrupt and duplicate events are mixed in,
#                      `koru report data-quality` and export are verified (lab/scripts/live-store-test.sh).
#   lab/lab.sh shell   Opens an interactive shell in the VM (working directory /koru).
#   lab/lab.sh destroy     Stops and deletes the VM.
#
# No directory from the Mac is mounted into the VM (KT-38). The paths
# excluded from the copy are in lab/sync-filter.txt.
#
# Compatible with macOS bash 3.2.
set -euo pipefail

VM_NAME="koru-lab"
# Where the measurement results (performance, resilience, scenarios) are written on the Mac.
SCENARIO_OUT="${KORU_SCENARIO_OUT:-lab/out/scenarios}"
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd -P)
TEMPLATE="${SCRIPT_DIR}/lima/koru-lab.yaml"
FILTER="${SCRIPT_DIR}/sync-filter.txt"
LIMA_HOME="${LIMA_HOME:-${HOME}/.lima}"
NTP_WAIT_S=180

info() { printf '[lab] %s\n' "$*"; }
fail() { printf '[lab] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Usage: lab/lab.sh <setup|sync|status|test|live-pulsar|live-detect|live-store|scenarios|demo|performance|resilience|shell|destroy>

  setup     Sets up the VM, copies the repo, installs and verifies NTP and Pulsar (idempotent)
  sync  Copies the repo except .env, .git, and build outputs to /koru in the VM
  status   Shows VM, NTP, and Pulsar status
  test    cargo test --workspace --locked in the VM (Linux)
  live-pulsar  Live Pulsar translation test with Koru's own binary
  live-detect  Live detection test with real Pulsar events (koru-pulsar -> koru-detect)
  live-store  Live store test with real Pulsar events (koru-pulsar -> koru-store; data-quality report)
  scenarios [--all]  The end-to-end scenario set (100 attacks + legitimate; lab/scripts/scenarios.py; writes golden data)
  demo        The demo scenario and asciinema recording (docs/demo/koru-demo.cast)
  performance  The performance measurement (CPU<2%, RAM<100MB, notification p95<5s)
  resilience The resilience tests (kill -9, full disk, network outage, corrupt config)
  shell   Opens a shell in the VM (/koru: the repo copy)
  destroy     Deletes the VM
USAGE
}

prerequisites() {
  [ "$(uname -s)" = "Darwin" ] || fail "this script is for macOS"
  [ "$(uname -m)" = "arm64" ] || fail "Apple Silicon (arm64) required"
  command -v limactl >/dev/null 2>&1 || fail "limactl not found: brew install lima"
  command -v python3 >/dev/null 2>&1 || fail "python3 not found (needed for the reverse-direction check)"
  command -v nc >/dev/null 2>&1 || fail "nc not found (needed for port checks)"
  command -v rsync >/dev/null 2>&1 || fail "rsync not found (needed for the repo copy)"
  [ -f "$TEMPLATE" ] || fail "template missing: ${TEMPLATE}"
  [ -f "$FILTER" ] || fail "sync filter missing: ${FILTER}"
}

# Lima's global configuration (_config/default.yaml, override.yaml, base.yaml)
# can change the mounts in the template. Since override.yaml is applied at every start,
# this check runs on every `setup` call.
check_global_config() {
  local f
  for f in default.yaml override.yaml base.yaml; do
    if [ -f "${LIMA_HOME}/_config/${f}" ] && grep -Eq '^[[:space:]]*(mounts|portForwards|ssh|plain):' "${LIMA_HOME}/_config/${f}"; then
      fail "${LIMA_HOME}/_config/${f} contains a mount/port/ssh setting; remove it for lab security"
    fi
  done
}

vm_state() {
  # Output: Running | Stopped | ... | none
  local row
  row=$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | awk -v name="$VM_NAME" '$1 == name { print $2 }')
  if [ -n "$row" ]; then printf '%s\n' "$row"; else printf 'absent\n'; fi
}

vm_shell() {
  limactl shell --workdir / "$VM_NAME" "$@"
}

# A temporary TCP listener on the Mac for the reverse-direction check (KT-37). The listener
# binds only to 127.0.0.1, picks a random free port, writes every connection it accepts to the
# `accepted` file in the temp directory, and closes by itself after at most 120 s.
# `trap` closes it in all cases (including errors and Ctrl-C) and deletes the temp directory.
REVERSE_LISTENER_PID=""
REVERSE_TMP=""

reverse_listener_close() {
  if [ -n "$REVERSE_LISTENER_PID" ]; then
    kill "$REVERSE_LISTENER_PID" 2>/dev/null || true
    wait "$REVERSE_LISTENER_PID" 2>/dev/null || true
    REVERSE_LISTENER_PID=""
  fi
  if [ -n "$REVERSE_TMP" ]; then
    rm -rf "$REVERSE_TMP"
    REVERSE_TMP=""
  fi
}

reverse_listener_open() {
  local i
  trap reverse_listener_close EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  REVERSE_TMP=$(mktemp -d -t koru-reverse)
  python3 - "$REVERSE_TMP" <<'PY' &
import os, random, socket, sys, time
directory = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
for _ in range(200):
    try:
        s.bind(("127.0.0.1", random.randint(49152, 65535)))
        break
    except OSError:
        continue
else:
    sys.exit("no free port found")
s.listen(16)
s.settimeout(0.5)
tmp_file = os.path.join(directory, "port.tmp")
with open(tmp_file, "w") as f:
    f.write("%d\n" % s.getsockname()[1])
os.rename(tmp_file, os.path.join(directory, "port"))
son = time.monotonic() + 120
while time.monotonic() < son:
    try:
        c, address = s.accept()
    except socket.timeout:
        continue
    with open(os.path.join(directory, "accepted"), "a") as f:
        f.write("%s:%d\n" % address)
    c.close()
PY
  REVERSE_LISTENER_PID=$!
  for i in $(seq 1 50); do
    [ -s "${REVERSE_TMP}/port" ] && break
    kill -0 "$REVERSE_LISTENER_PID" 2>/dev/null || fail "the reverse-direction listener did not start"
    sleep 0.1
  done
  [ -s "${REVERSE_TMP}/port" ] || fail "the reverse-direction listener did not report a port in ${i} attempts"
}

# The number of connections the listener on the Mac has accepted so far.
reverse_accept_count() {
  if [ -f "${REVERSE_TMP}/accepted" ]; then
    wc -l <"${REVERSE_TMP}/accepted" | tr -d ' '
  else
    printf '0\n'
  fi
}

vm_create() {
  info "creating the VM: ${VM_NAME} (template: lab/lima/koru-lab.yaml, no mounts)"
  limactl create --tty=false --name "$VM_NAME" "$TEMPLATE"
}

# Copies the repo to /koru in the VM (KT-38). The direction is Mac
# to VM only; changes in the VM do not return to the Mac. Exclusions
# lab/sync-filter.txt lists (.env, .env.*, .git, target/, node_modules/,
# .wrangler/, .dev.vars*, data/real/, .DS_Store). Compares by content digest with -c:
# a file changed in the VM with its size and time preserved also returns to its
# state on the Mac.
# --delete-excluded also deletes excluded paths that appeared later in the VM.
# /koru belongs to root; the guest user (koru) cannot write without sudo.
#
# Stale builds: -t carries the source's Mac modification time into the VM. If a file's content changed
# with an older time (e.g. another commit was checked out or an old tree copied), cargo may count
# the build output as up to date and skip compiling the new content. That is why the times of files
# rsync transferred (content changed) are updated in the VM with `touch`. The rsync options did NOT
# change (kept identical to lab/scripts/sync-test.sh; only --out-format was added); files whose
# content is unchanged are untouched, incremental builds are preserved.
copy_repo() {
  local ssh_config="${LIMA_HOME}/${VM_NAME}/ssh.config" leaked file_count transferred_list transferred_count
  [ -f "$ssh_config" ] || fail "Lima SSH config missing: ${ssh_config}"
  case "$ssh_config" in
    *[[:space:]]*) fail "the Lima SSH config path contains a space: ${ssh_config}" ;;
  esac
  info "copying the repo into the VM: ${REPO_ROOT}/ -> ${VM_NAME}:/koru/ (filter: lab/sync-filter.txt)"
  vm_shell sudo install -d -m 755 -o root -g root /koru
  transferred_list=$(rsync -rlptc --delete --delete-excluded --chmod=go-w --out-format='%n' \
    --exclude-from="$FILTER" \
    -e "ssh -F ${ssh_config}" --rsync-path="sudo rsync" \
    "${REPO_ROOT}/" "lima-${VM_NAME}:/koru/") || fail "rsync failed"
  # Transferred files (directories excluded) are stamped with the current time in the VM (see note above).
  transferred_list=$(printf '%s\n' "$transferred_list" | grep -v '/$' | grep -v '^$' || true)
  transferred_count=0
  if [ -n "$transferred_list" ]; then
    transferred_count=$(printf '%s\n' "$transferred_list" | wc -l | tr -d ' ')
    printf '%s\n' "$transferred_list" | vm_shell sudo sh -c 'cd /koru && xargs -d "\n" touch -c --' \
      || fail "could not update the transferred files' times"
  fi
  vm_shell sudo chown -R root:root /koru
  # Check: no path that must be excluded may exist in the VM.
  leaked=$(vm_shell sudo find /koru \( -name .git -o -name .env -o \( -name '.env.*' ! -name .env.example \) \
    -o -name '.dev.vars*' -o -name .DS_Store -o \( -type d \( -name target -o -name node_modules -o -name .wrangler \) \) \
    -o -path /koru/data/real \) -print)
  [ -z "$leaked" ] || fail "the copy in the VM contains paths that must be excluded: ${leaked}"
  vm_shell test ! -e /koru/.env || fail "/koru/.env exists in the VM (KT-38)"
  vm_shell test ! -e /koru/.git || fail "/koru/.git exists in the VM (KT-38)"
  file_count=$(vm_shell sudo find /koru -type f | wc -l | tr -d ' ')
  info "  /koru: ${file_count} files (${transferred_count} files transferred and re-stamped); .env, .git, and the filtered paths are absent"
}

# Effective configuration and mount/port security checks from inside the guest.
verify_security() {
  local mount_list guest_mounts
  # KT-38: no directory from the Mac is mounted into the VM. A VM created with the old (mounting)
  # template is rejected here; the fix: lab/lab.sh destroy && lab/lab.sh setup.
  info "security check: the Lima configuration must contain no mounts (KT-38)"
  mount_list=$(limactl list "$VM_NAME" --format '{{range .Config.Mounts}}{{.Location}} -> {{.MountPoint}}{{"\n"}}{{end}}')
  if [ -n "$(printf '%s\n' "$mount_list" | sed '/^$/d')" ]; then
    printf '%s\n' "$mount_list" | sed '/^$/d; s/^/[lab]   /'
    fail "the VM has mounts; the VM may have been created with the old template: lab/lab.sh destroy && lab/lab.sh setup"
  fi
  info "  no mounts in the Lima configuration"

  info "security check: the guest must have no virtiofs, 9p, or sshfs mounts (findmnt)"
  guest_mounts=$(vm_shell findmnt -rn -t virtiofs,9p,fuse.sshfs -o TARGET,FSTYPE || true)
  if [ -n "$guest_mounts" ]; then
    printf '%s\n' "$guest_mounts" | sed 's/^/[lab]   /'
    fail "the guest has a mount from the Mac"
  fi
  if vm_shell test -e "$HOME"; then fail "the Mac home directory (${HOME}) is visible in the guest"; fi
  info "  no mount from the Mac in the guest; ${HOME} is not in the guest"

  info "security check: a port opened in the guest must not be forwarded to the Mac"
  local port=47123
  if nc -z -G 1 127.0.0.1 "$port" 2>/dev/null; then
    fail "port ${port} is already open on the Mac; the check cannot run"
  fi
  # The server serves from an empty temp directory (a below-threshold finding):
  # it closes after 8 s and the directory is deleted.
  vm_shell bash -s -- "$port" <<'GUEST'
set -eu
directory=$(mktemp -d)
nohup sh -c 'timeout 8 python3 -m http.server "$1" --bind 0.0.0.0 --directory "$2" >/dev/null 2>&1; rmdir "$2"' \
  sh "$1" "$directory" </dev/null >/dev/null 2>&1 &
GUEST
  sleep 5
  if nc -z -G 1 127.0.0.1 "$port" 2>/dev/null; then
    fail "guest port ${port} was forwarded to the Mac"
  fi
  vm_shell bash -c "ss -ltn 'sport = :${port}' | grep -q LISTEN" \
    || fail "port check invalid: ${port} was not listening in the guest"
  info "  while 0.0.0.0:${port} listened in the guest, 127.0.0.1:${port} was closed on the Mac"

  # Reverse direction (KT-37): in Lima's usernet, the gateway (host.lima.internal) is NATed
  # to the Mac's 127.0.0.1. The guest must not be able to connect to a listener bound only
  # to 127.0.0.1 on the Mac. The block is the nftables rule inside the guest
  # (koru-lab.yaml, first provision step); it is not a trust boundary.
  info "security check: the guest must not connect to the Mac's 127.0.0.1 (reverse direction, KT-37)"
  local reverse_port accept_before accept_after address result gateway targets
  reverse_listener_open
  reverse_port=$(tr -d '\n' <"${REVERSE_TMP}/port")
  nc -z -G 2 127.0.0.1 "$reverse_port" 2>/dev/null \
    || fail "reverse check invalid: could not connect to the listener at 127.0.0.1:${reverse_port} on the Mac"
  sleep 1
  accept_before=$(reverse_accept_count)
  [ "$accept_before" -ge 1 ] \
    || fail "reverse check invalid: the listener did not record the trial connection from the Mac"
  info "  Mac: listening on 127.0.0.1:${reverse_port} (random free port; the trial connection from the Mac was accepted)"
  info "  in the guest host.lima.internal: $(vm_shell getent ahostsv4 host.lima.internal | awk 'NR == 1 { print $1 }')"
  targets="host.lima.internal 192.168.5.2"
  gateway=$(vm_shell ip -4 route show default | awk '{ print $3; exit }')
  [ -n "$gateway" ] || fail "could not read the guest's default gateway"
  case " ${targets} " in
    *" ${gateway} "*) ;;
    *) targets="${targets} ${gateway}" ;;
  esac
  for address in $targets; do
    result=$(vm_shell bash -c "if timeout 5 bash -c 'exec 3<>/dev/tcp/${address}/${reverse_port}' 2>/dev/null; then echo CONNECTED; else echo NO_CONNECT; fi")
    case "$result" in
      NO_CONNECT) info "  guest -> ${address}:${reverse_port}: connection failed" ;;
      CONNECTED) fail "the guest connected to the Mac's 127.0.0.1 via ${address}:${reverse_port} (KT-37)" ;;
      *) fail "the reverse check could not run (${address}): ${result}" ;;
    esac
  done
  # If the listener had closed while the attempts ran (e.g. its 120 s had expired),
  # a "connection failed" result would be a false positive (a below-threshold finding).
  kill -0 "$REVERSE_LISTENER_PID" 2>/dev/null \
    || fail "reverse check invalid: the listener on the Mac closed before the attempts ended (kill -0 failed)"
  info "  the listener on the Mac is still running after the attempts (kill -0 ${REVERSE_LISTENER_PID}: ok)"
  accept_after=$(reverse_accept_count)
  [ "$accept_after" = "$accept_before" ] \
    || fail "the listener on the Mac accepted a connection from the guest (${accept_before} -> ${accept_after}; KT-37)"
  info "  the listener on the Mac accepted no connection from the guest (accept count ${accept_after}, only the Mac's own trial)"
  nc -z -G 2 127.0.0.1 "$reverse_port" 2>/dev/null \
    || fail "reverse check invalid: could not connect to the listener on the Mac after the attempts"
  sleep 1
  [ "$(reverse_accept_count)" -gt "$accept_after" ] \
    || fail "reverse check invalid: the listener did not record the Mac's connection after the attempts"
  info "  a new connection from the Mac was accepted after the attempts (the listener was alive)"
  reverse_listener_close
  if nc -z -G 1 127.0.0.1 "$reverse_port" 2>/dev/null; then
    fail "could not close the reverse listener: 127.0.0.1:${reverse_port}"
  fi
  info "  the temporary listener on the Mac is closed, the temp directory deleted"
  vm_shell sudo nft list table inet koru_lab_reverse | sed 's/^/[lab]   /'

  info "security check: DNS must work in the guest (the Lima DNS path is exempt from the rule)"
  vm_shell sudo resolvectl flush-caches
  result=$(vm_shell getent hosts archive.ubuntu.com) \
    || fail "DNS is not working in the guest: archive.ubuntu.com could not be resolved"
  printf '%s\n' "$result" | sed 's/^/[lab]   /'
}

ntp_wait() {
  local i value=""
  info "waiting for NTP sync (at most ${NTP_WAIT_S} s)"
  for i in $(seq 1 "$NTP_WAIT_S"); do
    value=$(vm_shell timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
    if [ "$value" = "yes" ]; then
      info "NTPSynchronized=yes (${i} s)"
      return 0
    fi
    sleep 1
  done
  vm_shell chronyc -n sources >&2 || true
  fail "NTP sync not achieved within ${NTP_WAIT_S} s (NTPSynchronized=${value})"
}

setup() {
  prerequisites
  check_global_config
  local state
  state=$(vm_state)
  if [ "$state" = "absent" ]; then
    vm_create
    state=$(vm_state)
  else
    info "the VM already exists (status: ${state}); creation skipped"
  fi
  if [ "$state" != "Running" ]; then
    info "starting the VM"
    limactl start --tty=false "$VM_NAME"
  else
    info "the VM is already running"
  fi
  [ "$(vm_state)" = "Running" ] || fail "the VM is not running"

  verify_security
  copy_repo

  info "kernel: $(vm_shell uname -r)"
  vm_shell test -f /sys/kernel/btf/vmlinux || fail "/sys/kernel/btf/vmlinux missing (BTF required)"
  info "BTF: /sys/kernel/btf/vmlinux present"

  ntp_wait
  vm_shell chronyc -n tracking | sed 's/^/[lab]   /'

  info "installing Pulsar (lab/scripts/pulsar-setup.sh)"
  vm_shell sudo bash /koru/lab/scripts/pulsar-setup.sh

  info "verifying Pulsar (lab/scripts/pulsar-verify.sh)"
  vm_shell sudo bash /koru/lab/scripts/pulsar-verify.sh

  limactl list "$VM_NAME"
  info "RESULT: ${VM_NAME} $(vm_state); NTP in sync; the Pulsar THREAT event verified"
}

status() {
  prerequisites
  if [ "$(vm_state)" = "absent" ]; then
    info "no VM; to create one: lab/lab.sh setup"
    return 0
  fi
  limactl list "$VM_NAME"
  [ "$(vm_state)" = "Running" ] || return 0
  info "kernel: $(vm_shell uname -r)"
  info "NTPSynchronized: $(vm_shell timedatectl show -p NTPSynchronized --value)"
  vm_shell chronyc -n tracking | sed 's/^/[lab]   /' || true
  info "pulsard: $(vm_shell systemctl is-active pulsard.service 2>/dev/null || true)"
  vm_shell sudo pulsar status 2>/dev/null || true
}

sync() {
  prerequisites
  [ "$(vm_state)" = "Running" ] || fail "the VM is not running; first: lab/lab.sh setup"
  copy_repo
}

# cargo in the VM: /koru belongs to root and is a read-only copy; build outputs are written to the
# koru-target directory in the guest user's home.
vm_cargo() {
  # $HOME and "$@" deliberately expand in the VM shell.
  # shellcheck disable=SC2016
  limactl shell --workdir /koru "$VM_NAME" bash -lc 'CARGO_TARGET_DIR="$HOME/koru-target" cargo "$@"' cargo "$@"
}

prepare_dev() {
  prerequisites
  [ "$(vm_state)" = "Running" ] || fail "the VM is not running; first: lab/lab.sh setup"
  copy_repo
  info "Rust dev environment (lab/scripts/dev-setup.sh)"
  vm_shell sudo bash /koru/lab/scripts/dev-setup.sh
}

run_tests() {
  prepare_dev
  info "VM'de cargo test --workspace --locked"
  vm_cargo test --workspace --locked
}

live_pulsar() {
  local binary
  prepare_dev
  info "building the live-test binary (koru-pulsar, example live_translation)"
  vm_cargo build --locked -p koru-pulsar --example live_translation
  # $HOME deliberately expands in the VM shell.
  # shellcheck disable=SC2016
  binary=$(limactl shell --workdir / "$VM_NAME" bash -lc 'printf "%s" "$HOME/koru-target/debug/examples/live_translation"')
  info "live test (lab/scripts/live-pulsar-test.sh)"
  vm_shell sudo bash /koru/lab/scripts/live-pulsar-test.sh "$binary"
}

performance() {
  local target_dir
  prepare_dev
  info "building the performance binaries (release: koru, koru-agent)"
  vm_cargo build --locked --release -p koru --bin koru --bin koru-agent
  # shellcheck disable=SC2016
  target_dir=$(limactl shell --workdir / "$VM_NAME" bash -lc 'printf "%s" "$HOME/koru-target/release"')
  info "performance measurement (lab/scripts/performance.py; ~12 min)"
  local result=0
  vm_shell sudo python3 /koru/lab/scripts/performance.py "$target_dir" || result=$?
  mkdir -p "$SCENARIO_OUT"
  limactl shell --workdir / "$VM_NAME" sudo cat /tmp/koru-perf/result.json > "$SCENARIO_OUT"/performance.json || true
  return "$result"
}

resilience() {
  local target_dir
  prepare_dev
  vm_cargo build --locked --release -p koru --bin koru --bin koru-agent
  # shellcheck disable=SC2016
  target_dir=$(limactl shell --workdir / "$VM_NAME" bash -lc 'printf "%s" "$HOME/koru-target/release"')
  info "resilience tests (lab/scripts/resilience.py)"
  local result=0
  vm_shell sudo python3 /koru/lab/scripts/resilience.py "$target_dir" || result=$?
  mkdir -p "$SCENARIO_OUT"
  limactl shell --workdir / "$VM_NAME" sudo cat /tmp/koru-resilience/result.json > "$SCENARIO_OUT"/resilience.json || true
  return "$result"
}

demo() {
  local target_dir
  prepare_dev
  vm_cargo build --locked -p koru --bin koru --example live_detect
  # shellcheck disable=SC2016
  target_dir=$(limactl shell --workdir / "$VM_NAME" bash -lc 'printf "%s" "$HOME/koru-target/debug"')
  info "demo recording (lab/scripts/demo.sh; asciinema)"
  vm_shell sudo bash /koru/lab/scripts/demo.sh "$target_dir"
  mkdir -p docs/demo
  limactl shell --workdir / "$VM_NAME" sudo cat /koru/docs/demo/koru-demo.cast > docs/demo/koru-demo.cast
}

scenarios() {
  local target_dir
  prepare_dev
  info "building the scenario binaries (the koru binary, example live_detect)"
  vm_cargo build --locked -p koru --bin koru --example live_detect
  # shellcheck disable=SC2016
  target_dir=$(limactl shell --workdir / "$VM_NAME" bash -lc 'printf "%s" "$HOME/koru-target/debug"')
  info "scenarios (lab/scripts/scenarios.py; golden data is written)"
  local result=0
  vm_shell sudo python3 /koru/lab/scripts/scenarios.py "$target_dir" --write-golden || result=$?
  info "fetching the result and golden data to the Mac"
  mkdir -p "$SCENARIO_OUT"
  limactl shell --workdir / "$VM_NAME" sudo cat /tmp/koru-scenarios/result.json > "$SCENARIO_OUT"/scenarios-result.json
  limactl shell --workdir / "$VM_NAME" sudo cat /koru/data/golden/synthetic/events.jsonl > data/golden/synthetic/events.jsonl
  limactl shell --workdir / "$VM_NAME" sudo cat /koru/data/golden/legitimate/events.jsonl > data/golden/legitimate/events.jsonl
  limactl shell --workdir / "$VM_NAME" sudo cat /koru/data/golden/catalog.txt > data/golden/catalog.txt
  return "$result"
}

live_detect() {
  local target_dir
  prepare_dev
  info "building the live-test binaries (the koru binary, example live_detect)"
  vm_cargo build --locked -p koru --bin koru --example live_detect
  # $HOME deliberately expands in the VM shell.
  # shellcheck disable=SC2016
  target_dir=$(limactl shell --workdir / "$VM_NAME" bash -lc 'printf "%s" "$HOME/koru-target/debug"')
  info "live detection test (lab/scripts/live-detect-test.sh)"
  vm_shell sudo bash /koru/lab/scripts/live-detect-test.sh "$target_dir"
}

live_store() {
  local target_dir
  prepare_dev
  info "building the live-test binaries (the koru binary, example live_store)"
  vm_cargo build --locked -p koru --bin koru --example live_store
  # $HOME deliberately expands in the VM shell.
  # shellcheck disable=SC2016
  target_dir=$(limactl shell --workdir / "$VM_NAME" bash -lc 'printf "%s" "$HOME/koru-target/debug"')
  info "live store test (lab/scripts/live-store-test.sh)"
  vm_shell sudo bash /koru/lab/scripts/live-store-test.sh "$target_dir"
}

shell() {
  prerequisites
  [ "$(vm_state)" = "Running" ] || fail "the VM is not running; first: lab/lab.sh setup"
  exec limactl shell --workdir /koru "$VM_NAME"
}

destroy() {
  prerequisites
  if [ "$(vm_state)" = "absent" ]; then
    info "no VM; nothing to delete"
    return 0
  fi
  info "deleting the VM: ${VM_NAME}"
  limactl delete --force "$VM_NAME"
  info "deleted"
}

main() {
  [ "$#" -eq 1 ] || { usage >&2; exit 2; }
  case "$1" in
    setup) setup ;;
    sync) sync ;;
    status) status ;;
    test) run_tests ;;
    live-pulsar) live_pulsar ;;
    live-detect) live_detect ;;
    scenarios) scenarios ;;
    performance) performance ;;
    resilience) resilience ;;
    demo) demo ;;
    live-store) live_store ;;
    shell) shell ;;
    destroy) destroy ;;
    -h | --help) usage ;;
    *) usage >&2; exit 2 ;;
  esac
}

main "$@"
