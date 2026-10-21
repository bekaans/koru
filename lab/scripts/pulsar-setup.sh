#!/usr/bin/env bash
# Installs Pulsar into the Koru lab VM. Runs as root inside the VM:
#   limactl shell koru-lab sudo bash /koru/lab/scripts/pulsar-setup.sh
#
# Follows Pulsar's official install path (pulsar-install.sh, v0.10.1):
# - the `pulsard-aarch64-static` and `pulsar-aarch64-static` binaries for aarch64 are installed
#   as /usr/bin/pulsard and /usr/bin/pulsar;
# - an empty /var/lib/pulsar/pulsar.ini configuration file is created;
# - the `rules/` directory at the release tag is copied under /var/lib/pulsar/rules.
# Differences from the official script: the version, binary digests, and source commit are pinned
# and verified; pulsard runs in the background via a systemd unit.
#
# The script is idempotent: if the binaries and rules are already correct, nothing is downloaded.
set -euo pipefail

# --- Pinned version -----------------------------------------------------------
# The latest stable release was verified on the GitHub releases page on 2026-10-08
# (v0.10.1, published 2026-09-30, not a prerelease).
PULSAR_VERSION="v0.10.1"
# The commit the v0.10.1 tag points at (a lightweight tag).
PULSAR_COMMIT="e79d2eb3771b7ad657c0029ca2c7bbaeac5e61fb"
PULSAR_REPO="https://github.com/exein-io/pulsar"

# Pulsar publishes no separate SHA256SUMS file. GitHub shows a SHA-256 digest (asset digest) for
# each file on the release page. The values below were taken from
# `gh api repos/exein-io/pulsar/releases/tags/v0.10.1` output; downloaded files are verified
# against them.
PULSARD_FILE="pulsard-aarch64-static"
PULSARD_SHA256="69c4cc4497c09d469e518dfea6dad04221063f78c8020e15e3d539b195ba0380"
PULSAR_FILE="pulsar-aarch64-static"
PULSAR_SHA256="cdd34c2bc8075c6c2afc53d64707f143c4285cb6d50299b4c7419602ff1d8121"

# --- Paths (same as the official install) -------------------------------------
BIN_DIR="/usr/bin"
PULSAR_DIR="/var/lib/pulsar"
RULES_DIR="${PULSAR_DIR}/rules"
CONFIG_PATH="${PULSAR_DIR}/pulsar.ini"
SOURCE_DIR="/var/cache/koru/pulsar-${PULSAR_VERSION}"
UNIT_PATH="/etc/systemd/system/pulsard.service"

info() { printf '[pulsar-setup] %s\n' "$*"; }
fail() { printf '[pulsar-setup] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must be run as root"
[ "$(uname -m)" = "aarch64" ] || fail "only aarch64 is supported (found: $(uname -m))"
[ -f /sys/kernel/btf/vmlinux ] || fail "no /sys/kernel/btf/vmlinux: the kernel needs BTF"
for cmd in curl git sha256sum install systemctl jq; do
  command -v "$cmd" >/dev/null 2>&1 || fail "'$cmd' not found (see the lab/lima/koru-lab.yaml provision step)"
done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# --- 1. Latest stable version check (informational; does not change the install) --
latest=$(curl --proto '=https' --tlsv1.2 -fsS --max-time 20 \
  "https://api.github.com/repos/exein-io/pulsar/releases/latest" 2>/dev/null \
  | jq -r '.tag_name // empty' 2>/dev/null || true)
if [ -z "$latest" ]; then
  info "WARNING: the GitHub releases API could not be reached; the latest-version check was skipped"
elif [ "$latest" = "$PULSAR_VERSION" ]; then
  info "the pinned version ${PULSAR_VERSION} matches the latest stable release on GitHub"
else
  info "WARNING: a newer stable release exists on GitHub: ${latest}. The script is deliberately pinned to ${PULSAR_VERSION}; an upgrade means updating the pinned version in docs/architecture.md#toolchain-and-versions."
fi

# --- 2. Binaries ----------------------------------------------------------------
# Note: the function is not called in an `if` condition; otherwise bash disables `set -e` inside
# the function. The changed/unchanged result returns through a global variable.
restart_needed=0
install_binary() {
  local file="$1" expected="$2" dest="$3" current="" found=""
  if [ -f "$dest" ]; then
    current=$(sha256sum "$dest" | cut -d' ' -f1)
  fi
  if [ "$current" = "$expected" ]; then
    info "${dest} already installed and verified (sha256 ${expected})"
    return 0
  fi
  info "downloading: ${PULSAR_REPO}/releases/download/${PULSAR_VERSION}/${file}"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 \
    -o "${TMP}/${file}" \
    "${PULSAR_REPO}/releases/download/${PULSAR_VERSION}/${file}" \
    || fail "${file} could not be downloaded"
  found=$(sha256sum "${TMP}/${file}" | cut -d' ' -f1)
  [ "$found" = "$expected" ] \
    || fail "${file}: SHA-256 mismatch (expected ${expected}, found ${found})"
  info "${file}: SHA-256 verified (${found})"
  install -m 755 "${TMP}/${file}" "$dest"
  info "installed: ${dest}"
  restart_needed=1
}

install_binary "$PULSARD_FILE" "$PULSARD_SHA256" "${BIN_DIR}/pulsard"
install_binary "$PULSAR_FILE" "$PULSAR_SHA256" "${BIN_DIR}/pulsar"

# --- 3. Configuration -----------------------------------------------------------
install -d -m 755 "$PULSAR_DIR"
if [ ! -f "$CONFIG_PATH" ]; then
  # The official script creates an empty pulsar.ini; modules run with their defaults.
  install -m 644 /dev/null "$CONFIG_PATH"
  info "empty configuration created: ${CONFIG_PATH}"
else
  info "configuration exists, untouched: ${CONFIG_PATH}"
fi

# --- 4. Default rule set (rules/ at the release tag) --------------------------
if [ -d "${SOURCE_DIR}/.git" ] && [ "$(git -C "$SOURCE_DIR" rev-parse HEAD)" = "$PULSAR_COMMIT" ]; then
  info "source already present: ${SOURCE_DIR} (${PULSAR_COMMIT})"
else
  rm -rf "$SOURCE_DIR"
  install -d -m 755 "$(dirname "$SOURCE_DIR")"
  git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$PULSAR_VERSION" \
    "${PULSAR_REPO}.git" "$SOURCE_DIR"
fi
found_commit=$(git -C "$SOURCE_DIR" rev-parse HEAD)
[ "$found_commit" = "$PULSAR_COMMIT" ] \
  || fail "the tag ${PULSAR_VERSION} points at an unexpected commit: ${found_commit} (expected ${PULSAR_COMMIT})"
info "source commit verified: ${PULSAR_VERSION} = ${PULSAR_COMMIT}"

# Rules come only from the rules/ directory at the tag; no rule is added. If the rule directory
# differs from its state at the tag (extra, missing, or changed file) it is restored to the tag state.
new_rules="${TMP}/rules"
(cd "${SOURCE_DIR}/rules" && find . -type f -exec install -Dm 644 "{}" "${new_rules}/{}" \;)
if [ -d "$RULES_DIR" ] && diff -r "$new_rules" "$RULES_DIR" >/dev/null 2>&1; then
  info "the default rules are already installed and match the tag"
else
  rm -rf "$RULES_DIR"
  install -d -m 755 "$RULES_DIR"
  cp -a "${new_rules}/." "$RULES_DIR/"
  info "default rules installed: ${RULES_DIR}"
  restart_needed=1
fi
rule_file_count=$(find "$RULES_DIR" -type f -name '*.yaml' | wc -l)
rules_digest=$(cd "$RULES_DIR" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
info "rule file count: ${rule_file_count}; rule tree digest (sha256): ${rules_digest}"

# --- 5. systemd unit ------------------------------------------------------------
# The official docs say to start pulsard with administrator privileges; in the lab the systemd
# unit does that. There is no hardening: pulsard needs root and broad capabilities to load eBPF
# programs. This unit is lab-only; Koru's own hardened unit is written under distribution/.
new_unit="${TMP}/pulsard.service"
cat >"$new_unit" <<'UNIT'
# Koru lab: managed by lab/scripts/pulsar-setup.sh.
[Unit]
Description=Pulsar eBPF runtime security agent (pulsard)
Documentation=https://pulsar.sh/docs/getting-started/agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/pulsard
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
if ! cmp -s "$new_unit" "$UNIT_PATH"; then
  install -m 644 "$new_unit" "$UNIT_PATH"
  systemctl daemon-reload
  info "systemd unit written: ${UNIT_PATH}"
  restart_needed=1
fi
systemctl enable --quiet pulsard.service
if [ "$restart_needed" -eq 1 ] && systemctl is-active --quiet pulsard.service; then
  systemctl restart pulsard.service
  info "pulsard restarted"
else
  systemctl start pulsard.service
fi

# --- 6. Verification ------------------------------------------------------------
info "waiting for pulsard to start its modules"
ready=0
for _ in $(seq 1 60); do
  if pulsar status >"${TMP}/status" 2>/dev/null && grep -q 'rules-engine' "${TMP}/status"; then
    ready=1
    break
  fi
  sleep 1
done
[ "$ready" -eq 1 ] || { journalctl -u pulsard --no-pager -n 50 >&2; fail "pulsard was not ready within 60 s"; }

info "versions:"
pulsard --version
pulsar --version
info "binary digests (sha256):"
sha256sum "${BIN_DIR}/pulsard" "${BIN_DIR}/pulsar"
info "systemctl is-active pulsard: $(systemctl is-active pulsard.service)"
info "pulsar status:"
cat "${TMP}/status"
info "install complete"
