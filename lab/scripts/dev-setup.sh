#!/usr/bin/env bash
# Sets up the Rust dev environment in the Koru lab VM. Runs as root inside the VM:
#   limactl shell koru-lab sudo bash /koru/lab/scripts/dev-setup.sh
# Usually invoked not directly but via `lab/lab.sh test` and `lab/lab.sh live-pulsar`.
#
# What is installed:
# - build-essential, clang, llvm, libsqlite3-dev, pkg-config: building Pulsar's eBPF probes and
#   userspace crates (ADR-0001 conclusion 3; clang 18 and llvm-strip).
# - rustup (the Ubuntu package): the toolchain version is read from rust-toolchain.toml at the repo
#   root and installed for the guest user (koru). rustup verifies the toolchain files against the
#   SHA-256 digests in the official distribution manifest.
# - podman: in-container access in the live Pulsar test (lab/scripts/live-pulsar-test.sh).
# - jq: checking live-test output.
#
# The script is idempotent.
set -euo pipefail

USER_NAME="koru"
REPO="/koru"

info() { printf '[dev-setup] %s\n' "$*"; }
fail() { printf '[dev-setup] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must be run as root"
[ -f "${REPO}/rust-toolchain.toml" ] || fail "${REPO}/rust-toolchain.toml missing; first: lab/lab.sh sync"
id "$USER_NAME" >/dev/null 2>&1 || fail "guest user missing: ${USER_NAME}"

export DEBIAN_FRONTEND=noninteractive
packages="build-essential clang llvm libsqlite3-dev pkg-config rustup podman jq"
missing=""
for p in $packages; do
  if ! dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed"; then
    missing="$missing $p"
  fi
done
if [ -n "$missing" ]; then
  info "installing packages:${missing}"
  apt-get update -q
  # shellcheck disable=SC2086
  apt-get install -y -q --no-install-recommends $missing
else
  info "packages already installed: ${packages}"
fi

# rust-toolchain.toml: the version is read from the channel = "X.Y.Z" line and its format is validated.
channel=$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([0-9]+\.[0-9]+\.[0-9]+)"[[:space:]]*$/\1/p' \
  "${REPO}/rust-toolchain.toml")
[ -n "$channel" ] || fail "no channel in X.Y.Z format found in rust-toolchain.toml"
info "toolchain: ${channel} (rust-toolchain.toml)"
sudo -u "$USER_NAME" -H rustup toolchain install "$channel" --profile minimal -c clippy -c rustfmt
sudo -u "$USER_NAME" -H rustup run "$channel" rustc --version
sudo -u "$USER_NAME" -H rustup run "$channel" cargo --version
clang --version | head -1
llvm-strip --version | head -2 | tail -1
podman --version
info "setup complete"
