#!/bin/sh
# Assembles and signs a version package (ADR-0008).
#
# Usage:
#   sh prepare-release.sh <output-dir> --version X.Y.Z --binary-dir <dir> \
#       [--sbom-file <file>] [--env-file <path>]
#
# <binary-dir> holds the `koru` and `koru-agent` binaries (cargo build --release). The output
# directory must be new: koru, koru-agent, packages/{rules,agents,decoys}, thresholds.toml, VERSION,
# an optional sbom.cdx.json, SHA256SUMS, SHA256SUMS.sig. Signing is done by sign.sh.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
ROOT=${KORU_ROOT:-$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)}

usage() {
  printf 'Usage: sh prepare-release.sh <output-dir> --version X.Y.Z --binary-dir <dir> [--sbom-file <file>] [--env-file <path>]\n' >&2
  exit 2
}

fail() {
  printf 'prepare-release.sh: ERROR: %s\n' "$*" >&2
  exit 1
}

OUT_DIR=""
VERSION_STR=""
BIN_DIR=""
SBOM=""
ENV_ARG=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) [ "$#" -ge 2 ] || usage; VERSION_STR=$2; shift 2 ;;
    --binary-dir) [ "$#" -ge 2 ] || usage; BIN_DIR=$2; shift 2 ;;
    --sbom-file) [ "$#" -ge 2 ] || usage; SBOM=$2; shift 2 ;;
    --env-file) [ "$#" -ge 2 ] || usage; ENV_ARG=$2; shift 2 ;;
    -*) usage ;;
    *) [ -z "$OUT_DIR" ] || usage; OUT_DIR=$1; shift ;;
  esac
done
if [ -z "$OUT_DIR" ] || [ -z "$VERSION_STR" ] || [ -z "$BIN_DIR" ]; then usage; fi

printf '%s\n' "$VERSION_STR" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || fail "invalid version (must be X.Y.Z): $VERSION_STR"
[ -d "$BIN_DIR" ] || fail "binary directory not found: $BIN_DIR"
for name_v in koru koru-agent; do
  if ! { [ -f "$BIN_DIR/$name_v" ] && [ -x "$BIN_DIR/$name_v" ]; }; then fail "no executable $name_v binary: $BIN_DIR/$name_v"; fi
done
for d in rules agents decoys; do
  [ -d "$ROOT/packages/$d" ] || fail "no data package: $ROOT/packages/$d"
done
[ -f "$ROOT/thresholds.toml" ] || fail "thresholds.toml is missing"
if [ -n "$SBOM" ]; then
  [ -f "$SBOM" ] || fail "no SBOM file: $SBOM"
fi
[ ! -e "$OUT_DIR" ] || fail "the output directory already exists: $OUT_DIR"

mkdir -p "$OUT_DIR/packages"
cp "$BIN_DIR/koru" "$BIN_DIR/koru-agent" "$OUT_DIR/"
chmod 755 "$OUT_DIR/koru" "$OUT_DIR/koru-agent"
for d in rules agents decoys; do
  cp -R "$ROOT/packages/$d" "$OUT_DIR/packages/$d"
done
cp "$ROOT/thresholds.toml" "$OUT_DIR/thresholds.toml"
printf '%s\n' "$VERSION_STR" > "$OUT_DIR/VERSION"
if [ -n "$SBOM" ]; then
  cp "$SBOM" "$OUT_DIR/sbom.cdx.json"
fi
find "$OUT_DIR" -type d -exec chmod 755 {} +
find "$OUT_DIR" -type f ! -name koru ! -name koru-agent -exec chmod 644 {} +

if [ -n "$ENV_ARG" ]; then
  sh "$SCRIPT_DIR/sign.sh" "$OUT_DIR" --env-file "$ENV_ARG"
else
  sh "$SCRIPT_DIR/sign.sh" "$OUT_DIR"
fi
printf 'Version package ready: %s (version %s)\n' "$OUT_DIR" "$VERSION_STR"
