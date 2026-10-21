#!/bin/sh
# The Koru install script (ADR-0008): it does NOT install without verifying the signature
# and the SHA-256 digests.
#
# Usage:
#   sh install.sh [--verify-only] <version-dir> [-- koru install arguments]
#   sh install.sh --public-key <pem> --fingerprint <sha256> [--verify-only] <version-dir> [-- ...]
#
# Version directory: koru, koru-agent, packages/, thresholds.toml, VERSION, SHA256SUMS, SHA256SUMS.sig.
# The script copies the version directory into a private (0700) temp directory; the signature, the listed
# files and the SHA-256 digests are verified in that COPY; then `koru install` runs from the copy (no file
# can change between verification and use). The trusted public key is bound to a fingerprint pinned in
# this script: if the public key file's SHA-256 digest differs from EMBEDDED_FINGERPRINT the script
# stops. --public-key/--fingerprint exist only for forks and tests and are given together.
#
# Exit codes: 0 success, 1 verification/install error, 2 usage error. `koru install`'s exit code is
# passed through unchanged.
set -eu

EMBEDDED_FINGERPRINT="8b4a52e0aa4582b7268a291107ca67719b3c9097fef19feafe5e14fa82b75060"

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)

usage() {
  printf 'Usage: sh install.sh [--verify-only] [--public-key <pem> --fingerprint <sha256>] <version-dir> [-- koru install arguments]\n' >&2
  exit 2
}

fail() {
  printf 'install.sh: ERROR: %s\n' "$*" >&2
  exit 1
}

VERIFY_ONLY=0
PUBLIC_KEY=""
FINGERPRINT=""
VERSION_DIR=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --verify-only) VERIFY_ONLY=1; shift ;;
    --public-key) [ "$#" -ge 2 ] || usage; PUBLIC_KEY=$2; shift 2 ;;
    --fingerprint) [ "$#" -ge 2 ] || usage; FINGERPRINT=$2; shift 2 ;;
    --) shift; break ;;
    -*) usage ;;
    *)
      [ -z "$VERSION_DIR" ] || usage
      VERSION_DIR=$1
      shift
      ;;
  esac
done
[ -n "$VERSION_DIR" ] || usage
if [ -n "$PUBLIC_KEY" ] || [ -n "$FINGERPRINT" ]; then
  if ! { [ -n "$PUBLIC_KEY" ] && [ -n "$FINGERPRINT" ]; }; then usage; fi
else
  PUBLIC_KEY="$SCRIPT_DIR/signing-public-key.pem"
  FINGERPRINT=$EMBEDDED_FINGERPRINT
fi

command -v openssl >/dev/null 2>&1 || fail "openssl not found (needed for signature verification)"
if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum < "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 < "$1" | cut -d' ' -f1; }
else
  fail "neither sha256sum nor shasum found"
fi

# 1) The trusted public key: the file's SHA-256 digest must equal the pinned fingerprint.
[ -f "$PUBLIC_KEY" ] || fail "no public key file: $PUBLIC_KEY"
[ "$(sha256_of "$PUBLIC_KEY")" = "$FINGERPRINT" ] || fail "the public key fingerprint does not match; the pinned key has changed"

# 2) The version directory: may not be a symlink; copied into a private temp directory.
if ! { [ -d "$VERSION_DIR" ] && [ ! -L "$VERSION_DIR" ]; }; then fail "version directory not found or is a symlink: $VERSION_DIR"; fi
TEMP=$(mktemp -d) || fail "could not create a temp directory"
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
chmod 700 "$TEMP"
COPY="$TEMP/package"
cp -R "$VERSION_DIR" "$COPY" || fail "the version directory could not be copied"
# The key is also kept as the verified copy (koru install gets the same file).
cp "$PUBLIC_KEY" "$TEMP/public-key.pem"
[ "$(sha256_of "$TEMP/public-key.pem")" = "$FINGERPRINT" ] || fail "the public key fingerprint does not match"

if [ -n "$(find "$COPY" -type l)" ]; then
  fail "the version package contains a symlink"
fi
if [ -n "$(find "$COPY" ! -type f ! -type d)" ]; then
  fail "the version package contains a special file"
fi

# 3) Signature: SHA256SUMS must verify with the public key ("Verified OK").
[ -f "$COPY/SHA256SUMS" ] || fail "SHA256SUMS is missing"
[ -f "$COPY/SHA256SUMS.sig" ] || fail "no signature file (SHA256SUMS.sig)"
if ! VERDICT=$(openssl dgst -sha256 -verify "$TEMP/public-key.pem" -signature "$COPY/SHA256SUMS.sig" "$COPY/SHA256SUMS" 2>&1); then
  fail "the signature could not be verified (SHA256SUMS.sig does not match the public key)"
fi
case "$VERDICT" in
  *"Verified OK"*) printf '%s\n' "Verified OK" ;;
  *) fail "the signature could not be verified" ;;
esac

# 4) The digest list: format, file set and SHA-256. The list and the directory must match one to one.
LIST="$TEMP/list.txt"
: > "$LIST"
while IFS= read -r line_v || [ -n "$line_v" ]; do
  digest_v=${line_v%%  *}
  path_v=${line_v#*  }
  case "$digest_v" in *[!0-9a-f]*) fail "invalid SHA256SUMS digest: $line_v" ;; esac
  [ "${#digest_v}" -eq 64 ] || fail "invalid SHA256SUMS digest: $line_v"
  if ! { [ "$path_v" != "$line_v" ] && [ -n "$path_v" ]; }; then fail "invalid SHA256SUMS line: $line_v"; fi
  case "$path_v" in
    /* | *..* | */ | *//*) fail "invalid SHA256SUMS path: $path_v" ;;
  esac
  printf '%s\n' "$path_v" >> "$LIST"
done < "$COPY/SHA256SUMS"
LC_ALL=C sort "$LIST" > "$TEMP/list-sorted.txt"
(cd "$COPY" && find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.sig | sed 's|^\./||' | LC_ALL=C sort) > "$TEMP/present.txt"
EXTRA=$(LC_ALL=C comm -13 "$TEMP/list-sorted.txt" "$TEMP/present.txt" | head -1)
[ -z "$EXTRA" ] || fail "the package holds a file not in the list: $EXTRA"
MISSING=$(LC_ALL=C comm -23 "$TEMP/list-sorted.txt" "$TEMP/present.txt" | head -1)
[ -z "$MISSING" ] || fail "a listed file is missing from the package: $MISSING"
while IFS= read -r line_v || [ -n "$line_v" ]; do
  digest_v=${line_v%%  *}
  path_v=${line_v#*  }
  [ "$(sha256_of "$COPY/$path_v")" = "$digest_v" ] || fail "SHA-256 digest mismatch: $path_v"
done < "$COPY/SHA256SUMS"
printf '%s\n' "SHA-256 digests verified"

if [ "$VERIFY_ONLY" -eq 1 ]; then
  exit 0
fi

# 5) Install from the verified copy.
[ -x "$COPY/koru" ] || fail "no executable koru in the version package"
CODE=0
if [ "$PUBLIC_KEY" = "$SCRIPT_DIR/signing-public-key.pem" ]; then
  "$COPY/koru" install --version-dir "$COPY" "$@" || CODE=$?
else
  "$COPY/koru" install --version-dir "$COPY" --public-key "$TEMP/public-key.pem" "$@" || CODE=$?
fi
exit "$CODE"
