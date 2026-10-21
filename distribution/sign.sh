#!/bin/sh
# Signs a version package (ADR-0008): produces SHA256SUMS and signs it with the key
# (SHA256SUMS.sig). The repo is private, so signing is keyed; keyless Sigstore is not used.
#
#
# Usage: sh sign.sh <version-dir> [--env-file <path>]
#
# The key and passphrase are read from KORU_SIGNING_KEY (the PEM as single-line base64; passphrase-encrypted PKCS#8) and
# KORU_SIGNING_KEY_PASSWORD environment variables; failing that, from ONLY those two lines of `.env`
# (via grep; other lines of the file are never read). `.env` must be 0600.
# The private key and passphrase are never written to any output, log or file: the passphrase reaches openssl
# through an environment variable, not the command line; the decoded key sits in a 0700 temp directory and is
# deleted when done. Command tracing is never enabled in this script (it would leak the key).
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
ROOT=${KORU_ROOT:-$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)}

usage() {
  printf 'Usage: sh sign.sh <version-dir> [--env-file <path>]\n' >&2
  exit 2
}

fail() {
  printf 'sign.sh: ERROR: %s\n' "$*" >&2
  exit 1
}

PACKAGE=""
ENV_FILE="$ROOT/.env"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --env-file) [ "$#" -ge 2 ] || usage; ENV_FILE=$2; shift 2 ;;
    -*) usage ;;
    *) [ -z "$PACKAGE" ] || usage; PACKAGE=$1; shift ;;
  esac
done
[ -n "$PACKAGE" ] || usage
if ! { [ -d "$PACKAGE" ] && [ ! -L "$PACKAGE" ]; }; then fail "version directory not found: $PACKAGE"; fi
command -v openssl >/dev/null 2>&1 || fail "openssl not found"
if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum < "$1" | cut -d' ' -f1; }
else
  sha256_of() { shasum -a 256 < "$1" | cut -d' ' -f1; }
fi

# Key and passphrase: environment variables first, else only two lines of .env.
KEY_B64=${KORU_SIGNING_KEY:-}
PASSPHRASE=${KORU_SIGNING_KEY_PASSWORD:-}
if [ -z "$KEY_B64" ] || [ -z "$PASSPHRASE" ]; then
  [ -f "$ENV_FILE" ] || fail "KORU_SIGNING_KEY and KORU_SIGNING_KEY_PASSWORD are not in the environment and no env file was found"
  if [ -L "$ENV_FILE" ]; then
    fail "the env file may not be a symlink"
  fi
  MODE_BITS=$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ENV_FILE")
  [ "$MODE_BITS" = "600" ] || fail "the env file must be 0600 (now: $MODE_BITS)"
  KEY_B64=$(grep -E '^KORU_SIGNING_KEY=' "$ENV_FILE" | head -n 1 | cut -d= -f2- || true)
  PASSPHRASE=$(grep -E '^KORU_SIGNING_KEY_PASSWORD=' "$ENV_FILE" | head -n 1 | cut -d= -f2- || true)
fi
[ -n "$KEY_B64" ] || fail "KORU_SIGNING_KEY is empty (no key generated)"
[ -n "$PASSPHRASE" ] || fail "KORU_SIGNING_KEY_PASSWORD is empty"

TEMP=$(mktemp -d) || fail "could not create a temp directory"
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
chmod 700 "$TEMP"
umask 077
printf '%s' "$KEY_B64" | openssl base64 -d -A > "$TEMP/key.pem" 2>/dev/null || fail "KORU_SIGNING_KEY could not be base64-decoded"
# The passphrase travels only in this environment variable (never on the command line).
KORU_SIGNING_PASSPHRASE=$PASSPHRASE
export KORU_SIGNING_PASSPHRASE
unset KEY_B64 PASSPHRASE KORU_SIGNING_KEY KORU_SIGNING_KEY_PASSWORD

if [ -n "$(find "$PACKAGE" -type l)" ]; then
  fail "the version directory contains a symlink"
fi
rm -f "$PACKAGE/SHA256SUMS" "$PACKAGE/SHA256SUMS.sig"
(cd "$PACKAGE" && find . -type f | sed 's|^\./||' | LC_ALL=C sort) > "$TEMP/files.txt"
[ -s "$TEMP/files.txt" ] || fail "the version directory is empty"
COUNT=0
: > "$TEMP/SHA256SUMS"
while IFS= read -r path_v; do
  case "$path_v" in
    *[!A-Za-z0-9._/-]*) fail "a file name may contain only A-Z a-z 0-9 . _ / -: $path_v" ;;
  esac
  printf '%s  %s\n' "$(sha256_of "$PACKAGE/$path_v")" "$path_v" >> "$TEMP/SHA256SUMS"
  COUNT=$((COUNT + 1))
done < "$TEMP/files.txt"

openssl dgst -sha256 -sign "$TEMP/key.pem" -passin env:KORU_SIGNING_PASSPHRASE -out "$TEMP/SHA256SUMS.sig" "$TEMP/SHA256SUMS" 2>/dev/null \
  || fail "signing failed (the key or passphrase may be invalid)"
# Verification: extract the public key and test the signature.
openssl pkey -in "$TEMP/key.pem" -passin env:KORU_SIGNING_PASSPHRASE -pubout -out "$TEMP/public.pem" 2>/dev/null \
  || fail "the public key could not be extracted"
OUTCOME=$(openssl dgst -sha256 -verify "$TEMP/public.pem" -signature "$TEMP/SHA256SUMS.sig" "$TEMP/SHA256SUMS" 2>&1) || fail "the produced signature could not be verified"
case "$OUTCOME" in *"Verified OK"*) ;; *) fail "the produced signature could not be verified" ;; esac
cp "$TEMP/SHA256SUMS" "$PACKAGE/SHA256SUMS"
cp "$TEMP/SHA256SUMS.sig" "$PACKAGE/SHA256SUMS.sig"
chmod 644 "$PACKAGE/SHA256SUMS" "$PACKAGE/SHA256SUMS.sig"
printf 'SHA256SUMS and SHA256SUMS.sig written (%s files); public key fingerprint: %s\n' "$COUNT" "$(sha256_of "$TEMP/public.pem")"
