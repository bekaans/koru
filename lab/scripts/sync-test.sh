#!/usr/bin/env bash
# A local test for lab/sync-filter.txt (KT-38). Needs no VM; runs on the Mac:
#   bash lab/scripts/sync-test.sh
#
# Builds a fake repo tree in a temp directory (files containing only "FAKE" as an
# imitation of secret data), copies it to another temp directory with the SAME rsync
# options and the same filter as `lab/lab.sh sync`, then checks:
# - that every path that must be excluded is ABSENT at the target,
# - that every path that must be copied is PRESENT at the target,
# - that excluded paths pre-existing at the target are deleted (--delete-excluded),
# - that a file modified at the target with its size and time preserved returns to
#   its state at the source (-c).
# The temp directories are deleted in all cases.
#
# Note: the rsync options must be kept identical to copy_repo() in lab/lab.sh.
# KORU_SYNC_FILTER gives another filter file (to show the test going red,
# e.g. an empty file).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
FILTER="${KORU_SYNC_FILTER:-${SCRIPT_DIR}/../sync-filter.txt}"
[ -f "$FILTER" ] || { printf 'ERROR: filter file missing: %s\n' "$FILTER" >&2; exit 2; }
command -v rsync >/dev/null 2>&1 || { printf 'ERROR: rsync not found\n' >&2; exit 2; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/koru-sync-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
SOURCE="${TMP}/source"
TARGET="${TMP}/target"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf 'PASS  %s\n' "$*"; }
failcase() { FAILED=$((FAILED + 1)); printf 'FAIL  %s\n' "$*"; }

mkfile() { # <path> [content]
  mkdir -p "$(dirname "${SOURCE}/$1")"
  printf '%s\n' "${2:-FAKE}" >"${SOURCE}/$1"
}

# Paths that must be excluded (at every level).
EXCLUDED="
.env
.env.local
.env.production
alt/.env
alt/.env.test
.git/config
alt/module/.git
target/debug/koru
crates/koru-event/target/debug/x
node_modules/package/index.js
docs/site/node_modules/package/index.js
docs/site/.wrangler/state/v3/d1/x.sqlite
docs/site/.dev.vars
docs/site/.dev.vars.example
data/real/events.jsonl
.DS_Store
docs/.DS_Store
"
# Paths that must be copied.
INCLUDED="
.env.example
alt/.env.example
README.md
lab/lab.sh
src/target.rs
docs/target
data/golden/synthetic/events.jsonl
data/real.md
docs/site/public/index.html
"

for y in $EXCLUDED $INCLUDED; do mkfile "$y"; done

# Excluded paths pre-existing at the target (e.g. created later in the VM).
mkdir -p "${TARGET}/target" "${TARGET}/alt"
printf 'OLD\n' >"${TARGET}/.env"
printf 'OLD\n' >"${TARGET}/target/old"
printf 'OLD\n' >"${TARGET}/alt/.env.local"

# A file modified at the target with size and time preserved: different content, same size and mtime.
printf 'ORIGINAL\n' >"${SOURCE}/README.md"
printf 'CORRUPT\n' >"${TARGET}/README.md"
touch -r "${SOURCE}/README.md" "${TARGET}/README.md"

rsync -rlptc --delete --delete-excluded --chmod=go-w \
  --exclude-from="$FILTER" \
  "${SOURCE}/" "${TARGET}/"

for y in $EXCLUDED; do
  if [ -e "${TARGET}/${y}" ]; then failcase "not excluded: ${y}"; else pass "excluded: ${y}"; fi
done
for y in $INCLUDED; do
  if [ -f "${TARGET}/${y}" ]; then pass "copied: ${y}"; else failcase "not copied: ${y}"; fi
done
for y in .env target/old target alt/.env.local; do
  if [ -e "${TARGET}/${y}" ]; then failcase "stale path at the target was not deleted: ${y}"; else pass "stale path at the target was deleted: ${y}"; fi
done
if [ "$(cat "${TARGET}/README.md")" = "ORIGINAL" ]; then
  pass "the file with the same size and time but different content returned to its source state (-c)"
else
  failcase "the file with the same size and time but different content was not fixed"
fi
# The target must carry no group/other write permission (--chmod=go-w).
writable=$(find "$TARGET" -perm -g+w -o -perm -o+w | sed "s|^${TARGET}|.|" || true)
if [ -z "$writable" ]; then pass "no group/other write permission at the target"; else failcase "writable: ${writable}"; fi

printf 'RESULT: %d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
