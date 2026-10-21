#!/usr/bin/env bash
# Digest of a target tree (the digest before planting and after removal
# must be identical).
#
# Usage: lab/scripts/file-digest.sh <root-dir>
#
# One line per entry (tab-separated), ordered by relative path:
#   path  type  mode  uid:gid  size  content-SHA-256  mtime (seconds.nanoseconds)
# - Regular files get size and content digest; directories get "-" for both (ext4 directories do
#   not shrink when entries are deleted; directory size is allocation size, not content).
# - Symlinks are not followed; the target is printed instead of a digest, mtime is "-".
# - The root directory itself is the "." line; directory mtimes enter the digest too.
# - Only the root's filesystem (-xdev).
#
# Runs in the lab VM (Ubuntu 24.04; GNU findutils and coreutils). Another user's home directory
# needs root (sudo). It changes no file; it only reads.
set -euo pipefail
export LC_ALL=C

if [ $# -ne 1 ]; then
  printf 'Usage: %s <root-dir>\n' "$0" >&2
  exit 2
fi
root=$1
if [ ! -d "$root" ] || [ -L "$root" ]; then
  printf 'not a directory or a symlink: %s\n' "$root" >&2
  exit 2
fi
if ! stat --version 2>/dev/null | grep -q 'GNU coreutils'; then
  printf 'GNU coreutils required (lab VM)\n' >&2
  exit 2
fi

cd -- "$root"
find . -xdev -print0 | sort -z | while IFS= read -r -d '' path; do
  type=$(stat -c '%F' -- "$path")
  mode=$(stat -c '%a' -- "$path")
  owner=$(stat -c '%u:%g' -- "$path")
  mtime=$(stat -c '%.9Y' -- "$path")
  case "$type" in
    "regular file" | "regular empty file")
      size=$(stat -c '%s' -- "$path")
      digest=$(sha256sum -- "$path" | cut -d' ' -f1)
      ;;
    "symbolic link")
      size=-
      digest="-> $(readlink -- "$path")"
      mtime=-
      ;;
    *)
      size=-
      digest=-
      ;;
  esac
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$path" "$type" "$mode" "$owner" "$size" "$digest" "$mtime"
done
