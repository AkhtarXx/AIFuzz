#!/usr/bin/env bash
set -euo pipefail

SRC="${1:-/mnt/c/Users/hp/Desktop/AIFuzz}"
DST="${2:-$HOME/AIFuzz}"

if [ ! -f "${SRC}/tools/harness_check.py" ]; then
  echo "source does not look like the AIFuzz repo: ${SRC}" >&2
  exit 1
fi

mkdir -p "${DST}"
rm -rf "${DST}"
cp -r "${SRC}/." "${DST}/"
rm -rf "${DST}/artifacts"

echo "synced ${SRC} -> ${DST}"
