#!/bin/sh
# Mechanical VM launcher for the source-CI lane. Dumb by design:
# it only materializes the qcow2 overlay for the prepared base image and then exec's the
# exact validated argv from <run>/launch/argv.args. All decisions were made in Python.
set -eu
[ "$#" -eq 1 ] || { echo "usage: ci_start.sh <run-dir>" >&2; exit 64; }
dir="$1"
base=$(sed -n '1p' "$dir/launch/overlay.txt")
overlay=$(sed -n '2p' "$dir/launch/overlay.txt")
[ -f "$base" ] || { echo "missing base image: $base" >&2; exit 65; }
[ -f "$overlay" ] || qemu-img create -f qcow2 -b "$base" -F raw "$overlay"
relay_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
git -C "$relay_root" rev-parse HEAD > "$dir/relay-head.txt"
date -u +%Y-%m-%dT%H:%M:%SZ > "$dir/started-at.txt"
set --
while IFS= read -r line; do
  set -- "$@" "$line"
done < "$dir/launch/argv.args"
exec "$@"
