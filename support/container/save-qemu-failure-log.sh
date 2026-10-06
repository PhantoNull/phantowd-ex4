#!/bin/sh
set -eu

# Inputs are fixed paths supplied by the build harness, not product/HTTP input.
# Only synthetic guest diagnostics belong here; never pass operator logs.
[ "$#" -eq 2 ] || { echo 'Expected destination and guest log paths' >&2; exit 2; }
destination=$1
source_log=$2
install -d -m 0755 "$(dirname "$destination")"
if [ -f "$source_log" ]; then
    install -m 0644 "$source_log" "$destination"
else
    printf '%s\n' "QEMU test did not create its log: $source_log" > "$destination"
fi
printf 'QEMU failure diagnostics (last 120 lines):\n' >&2
tail -n 120 "$destination" >&2
