#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Actual snapshot-open regression; VM paused, no kernel or network activity.
set -eu
source_dir=${1:?source checkout required}
scratch=$(mktemp -d /tmp/phantowd-lio-temp-test.XXXXXX)
cleanup() {
    rm -f "$scratch/disk.raw" "$scratch/unset.log" "$scratch/set.log"
    rmdir "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
truncate -s 1M "$scratch/disk.raw"
status=0
env -u TMPDIR -u TMP -u TEMP timeout 1 qemu-system-arm -M versatilepb \
    -drive "file=$scratch/disk.raw,if=none,format=raw,snapshot=on" \
    -display none -serial none -monitor none -nic none -S \
    > "$scratch/unset.log" 2>&1 || status=$?
[ "$status" -eq 1 ]
grep -F "Could not open temporary file '/var/tmp/" "$scratch/unset.log" >/dev/null
grep -F 'Read-only file system' "$scratch/unset.log" >/dev/null
status=0
TMPDIR="$scratch" timeout 1 qemu-system-arm -M versatilepb \
    -drive "file=$scratch/disk.raw,if=none,format=raw,snapshot=on" \
    -display none -serial none -monitor none -nic none -S \
    > "$scratch/set.log" 2>&1 || status=$?
# Timeout means the real paused VM survived snapshot creation, not a guest pass.
[ "$status" -eq 124 ]
if grep -F 'Could not open temporary file' "$scratch/set.log" >/dev/null; then exit 1; fi
# Keep the actual fixture call site coupled to that verified environment.
awk '$0 == "export TMPDIR=\"$temporary\"" { owned = 1 }
     /^qemu-system-arm / { if (!owned) exit 1; call = 1 }
     END { if (!call || !owned) exit 1 }' "$source_dir/support/qemu-lio-fixture.sh"
echo 'PHANTOWD_LIO_SNAPSHOT_TEMP_READY unset_refused=true owned_tmpfs=true scope=paused-snapshot-open-only'
