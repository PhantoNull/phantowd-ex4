#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Descriptor host tests and ARM compile, never a privileged host/QEMU launch.
set -eu
output=${1:?existing pinned Buildroot output required}
source=${2:?repository source required}
[ "$#" -eq 2 ] || exit 1
tmpdir=${TMPDIR:-/tmp}
case "$output:$source:$tmpdir" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$output:$source:$tmpdir" in /*:/*:/*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || exit 1
scratch=$(mktemp -d "$tmpdir/phantowd-pending-launcher.XXXXXX")
trap 'rm -f "$scratch/host-test" "$scratch/host.log" "$scratch/arm-launcher" "$scratch/arm-headers"; rmdir "$scratch"' EXIT
cc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie \
    -o "$scratch/host-test" "$source/support/tests/samba-pending-write-launcher-host-test.c"
status=0
(ulimit -c 0; ulimit -f 128; ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
    timeout --signal=TERM --kill-after=1 5 "$scratch/host-test") >"$scratch/host.log" 2>&1 || status=$?
head -n 40 "$scratch/host.log"
[ "$status" -eq 0 ] || { printf 'Launcher host tests failed status=%s\n' "$status" >&2; exit 1; }
"$output/host/bin/arm-buildroot-linux-gnueabi-gcc" -std=c11 -O2 -static -Wall -Wextra -Werror \
    -o "$scratch/arm-launcher" "$source/support/tests/samba-pending-write-launcher-fixture.c"
"$output/host/bin/arm-buildroot-linux-gnueabi-readelf" -h -A -l -d "$scratch/arm-launcher" >"$scratch/arm-headers"
grep -Eq 'Class:.*ELF32' "$scratch/arm-headers"
grep -Eq 'Machine:.*ARM' "$scratch/arm-headers"
grep -Eq 'Flags:.*Version5 EABI, soft-float ABI' "$scratch/arm-headers"
grep -F 'Tag_CPU_arch: v5TEJ' "$scratch/arm-headers"
if grep -Eq 'INTERP|NEEDED' "$scratch/arm-headers"; then exit 1; fi
sha256sum "$scratch/arm-launcher"
printf 'PHANTOWD_SMB_WRITE_LAUNCHER_ELF_BYTES=%s\n' "$(stat -c %s "$scratch/arm-launcher")"
printf '%s\n' 'PHANTOWD_SMB_WRITE_LAUNCHER_COMPILE_DONE arm_executed=false guest=false product_installed=false scope=compile-only'
