#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# No guest boot, real SMB, server, network or installed product helper.
set -eu
output=${1:?existing pinned Buildroot output required}
source=${2:?repository source required}
[ "$#" -eq 2 ] || exit 1
tmpdir=${TMPDIR:-/tmp}
case "$output:$source:$tmpdir" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$output:$source:$tmpdir" in /*:/*:/*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || exit 1
scratch=$(mktemp -d "$tmpdir/phantowd-pending-client.XXXXXX")
trap 'rm -f "$scratch/host-test" "$scratch/host.log" "$scratch/arm-client" "$scratch/arm-headers"; rmdir "$scratch"' EXIT
header="$output/staging/usr/include/samba-4.0"
# Host mock only: fixed non-PIE executable; ARM client remains PIE. ASan PIE
# startup failed even for a puts-only control, but later PIE controls passed.
# This choice is not a demonstrated fix for that intermittent environment fault.
cc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie \
    -I"$header" -o "$scratch/host-test" "$source/support/tests/samba-pending-write-host-test.c"
status=0
(ulimit -c 0; ulimit -f 128; ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
    timeout --signal=TERM --kill-after=1 5 "$scratch/host-test") >"$scratch/host.log" 2>&1 || status=$?
head -n 40 "$scratch/host.log"
[ "$status" -eq 0 ] || { printf 'Host mock failed status=%s\n' "$status" >&2; exit 1; }
"$output/host/bin/arm-buildroot-linux-gnueabi-gcc" -std=c11 -O2 -Wall -Wextra -Werror \
    -I"$header" -Wl,-rpath-link,"$output/staging/usr/lib/samba" \
    -o "$scratch/arm-client" "$source/support/tests/samba-pending-write-fixture.c" -lsmbclient
"$output/host/bin/arm-buildroot-linux-gnueabi-readelf" -h -A -d "$scratch/arm-client" >"$scratch/arm-headers"
grep -Eq 'Class:.*ELF32' "$scratch/arm-headers"
grep -Eq 'Machine:.*ARM' "$scratch/arm-headers"
grep -Eq 'Flags:.*Version5 EABI, soft-float ABI' "$scratch/arm-headers"
grep -F 'Tag_CPU_arch: v5TEJ' "$scratch/arm-headers"
grep -F 'Shared library: [libsmbclient.so.0]' "$scratch/arm-headers"
sha256sum "$scratch/arm-client"
printf 'PHANTOWD_SMB_WRITE_CLIENT_ELF_BYTES=%s\n' "$(stat -c %s "$scratch/arm-client")"
printf '%s\n' 'PHANTOWD_SMB_WRITE_CLIENT_COMPILE_DONE arm_executed=false guest=false network=false product_installed=false scope=compile-only'
