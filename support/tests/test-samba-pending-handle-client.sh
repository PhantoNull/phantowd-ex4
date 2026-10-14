#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Mock orchestration plus target compilation; never real SMB/transport proof.
set -eu
output=${1:?existing pinned output required}
source=${2:?repository required}
scratch=${3:?caller-owned tmpfs directory with observer.so required}
[ "$#" -eq 3 ] || exit 1
case "$output:$source:$scratch" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$output:$source:$scratch" in /*:/*:/*) ;; *) exit 1 ;; esac
[ -d "$scratch" ] && [ ! -L "$scratch" ] && [ -f "$scratch/observer.so" ] && [ ! -L "$scratch/observer.so" ] || exit 1
awk -v target="$scratch" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || exit 1
for name in handle-host-test handle-host.log handle-client handle-client.headers handle-client.symbols; do
    [ ! -e "$scratch/$name" ] && [ ! -L "$scratch/$name" ] || exit 1
done
header="$output/staging/usr/include/samba-4.0"
cc -DPHANTOWD_PENDING_HANDLE_OBSERVER_QEMU=1 -std=c11 -O1 -g -Wall -Wextra -Werror \
    -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie \
    -I"$header" -o "$scratch/handle-host-test" "$source/support/tests/samba-pending-write-host-test.c"
status=0
(ulimit -c 0; ulimit -f 128; ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
    timeout --signal=TERM --kill-after=1 5 "$scratch/handle-host-test") >"$scratch/handle-host.log" 2>&1 || status=$?
head -n 40 "$scratch/handle-host.log"
[ "$status" -eq 0 ] || exit 1
grep -Fx 'PHANTOWD_SMB_HANDLE_CLIENT_HOST_MOCK_DONE handle_refusals=16 close_only=true actual_smb=false guest=false transport=false scope=host-mock-only' "$scratch/handle-host.log"
"$output/host/bin/arm-buildroot-linux-gnueabi-gcc" \
    -DPHANTOWD_PENDING_HANDLE_OBSERVER_QEMU=1 -std=c11 -O2 -Wall -Wextra -Werror \
    -I"$header" -Wl,-z,defs -Wl,-rpath-link,"$output/staging/usr/lib/samba" \
    -o "$scratch/handle-client" "$source/support/tests/samba-pending-write-fixture.c" \
    -lsmbclient "$scratch/observer.so"
readelf="$output/host/bin/arm-buildroot-linux-gnueabi-readelf"
"$readelf" -h -A -d "$scratch/handle-client" >"$scratch/handle-client.headers"
grep -Eq 'Class:.*ELF32' "$scratch/handle-client.headers"
grep -Eq 'Machine:.*ARM' "$scratch/handle-client.headers"
grep -Eq 'Flags:.*Version5 EABI, soft-float ABI' "$scratch/handle-client.headers"
grep -F 'Tag_CPU_arch: v5TEJ' "$scratch/handle-client.headers"
grep -F 'Shared library: [libsmbclient.so.0]' "$scratch/handle-client.headers"
grep -F 'Shared library: [libphantowd-pending-handle-qemu.so]' "$scratch/handle-client.headers"
# No build-scratch DT_NEEDED/RPATH or source reader masquerading as WRITE.
if grep -F "$scratch" "$scratch/handle-client.headers"; then exit 1; fi
"$readelf" --dyn-syms -W "$scratch/handle-client" >"$scratch/handle-client.symbols"
grep -Eq 'UND.*phantowd_qemu_observe_smb_handle_v1' "$scratch/handle-client.symbols"
if grep -Eq 'smbc_getFunction(Write|Lseek)' "$scratch/handle-client.symbols"; then exit 1; fi
sha256sum "$scratch/handle-client"
printf '%s\n' 'PHANTOWD_SMB_HANDLE_CLIENT_COMPILE_DONE close_only=true arm_executed=false actual_smb=false authority=false scope=compile-only'
