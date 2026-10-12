#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Mock orchestration + actual ARM ELF; NOT guest/network/retained-worker proof.
set -eu
output=${1:?existing pinned output required}
source=${2:?repository required}
scratch=${3:?caller-owned tmpfs scratch with observer.so required}
withheld=false
if [ "$#" -eq 4 ] && [ "$4" = --withheld-read ]; then withheld=true
elif [ "$#" -ne 3 ]; then exit 1
fi
case "$output:$source:$scratch" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$output:$source:$scratch" in /*:/*:/*) ;; *) exit 1 ;; esac
[ -d "$scratch" ] && [ ! -L "$scratch" ] && [ -f "$scratch/observer.so" ] && [ ! -L "$scratch/observer.so" ] || exit 1
awk -v target="$scratch" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts
for name in capture-client-host-test capture-client-host.log capture-client capture-client.headers capture-client.symbols; do
    [ ! -e "$scratch/$name" ] && [ ! -L "$scratch/$name" ] || exit 1
done
header="$output/staging/usr/include/samba-4.0"
cc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie \
    -I"$header" -o "$scratch/capture-client-host-test" "$source/support/tests/samba-server-capture-client-host-test.c"
status=0
(ulimit -c 0; ulimit -f 128; ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
    timeout --signal=TERM --kill-after=1 5 "$scratch/capture-client-host-test") >"$scratch/capture-client-host.log" 2>&1 || status=$?
head -n 40 "$scratch/capture-client-host.log"
[ "$status" -eq 0 ] || exit 1
grep -Fx 'PHANTOWD_CAPTURE_CLIENT_HOST_DONE same_open=true reads=2 refusals=121 actual_smb=false scope=host-mock-only' "$scratch/capture-client-host.log"
flags=()
if "$withheld"; then
    flags=(-DPHANTOWD_CAPTURE_WITHHELD_READ_FIXTURE=1)
    cc -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie \
        -DPHANTOWD_CAPTURE_WITHHELD_READ_HOST_TEST=1 -I"$header" \
        -o "$scratch/withheld-host-test" "$source/support/tests/samba-server-capture-client-host-test.c"
    (ulimit -c 0; ulimit -f 128; ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
        timeout --signal=TERM --kill-after=1 5 "$scratch/withheld-host-test") >"$scratch/withheld-host.log" 2>&1
    cat "$scratch/withheld-host.log"
    grep -Fx 'PHANTOWD_CAPTURE_WITHHELD_HOST_DONE completed_mock_read=true read_ack=false close=false retries=false actual_smb=false scope=host-mock-only' "$scratch/withheld-host.log"
fi
timeout --signal=TERM --kill-after=1 30 "$output/host/bin/arm-buildroot-linux-gnueabi-gcc" \
    -DPHANTOWD_SAMBA_CAPTURE_CLIENT_FIXTURE=1 "${flags[@]}" -std=c11 -O2 -Wall -Wextra -Werror \
    -I"$header" -Wl,-z,defs,-z,relro,-z,now -Wl,-rpath-link,"$output/staging/usr/lib/samba" \
    -o "$scratch/capture-client" "$source/support/tests/samba-server-capture-client-qemu.c" -lsmbclient "$scratch/observer.so"
readelf="$output/host/bin/arm-buildroot-linux-gnueabi-readelf"
"$readelf" -h -A -d -l -W "$scratch/capture-client" >"$scratch/capture-client.headers"
grep -Eq 'Class:.*ELF32' "$scratch/capture-client.headers"
grep -Eq 'Type:.*DYN' "$scratch/capture-client.headers"
grep -Eq 'Machine:.*ARM' "$scratch/capture-client.headers"
grep -Eq 'Flags:.*Version5 EABI, soft-float ABI' "$scratch/capture-client.headers"
grep -F 'Tag_CPU_arch: v5TEJ' "$scratch/capture-client.headers"
grep -F 'Shared library: [libsmbclient.so.0]' "$scratch/capture-client.headers"
grep -F 'Shared library: [libphantowd-pending-handle-qemu.so]' "$scratch/capture-client.headers"
grep -F 'Requesting program interpreter: /lib/ld-linux.so.3' "$scratch/capture-client.headers"
grep -F 'GNU_RELRO' "$scratch/capture-client.headers"
grep -Eq '\(FLAGS(_1)?\).*NOW' "$scratch/capture-client.headers"
grep -Eq 'GNU_STACK.* RW ' "$scratch/capture-client.headers"
if grep -Eq '\((RPATH|RUNPATH)\)|GNU_STACK.* RWE' "$scratch/capture-client.headers" || grep -F "$scratch" "$scratch/capture-client.headers"; then exit 1; fi
"$readelf" --dyn-syms -W "$scratch/capture-client" >"$scratch/capture-client.symbols"
for name in Read Lseek; do
    grep -Eq "UND.*smbc_getFunction$name(@|$)" "$scratch/capture-client.symbols"
done
grep -Eq 'UND.*phantowd_qemu_observe_smb_handle_v1(@|$)' "$scratch/capture-client.symbols"
# No WRITE/open-create/delete/rename/mkdir accessors may enter this fixture.
if grep -Eq 'smbc_getFunction(Write|Creat|Unlink|Rename|Mkdir|Rmdir|Chmod|Utimes)' "$scratch/capture-client.symbols"; then exit 1; fi
sha256sum "$scratch/capture-client"
if "$withheld"; then
    printf 'PHANTOWD_CAPTURE_WITHHELD_BUILD_DONE max_reads=1 read_ack=false bytes=%s arm_executed=false actual_smb=false authority=false scope=compile-only\n' "$(stat -c %s "$scratch/capture-client")"
else
    printf 'PHANTOWD_CAPTURE_CLIENT_BUILD_DONE reads=2 bytes=%s arm_executed=false actual_smb=false authority=false scope=compile-only\n' "$(stat -c %s "$scratch/capture-client")"
fi
