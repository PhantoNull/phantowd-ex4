#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Existing image, disposable snapshot and CPU/RAM-only operations.
set -eu
base=${1:?BASE CC DEBUGFS TARGET SOURCE required}
cc=${2:?cross compiler required}
debugfs=${3:?debugfs required}
target=${4:?target tree required}
source_dir=${5:?source required}
failure_log=${6:-}
tmpdir=${TMPDIR:-/tmp}
# Resolve traversal/symlinks before testing that scratch actually lives in tmpfs.
case "$tmpdir" in /*) ;; *) exit 1 ;; esac
tmpdir=$(realpath -e "$tmpdir")
case "$base:$cc:$debugfs:$target:$source_dir:$failure_log:$tmpdir" in
    *[!a-zA-Z0-9_./:+-]*) exit 1 ;;
esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')
scratch=$(mktemp -d "$tmpdir/phantowd-atomic-dispatch.XXXXXX")
export TMPDIR="$scratch"
child_pid=
cleanup() {
    if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    rm -rf "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
library="$target/lib/libatomic.so.1.2.0"
[ -f "$library" ] && [ ! -L "$library" ]
# Prove the runtime image has exactly the library observed in the target tree.
"$debugfs" -R "dump /lib/libatomic.so.1.2.0 $scratch/libatomic.so" "$base/rootfs.ext2" >/dev/null 2>&1
[ -f "$scratch/libatomic.so" ]
[ "$(sha256sum "$library" | awk '{print $1}')" = "$(sha256sum "$scratch/libatomic.so" | awk '{print $1}')" ]
readelf="$(dirname "$cc")/arm-buildroot-linux-gnueabi-readelf"
"$readelf" --dyn-syms --wide "$library" >"$scratch/symbols"
timeout --signal=TERM --kill-after=5 30 "$cc" -std=c11 -Os -Wall -Wextra -Werror \
    -march=armv5te -mfloat-abi=soft -fno-builtin -pthread \
    "$source_dir/support/tests/atomic-dispatch-fixture.c" -ldl -o "$scratch/probe"
"$readelf" -A "$scratch/probe" >"$scratch/attributes"
grep -E 'Tag_CPU_arch: v5TE(J)?$' "$scratch/attributes" >/dev/null
"$readelf" -h "$scratch/probe" >"$scratch/header"
grep -E 'Class: *ELF32' "$scratch/header" >/dev/null
grep -E 'Machine: *ARM' "$scratch/header" >/dev/null
grep -E 'Flags:.*Version5 EABI, soft-float ABI' "$scratch/header" >/dev/null
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
for pair in "$scratch/probe phantowd-atomic-dispatch" \
    "$source_dir/support/tests/atomic-dispatch-init.sh phantowd-atomic-dispatch-init"; do
    input=${pair%% *}
    output=${pair#* }
    "$debugfs" -w -R "write $input /usr/sbin/$output" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output mode 0100755" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
done
timeout --signal=TERM --kill-after=5 90 qemu-system-arm \
    -M versatilepb -cpu arm926 -m 256M -nographic -no-reboot -nic none \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 init=/usr/sbin/phantowd-atomic-dispatch-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    >"$scratch/guest.log" 2>&1 &
child_pid=$!
status=0
wait "$child_pid" || status=$?
child_pid=
if [ "$status" -ne 0 ] || ! python3 -B "$source_dir/support/tests/atomic_dispatch_fixture.py" \
    "$scratch/symbols" "$scratch/guest.log" "$(stat -c %s "$library")"; then
    if [ -n "$failure_log" ]; then
        mkdir -p "$(dirname "$failure_log")"
        cp "$scratch/guest.log" "$failure_log"
    fi
    tail -n 100 "$scratch/guest.log" >&2
    exit 1
fi
grep '^PHANTOWD_ATOMIC_' "$scratch/guest.log"
printf 'PHANTOWD_ATOMIC_LIBRARY sha256=%s\n' "$(sha256sum "$library" | awk '{print $1}')"
[ "$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')" = "$base_hash" ]
echo 'PHANTOWD_ATOMIC_BASE_UNCHANGED'
