#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# One standalone source/mapping guest, no existing campaign change or real SMB.
set -eu
base=${1:?base artifacts required}
output=${2:?existing pinned output required}
source=${3:?repository required}
[ "$#" -eq 3 ] || exit 1
tmpdir=${TMPDIR:-/tmp}
case "$base:$output:$source:$tmpdir" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$base:$output:$source:$tmpdir" in /*:/*:/*:/*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || exit 1
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)
scratch=$(mktemp -d "$tmpdir/phantowd-handle-source.XXXXXX")
trap 'rm -f "$scratch/observer.o" "$scratch/observer.so" "$scratch/observer-test" "$scratch/observer-test.o" "$scratch/observer-test-reduced.o" "$scratch/observer.headers" "$scratch/observer.symbols" "$scratch/rootfs.ext2" "$scratch/guest.log" "$scratch/inserted.so" "$scratch/inserted-test"; rmdir "$scratch"' EXIT
bash "$source/support/tests/build-samba-pending-handle-observer.sh" "$output" "$source" "$scratch"
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
debugfs="$output/host/sbin/debugfs"
for pair in "$scratch/observer.so /usr/lib/phantowd-pending-handle-fixture.so" \
    "$scratch/observer-test /usr/sbin/phantowd-pending-handle-source-test" \
    "$source/support/tests/pending-handle-observer-init.sh /usr/sbin/phantowd-pending-handle-source-init"; do
    input=${pair%% *}
    name=${pair#* }
    "$debugfs" -w -R "write $input $name" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name mode 0100555" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
done
"$debugfs" -R "dump /usr/lib/phantowd-pending-handle-fixture.so $scratch/inserted.so" "$scratch/rootfs.ext2" >/dev/null 2>&1
"$debugfs" -R "dump /usr/sbin/phantowd-pending-handle-source-test $scratch/inserted-test" "$scratch/rootfs.ext2" >/dev/null 2>&1
cmp "$scratch/observer.so" "$scratch/inserted.so"
cmp "$scratch/observer-test" "$scratch/inserted-test"
status=0
timeout --signal=TERM --kill-after=2 30 qemu-system-arm -M versatilepb -m 256M \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 init=/usr/sbin/phantowd-pending-handle-source-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    -display none -serial stdio -monitor none -nic none -no-reboot >"$scratch/guest.log" 2>&1 || status=$?
cat "$scratch/guest.log"
[ "$status" -eq 0 ] || exit 1
awk -f "$source/support/tests/verify-pending-handle-observer-log.awk" "$scratch/guest.log"
[ "$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)" = "$base_hash" ]
printf '%s\n' 'PHANTOWD_PENDING_HANDLE_SOURCE_COMPLETE base_unchanged=true actual_smb=false authority=false full_image=false scope=qemu-only'
