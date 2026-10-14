#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
base=${1:?base artifacts required}
output=${2:?existing output required}
source=${3:?repository required}
[ "$#" -eq 3 ] || exit 1
tmpdir=${TMPDIR:-/tmp}
case "$base:$output:$source:$tmpdir" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$base:$output:$source:$tmpdir" in /*:/*:/*:/*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)
scratch=$(mktemp -d "$tmpdir/phantowd-capture.XXXXXX")
# Fixed mktemp-owned tmpfs only, never cached output or a host filesystem.
trap 'rm -rf "$scratch"' EXIT
bash "$source/support/tests/build-samba-server-capture-fixture.sh" "$output" "$source" "$scratch"
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
debugfs="$output/host/sbin/debugfs"
for pair in "$scratch/phantowd_open_qemu.so /usr/lib/samba/vfs/phantowd_open_qemu.so" \
    "$scratch/capture-test /usr/sbin/phantowd-server-capture-test" \
    "$source/support/tests/server-capture-init.sh /usr/sbin/phantowd-server-capture-init"; do
    input=${pair%% *}
    name=${pair#* }
    "$debugfs" -w -R "write $input $name" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name mode 0100555" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -R "dump $name $scratch/inserted" "$scratch/rootfs.ext2" >/dev/null 2>&1
    cmp "$input" "$scratch/inserted"
    metadata=$("$debugfs" -R "stat $name" "$scratch/rootfs.ext2" 2>/dev/null)
    printf '%s\n' "$metadata" | grep -Eq '^Inode: [0-9]+ +Type: regular +Mode: +0555 +'
    printf '%s\n' "$metadata" | grep -Eq '^User: +0 +Group: +0 +'
    rm "$scratch/inserted"
done
export TMPDIR="$scratch"
status=0
timeout --signal=TERM --kill-after=2 30 qemu-system-arm -M versatilepb -cpu arm926 -m 256M \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 phantowd_capture_fixture=1 init=/usr/sbin/phantowd-server-capture-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    -display none -serial stdio -monitor none -nic none -no-reboot >"$scratch/guest.log" 2>&1 || status=$?
cat "$scratch/guest.log"
[ "$status" -eq 0 ] || exit 1
awk -f "$source/support/tests/verify-server-capture-log.awk" "$scratch/guest.log"
[ "$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)" = "$base_hash" ]
echo 'PHANTOWD_SERVER_CAPTURE_COMPLETE base_unchanged=true synthetic_open=true active_worker=false authority=false scope=qemu-only'
