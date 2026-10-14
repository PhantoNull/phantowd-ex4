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
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)
scratch=$(mktemp -d "$tmpdir/phantowd-observer-context.XXXXXX")
# Fixed newly-created tmpfs scratch only.
trap 'rm -rf "$scratch"' EXIT
cc="$output/host/bin/arm-buildroot-linux-gnueabi-gcc"
flags=(-static -std=c11 -O2 -Wall -Wextra -Werror -Wno-unused-function -ffunction-sections -fdata-sections '-Wl,--gc-sections,-z,relro,-z,now')
timeout --signal=TERM --kill-after=1 30 "$cc" "${flags[@]}" -DPHANTOWD_SAMBA_OBSERVER_CONTEXT_FIXTURE=1 -o "$scratch/bootstrap" "$source/support/tests/samba-server-observer-bootstrap-qemu.c"
timeout --signal=TERM --kill-after=1 30 "$cc" "${flags[@]}" -o "$scratch/controller" "$source/support/tests/samba-server-observer-context-test.c"
timeout --signal=TERM --kill-after=1 30 "$cc" "${flags[@]}" -DPHANTOWD_OBSERVER_PROBE=1 -o "$scratch/probe" "$source/support/tests/samba-server-observer-context-test.c"
nm="$output/host/bin/arm-buildroot-linux-gnueabi-nm"
if "$nm" "$scratch/bootstrap" | grep 'phantowd_legacy_fixture_unused_entry'; then exit 1; fi
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
debugfs="$output/host/sbin/debugfs"
for pair in "$scratch/bootstrap /usr/sbin/phantowd-server-observer-bootstrap" \
    "$scratch/controller /usr/sbin/phantowd-server-observer-context-test" \
    "$scratch/probe /usr/sbin/phantowd-server-observer-context-probe" \
    "$source/support/tests/server-observer-context-init.sh /usr/sbin/phantowd-server-observer-context-init"; do
    input=${pair%% *}
    name=${pair#* }
    [ -f "$input" ] && [ ! -L "$input" ] || exit 1
    "$debugfs" -w -R "write $input $name" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name mode 0100555" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -R "dump $name $scratch/readback" "$scratch/rootfs.ext2" >/dev/null 2>&1
    cmp "$input" "$scratch/readback"
    metadata=$("$debugfs" -R "stat $name" "$scratch/rootfs.ext2" 2>/dev/null)
    printf '%s\n' "$metadata" | grep -Eq '^Inode: [0-9]+ +Type: regular +Mode: +0555 +'
    printf '%s\n' "$metadata" | grep -Eq '^User: +0 +Group: +0 +'
    rm "$scratch/readback"
done
for name in readonly writable; do
    truncate -s 16M "$scratch/$name.ext4"
    [ -f "$scratch/$name.ext4" ] && [ ! -L "$scratch/$name.ext4" ] || exit 1
    "$output/host/sbin/mke2fs" -q -F -t ext4 -E lazy_itable_init=0,lazy_journal_init=0 "$scratch/$name.ext4"
done
export TMPDIR="$scratch"
status=0
timeout --signal=TERM --kill-after=2 45 qemu-system-arm -M versatilepb -cpu arm926 -m 256M \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 init=/usr/sbin/phantowd-server-observer-context-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    -drive "file=$scratch/readonly.ext4,format=raw,if=scsi,snapshot=on" \
    -drive "file=$scratch/writable.ext4,format=raw,if=scsi,snapshot=on" \
    -display none -serial stdio -monitor none -nic none -no-reboot >"$scratch/guest.log" 2>&1 || status=$?
cat "$scratch/guest.log"
[ "$status" -eq 0 ] || exit 1
awk -f "$source/support/tests/verify-server-observer-context-log.awk" "$scratch/guest.log"
[ "$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)" = "$base_hash" ]
echo 'PHANTOWD_SERVER_OBSERVER_CONTEXT_COMPLETE base_unchanged=true active_worker=false producer=false authority=false scope=qemu-only'
