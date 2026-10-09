#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# One synthetic boundary guest. Existing ten-campaign union is untouched.
set -eu
base=${1:?base artifacts required}
output=${2:?existing pinned output required}
source=${3:?repository source required}
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
scratch=$(mktemp -d "$tmpdir/phantowd-launcher-boundary.XXXXXX")
trap 'rm -f "$scratch/launcher" "$scratch/boundary" "$scratch/rootfs.ext2" "$scratch/guest.log"; rmdir "$scratch"' EXIT
compiler="$output/host/bin/arm-buildroot-linux-gnueabi-gcc"
debugfs="$output/host/sbin/debugfs"
for pair in 'launcher samba-pending-write-launcher-fixture.c' 'boundary samba-pending-write-launcher-qemu-test.c'; do
    "$compiler" -std=c11 -O2 -static -Wall -Wextra -Werror -o "$scratch/${pair%% *}" "$source/support/tests/${pair#* }"
done
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
for pair in "$scratch/launcher phantowd-pending-write-launcher" \
    "$scratch/boundary phantowd-pending-launcher-boundary" \
    "$source/support/tests/samba-pending-write-launcher-init.sh phantowd-pending-launcher-init"; do
    input=${pair%% *}
    name=${pair#* }
    "$debugfs" -w -R "write $input /usr/sbin/$name" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$name mode 0100755" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$name uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$name gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
done
status=0
timeout --signal=TERM --kill-after=2 45 qemu-system-arm -M versatilepb -m 256M \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 init=/usr/sbin/phantowd-pending-launcher-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    -display none -serial stdio -monitor none -nic none -no-reboot >"$scratch/guest.log" 2>&1 || status=$?
cat "$scratch/guest.log"
[ "$status" -eq 0 ] || exit 1
awk -f "$source/support/tests/verify-samba-pending-launcher-log.awk" "$scratch/guest.log"
[ "$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)" = "$base_hash" ]
printf '%s\n' 'PHANTOWD_PENDING_LAUNCHER_QEMU_COMPLETE base_unchanged=true synthetic_probe=true real_client=false smb=false full_image=false scope=qemu-only'
