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
scratch=$(mktemp -d "$tmpdir/phantowd-revisionstore-media.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
go="$output/host/bin/go"
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
export GOCACHE="$scratch/go-cache" GOPATH="$scratch/go-path"
(cd "$source/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    timeout --signal=TERM --kill-after=1 30 "$go" test -tags=qemu -c -trimpath -o "$scratch/tests" ./internal/revisionstore)
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
[ "$(wc -c < "$scratch/rootfs.ext2")" -le 134217728 ] || exit 1
truncate -s 128M "$scratch/rootfs.ext2"
"$output/host/sbin/resize2fs" -f "$scratch/rootfs.ext2" >/dev/null 2>&1
debugfs="$output/host/sbin/debugfs"
for pair in "$scratch/tests /usr/sbin/phantowd-revisionstore-media-tests" \
    "$source/support/tests/revisionstore-media-init.sh /usr/sbin/phantowd-revisionstore-media-init"; do
    input=${pair%% *}; name=${pair#* }
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
truncate -s 32M "$scratch/media.ext4"
"$output/host/sbin/mke2fs" -q -F -t ext4 -m 0 -E lazy_itable_init=0,lazy_journal_init=0 "$scratch/media.ext4"
export TMPDIR="$scratch"
status=0
timeout --signal=TERM --kill-after=2 60 qemu-system-arm -M versatilepb -cpu arm926 -m 256M \
    -object rng-random,id=media-rng,filename=/dev/urandom -device virtio-rng-pci,rng=media-rng \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 phantowd_revisionstore_media_fixture=1 init=/usr/sbin/phantowd-revisionstore-media-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    -drive "file=$scratch/media.ext4,format=raw,if=scsi,snapshot=on" \
    -display none -serial stdio -monitor none -nic none -no-reboot >"$scratch/guest.log" 2>&1 || status=$?
cat "$scratch/guest.log"
[ "$status" -eq 0 ] || exit 1
awk -f "$source/support/tests/verify-revisionstore-media-log.awk" "$scratch/guest.log"
[ "$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)" = "$base_hash" ]
echo 'PHANTOWD_REVISIONSTORE_MEDIA_COMPLETE base_unchanged=true authority=false scope=qemu-only'
