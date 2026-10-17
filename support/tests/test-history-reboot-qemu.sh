#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# One private synthetic RAW working copy across two bounded kernel lifetimes.
set -eu
umask 077
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
scratch=$(mktemp -d "$tmpdir/phantowd-history-reboot.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
go="$output/host/bin/go"
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
export GOCACHE="$scratch/go-cache" GOPATH="$scratch/go-path"
(cd "$source/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    timeout --signal=TERM --kill-after=1 30 "$go" test -tags=qemu -c -trimpath -o "$scratch/tests" ./internal/policytransaction)
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
[ "$(wc -c < "$scratch/rootfs.ext2")" -le 134217728 ] || exit 1
truncate -s 128M "$scratch/rootfs.ext2"
"$output/host/sbin/resize2fs" -f "$scratch/rootfs.ext2" >/dev/null 2>&1
debugfs="$output/host/sbin/debugfs"
for pair in "$scratch/tests /usr/sbin/phantowd-policy-operation-tests" \
    "$source/support/tests/history-reboot-init.sh /usr/sbin/phantowd-history-reboot-init"; do
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
truncate -s 32M "$scratch/seed.ext4"
"$output/host/sbin/mke2fs" -q -F -t ext4 -m 0 -E lazy_itable_init=0,lazy_journal_init=0 "$scratch/seed.ext4"
chmod 0400 "$scratch/seed.ext4"
seed_hash=$(sha256sum "$scratch/seed.ext4" | cut -d ' ' -f 1)
cp "$scratch/seed.ext4" "$scratch/working.ext4"
chmod 0600 "$scratch/working.ext4"
nonce=$(tr -d '\n-' </proc/sys/kernel/random/uuid)
[[ "$nonce" =~ ^[0-9a-f]{32}$ ]] && [ "$nonce" != 00000000000000000000000000000000 ] || exit 1
result="$source/support/tests/history-reboot-result.py"
# QEMU's root-disk snapshot must use this same bounded writable tmpfs, not
# the container's read-only /var/tmp. Never loosen the container mount policy.
export TMPDIR="$scratch"
run_boot() {
    local phase=$1 extra=$2 disk_readonly status
    case "$phase" in produce) disk_readonly=off ;; observe) disk_readonly=on ;; *) return 1 ;; esac
    status=0
    timeout --signal=TERM --kill-after=2 60 qemu-system-arm -M versatilepb -cpu arm926 -m 256M \
        -object rng-random,id=reboot-rng,filename=/dev/urandom -device virtio-rng-pci,rng=reboot-rng \
        -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
        -append "console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 phantowd_revisionstore_media_fixture=1 phantowd_history_reboot_phase=$phase phantowd_history_reboot_nonce=$nonce $extra init=/usr/sbin/phantowd-history-reboot-init" \
        -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
        -drive "file=$scratch/working.ext4,format=raw,if=scsi,readonly=$disk_readonly" \
        -display none -serial stdio -monitor none -nic none -no-reboot >"$scratch/$phase.log" 2>&1 || status=$?
    cat "$scratch/$phase.log"
    [ "$status" -eq 0 ] || return 1
    python3 -B "$result" log "$phase" "$nonce" "$scratch/$phase.log" >"$scratch/$phase.json"
}
run_boot produce ''
bindings=$(python3 -B "$result" bindings "$nonce" "$scratch/produce.json")
read -r expected_root previous_boot unexpected <<<"$bindings"
[ -n "$expected_root" ] && [ -n "$previous_boot" ] && [ -z "$unexpected" ] || exit 1
working_hash=$(sha256sum "$scratch/working.ext4" | cut -d ' ' -f 1)
run_boot observe "phantowd_history_reboot_root=$expected_root phantowd_history_reboot_previous=$previous_boot"
[ "$(sha256sum "$scratch/working.ext4" | cut -d ' ' -f 1)" = "$working_hash" ]
python3 -B "$result" compare "$nonce" "$scratch/produce.json" "$scratch/observe.json"
[ "$(sha256sum "$scratch/seed.ext4" | cut -d ' ' -f 1)" = "$seed_hash" ]
[ "$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)" = "$base_hash" ]
echo 'PHANTOWD_HISTORY_REBOOT_COMPLETE boots=2 working_disk_readonly_unchanged=true seed_unchanged=true base_unchanged=true authority=false scope=qemu-only'
