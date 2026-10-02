#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Use a verified cached image and a tmpfs/snapshot copy, never physical media.
set -eu
base=${1:?BASE GO DEBUGFS SOURCE [FAILURE_LOG]}
go_binary=${2:?pinned Go required}
debugfs=${3:?pinned debugfs required}
source_dir=${4:?source required}
failure_log=${5:-}
tmpdir=${TMPDIR:-/tmp}
export TMPDIR="$tmpdir"
case "$base:$go_binary:$debugfs:$source_dir:$failure_log:$tmpdir" in
    *[!a-zA-Z0-9_./:-]*) exit 1 ;;
esac
case "$tmpdir" in /*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')
scratch=$(mktemp -d "$tmpdir/phantowd-code-owner.XXXXXX")
child_pid=
cleanup() {
    if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    rm -f "$scratch/rootfs.ext2" "$scratch/probe" "$scratch/guest.log"
    rm -rf "$scratch/go-cache" "$scratch/go-path"
    rmdir "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
export GOCACHE="$scratch/go-cache" GOPATH="$scratch/go-path"
(cd "$source_dir/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    "$go_binary" build -tags=qemu -trimpath -ldflags='-s -w' \
    -o "$scratch/probe" ./cmd/qemu-runtime-bundle)
rm -rf "$scratch/go-cache" "$scratch/go-path"
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
for pair in "$scratch/probe phantowd-runtime-bundle-probe" \
    "$source_dir/support/tests/runtime-owner-init.sh phantowd-runtime-owner-init"; do
    input=${pair%% *}
    output=${pair#* }
    "$debugfs" -w -R "write $input /usr/sbin/$output" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output mode 0100755" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
done
timeout --signal=TERM --kill-after=5 120 qemu-system-arm \
    -M versatilepb -cpu arm926 -m 256M -nographic -no-reboot -nic none \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 phantowd_code_owner_fixture=1 init=/usr/sbin/phantowd-runtime-owner-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    >"$scratch/guest.log" 2>&1 &
child_pid=$!
status=0
wait "$child_pid" || status=$?
child_pid=
expected='PHANTOWD_CODE_OWNER_READY caller_close=true fixed_spec=true pinned_exec=true duplicate_start_no_effect=true stop_reaped=true scope=qemu-only'
review='PHANTOWD_CODE_OWNER_REVIEW_READY same_bytes_replacement=true before_child=true live_root_drift=true group_reaped=true restoration_not_retried=true scope=qemu-only'
if [ "$status" -ne 0 ] || [ "$(grep '^PHANTOWD_CODE_OWNER_' "$scratch/guest.log" | tr -d '\r')" != "$(printf '%s\n%s\n%s' "$expected" "$review" PHANTOWD_CODE_OWNER_DONE)" ]; then
    if [ -n "$failure_log" ]; then
        mkdir -p "$(dirname "$failure_log")"
        cp "$scratch/guest.log" "$failure_log"
    fi
    tail -n 100 "$scratch/guest.log" >&2
    exit 1
fi
[ "$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')" = "$base_hash" ]
grep '^PHANTOWD_CODE_OWNER_' "$scratch/guest.log"
echo PHANTOWD_CODE_OWNER_BASE_UNCHANGED
