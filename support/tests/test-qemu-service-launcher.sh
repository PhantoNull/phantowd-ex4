#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Build and boot only disposable copies using an existing pinned toolchain/base.
set -eu
base=${1:?usage: test-qemu-service-launcher.sh BASE TARGET_CC DEBUGFS SOURCE FAILURE_LOG GO_BINARY}
target_cc=${2:?pinned compiler required}
debugfs=${3:?pinned debugfs required}
source_dir=${4:?source required}
failure_log=${5:-}
go_binary=${6:?pinned Go required}
tmpdir=${TMPDIR:-/tmp}
export TMPDIR="$tmpdir"
case "$base:$target_cc:$debugfs:$source_dir:$failure_log:$tmpdir:$go_binary" in
    *[!a-zA-Z0-9_./:-]*) echo 'Unsupported fixture path' >&2; exit 1 ;;
esac
case "$tmpdir" in /*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || {
    echo 'Launcher fixture requires temporary tmpfs storage' >&2
    exit 1
}
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
scratch=$(mktemp -d "$tmpdir/phantowd-launcher.XXXXXX")
child_pid=
cleanup() {
    if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    # Everything here was generated under this exact mktemp tmpfs directory.
    rm -f "$scratch/rootfs.ext2" "$scratch/storage.ext2" "$scratch/launcher" "$scratch/fixture" "$scratch/init.sh" "$scratch/owner-fixture" "$scratch/guest.log"
    # Go's bounded per-test compiler cache is not a persistent Docker volume.
    rm -rf "$scratch/go-cache" "$scratch/go-path"
    rmdir "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
base_hash=$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')
(cd "$base" && sha256sum -c SHA256SUMS)
"$target_cc" -std=c11 -O2 -static -Wall -Wextra -Werror \
    -o "$scratch/launcher" "$source_dir/src/phantowd-service-launcher/launcher.c"
"$target_cc" -std=c11 -O2 -static -Wall -Wextra -Werror \
    -o "$scratch/fixture" "$source_dir/support/tests/service-launcher-fixture.c"
cp "$source_dir/support/tests/service-launcher-init.sh" "$scratch/init.sh"
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
export GOCACHE="$scratch/go-cache" GOPATH="$scratch/go-path"
(cd "$source_dir/src/phantowd-api" && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 "$go_binary" build -tags=qemu \
    -trimpath -ldflags='-s -w' -o "$scratch/owner-fixture" ./cmd/qemu-service-launcher-fixture)
rm -rf "$scratch/go-cache" "$scratch/go-path"
# Do not retain compiler cache and a rootfs copy at the same time.
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
truncate -s 16M "$scratch/storage.ext2"
mkfs.ext2 -q -F -U 11111111-2222-3333-4444-555555555555 "$scratch/storage.ext2"
for pair in 'launcher phantowd-service-launcher' 'fixture phantowd-service-launcher-fixture' 'init.sh phantowd-service-launcher-init' 'owner-fixture phantowd-service-launcher-owner-fixture'; do
    source_name=${pair%% *}
    target_name=${pair#* }
    "$debugfs" -w -R "write $scratch/$source_name /usr/sbin/$target_name" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$target_name mode 0100755" "$scratch/rootfs.ext2" >/dev/null 2>&1
    # Do not inherit the builder UID or Windows bind-mount metadata.
    "$debugfs" -w -R "set_inode_field /usr/sbin/$target_name uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$target_name gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
done
timeout --signal=TERM --kill-after=5 90 qemu-system-arm \
    -M versatilepb -cpu arm926 -m 256M -nographic -no-reboot -nic none \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait rw panic=-1 init=/usr/sbin/phantowd-service-launcher-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    -drive "file=$scratch/storage.ext2,format=raw,if=scsi,snapshot=on" \
    >"$scratch/guest.log" 2>&1 &
child_pid=$!
status=0
wait "$child_pid" || status=$?
child_pid=
if [ "$status" -ne 0 ] || ! grep -F PHANTOWD_SERVICE_LAUNCHER_DONE "$scratch/guest.log" >/dev/null; then
    if [ -n "$failure_log" ]; then
        mkdir -p "$(dirname "$failure_log")"
        cp "$scratch/guest.log" "$failure_log"
    fi
    tail -n 120 "$scratch/guest.log" >&2
    exit 1
fi
grep -F 'PHANTOWD_SERVICE_LAUNCHER_READY private_namespace=true root_restricted=true nonroot=true capabilities_zero=true fd_cleanup=true high_fd_cleanup=true diagnostic_pipes=true pid_preserved=true read_only=true signals_reset=true denied_cases=11' "$scratch/guest.log" >/dev/null
grep -F 'PHANTOWD_SERVICE_LAUNCHER_OWNER_READY pinned_inputs=true immutable_spec=true readiness=true same_pid=true private_namespace=true stop_reaped=true close_gated=true' "$scratch/guest.log" >/dev/null
grep -F 'PHANTOWD_SERVICE_LAUNCHER_INPUT_REVIEW_READY before_child=true restoration_not_retried=true' "$scratch/guest.log" >/dev/null
grep -F 'PHANTOWD_SERVICE_LAUNCHER_LIVE_REVIEW_READY stop_before_close=true group_reaped=true restoration_not_retried=true' "$scratch/guest.log" >/dev/null
grep -F 'PHANTOWD_SERVICE_LAUNCHER_CLOSING_ROOT_READY rejected=true caller_close=true scope=disposable-qemu-only' "$scratch/guest.log" >/dev/null
grep -F 'PHANTOWD_ISOLATED_HANDOFF_READY grant_only_root=true original_path_denied=true nonroot=true read_only=true close_gated=true stop_before_release=true source_loss_review=true no_restart=true scope=disposable-qemu-only' "$scratch/guest.log" >/dev/null
if grep -F PHANTOWD_SERVICE_LAUNCHER_UNMOUNT_FAILED "$scratch/guest.log" >/dev/null; then
    tail -n 120 "$scratch/guest.log" >&2
    exit 1
fi
grep -F PHANTOWD_SERVICE_LAUNCHER_OWNER_READY "$scratch/guest.log"
grep -F PHANTOWD_SERVICE_LAUNCHER_INPUT_REVIEW_READY "$scratch/guest.log"
grep -F PHANTOWD_SERVICE_LAUNCHER_LIVE_REVIEW_READY "$scratch/guest.log"
grep -F PHANTOWD_SERVICE_LAUNCHER_CLOSING_ROOT_READY "$scratch/guest.log"
grep -F PHANTOWD_ISOLATED_HANDOFF_READY "$scratch/guest.log"
grep -F PHANTOWD_SERVICE_LAUNCHER_READY "$scratch/guest.log"
grep -F PHANTOWD_SERVICE_LAUNCHER_DONE "$scratch/guest.log"
[ "$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')" = "$base_hash" ]
echo 'PHANTOWD_SERVICE_LAUNCHER_BASE_UNCHANGED'
