#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Build and boot only disposable copies using an existing pinned toolchain/base.
set -eu
base=${1:?usage: test-qemu-service-launcher.sh BASE TARGET_CC DEBUGFS SOURCE}
target_cc=${2:?pinned compiler required}
debugfs=${3:?pinned debugfs required}
source_dir=${4:?source required}
failure_log=${5:-}
tmpdir=${TMPDIR:-/tmp}
export TMPDIR="$tmpdir"
case "$base:$target_cc:$debugfs:$source_dir:$failure_log:$tmpdir" in
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
    rm -f "$scratch/rootfs.ext2" "$scratch/launcher" "$scratch/fixture" "$scratch/init.sh" "$scratch/guest.log"
    rmdir "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
base_hash=$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')
(cd "$base" && sha256sum -c SHA256SUMS)
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
"$target_cc" -std=c11 -O2 -static -Wall -Wextra -Werror \
    -o "$scratch/launcher" "$source_dir/src/phantowd-service-launcher/launcher.c"
"$target_cc" -std=c11 -O2 -static -Wall -Wextra -Werror \
    -o "$scratch/fixture" "$source_dir/support/tests/service-launcher-fixture.c"
cp "$source_dir/support/tests/service-launcher-init.sh" "$scratch/init.sh"
for pair in 'launcher phantowd-service-launcher' 'fixture phantowd-service-launcher-fixture' 'init.sh phantowd-service-launcher-init'; do
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
grep -F 'PHANTOWD_SERVICE_LAUNCHER_READY private_namespace=true root_restricted=true nonroot=true capabilities_zero=true fd_cleanup=true pid_preserved=true read_only=true signals_reset=true denied_cases=7' "$scratch/guest.log" >/dev/null
grep -F PHANTOWD_SERVICE_LAUNCHER_READY "$scratch/guest.log"
grep -F PHANTOWD_SERVICE_LAUNCHER_DONE "$scratch/guest.log"
[ "$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')" = "$base_hash" ]
echo 'PHANTOWD_SERVICE_LAUNCHER_BASE_UNCHANGED'
