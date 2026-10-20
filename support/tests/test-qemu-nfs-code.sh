#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Optional isolated code/loader lane: regular image copy and guest RAM only.
set -eu
base=${1:?BASE TARGET GO DEBUGFS SOURCE [FAILURE_LOG]}
target=${2:?cached Buildroot target required}
go_binary=${3:?pinned Go required}
debugfs=${4:?pinned debugfs required}
source_dir=${5:?source required}
failure_log=${6:-}
fixture_mode=${7:-code}
case "$fixture_mode" in code|source|source-loss|source-daemon-loss|source-owner-policy-loss|source-owner-daemon-loss|source-owner-daemon-stop-loss|source-owner-partial-start|source-owner-kernel-refusal) ;; *) echo 'Unknown NFS fixture mode' >&2; exit 1 ;; esac
tmpdir=${TMPDIR:-/tmp}
case "$base:$target:$go_binary:$debugfs:$source_dir:$failure_log:$tmpdir" in
    *[!a-zA-Z0-9_./:-]*) echo 'Unsupported fixture path' >&2; exit 1 ;;
esac
case "$tmpdir" in /*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found=1 } END { exit !found }' /proc/mounts || {
    echo 'NFS code fixture requires tmpfs scratch' >&2; exit 1
}
for name in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$name" ] && [ ! -L "$base/$name" ] || exit 1
done
[ -d "$target" ] && [ ! -L "$target" ] || exit 1
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')
scratch=$(mktemp -d "$tmpdir/phantowd-nfs-code.XXXXXX")
child_pid=
cleanup() {
    if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    # Exact newly allocated RAM directory only; never base/source/cache volumes.
    rm -rf "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false' CGO_ENABLED=0
# An explicitly supplied Go cache may be reused only inside this RAM root.
GOCACHE=${GOCACHE:-$scratch/go-cache}
GOPATH=${GOPATH:-$scratch/go-path}
case "$GOCACHE:$GOPATH" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$GOCACHE" in "$tmpdir"/*) ;; *) exit 1 ;; esac
case "$GOPATH" in "$tmpdir"/*) ;; *) exit 1 ;; esac
export GOCACHE GOPATH
host_arch=$("$go_binary" env GOHOSTARCH)
(cd "$source_dir/tools/phantowd-lab" && GOOS=linux GOARCH="$host_arch" "$go_binary" build -trimpath -o "$scratch/lab" ./cmd/phantowd-lab)
"$scratch/lab" inspect-nfs-runtime-closure "$target" >"$scratch/expected.json"
for entry in rpcbind rpc.mountd exportfs; do
    "$scratch/lab" inspect-runtime-closure "$target" "usr/sbin/$entry" >"$scratch/$entry.json"
done
target_cc="$(dirname "$go_binary")/arm-buildroot-linux-gnueabi-gcc"
"$target_cc" -std=c11 -O2 -static -Wall -Wextra -Werror \
    -o "$scratch/launcher" "$source_dir/src/phantowd-service-launcher/launcher.c"
"$target_cc" -std=c11 -O2 -static -Wall -Wextra -Werror \
    -o "$scratch/nfs-table-bootstrap" "$source_dir/support/tests/nfs-table-bootstrap.c"
(cd "$source_dir/src/phantowd-api" && GOOS=linux GOARCH=arm GOARM=5 "$go_binary" build -tags=qemu -trimpath -ldflags='-s -w' -o "$scratch/probe" ./cmd/qemu-nfs-code-fixture)
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
"$debugfs" -w -R 'mkdir /usr/lib/phantowd' "$scratch/rootfs.ext2" >/dev/null 2>&1 || true
install_image_file() {
    from=$1
    to=$2
    mode=$3
    "$debugfs" -w -R "write $from $to" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $to mode $mode" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $to uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $to gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -R "dump $to $scratch/verify" "$scratch/rootfs.ext2" >/dev/null 2>&1
    cmp "$from" "$scratch/verify"
    rm "$scratch/verify"
}
install_image_file "$scratch/expected.json" /usr/lib/phantowd/qemu-nfs-code-expected.json 0100444
install_image_file "$scratch/probe" /usr/sbin/phantowd-nfs-code-fixture 0100555
install_image_file "$scratch/launcher" /usr/sbin/phantowd-service-launcher 0100555
install_image_file "$scratch/nfs-table-bootstrap" /usr/sbin/phantowd-nfs-table-bootstrap 0100555
install_image_file "$source_dir/support/tests/nfs-code-init.sh" /usr/sbin/phantowd-nfs-code-init 0100555
selector=
set --
if [ "$fixture_mode" != code ]; then
    # Only this fresh regular RAM file is formatted, never a host block device.
    truncate -s 32M "$scratch/source.ext2"
    [ -f "$scratch/source.ext2" ] && [ ! -L "$scratch/source.ext2" ] || exit 1
    "$(dirname "$debugfs")/mke2fs" -q -F -t ext2 -m 0 \
        -U 11111111-2222-3333-4444-555555555555 "$scratch/source.ext2"
    source_hash=$(sha256sum "$scratch/source.ext2" | awk '{print $1}')
    selector=' phantowd_nfs_source_fixture=1'
    if [ "$fixture_mode" = source-loss ] || [ "$fixture_mode" = source-daemon-loss ]; then selector="$selector phantowd_nfs_source_loss_fixture=1"; fi
    if [ "$fixture_mode" = source-daemon-loss ]; then selector="$selector phantowd_nfs_source_daemon_loss_fixture=1"; fi
    if [ "$fixture_mode" = source-owner-policy-loss ]; then selector="$selector phantowd_nfs_source_owner_policy_loss_fixture=1"; fi
    if [ "$fixture_mode" = source-owner-daemon-loss ] || [ "$fixture_mode" = source-owner-daemon-stop-loss ]; then selector="$selector phantowd_nfs_source_owner_daemon_loss_fixture=1"; fi
    if [ "$fixture_mode" = source-owner-daemon-stop-loss ]; then selector="$selector phantowd_nfs_source_owner_stop_loss_fixture=1"; fi
    if [ "$fixture_mode" = source-owner-partial-start ]; then selector="$selector phantowd_nfs_source_owner_rpc_start_failure_fixture=1"; fi
    if [ "$fixture_mode" = source-owner-kernel-refusal ]; then selector="$selector phantowd_nfs_source_owner_kernel_construct_refusal_fixture=1"; fi
    set -- -drive "file=$scratch/source.ext2,format=raw,if=scsi,snapshot=on"
fi
# QEMU's default /tmp selection may fall back to /var/tmp for snapshots. Use
# this exact owned RAM directory; never broaden the container's writable roots.
TMPDIR="$scratch" timeout --signal=TERM --kill-after=5s 90s qemu-system-arm \
    -M versatilepb -cpu arm926 -m 256M -nographic -no-reboot -nic none \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append "console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 phantowd_nfs_code_fixture=1$selector init=/usr/sbin/phantowd-nfs-code-init" \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" "$@" >"$scratch/guest.log" 2>&1 &
child_pid=$!
status=0
wait "$child_pid" || status=$?
child_pid=
cat "$scratch/guest.log"
verify_guest() {
    [ "$status" -eq 0 ] || return 1
    if [ "$fixture_mode" != code ]; then
        if [ "$fixture_mode" = source-owner-kernel-refusal ]; then
            python3 -B "$source_dir/support/nfs-code-result.py" --source-owner-kernel-refusal "$scratch/guest.log" "$scratch/expected.json" || return 1
        elif [ "$fixture_mode" = source-owner-partial-start ]; then
            python3 -B "$source_dir/support/nfs-code-result.py" --source-owner-partial-start "$scratch/guest.log" "$scratch/expected.json" || return 1
        elif [ "$fixture_mode" = source-owner-daemon-stop-loss ]; then
            python3 -B "$source_dir/support/nfs-code-result.py" --source-owner-daemon-stop-loss "$scratch/guest.log" "$scratch/expected.json" || return 1
        elif [ "$fixture_mode" = source-owner-daemon-loss ]; then
            python3 -B "$source_dir/support/nfs-code-result.py" --source-owner-daemon-loss "$scratch/guest.log" "$scratch/expected.json" || return 1
        elif [ "$fixture_mode" = source-owner-policy-loss ]; then
            python3 -B "$source_dir/support/nfs-code-result.py" --source-owner-policy-loss "$scratch/guest.log" "$scratch/expected.json" || return 1
        elif [ "$fixture_mode" = source-daemon-loss ]; then
            python3 -B "$source_dir/support/nfs-code-result.py" --source-daemon-loss "$scratch/guest.log" "$scratch/expected.json" || return 1
        elif [ "$fixture_mode" = source-loss ]; then
            python3 -B "$source_dir/support/nfs-code-result.py" --source-loss "$scratch/guest.log" "$scratch/expected.json" || return 1
        else
            python3 -B "$source_dir/support/nfs-code-result.py" --source "$scratch/guest.log" "$scratch/expected.json" || return 1
        fi
        [ "$(sha256sum "$scratch/source.ext2" | awk '{print $1}')" = "$source_hash" ] || return 1
        echo PHANTOWD_NFS_SOURCE_SNAPSHOT_UNCHANGED
    else
        python3 -B "$source_dir/support/nfs-code-result.py" "$scratch/guest.log" "$scratch/expected.json" || return 1
        python3 -B "$source_dir/support/tests/nfs_loader_result.py" "$scratch/guest.log" "$scratch/expected.json" \
            "$scratch/rpcbind.json" "$scratch/rpc.mountd.json" "$scratch/exportfs.json" || return 1
    fi
}
if ! verify_guest; then
    if [ -n "$failure_log" ]; then cp "$scratch/guest.log" "$failure_log"; fi
    exit 1
fi
[ "$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')" = "$base_hash" ]
sha256sum "$scratch/probe" "$scratch/launcher" "$scratch/expected.json" "$scratch/rootfs.ext2" \
    "$scratch/rpcbind.json" "$scratch/rpc.mountd.json" "$scratch/exportfs.json" "$scratch/nfs-table-bootstrap"
echo PHANTOWD_NFS_CODE_BASE_UNCHANGED
