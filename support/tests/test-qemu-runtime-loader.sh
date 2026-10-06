#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Compare public Buildroot ELF bytes/aliases with its actual ARMv5 loader.
set -eu
base=${1:?usage: test-qemu-runtime-loader.sh BASE TARGET GO DEBUGFS SOURCE [FAILURE_LOG]}
target=${2:?existing extracted Buildroot target required}
go_binary=${3:?pinned Go required}
debugfs=${4:?pinned debugfs required}
source_dir=${5:?source required}
failure_log=${6:-}
tmpdir=${TMPDIR:-/tmp}
export TMPDIR="$tmpdir"
case "$base:$target:$go_binary:$debugfs:$source_dir:$failure_log:$tmpdir" in
    *[!a-zA-Z0-9_./:-]*) echo 'Unsupported fixture path' >&2; exit 1 ;;
esac
case "$tmpdir" in /*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || {
    echo 'Runtime fixture requires temporary tmpfs storage' >&2
    exit 1
}
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
[ -d "$target" ] && [ ! -L "$target" ] || exit 1
scratch=$(mktemp -d "$tmpdir/phantowd-runtime-loader.XXXXXX")
child_pid=
cleanup() {
    if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    # Only this exact newly-created tmpfs directory owns these generated files.
    rm -f "$scratch/rootfs.ext2" "$scratch/lab" "$scratch/candidate.json" \
        "$scratch/init.sh" "$scratch/manifest" "$scratch/guest.log"
    rm -rf "$scratch/go-cache" "$scratch/go-path"
    rmdir "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
export GOCACHE="$scratch/go-cache" GOPATH="$scratch/go-path"
(cd "$source_dir/tools/phantowd-lab" && \
    "$go_binary" build -trimpath -o "$scratch/lab" ./cmd/phantowd-lab)
"$scratch/lab" inspect-runtime-closure "$target" usr/sbin/smbd >"$scratch/candidate.json"
python3 -B "$source_dir/support/tests/runtime_loader_fixture.py" prepare \
    "$scratch/candidate.json" "$scratch"
shellcheck "$scratch/init.sh"
# Compiler cache and the temporary image must not coexist unnecessarily.
rm -rf "$scratch/go-cache" "$scratch/go-path"
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
"$debugfs" -w -R "write $scratch/init.sh /usr/sbin/phantowd-runtime-loader-init" "$scratch/rootfs.ext2" >/dev/null 2>&1
"$debugfs" -w -R 'set_inode_field /usr/sbin/phantowd-runtime-loader-init mode 0100755' "$scratch/rootfs.ext2" >/dev/null 2>&1
"$debugfs" -w -R 'set_inode_field /usr/sbin/phantowd-runtime-loader-init uid 0' "$scratch/rootfs.ext2" >/dev/null 2>&1
"$debugfs" -w -R 'set_inode_field /usr/sbin/phantowd-runtime-loader-init gid 0' "$scratch/rootfs.ext2" >/dev/null 2>&1
"$debugfs" -w -R "write $scratch/manifest /usr/lib/phantowd/qemu-runtime-loader.manifest" "$scratch/rootfs.ext2" >/dev/null 2>&1
timeout --signal=TERM --kill-after=5 90 qemu-system-arm \
    -M versatilepb -cpu arm926 -m 256M -nographic -no-reboot -nic none \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 init=/usr/sbin/phantowd-runtime-loader-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    >"$scratch/guest.log" 2>&1 &
child_pid=$!
status=0
wait "$child_pid" || status=$?
child_pid=
if [ "$status" -ne 0 ] || ! python3 -B "$source_dir/support/tests/runtime_loader_fixture.py" compare \
    "$scratch/candidate.json" "$scratch/guest.log"; then
    if [ -n "$failure_log" ]; then
        mkdir -p "$(dirname "$failure_log")"
        cp "$scratch/guest.log" "$failure_log"
    fi
    tail -n 120 "$scratch/guest.log" >&2
    exit 1
fi
[ "$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')" = "$base_hash" ]
echo PHANTOWD_RUNTIME_LOADER_BASE_UNCHANGED
