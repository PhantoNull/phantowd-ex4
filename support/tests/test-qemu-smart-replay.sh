#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Build the actual generic-only producer and test it in a diskless ARMv5 guest.
set -eu
base=${1:?BASE CXX GO DEBUGFS SOURCE ARCHIVE required}
cxx=${2:?cross C++ compiler required}
go_binary=${3:?pinned Go required}
debugfs=${4:?pinned debugfs required}
source_dir=${5:?source required}
archive=${6:?source archive required}
failure_log=${7:-}
tmpdir=${TMPDIR:-/tmp}
case "$base:$cxx:$go_binary:$debugfs:$source_dir:$archive:$failure_log:$tmpdir" in
    *[!a-zA-Z0-9_./:+-]*) exit 1 ;;
esac
if [ ! -x "$cxx" ]; then
    echo 'PHANTOWD_SMART_ARM_REPLAY_MISSING_CXX full-rebuild-required=true' >&2
    exit 2
fi
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts
[ -f "$archive" ] && [ ! -L "$archive" ]
[ "$(sha256sum "$archive" | awk '{print $1}')" = 690b83ca331378da9ea0d9d61008c4b22dde391387b9bbad7f29387f2595f76e ]
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')
scratch=$(mktemp -d "$tmpdir/phantowd-smart-arm-replay.XXXXXX")
# QEMU 7.2 rewrites exactly /tmp to /var/tmp for snapshots. Use the owned
# subdirectory so snapshot overlays stay inside the checked tmpfs and cleanup.
export TMPDIR="$scratch"
child_pid=
cleanup() {
    if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    rm -rf "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
tar -xzf "$archive" -C "$scratch"
cd "$scratch/smartmontools-7.5"
if ! CXX="$cxx" CXXFLAGS='-Os -march=armv5te -mfloat-abi=soft' LDFLAGS=-static \
    timeout --signal=TERM --kill-after=5 120 ./configure \
    --host=arm-buildroot-linux-gnueabi --with-os-deps=os_generic.o \
    --without-libsystemd --without-libcap-ng --without-selinux \
    >"$scratch/configure.log" 2>&1; then
    tail -n 40 "$scratch/configure.log" >&2
    exit 1
fi
grep -x 'os_deps = os_generic.o' Makefile >/dev/null
if ! timeout --signal=TERM --kill-after=5 300 make -j2 smartctl >"$scratch/build.log" 2>&1; then
    tail -n 40 "$scratch/build.log" >&2
    exit 1
fi
[ -f os_generic.o ] && [ ! -f os_linux.o ] && [ ! -f smartd ]
readelf="$(dirname "$cxx")/arm-buildroot-linux-gnueabi-readelf"
"$readelf" -h smartctl >"$scratch/elf-header"
grep -E 'Class: *ELF32' "$scratch/elf-header" >/dev/null
grep -E 'Machine: *ARM' "$scratch/elf-header" >/dev/null
grep -E 'Flags:.*soft-float ABI' "$scratch/elf-header" >/dev/null
"$readelf" -A smartctl >"$scratch/elf-attributes"
# The ARM926 Buildroot libraries carry v5TEJ even when the producer's own
# objects request -march=armv5te. Both are explicit ARM926 guest profiles;
# this is not permission for v6/v7 or physical EX4 qualification.
grep -E 'Tag_CPU_arch: v5TE(J)?$' "$scratch/elf-attributes" >/dev/null
if grep -E 'Tag_ABI_VFP_args: VFP registers' "$scratch/elf-attributes" >/dev/null; then exit 1; fi
"$readelf" -l smartctl >"$scratch/elf-segments"
if grep -E 'INTERP|DYNAMIC' "$scratch/elf-segments" >/dev/null; then exit 1; fi
echo 'PHANTOWD_SMART_ARM_REPLAY_ELF_READY abi=armv5te-or-v5tej-soft-float linkage=static backend=generic'
mkdir "$scratch/traces"
python3 -B "$source_dir/support/tests/smart-replay-corpus.py" --traces "$scratch/traces" 7.5
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false -p=2' GOMAXPROCS=2
export GOCACHE="$scratch/go-cache" GOPATH="$scratch/go-path"
(cd "$source_dir/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    timeout --signal=TERM --kill-after=5 180 "$go_binary" test -tags smartreplay -c -trimpath \
    -o "$scratch/replay.test" ./internal/smartreport)
rm -rf "$scratch/go-cache" "$scratch/go-path"
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
"$debugfs" -w -R 'mkdir /usr/share/phantowd-smart-replay' "$scratch/rootfs.ext2" >/dev/null 2>&1
for name in pass fail partial-fail partial-pass unsupported disabled empty; do
    "$debugfs" -w -R "write $scratch/traces/$name.trace /usr/share/phantowd-smart-replay/$name.trace" "$scratch/rootfs.ext2" >/dev/null 2>&1
done
for pair in "$scratch/smartmontools-7.5/smartctl phantowd-smartctl-replay" \
    "$scratch/replay.test phantowd-smart-replay-test" \
    "$source_dir/support/tests/smart-replay-arm-init.sh phantowd-smart-replay-init"; do
    input=${pair%% *}
    output=${pair#* }
    "$debugfs" -w -R "write $input /usr/sbin/$output" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output mode 0100755" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
done
timeout --signal=TERM --kill-after=5 90 qemu-system-arm \
    -M versatilepb -cpu arm926 -m 256M -nographic -no-reboot -nic none \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 init=/usr/sbin/phantowd-smart-replay-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    >"$scratch/guest.log" 2>&1 &
child_pid=$!
status=0
wait "$child_pid" || status=$?
child_pid=
cr=$(printf '\r')
if [ "$status" -ne 0 ] || ! grep -E "^PHANTOWD_SMART_ARM_REPLAY_READY scope=generic-synthetic-only version=7.5 cases=7${cr}?$" "$scratch/guest.log" >/dev/null; then
    printf 'PHANTOWD_SMART_ARM_REPLAY_RUNNER_FAILED exit=%s\n' "$status" >&2
    if [ -n "$failure_log" ]; then
        mkdir -p "$(dirname "$failure_log")"
        cp "$scratch/guest.log" "$failure_log"
    fi
    tail -n 100 "$scratch/guest.log" >&2
    exit 1
fi
grep -E "^PASS${cr}?$" "$scratch/guest.log" >/dev/null
[ "$(grep -c '^PHANTOWD_SMART_ARM_PRODUCER case=' "$scratch/guest.log")" = 7 ]
grep -E '^--- PASS: TestUpstreamReplayCorpus ' "$scratch/guest.log" >/dev/null
grep -E '^PHANTOWD_SMART_ARM_(PRODUCER|REPLAY_READY)' "$scratch/guest.log"
[ "$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')" = "$base_hash" ]
echo 'PHANTOWD_SMART_ARM_REPLAY_BASE_UNCHANGED'
