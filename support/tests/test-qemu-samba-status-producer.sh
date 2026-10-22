#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# No Go/package rebuild. Existing stock tools, synthetic tmpfs and one snapshot.
set -eu
[ "$#" -eq 4 ] || [ "$#" -eq 5 ] || exit 1
base=$1 target=$2 debugfs=$3 source_dir=$4
experiment=${5:-}
tmpdir=${TMPDIR:-/tmp}
export TMPDIR="$tmpdir"
case "$base:$target:$debugfs:$source_dir:$tmpdir:$experiment" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
[ "$(realpath -e "$tmpdir")" = "$tmpdir" ] || exit 1
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target,$2 "/") == 1) { found=1 } END { exit !found }' /proc/mounts || exit 1
for name in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$name" ] && [ ! -L "$base/$name" ] || exit 1
done
[ "$(wc -c <"$base/rootfs.ext2")" -le 134217728 ] || exit 1
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f1)
scratch=$(mktemp -d "$tmpdir/phantowd-status-producer.XXXXXX")
export TMPDIR="$scratch"
child_pid=
cleanup() {
    if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    # Only this newly allocated, validated tmpfs directory owns these files.
    rm -f "$scratch/rootfs.ext2" "$scratch/smbstatus" "$scratch/tdbtool" \
        "$scratch/tdbdump" "$scratch/check" "$scratch/guest.log" "$scratch/deadline" "$scratch/smbconf"
    rmdir "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
for program in smbstatus tdbtool tdbdump; do
    "$debugfs" -R "dump /usr/bin/$program $scratch/$program" "$base/rootfs.ext2" >/dev/null 2>&1
    [ -f "$scratch/$program" ] && [ ! -L "$scratch/$program" ] || exit 1
    cmp "$target/usr/bin/$program" "$scratch/$program" || exit 1
done
"$debugfs" -R "dump /usr/lib/libsmbconf.so.0.0.1 $scratch/smbconf" "$base/rootfs.ext2" >/dev/null 2>&1
[ -f "$scratch/smbconf" ] && [ ! -L "$scratch/smbconf" ] || exit 1
cmp "$target/usr/lib/libsmbconf.so.0.0.1" "$scratch/smbconf" || exit 1
library_hash=$(sha256sum "$scratch/smbconf" | cut -d ' ' -f1)
status_hash=$(sha256sum "$scratch/smbstatus" | cut -d ' ' -f1)
tool_hash=$(sha256sum "$scratch/tdbtool" | cut -d ' ' -f1)
dump_hash=$(sha256sum "$scratch/tdbdump" | cut -d ' ' -f1)
cp --sparse=always "$base/rootfs.ext2" "$scratch/rootfs.ext2"
if [ -n "$experiment" ]; then
    # Only the new, caller-owned tmpfs copy is modified. Verify stock inputs
    # above, then remove exact existing entries before debugfs's write command.
    "$debugfs" -w -R 'rm /usr/bin/smbstatus' "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R 'rm /usr/lib/libsmbconf.so.0.0.1' "$scratch/rootfs.ext2" >/dev/null 2>&1
    sh "$source_dir/support/tests/stage-samba-root-file.sh" "$debugfs" \
        "$scratch/rootfs.ext2" "$experiment/bin/default/source3/utils/smbstatus.inst" \
        /usr/bin/smbstatus "$scratch/check" 0100755
    sh "$source_dir/support/tests/stage-samba-root-file.sh" "$debugfs" \
        "$scratch/rootfs.ext2" "$experiment/bin/default/source3/libsmbconf.inst.so" \
        /usr/lib/libsmbconf.so.0.0.1 "$scratch/check" 0100755
    status_hash=$(sha256sum "$experiment/bin/default/source3/utils/smbstatus.inst" | cut -d ' ' -f1)
    library_hash=$(sha256sum "$experiment/bin/default/source3/libsmbconf.inst.so" | cut -d ' ' -f1)
fi
"$target/../host/bin/arm-buildroot-linux-gnueabi-gcc" -std=c11 -Wall -Wextra -Werror -O2 -static \
    "$source_dir/support/tests/samba-status-producer-deadline.c" -o "$scratch/deadline"
sh "$source_dir/support/tests/stage-samba-root-file.sh" "$debugfs" \
    "$scratch/rootfs.ext2" "$scratch/deadline" \
    /usr/sbin/phantowd-status-producer-deadline "$scratch/check" 0100755
sh "$source_dir/support/tests/stage-samba-root-file.sh" "$debugfs" \
    "$scratch/rootfs.ext2" "$source_dir/support/tests/samba-status-producer-init.sh" \
    /usr/sbin/phantowd-samba-root-init "$scratch/check" 0100755
timeout --signal=TERM --kill-after=5 60 qemu-system-arm \
    -M versatilepb -cpu arm926 -m 256M -nographic -no-reboot -nic none \
    -object rng-random,id=producer-rng,filename=/dev/urandom \
    -device virtio-rng-pci,rng=producer-rng \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 phantowd_status_producer_fixture=1 init=/usr/sbin/phantowd-samba-root-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    >"$scratch/guest.log" 2>&1 &
child_pid=$!
guest_status=0
wait "$child_pid" || guest_status=$?
child_pid=
python3 -B "$source_dir/support/tests/samba_status_producer_fixture.py" record "$scratch/guest.log" "$guest_status"
[ "$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f1)" = "$base_hash" ]
echo 'PHANTOWD_STATUS_PRODUCER_BASE_UNCHANGED scope=qemu-only'
[ "$guest_status" -eq 0 ] || exit 1
python3 -B "$source_dir/support/tests/samba_status_producer_fixture.py" verify \
    "$scratch/guest.log" "$status_hash" "$tool_hash" "$dump_hash" "$library_hash"
echo 'PHANTOWD_STATUS_PRODUCER_COMPLETE base_unchanged=true complete_image=false scope=qemu-only'
