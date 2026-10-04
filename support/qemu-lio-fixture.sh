#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Host non-root runner; guest alone may configure synthetic LIO.
set -eu
base=${1:?verified base artifact directory required}
kernel=${2:?compiled research zImage required}
dtb=${3:?compiled research DTB required}
client=${4:?compiled synthetic initiator required}
source_dir=${5:?source checkout required}
log=${6:?output log required}
required_mutual=${PHANTOWD_LIO_REQUIRE_MUTUAL:-0}
case "$required_mutual" in 0) mutual_mode=default ;; 1) mutual_mode=strict ;; *) exit 1 ;; esac
for input in "$base" "$kernel" "$dtb" "$client" "$source_dir" "$log"; do
    case "$input" in /*) ;; *) exit 1 ;; esac
    case "$input" in *[!a-zA-Z0-9_./-]*) exit 1 ;; esac
done
for file in "$base/rootfs.ext2" "$base/SHA256SUMS" "$kernel" "$dtb" "$client"; do
    [ -f "$file" ] && [ ! -L "$file" ]
done
(cd "$base" && sha256sum -c SHA256SUMS)
tmpdir=${TMPDIR:-/tmp}
case "$tmpdir" in /*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts
temporary=$(mktemp -d "$tmpdir/phantowd-lio-guest.XXXXXX")
export TMPDIR="$temporary"
qemu_pid=
cleanup() {
    if [ -n "$qemu_pid" ]; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    rm -f "$temporary/rootfs.ext2" "$temporary/verify" "$temporary/qemu.log"
    rmdir "$temporary"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
root_hash=$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')
cp "$base/rootfs.ext2" "$temporary/rootfs.ext2"
replace() {
    from=$1
    to=$2
    debugfs -w -R "write $from $to" "$temporary/rootfs.ext2"
    debugfs -w -R "set_inode_field $to mode 0100755" "$temporary/rootfs.ext2"
    debugfs -R "dump $to $temporary/verify" "$temporary/rootfs.ext2"
    cmp "$from" "$temporary/verify"
    rm "$temporary/verify"
}
replace "$client" /usr/libexec/phantowd-iscsi-fixture-client
replace "$source_dir/support/fixtures/qemu-lio-init.sh" /usr/libexec/phantowd-lio-fixture-init
: > "$log"
qemu-system-arm -M versatilepb -cpu arm926 -m 256M \
    -kernel "$kernel" -dtb "$dtb" \
    -drive "file=$temporary/rootfs.ext2,if=none,id=rootdisk,format=raw,snapshot=on" \
    -device lsi53c895a,id=scsi0 \
    -device scsi-hd,bus=scsi0.0,drive=rootdisk \
    -object rng-random,filename=/dev/urandom,id=fixture-rng \
    -device virtio-rng-pci,rng=fixture-rng \
    -append "rootwait root=/dev/sda ro console=ttyAMA0,115200 init=/usr/libexec/phantowd-lio-fixture-init phantowd.lio_mutual=$mutual_mode" \
    -display none -serial stdio -monitor none -no-reboot -nic none \
    > "$temporary/qemu.log" 2>&1 &
qemu_pid=$!
attempt=0
while kill -0 "$qemu_pid" 2>/dev/null && [ "$attempt" -lt 180 ]; do
    if grep -E 'PHANTOWD_LIO_ERROR|PHANTOWD_LIO_CLIENT_ERROR|Kernel panic' "$temporary/qemu.log" >/dev/null; then
        break
    fi
    sleep 1
    attempt=$((attempt + 1))
done
cat "$temporary/qemu.log" > "$log"
if kill -0 "$qemu_pid" 2>/dev/null; then
    echo 'LIO guest failed or exceeded its fixed budget' >&2
    exit 1
fi
status=0
wait "$qemu_pid" || status=$?
qemu_pid=
[ "$status" -eq 0 ]
if [ "$required_mutual" = 1 ]; then
    python3 -B "$source_dir/support/container/qemu_lio_result.py" --required-mutual "$log"
else
    python3 -B "$source_dir/support/container/qemu_lio_result.py" "$log"
fi
[ "$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')" = "$root_hash" ]
(cd "$base" && sha256sum -c SHA256SUMS)
echo 'QEMU ARMv5 synthetic LIO fixture passed'
