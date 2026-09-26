#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Guest-only integration fixture. Never run on a host or physical NAS.
set -eu

# shellcheck disable=SC1091 # fixed QEMU overlay file
. /etc/phantowd-release
[ "$PHANTOWD_TARGET" = qemu-armv5 ] && [ "$PHANTOWD_FLASHABLE" = no ] || exit 1
# The Go fixture additionally refuses non-ARMv5 / non-Versatile PB machines.
candidate=$(/usr/bin/phantowd-api --qemu-nfs-test=exports) || exit 1

workspace=/srv/phantowd-nfs-policy-smoke
anchor=/srv/phantowd/volumes/11111111-2222-3333-4444-555555555555
exports_file=/etc/exports.d/phantowd-policy-smoke.exports
rw_path='RW #1 "quoted"'
for unused in "$workspace" "$anchor" "$exports_file"; do
    if [ -e "$unused" ] || [ -L "$unused" ]; then
        echo 'PHANTOWD_QEMU_ERROR nfs-policy-fixture-already-exists'
        exit 1
    fi
done
mkdir -p "$workspace/rw-client" "$workspace/ro-client" "$workspace/denied-client" \
    "$anchor/$rw_path" "$anchor/read-only" "$anchor/denied-client" /etc/exports.d

rw_mounted=no
ro_mounted=no
anchor_mounted=no
cleanup() {
    # shellcheck disable=SC2317 # trap entry
    result=$?
    trap - EXIT INT TERM
    # Only mounts/exports created by this fixed disposable guest fixture.
    # Failure is reported; no lazy/forced unmount or global unexport fallback.
    if [ "$ro_mounted" = yes ]; then umount "$workspace/ro-client" || result=1; fi
    if [ "$rw_mounted" = yes ]; then umount "$workspace/rw-client" || result=1; fi
    rm -f "$exports_file" || result=1
    exportfs -r || result=1
    if [ "$anchor_mounted" = yes ]; then umount "$anchor" || result=1; fi
    if [ "$result" -ne 0 ]; then echo 'PHANTOWD_QEMU_ERROR nfs-policy-fixture-failed'; fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

printf '%s\n' "$candidate" >"$exports_file"
# exportfs lists configured entries even without a backing mount. Probe the
# mountd access decision instead of confusing the table with usable exports.
exportfs -r
/usr/bin/phantowd-api --qemu-nfs-test=guard

# The smoke runner creates this entire 16-MiB virtual disk from scratch;
# none of these fixed device/path assumptions are product discovery logic.
/usr/bin/phantowd-api --qemu-nfs-test=verify-disk
mount -t ext2 -o rw /dev/sdb "$anchor"
anchor_mounted=yes
mkdir "$anchor/$rw_path" "$anchor/read-only" "$anchor/denied-client"
chown 101000:101000 "$anchor/$rw_path" "$anchor/read-only" "$anchor/denied-client"
chmod 0770 "$anchor/$rw_path" "$anchor/read-only" "$anchor/denied-client"
printf '%s\n' phantowd-nfs-ro-marker >"$anchor/read-only/marker"
chmod 0644 "$anchor/read-only/marker"
exportfs -r
exportfs -s >"$workspace/export-table"
if [ "$(grep -c 'fsid=aaaaaaaa-bbbb-cccc-dddd-' "$workspace/export-table")" -ne 3 ]; then
    echo 'PHANTOWD_QEMU_ERROR nfs-policy-export-count-mismatch'
    cat "$workspace/export-table"
    exit 1
fi

# soft/nolock are deliberate bounded test settings, not product mount policy.
if ! /usr/bin/phantowd-api --qemu-nfs-test=mount-rw; then
    echo 'NFS generated-policy fixture mount diagnostics:'
    cat "$workspace/export-table"
    grep -F "$anchor" /proc/self/mountinfo
    tail -n 15 /var/log/messages
    exit 1
fi
rw_mounted=yes
/usr/bin/phantowd-api --qemu-nfs-test=mount-ro
ro_mounted=yes
for client in rw-client ro-client; do
    awk -v point="$workspace/$client" \
        '$2 == point && $3 == "nfs" && $4 ~ /(^|,)rw(,|$)/ && $4 ~ /vers=3/ && $4 ~ /proto=tcp/ { found=1 } END { exit !found }' \
        /proc/mounts
done
/usr/bin/phantowd-api --qemu-nfs-test=io

/usr/bin/phantowd-api --qemu-nfs-test=denied-client

# A separate loopback smbd instance exercises generated policy and effective
# Unix permissions while the verified disposable data disk is still mounted.
/usr/bin/phantowd-api --qemu-smb-test
/usr/bin/phantowd-api --qemu-mount-guard-test

umount "$workspace/ro-client"
ro_mounted=no
umount "$workspace/rw-client"
rw_mounted=no
# Withdraw generated exports before the artificial volume mount is removed.
rm -f "$exports_file"
exportfs -r
unmount_attempt=0
while ! umount "$anchor" 2>"$workspace/unmount.log"; do
    unmount_attempt=$((unmount_attempt + 1))
    if [ "$unmount_attempt" -ge 10 ]; then
        cat "$workspace/unmount.log"
        echo 'PHANTOWD_QEMU_ERROR nfs-policy-volume-still-busy-after-revocation'
        exit 1
    fi
    sleep 1
    # Flush kernel export caches only in this isolated disposable guest.
    # This is not per-volume production orchestration or a forced unmount.
    exportfs -f
done
anchor_mounted=no
printf '%s\n' "$candidate" >"$exports_file"
exportfs -r
/usr/bin/phantowd-api --qemu-nfs-test=guard
rm -f "$exports_file"
exportfs -r
trap - EXIT INT TERM
echo 'PHANTOWD_NFS_POLICY_IO_READY generated=exportfs rw=sync-verified ro=EROFS uid=101000 gid=101000 denied_client=true mount_guard=true scope=qemu-fixture-only'
