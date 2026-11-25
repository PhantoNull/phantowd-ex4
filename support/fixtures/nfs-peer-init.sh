#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# PID 1 for two disposable, directly connected QEMU guests only.
set -eu
export PATH=/sbin:/usr/sbin:/bin:/usr/bin
[ "$$" -eq 1 ]
mount -t proc proc /proc
mount -t sysfs sysfs /sys
grep -q ' /dev devtmpfs ' /proc/mounts
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
mkdir -p /run/rpcbind
trap 'echo PHANTOWD_NFS_PEER_ERROR; exec /sbin/reboot -f' EXIT
case " $(cat /proc/cmdline) " in
    *' phantowd_nfs_peer=server '*) role=server; nic=1; host=1 ;;
    *' phantowd_nfs_peer=client '*) role=client; nic=2; host=3 ;;
    *) exit 1 ;;
esac
ifconfig lo up
found=
for device in /sys/class/net/*; do
    [ "$(cat "$device/address")" = "52:54:00:12:34:0$nic" ] || continue
    [ -z "$found" ]
    found=1
    ifconfig "${device##*/}" "192.0.2.$host" netmask 255.255.255.248 up
done
[ -n "$found" ]
if [ "$role" = server ]; then
    /usr/bin/phantowd-api --qemu-nfs-test=verify-disk
    mkdir -p /srv/phantowd/volumes/qemu-only /proc/fs/nfsd
    mount -t ext2 -o rw /dev/sdb /srv/phantowd/volumes/qemu-only
    mount -t nfsd nfsd /proc/fs/nfsd
fi
/usr/bin/phantowd-api --qemu-nfs-test="peer-$role"
if [ "$role" = server ]; then
    umount /proc/fs/nfsd
    umount /srv/phantowd/volumes/qemu-only
fi
trap - EXIT
exec /sbin/reboot -f
