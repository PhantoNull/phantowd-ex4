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
mount -t tmpfs tmpfs /run
mkdir -p /run/nfs
: > /run/nfs/etab
trap 'echo PHANTOWD_NFS_PEER_ERROR; exec /sbin/reboot -f' EXIT
case " $(cat /proc/cmdline) " in
    *' phantowd_nfs_peer=server '*) role=server; host=1 ;;
    *' phantowd_nfs_peer=client '*) role=client; host=2 ;;
    *) exit 1 ;;
esac
ifconfig lo up
for device in /sys/class/net/*; do
    [ "$(cat "$device/address")" = "52:54:00:12:34:0$host" ] || continue
    ifconfig "${device##*/}" "192.0.2.$host" netmask 255.255.255.252 up
done
mkdir -p /proc/fs/nfsd
mount -t nfsd nfsd /proc/fs/nfsd
/usr/bin/phantowd-api --qemu-nfs-test="peer-$role"
trap - EXIT
exec /sbin/reboot -f
