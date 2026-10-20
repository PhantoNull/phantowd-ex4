#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Dedicated NIC-less, diskless-data component fixture. Root image is a snapshot.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
prepare() {
    mount -t proc proc /proc || return 1
    mount -t sysfs sysfs /sys || return 1
    mount -t tmpfs -o mode=0755,size=16m,nosuid,nodev,noexec tmpfs /run || return 1
    mount -t nfsd -o nosuid,nodev,noexec nfsd /proc/fs/nfsd || return 1
    ip link set lo up || return 1
    printf '%s\n' '-2 -4 +3' >/proc/fs/nfsd/versions || return 1
}
if prepare && /usr/sbin/phantowd-nfs-code-fixture --kernel-socket-refusal; then
    echo PHANTOWD_NFS_KERNEL_SOCKET_DONE
else
    echo PHANTOWD_NFS_KERNEL_SOCKET_FAILED
fi
reboot -f
