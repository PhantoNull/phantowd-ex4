#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Explicit disposable guests only; source mode has one synthetic snapshot disk.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
prepare_source_identity() {
    # Fixed locked test identity in NEW guest RAM. Copy the whole directory:
    # the unchanged census rejects individual cross-mount source files.
    ! awk -F: '$1 == "nfsfixture" || $3 == 1000 { found=1 } END { exit !found }' /etc/passwd || return 1
    ! awk -F: '$1 == "nfsfixture" || $3 == 1000 { found=1 } END { exit !found }' /etc/group || return 1
    cp -a /etc /run/nfs-fixture-etc || return 1
    printf 'nfsfixture:!:1000:1000::/:/sbin/nologin\n' >>/run/nfs-fixture-etc/passwd || return 1
    printf 'nfsfixture:!:1000:\n' >>/run/nfs-fixture-etc/group || return 1
    chmod 0644 /run/nfs-fixture-etc/passwd /run/nfs-fixture-etc/group || return 1
    mount -o bind /run/nfs-fixture-etc /etc || return 1
    mount -o remount,bind,ro /etc || return 1
}
prepare() {
    mount -t proc proc /proc || return 1
    mount -t sysfs sysfs /sys || return 1
    grep -Eq '(^| )phantowd_nfs_code_fixture=1( |$)' /proc/cmdline || return 1
    if grep -Eq '(^| )phantowd_nfs_source_fixture=1( |$)' /proc/cmdline; then
        mount -t tmpfs -o mode=0755,size=32m,nosuid,nodev,noexec tmpfs /run || return 1
        mount -t tmpfs -o mode=0755,size=1m,nosuid,nodev,noexec tmpfs /srv/phantowd/volumes || return 1
        mkdir /srv/phantowd/volumes/qemu-only || return 1
        mount -t ext2 -o rw,nosuid,nodev,noexec /dev/sdb /srv/phantowd/volumes/qemu-only || return 1
        mount -t nfsd -o nosuid,nodev,noexec nfsd /proc/fs/nfsd || return 1
        ip link set lo up || return 1
        prepare_source_identity || return 1
        return 0
    fi
    mount -t tmpfs -o mode=0755,size=32m,nosuid,nodev tmpfs /run || return 1
    mount -t nfsd nfsd /proc/fs/nfsd || return 1
    ip link set lo up || return 1
}
if prepare; then
    if grep -Eq '(^| )phantowd_nfs_source_daemon_loss_fixture=1( |$)' /proc/cmdline; then
        if /usr/sbin/phantowd-nfs-code-fixture --source-daemon-loss; then
            echo PHANTOWD_NFS_SOURCE_DAEMON_LOSS_DONE
        else
            echo PHANTOWD_NFS_SOURCE_DAEMON_LOSS_FAILED
        fi
    elif grep -Eq '(^| )phantowd_nfs_source_loss_fixture=1( |$)' /proc/cmdline; then
        if /usr/sbin/phantowd-nfs-code-fixture --source-loss; then
            echo PHANTOWD_NFS_SOURCE_LOSS_DONE
        else
            echo PHANTOWD_NFS_SOURCE_LOSS_FAILED
        fi
    elif grep -Eq '(^| )phantowd_nfs_source_fixture=1( |$)' /proc/cmdline; then
        if /usr/sbin/phantowd-nfs-code-fixture --source-binding; then
            echo PHANTOWD_NFS_SOURCE_DONE
        else
            echo PHANTOWD_NFS_SOURCE_FAILED
        fi
    elif /usr/sbin/phantowd-nfs-code-fixture; then
        echo PHANTOWD_NFS_CODE_DONE
    else
        echo PHANTOWD_NFS_CODE_FAILED
    fi
else
    echo PHANTOWD_NFS_CODE_FAILED
fi
reboot -f
