#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Explicit disposable guest only; no normal init/services or data-disk access.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
prepare() {
    mount -t proc proc /proc || return 1
    mount -t sysfs sysfs /sys || return 1
    grep -Eq '(^| )phantowd_nfs_code_fixture=1( |$)' /proc/cmdline || return 1
    mount -t tmpfs -o mode=0755,size=32m,nosuid,nodev tmpfs /run || return 1
}
if prepare && /usr/sbin/phantowd-nfs-code-fixture; then
    echo PHANTOWD_NFS_CODE_DONE
else
    echo PHANTOWD_NFS_CODE_FAILED
fi
reboot -f
