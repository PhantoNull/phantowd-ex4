#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Dedicated synthetic mapping guest: no daemon, NIC, mount of data or SMB I/O.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
run_fixture() {
    mount -t proc -o nosuid,nodev,noexec proc /proc || return 1
    mount -t sysfs -o nosuid,nodev,noexec sysfs /sys || return 1
    /usr/sbin/phantowd-pending-handle-source-test
}
if run_fixture; then
    echo PHANTOWD_PENDING_HANDLE_SOURCE_GUEST_DONE
else
    echo PHANTOWD_PENDING_HANDLE_SOURCE_GUEST_FAILED
fi
sync
reboot -f
