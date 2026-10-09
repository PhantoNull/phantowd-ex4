#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Fixed root construction/admission only, no client or daemon execution.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
run_fixture() {
    mount -t proc -o nosuid,nodev,noexec proc /proc || return 1
    mount -t sysfs -o nosuid,nodev,noexec sysfs /sys || return 1
    mount -t tmpfs -o mode=0755,size=48m,nosuid,nodev,noexec tmpfs /run || return 1
    mkdir -m 0700 /run/phantowd-pending-client-input /run/phantowd-pending-client-bootstrap || return 1
    mount -t tmpfs -o mode=0700,size=32m,nosuid,nodev tmpfs /run/phantowd-pending-client-input || return 1
    mount -t tmpfs -o mode=0700,size=1m,nosuid,nodev tmpfs /run/phantowd-pending-client-bootstrap || return 1
    /usr/sbin/phantowd-pending-client-inputs stage || return 1
    mount -o remount,ro,nosuid,nodev /run/phantowd-pending-client-input || return 1
    mount -o remount,ro,nosuid,nodev /run/phantowd-pending-client-bootstrap || return 1
    /usr/sbin/phantowd-pending-client-inputs retain
}
if run_fixture; then
    echo PHANTOWD_PENDING_INPUTS_GUEST_DONE
else
    echo PHANTOWD_PENDING_INPUTS_GUEST_FAILED
fi
sync
reboot -f
