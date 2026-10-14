#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Synthetic open records and temporary files only; no daemon/NIC/data disks.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
run_fixture() {
    mount -t proc -o nosuid,nodev,noexec proc /proc || return 1
    mount -t tmpfs -o mode=0700,size=1m,nosuid,nodev,noexec tmpfs /tmp || return 1
    /usr/sbin/phantowd-server-open-source-test
}
if run_fixture; then
    echo PHANTOWD_SERVER_OPEN_SOURCE_GUEST_DONE
else
    echo PHANTOWD_SERVER_OPEN_SOURCE_GUEST_FAILED
fi
sync
reboot -f
