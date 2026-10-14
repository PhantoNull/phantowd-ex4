#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Loader only, no daemon/NIC/data disk. Test drops privileges before loading.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs -o nosuid,nodev,noexec,size=64k,mode=1777 tmpfs /tmp
if /usr/sbin/phantowd-server-capture-test; then
    echo PHANTOWD_SERVER_CAPTURE_GUEST_DONE
else
    echo PHANTOWD_SERVER_CAPTURE_GUEST_FAILED
fi
sync
reboot -f
