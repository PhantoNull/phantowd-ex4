#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
prepare() {
    mount -t proc proc /proc || return 1
    mount -t sysfs sysfs /sys || return 1
    grep -q ' /dev devtmpfs ' /proc/mounts || mount -t devtmpfs devtmpfs /dev || return 1
    mount -t tmpfs tmpfs /run || return 1
}
if prepare && /usr/sbin/phantowd-service-launcher-fixture &&
    /usr/sbin/phantowd-service-launcher-fixture --prepare &&
    /usr/sbin/phantowd-service-launcher-owner-fixture &&
    /usr/sbin/phantowd-service-launcher-fixture --cleanup; then
    echo PHANTOWD_SERVICE_LAUNCHER_DONE
else
    echo PHANTOWD_SERVICE_LAUNCHER_FAILED
fi
sync
reboot -f
