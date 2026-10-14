#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Synthetic boundary guest only. No server, libsmbclient or physical storage.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
run_fixture() {
    mount -t proc -o nosuid,nodev,noexec proc /proc || return 1
    mount -t sysfs -o nosuid,nodev,noexec sysfs /sys || return 1
    mount -t tmpfs -o mode=0755,size=8m,nosuid,nodev,noexec tmpfs /run || return 1
    mkdir -m 0700 /run/phantowd-pending-client-root || return 1
    mkdir -m 0755 /run/phantowd-pending-client-input || return 1
    mount -t tmpfs -o mode=0755,size=2m,nosuid,nodev tmpfs /run/phantowd-pending-client-input || return 1
    input=/run/phantowd-pending-client-input
    mkdir -p "$input/fixture" "$input/sys/firmware/devicetree/base" || return 1
    cp /usr/sbin/phantowd-pending-launcher-boundary "$input/fixture/pending-write" || return 1
    chmod 0555 "$input/fixture/pending-write" || return 1
    cmp /usr/sbin/phantowd-pending-launcher-boundary "$input/fixture/pending-write" || return 1
    cp /sys/firmware/devicetree/base/model "$input/sys/firmware/devicetree/base/model" || return 1
    chmod 0444 "$input/sys/firmware/devicetree/base/model" || return 1
    cmp /sys/firmware/devicetree/base/model "$input/sys/firmware/devicetree/base/model" || return 1
    mount -o remount,ro,nosuid,nodev "$input" || return 1
    /usr/sbin/phantowd-pending-launcher-boundary
}
if run_fixture; then
    echo PHANTOWD_PENDING_LAUNCHER_GUEST_DONE
else
    echo PHANTOWD_PENDING_LAUNCHER_GUEST_FAILED
fi
sync
reboot -f
