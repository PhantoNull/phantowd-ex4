#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Explicit synthetic two-boot path only, never normal firmware init.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
awk '$2 == "/dev" && $3 == "devtmpfs" { found = 1 } END { exit !found }' /proc/mounts
phase=''
read -r cmdline </proc/cmdline
set -f
for item in $cmdline; do
    case "$item" in
        phantowd_history_reboot_phase=*)
            [ -z "$phase" ] || exit 1
            phase=${item#*=}
            ;;
    esac
done
case "$phase" in produce|observe) ;; *) exit 1 ;; esac
mount -t tmpfs -o nosuid,nodev,noexec,size=16m,mode=0755 tmpfs /run
mount -t tmpfs -o nosuid,nodev,noexec,size=16m,mode=1777 tmpfs /tmp
mkdir /run/phantowd-revisionstore-media
if [ "$phase" = produce ]; then
    mount -t ext4 -o rw,nosuid,nodev,noexec /dev/sdb /run/phantowd-revisionstore-media
else
    mount -t ext4 -o ro,noload,nosuid,nodev,noexec /dev/sdb /run/phantowd-revisionstore-media
fi
export TMPDIR=/run/phantowd-revisionstore-media
echo "PHANTOWD_HISTORY_REBOOT_PREPARED phase=$phase scope=qemu-only"
run_tests() {
    /usr/sbin/phantowd-policy-operation-tests -test.run '^TestRuntimeHistoryAcrossCleanReboot$' -test.timeout 45s -test.count 1 -test.v &
    test_pid=$!
    wait "$test_pid" || return 1
    umount /tmp || return 1
    umount /run/phantowd-revisionstore-media || return 1
    echo "PHANTOWD_HISTORY_REBOOT_DONE phase=$phase pid=$test_pid normal_unmount=true scope=qemu-only"
}
if ! run_tests; then
    echo PHANTOWD_HISTORY_REBOOT_FAILED
fi
sync
reboot -f
