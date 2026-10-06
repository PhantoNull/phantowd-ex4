#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Dedicated PID 1 for a host-owned two-boot virtual-disk test. Only a guarded,
# guest-loopback Samba fixture is started; no ordinary NAS init/services.
set -efu
[ "$$" -eq 1 ]
mount -t proc proc /proc
mount -t sysfs sysfs /sys
# The pinned kernel auto-mounts devtmpfs before execing init. Require it;
# mounting a second instance fails with EBUSY on this baseline.
grep -q ' /dev devtmpfs ' /proc/mounts
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
# Do not install the reboot trap until the compiled exact-machine/virtual-disk
# guard passes. In particular, accidental shell invocation is rejected above.
/usr/bin/phantowd-api --qemu-nfs-test=verify-disk
trap 'echo PHANTOWD_STATE_ERROR; exec /sbin/reboot -f' EXIT
# The harness has no NIC. Only guest loopback is raised for bounded HTTP(S)
# transaction tests; no external interface, DHCP or listener is configured.
/sbin/ip link set dev lo up
phase=
# Kernel arguments are intentionally whitespace-separated words, not lines.
# shellcheck disable=SC2013
for option in $(cat /proc/cmdline); do
    case "$option" in
        phantowd.state=seed|phantowd.state=verify)
            [ -z "$phase" ]
            phase=${option#phantowd.state=}
            ;;
    esac
done
[ -n "$phase" ]
/usr/bin/phantowd-api --qemu-state-test="$phase"
# The helper has closed its stores and ordinarily unmounted the data disk.
echo "PHANTOWD_STATE_BOOT_READY phase=$phase scope=disposable-qemu-only"
trap - EXIT
exec /sbin/reboot -f
