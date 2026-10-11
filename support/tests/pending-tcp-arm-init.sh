#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Test-only loopback observations. Never installed in a product image.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc || exit 1
mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys || exit 1
grep -q '^ARM Versatile PB' /sys/firmware/devicetree/base/model || exit 1
case " $(cat /proc/cmdline) " in
    *' phantowd_pending_tcp_wire=1 '*) ;;
    *) exit 1 ;;
esac
mount -t tmpfs -o size=4m,mode=0700 tmpfs /tmp || exit 1
ip link set lo up || exit 1
ulimit -f 128 || exit 1
if /usr/sbin/phantowd-pending-tcp-test -test.v -test.count=3 -test.timeout=30s -test.run '^TestPendingTCPWire'; then
    echo 'PHANTOWD_PENDING_TCP_ARM_DONE cases=11 repetitions=3 binding=false scope=qemu-only'
else
    echo 'PHANTOWD_PENDING_TCP_ARM_FAILED'
fi
sync
reboot -f
