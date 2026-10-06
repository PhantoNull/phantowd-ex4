#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Dedicated PID 1 for the host-owned MD v1.0 metadata fixture.
set -efu
[ "$$" -eq 1 ]
mount -t proc proc /proc
mount -t sysfs sysfs /sys
# The pinned kernel auto-mounts devtmpfs before execing init.
grep -q ' /dev devtmpfs ' /proc/mounts
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
mount -t tmpfs -o mode=0755,nosuid,nodev,size=1m tmpfs /srv/phantowd/volumes
trap 'echo PHANTOWD_MD_V10_ERROR; /etc/init.d/S40phantowd-storage-broker stop >/dev/null 2>&1 || true; exec /sbin/reboot -f' EXIT
/sbin/mdev -s
/etc/init.d/S40phantowd-storage-broker start
/usr/bin/phantowd-api --qemu-md-v10-fixture
/etc/init.d/S40phantowd-storage-broker stop
trap - EXIT
exec /sbin/reboot -f
