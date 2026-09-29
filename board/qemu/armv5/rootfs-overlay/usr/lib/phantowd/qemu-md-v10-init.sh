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
trap 'echo PHANTOWD_MD_V10_ERROR; exec /sbin/reboot -f' EXIT
/usr/bin/phantowd-api --qemu-md-v10-fixture
trap - EXIT
exec /sbin/reboot -f
