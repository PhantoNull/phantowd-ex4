#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc || exit 1
# No networking, extra disks, SMART binary or device probes in this fixture.
if /usr/sbin/phantowd-smart-report-test -test.v -test.timeout=45s; then
    echo 'PHANTOWD_SMART_REPORT_TESTS_READY scope=synthetic-parser-only'
else
    echo 'PHANTOWD_SMART_REPORT_TESTS_FAILED'
fi
sync
reboot -f
