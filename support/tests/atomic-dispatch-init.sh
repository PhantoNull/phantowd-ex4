#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc || exit 1
mount -t tmpfs -o size=1m,mode=0700 tmpfs /run || exit 1
ulimit -f 128 || exit 1
# BusyBox ash supports the Linux core-file limit; this is not generic POSIX sh.
# shellcheck disable=SC3045
ulimit -c 0 || exit 1
failed=0
/bin/busybox env -i /usr/sbin/phantowd-atomic-dispatch > /run/positive.log 2>&1 || failed=1
cat /run/positive.log
status=0
/bin/busybox env -i /usr/sbin/phantowd-atomic-dispatch --missing-symbol > /run/negative.log 2>&1 || status=$?
if [ "$failed" = 0 ] && [ "$status" = 1 ] &&
    grep -x PHANTOWD_ATOMIC_FAILED /run/negative.log >/dev/null &&
    ! grep PHANTOWD_ATOMIC_READY /run/negative.log >/dev/null; then
    echo 'PHANTOWD_ATOMIC_NEGATIVE missing-symbol=refused'
    echo 'PHANTOWD_ATOMIC_DONE'
else
    echo 'PHANTOWD_ATOMIC_GUEST_FAILED'
fi
sync
reboot -f
