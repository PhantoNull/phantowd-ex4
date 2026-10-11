#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Private C-to-Go bytes/credentialled packets; no active server or service owner.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
run_fixture() {
    mount -t proc -o nosuid,nodev,noexec proc /proc || return 1
    mount -t tmpfs -o mode=0700,size=1m,nosuid,nodev,noexec tmpfs /tmp || return 1
    /usr/sbin/phantowd-server-open-source-test || return 1
    PHANTOWD_SERVER_OPEN_WIRE_FIXTURE=1 GOMAXPROCS=1 GOMEMLIMIT=64MiB \
        /usr/sbin/phantowd-server-open-wire-test -test.v -test.count=1 \
        -test.run='^TestPendingServerOpen' -test.timeout=20s
}
if run_fixture; then
    echo PHANTOWD_SERVER_OPEN_SOURCE_GUEST_DONE
else
    echo PHANTOWD_SERVER_OPEN_SOURCE_GUEST_FAILED
fi
sync
reboot -f
