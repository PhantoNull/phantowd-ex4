#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# CPU-only generic-backend producer, no data disks or hardware commands.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc || exit 1
mount -t tmpfs -o size=4m,mode=0700 tmpfs /run || exit 1
mkdir /run/corpus || exit 1
export PHANTOWD_SMART_REPLAY_CORPUS=/run/corpus PHANTOWD_REPLAY_VERSION=7.5
failed=0
# Bound accidental output growth; the Go reader separately enforces 64KiB.
ulimit -f 128 || exit 1
for entry in pass:0 fail:8 partial-fail:12 partial-pass:4 unsupported:4 disabled:0 empty:2; do
    name=${entry%:*}
    expected=${entry#*:}
    status=0
    /usr/sbin/phantowd-smartctl-replay -j -i -H - \
        <"/usr/share/phantowd-smart-replay/$name.trace" \
        >"/run/corpus/$name.json" 2>"/run/$name.stderr" || status=$?
    if [ "$status" != "$expected" ] || [ -s "/run/$name.stderr" ] || \
        grep -F 'REPLAY-IOCTL' "/run/corpus/$name.json" >/dev/null; then
        echo "PHANTOWD_SMART_ARM_PRODUCER_FAILED case=$name exit=$status"
        failed=1
        break
    fi
    echo "PHANTOWD_SMART_ARM_PRODUCER case=$name exit=$status"
done
if [ "$failed" = 0 ] && /usr/sbin/phantowd-smart-replay-test -test.v -test.timeout=45s; then
    echo 'PHANTOWD_SMART_ARM_REPLAY_READY scope=generic-synthetic-only version=7.5 cases=7'
    export PHANTOWD_SMART_CAPTURE_FIXTURE=generic-only
    if /usr/sbin/phantowd-smart-capture-test -test.v -test.run '^TestFixedProducerCapture$' -test.timeout=30s; then
        echo 'PHANTOWD_SMART_ARM_CAPTURE_READY scope=generic-synthetic-only source=fake cases=7'
    else
        echo 'PHANTOWD_SMART_ARM_CAPTURE_FAILED'
    fi
else
    echo 'PHANTOWD_SMART_ARM_REPLAY_FAILED'
fi
sync
reboot -f
