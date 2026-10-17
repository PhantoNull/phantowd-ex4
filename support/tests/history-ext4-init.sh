#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Opt-in synthetic ext4 history qualification; never product boot/CI default.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
awk '$2 == "/dev" && $3 == "devtmpfs" { found = 1 } END { exit !found }' /proc/mounts
mount -t tmpfs -o nosuid,nodev,noexec,size=16m,mode=0755 tmpfs /run
mount -t tmpfs -o nosuid,nodev,noexec,size=16m,mode=1777 tmpfs /tmp
mkdir /run/phantowd-revisionstore-media
mount -t ext4 -o rw,nosuid,nodev,noexec /dev/sdb /run/phantowd-revisionstore-media
export TMPDIR=/run/phantowd-revisionstore-media
echo 'PHANTOWD_HISTORY_EXT4_PREPARED synthetic_ext4=true snapshot=true stages=21 admission=false scope=qemu-only'
run_tests() {
    selected='^(TestHistoryExt4RemountRejectsUnlinkedReadPin|TestRuntimeHistoryWriterOnExt4|TestRuntimeHistoryObserverAfterExt4ProcessLoss)$'
    /usr/sbin/phantowd-policy-operation-tests -test.run "$selected" -test.timeout 45s -test.count 1 -test.v || return 1
    umount /tmp || return 1
    umount /run/phantowd-revisionstore-media || return 1
}
if run_tests; then
    echo 'PHANTOWD_HISTORY_EXT4_DONE sigkill=21 original_refs=true first_record_preserved=true runtime_reader=true pending_review=true review=true loss_observer_readonly=true process_boundary=true normal_unmount=true scope=qemu-only'
else
    echo PHANTOWD_HISTORY_EXT4_FAILED
fi
sync
reboot -f
