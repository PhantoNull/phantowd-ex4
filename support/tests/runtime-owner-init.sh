#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Disposable static-code Owner proof only; no service/product startup.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
prepare() {
    mount -t proc proc /proc || return 1
    mount -t sysfs sysfs /sys || return 1
    grep -Eq '(^| )phantowd_code_owner_fixture=1( |$)' /proc/cmdline || return 1
    mount -t tmpfs -o mode=0755,size=32m tmpfs /run || return 1
    export TMPDIR=/run
}
readiness() {
    /usr/sbin/phantowd-process-readiness-tests -test.v -test.run '^TestReadiness(CannotCommitAfterContextEnds|ContextChecksOriginalAndDerivedMonotonicDeadlines)$' -test.count=3 -test.cpu=1 -test.timeout=15s || return 1
    echo 'PHANTOWD_CODE_OWNER_READINESS_READY cases=8 repeats=3 late_ready_refused=true context_cause=true stopped=true generation_unchanged=true scope=qemu-only'
}
metadata() {
    /usr/sbin/phantowd-runtime-metadata-tests -test.v -test.run '^TestRetainedMetadata' -test.count=3 -test.cpu=1 || return 1
    echo 'PHANTOWD_CODE_OWNER_METADATA_READY late_cancellation=true original_pins=true transient_table_removed=true scope=qemu-only'
}
identity_context() {
    /usr/sbin/phantowd-identity-context-tests -test.v -test.run '^TestFileServiceLeaseAdmittedContextFailureKeepsCauseAndReview$' -test.count=3 -test.cpu=1 -test.timeout=15s || return 1
    echo 'PHANTOWD_CODE_OWNER_IDENTITY_CONTEXT_READY cases=4 repeats=3 context_cause=true private_cause=false review_retained=true retry=false scope=qemu-only'
}
if prepare && readiness && metadata && identity_context && /usr/sbin/phantowd-runtime-bundle-probe owner; then
    echo PHANTOWD_CODE_OWNER_DONE
else
    echo PHANTOWD_CODE_OWNER_FAILED
fi
reboot -f
