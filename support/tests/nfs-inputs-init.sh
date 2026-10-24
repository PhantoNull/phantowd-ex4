#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Disposable code-data fixture; no NFS services or data exports.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
prepare() {
    mount -t proc proc /proc || return 1
    mount -t sysfs sysfs /sys || return 1
    grep -Eq '(^| )phantowd_nfs_inputs_fixture=1( |$)' /proc/cmdline || return 1
    mount -t tmpfs -o mode=0755,size=20m tmpfs /run || return 1
    export TMPDIR=/run
    /usr/sbin/phantowd-runtime-metadata-tests -test.v -test.run '^(TestNFSExpectedQEMU|TestNFSCodeProbe|TestNFSDocuments|TestQEMUNFSConfiguration)' -test.count=1 || return 1
    mkdir /run/phantowd-nfs-code || return 1
    mount -t tmpfs -o mode=0700,size=16m,nodev,nosuid tmpfs /run/phantowd-nfs-code || return 1
    IFS= read -r expected </usr/lib/phantowd/qemu-nfs-expected-root || return 1
    /usr/sbin/phantowd-runtime-bundle-probe nfs-code "$expected"
}
if prepare; then
    echo PHANTOWD_NFS_CODE_INPUTS_DONE
else
    echo PHANTOWD_NFS_CODE_INPUTS_FAILED
fi
reboot -f
