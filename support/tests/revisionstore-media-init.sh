#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Dedicated synthetic storage only; no service/API/NAS or physical disks.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
awk '$2 == "/dev" && $3 == "devtmpfs" { found = 1 } END { exit !found }' /proc/mounts
mount -t tmpfs -o nosuid,nodev,noexec,size=16m,mode=0755 tmpfs /run
mkdir /run/phantowd-revisionstore-media
mount -t ext4 -o rw,nosuid,nodev,noexec /dev/sdb /run/phantowd-revisionstore-media
export TMPDIR=/run/phantowd-revisionstore-media
echo 'PHANTOWD_REVISIONSTORE_MEDIA_PREPARED synthetic_ext4=true snapshot=true profiles=2 stages=7 scope=qemu-only'
if /usr/sbin/phantowd-revisionstore-media-tests -test.run '^(TestBootstrap.*|TestNASBootstrapAdapterNeverImportsLegacyState|TestBundleSIGKILLRecovery|TestNASBundleSIGKILLRecovery|TestRevisionStoreMediaReadOnlyRetainsConfirmedPolicyAndReview|TestRevisionStoreMediaFullFilesystemRetainsConfirmedPolicyAndReview|TestNASEvidenceMedia.*)$' -test.timeout 45s -test.count 1 -test.v; then
    umount /run/phantowd-revisionstore-media
    echo 'PHANTOWD_REVISIONSTORE_MEDIA_DONE sigkill=14 readonly=true enospc=true bootstrap=true normal_unmount=true scope=qemu-only'
else
    echo PHANTOWD_REVISIONSTORE_MEDIA_FAILED
fi
sync
reboot -f
