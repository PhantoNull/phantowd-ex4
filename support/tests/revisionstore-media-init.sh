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
run_tests() {
    selected='^(TestBootstrapAuthorityRetainsOneLockAcrossFreshReadOnlyObservations|TestBootstrapAuthorityWritableLifetimeDriftKeepsReviewAndLockWithUnchangedMetadata|TestBootstrapAuthorityCanceledReadRetainsReviewButPreworkCancelHasNoEffects|TestBootstrapAuthorityRejectsCopiesSerializationAndInvalidConstruction|TestBootstrapAuthorityUncertainCloseRetainsUnattemptedRootWithoutRetry|TestBootstrapEmptyDirectoryObservationDoesNotInitializeOrChangeMetadata|TestBootstrapPendingEvidenceIsNeverPromotedOrDiscarded|TestBootstrapValidCurrentPolicyObservationDoesNotChangeFilesOrReturnPolicy|TestBootstrapInvalidOrUnsupportedPolicyIsNeverMissingOrReset|TestBootstrapUnrecognizedEntriesArePreservedWithoutClaimingEmptyOrConfirmed|TestBootstrapRefusesUnsafeNamedObjectsWithoutOpeningTheirData|TestBootstrapRefusesBusyCanceledMissingAndOversizedStateWithoutMutation|TestBootstrapWritableOpenDuringDecodeRefusesEvenWithUnchangedMetadata|TestBootstrapCancellationDuringDecodeReturnsNoObservation|TestBootstrapRefusesInvalidCodecDirectoryAndMissingRootWithoutInitialization|TestBootstrapParentAndSiblingLocksDoNotReplaceOriginalPolicyLock|TestBundleSIGKILLRecovery|TestNASBundleSIGKILLRecovery|TestRevisionStoreMediaReadOnlyRetainsConfirmedPolicyAndReview|TestRevisionStoreMediaFullFilesystemRetainsConfirmedPolicyAndReview|TestNASBootstrapAdapterNeverImportsLegacyState)$'
    started=$(cut -d . -f 1 /proc/uptime) || return 1
    /usr/sbin/phantowd-revisionstore-media-tests -test.run "$selected" -test.timeout 45s -test.count 1 -test.v || return 1
    now=$(cut -d . -f 1 /proc/uptime) || return 1
    # Reserve one second for rounded uptime accounting; do not grant a second
    # independent 45-second suite or increase the original 60-second VM limit.
    remaining=$((44 + started - now))
    [ "$remaining" -gt 0 ] && [ "$remaining" -le 45 ] || return 1
    mount -t tmpfs -o nosuid,nodev,noexec,size=16m,mode=1777 tmpfs /tmp || return 1
    operation_selected='^(TestPolicyOperationSIGKILLObservation|TestPolicyOperationSyscallSIGKILLObservation|TestRuntimeBundleObserverAfterProcessLoss|TestRuntimeBundleObserverOnReadOnlyExt4|TestRuntimeHistoryObserverAfterProcessLoss)$'
    echo 'PHANTOWD_POLICY_OPERATION_PROCESSLOSS_PREPARED synthetic_tmpfs=true snapshot=true stages=77 runtime_reader=true history_reader=true readonly_ext4=true admission=false scope=qemu-only'
    /usr/sbin/phantowd-policy-operation-tests -test.run "$operation_selected" -test.timeout "${remaining}s" -test.count 1 -test.v || return 1
    umount /tmp || return 1
    echo 'PHANTOWD_POLICY_OPERATION_PROCESSLOSS_DONE sigkill=77 runtime_reader=true history_reader=true readonly_ext4=true original_refs=true first_record_preserved=true readonly=true review=true pending_review=true normal_cleanup=true scope=qemu-only'
    umount /run/phantowd-revisionstore-media || return 1
}
if run_tests; then
    echo 'PHANTOWD_REVISIONSTORE_MEDIA_DONE sigkill=14 readonly=true enospc=true bootstrap=true normal_unmount=true scope=qemu-only'
else
    echo PHANTOWD_REVISIONSTORE_MEDIA_FAILED
fi
sync
reboot -f
