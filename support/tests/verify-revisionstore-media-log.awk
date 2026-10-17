# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
BEGIN {
    stage = "PHANTOWD_REVISIONSTORE_MEDIA_PREPARED synthetic_ext4=true snapshot=true profiles=2 stages=7 scope=qemu-only"
    done = "PHANTOWD_REVISIONSTORE_MEDIA_DONE sigkill=14 readonly=true enospc=true bootstrap=true normal_unmount=true scope=qemu-only"
    op_stage = "PHANTOWD_POLICY_OPERATION_PROCESSLOSS_PREPARED synthetic_tmpfs=true snapshot=true stages=77 runtime_reader=true history_reader=true readonly_ext4=true admission=false scope=qemu-only"
    op_done = "PHANTOWD_POLICY_OPERATION_PROCESSLOSS_DONE sigkill=77 runtime_reader=true history_reader=true readonly_ext4=true original_refs=true first_record_preserved=true readonly=true review=true pending_review=true normal_cleanup=true scope=qemu-only"
    operation[++op_required] = "TestPolicyOperationSIGKILLObservation"
    split("before-intent after-intent before-policy after-policy after-readback before-receipt after-receipt", operation_points, " ")
    for (i = 1; i <= 7; i++) { operation[++op_required] = "TestPolicyOperationSIGKILLObservation/" operation_points[i] }
    operation[++op_required] = "TestPolicyOperationSyscallSIGKILLObservation"
    split("intent policy receipt", operation_roles, " ")
    split("partial-write full-write file-sync file-close before-rename after-rename directory-sync", syscall_points, " ")
    for (r = 1; r <= 3; r++) {
        for (i = 1; i <= 7; i++) { operation[++op_required] = "TestPolicyOperationSyscallSIGKILLObservation/" operation_roles[r] "/" syscall_points[i] }
    }
    operation[++op_required] = "TestRuntimeBundleObserverAfterProcessLoss"
    for (i = 1; i <= 7; i++) { operation[++op_required] = "TestRuntimeBundleObserverAfterProcessLoss/" operation_points[i] }
    for (r = 1; r <= 3; r++) {
        for (i = 1; i <= 7; i++) { operation[++op_required] = "TestRuntimeBundleObserverAfterProcessLoss/" operation_roles[r] "/" syscall_points[i] }
    }
    operation[++op_required] = "TestRuntimeBundleObserverOnReadOnlyExt4"
    split("no-operation base published confirmed inconsistent missing-current policy-pending operation-pending", media_cases, " ")
    for (i = 1; i <= 8; i++) { operation[++op_required] = "TestRuntimeBundleObserverOnReadOnlyExt4/" media_cases[i] }
    operation[++op_required] = "TestRuntimeHistoryObserverAfterProcessLoss"
    for (r = 1; r <= 3; r++) {
        for (i = 1; i <= 7; i++) { operation[++op_required] = "TestRuntimeHistoryObserverAfterProcessLoss/" operation_roles[r] "/" syscall_points[i] }
    }
    expected[++required] = "TestBootstrapEmptyDirectoryObservationDoesNotInitializeOrChangeMetadata"
    expected[++required] = "TestBootstrapPendingEvidenceIsNeverPromotedOrDiscarded"
    expected[++required] = "TestBootstrapPendingEvidenceIsNeverPromotedOrDiscarded/false"
    expected[++required] = "TestBootstrapPendingEvidenceIsNeverPromotedOrDiscarded/true"
    expected[++required] = "TestBootstrapValidCurrentPolicyObservationDoesNotChangeFilesOrReturnPolicy"
    expected[++required] = "TestBootstrapInvalidOrUnsupportedPolicyIsNeverMissingOrReset"
    split("0 11 2 50", invalid, " ")
    for (i = 1; i <= 4; i++) { expected[++required] = "TestBootstrapInvalidOrUnsupportedPolicyIsNeverMissingOrReset/" invalid[i] }
    expected[++required] = "TestBootstrapUnrecognizedEntriesArePreservedWithoutClaimingEmptyOrConfirmed"
    expected[++required] = "TestBootstrapUnrecognizedEntriesArePreservedWithoutClaimingEmptyOrConfirmed/1"
    expected[++required] = "TestBootstrapUnrecognizedEntriesArePreservedWithoutClaimingEmptyOrConfirmed/16"
    expected[++required] = "TestBootstrapRefusesUnsafeNamedObjectsWithoutOpeningTheirData"
    split("shares.json .shares.pending", roles, " ")
    split("symlink hardlink fifo directory permissions", objects, " ")
    for (r = 1; r <= 2; r++) {
        for (i = 1; i <= 5; i++) { expected[++required] = "TestBootstrapRefusesUnsafeNamedObjectsWithoutOpeningTheirData/" roles[r] "/" objects[i] }
    }
    expected[++required] = "TestBootstrapRefusesBusyCanceledMissingAndOversizedStateWithoutMutation"
    expected[++required] = "TestBootstrapWritableOpenDuringDecodeRefusesEvenWithUnchangedMetadata"
    expected[++required] = "TestBootstrapCancellationDuringDecodeReturnsNoObservation"
    expected[++required] = "TestBootstrapRefusesInvalidCodecDirectoryAndMissingRootWithoutInitialization"
    split("partial-write full-write file-sync file-close before-rename after-rename directory-sync", points, " ")
    # bootstrap_authority_linux_test.go sorts before bootstrap_linux_test.go.
    # Prepend its independently required receipts to the existing collector list.
    for (i = required; i >= 1; i--) { expected[i+5] = expected[i] }
    expected[1] = "TestBootstrapAuthorityRetainsOneLockAcrossFreshReadOnlyObservations"
    expected[2] = "TestBootstrapAuthorityWritableLifetimeDriftKeepsReviewAndLockWithUnchangedMetadata"
    expected[3] = "TestBootstrapAuthorityCanceledReadRetainsReviewButPreworkCancelHasNoEffects"
    expected[4] = "TestBootstrapAuthorityRejectsCopiesSerializationAndInvalidConstruction"
    expected[5] = "TestBootstrapAuthorityUncertainCloseRetainsUnattemptedRootWithoutRetry"
    required += 5
    expected[++required] = "TestBootstrapParentAndSiblingLocksDoNotReplaceOriginalPolicyLock"
    split("TestBundleSIGKILLRecovery TestNASBundleSIGKILLRecovery", profiles, " ")
    for (p = 1; p <= 2; p++) {
        expected[++required] = profiles[p]
        for (i = 1; i <= 7; i++) { expected[++required] = profiles[p] "/" points[i] }
    }
    expected[++required] = "TestRevisionStoreMediaReadOnlyRetainsConfirmedPolicyAndReview"
    expected[++required] = "TestRevisionStoreMediaFullFilesystemRetainsConfirmedPolicyAndReview"
    expected[++required] = "TestNASBootstrapAdapterNeverImportsLegacyState"
    # The init selector is closed and checked against this exact top-level
    # catalogue before compilation/boot. Subprocess-only helpers never enroll.
    if (selection == 1 || selection == 2) {
        expression = "^("; separator = ""
        count = selection == 1 ? required : op_required
        for (i = 1; i <= count; i++) {
            candidate = selection == 1 ? expected[i] : operation[i]
            if (index(candidate, "/") == 0) {
                expression = expression separator candidate; separator = "|"
            }
        }
        print expression ")$"
        exit
    }
}
{ sub(/\r$/, "") }
/^[ \t]*--- PASS: / {
    name = $0
    sub(/^[ \t]*--- PASS: /, "", name)
    if (!sub(/ \([0-9]+(\.[0-9]+)?s\)$/, "", name)) { refused = 1; next }
    if (state == 1) { if (name != expected[++passed]) refused = 1 }
    else if (state == 3) { if (name != operation[++op_passed]) refused = 1 }
    else refused = 1
    next
}
/^PASS$/ {
    if (state == 1 && passed == required) state = 2
    else if (state == 3 && op_passed == op_required) state = 4
    else refused = 1
    next
}
/PHANTOWD_/ {
    if (state == 0 && $0 == stage) { state = 1; next }
    if (state == 2 && $0 == op_stage) { state = 3; next }
    if (state == 4 && $0 == op_done) { state = 5; next }
    if (state == 5 && $0 == done) { state = 6; next }
    refused = 1
}
/--- (FAIL|SKIP):|^FAIL$|testing: warning: no tests to run|Kernel panic|INTERNAL ERROR|AddressSanitizer|runtime error:|WARNING: DATA RACE/ { refused = 1 }
END {
    if (selection == 1 || selection == 2) exit 0
    if (state != 6 || passed != required || op_passed != op_required || refused) exit 1
}
