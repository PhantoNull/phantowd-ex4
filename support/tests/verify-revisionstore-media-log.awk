# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
BEGIN {
    stage = "PHANTOWD_REVISIONSTORE_MEDIA_PREPARED synthetic_ext4=true snapshot=true profiles=2 stages=7 scope=qemu-only"
    done = "PHANTOWD_REVISIONSTORE_MEDIA_DONE sigkill=14 readonly=true enospc=true bootstrap=true normal_unmount=true scope=qemu-only"
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
    split("TestBundleSIGKILLRecovery TestNASBundleSIGKILLRecovery", profiles, " ")
    for (p = 1; p <= 2; p++) {
        expected[++required] = profiles[p]
        for (i = 1; i <= 7; i++) { expected[++required] = profiles[p] "/" points[i] }
    }
    expected[++required] = "TestRevisionStoreMediaReadOnlyRetainsConfirmedPolicyAndReview"
    expected[++required] = "TestRevisionStoreMediaFullFilesystemRetainsConfirmedPolicyAndReview"
    split("nas-evidence.json nas-services.json .nas-services.pending .nas-services.intent .nas-services.receipt .nas-services.base", nasRoles, " ")
    expected[++required] = "TestNASEvidenceMediaForeignOwner"
    expected[++required] = "TestNASEvidenceMediaForeignOwner/container"
    for (i = 1; i <= 6; i++) { expected[++required] = "TestNASEvidenceMediaForeignOwner/" nasRoles[i] }
    expected[++required] = "TestNASEvidenceMediaMountCrossings"
    split("same-dev other-dev", mounts, " ")
    for (m = 1; m <= 2; m++) {
        for (i = 1; i <= 6; i++) {
            if (m == 1 && i == 3) continue # Pending is metadata-only, never opened.
            expected[++required] = "TestNASEvidenceMediaMountCrossings/" mounts[m] "-" nasRoles[i]
        }
    }
    expected[++required] = "TestNASBootstrapAdapterNeverImportsLegacyState"
}
{ sub(/\r$/, "") }
/^[ \t]*--- PASS: / {
    name = $0
    sub(/^[ \t]*--- PASS: /, "", name)
    if (!sub(/ \([0-9]+(\.[0-9]+)?s\)$/, "", name) || state != 1 || name != expected[++passed]) { refused = 1 }
    next
}
/^PASS$/ {
    if (state != 1 || passed != required) { refused = 1 }
    state = 2
    next
}
/PHANTOWD_/ {
    if (state == 0 && $0 == stage) { state = 1; next }
    if (state == 2 && $0 == done) { state = 3; next }
    refused = 1
}
/--- (FAIL|SKIP):|^FAIL$|testing: warning: no tests to run|Kernel panic|INTERNAL ERROR|AddressSanitizer|runtime error:|WARNING: DATA RACE/ { refused = 1 }
END { if (state != 3 || passed != required || refused) exit 1 }
