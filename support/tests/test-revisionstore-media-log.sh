#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository required}
[ "$#" -eq 1 ] || exit 1
stage='PHANTOWD_REVISIONSTORE_MEDIA_PREPARED synthetic_ext4=true snapshot=true profiles=2 stages=7 scope=qemu-only'
done='PHANTOWD_REVISIONSTORE_MEDIA_DONE sigkill=14 readonly=true enospc=true bootstrap=true normal_unmount=true scope=qemu-only'
proof="$stage"
for name in TestBootstrapEmptyDirectoryObservationDoesNotInitializeOrChangeMetadata \
    TestBootstrapPendingEvidenceIsNeverPromotedOrDiscarded \
    TestBootstrapPendingEvidenceIsNeverPromotedOrDiscarded/false \
    TestBootstrapPendingEvidenceIsNeverPromotedOrDiscarded/true \
    TestBootstrapValidCurrentPolicyObservationDoesNotChangeFilesOrReturnPolicy \
    TestBootstrapInvalidOrUnsupportedPolicyIsNeverMissingOrReset; do
    proof+=$'\n'"--- PASS: $name (0.01s)"
done
for value in 0 11 2 50; do proof+=$'\n'"--- PASS: TestBootstrapInvalidOrUnsupportedPolicyIsNeverMissingOrReset/$value (0.01s)"; done
proof+=$'\n--- PASS: TestBootstrapUnrecognizedEntriesArePreservedWithoutClaimingEmptyOrConfirmed (0.01s)'
for value in 1 16; do proof+=$'\n'"--- PASS: TestBootstrapUnrecognizedEntriesArePreservedWithoutClaimingEmptyOrConfirmed/$value (0.01s)"; done
proof+=$'\n--- PASS: TestBootstrapRefusesUnsafeNamedObjectsWithoutOpeningTheirData (0.01s)'
for role in shares.json .shares.pending; do
    for kind in symlink hardlink fifo directory permissions; do
        proof+=$'\n'"--- PASS: TestBootstrapRefusesUnsafeNamedObjectsWithoutOpeningTheirData/$role/$kind (0.01s)"
    done
done
for name in TestBootstrapRefusesBusyCanceledMissingAndOversizedStateWithoutMutation \
    TestBootstrapWritableOpenDuringDecodeRefusesEvenWithUnchangedMetadata \
    TestBootstrapCancellationDuringDecodeReturnsNoObservation \
    TestBootstrapRefusesInvalidCodecDirectoryAndMissingRootWithoutInitialization; do
    proof+=$'\n'"--- PASS: $name (0.01s)"
done
for name in TestBundleSIGKILLRecovery TestNASBundleSIGKILLRecovery; do
    proof+=$'\n'"--- PASS: $name (0.02s)"
    for point in partial-write full-write file-sync file-close before-rename after-rename directory-sync; do
        proof+=$'\n'"    --- PASS: $name/$point (0.01s)"
    done
done
proof+=$'\n--- PASS: TestRevisionStoreMediaReadOnlyRetainsConfirmedPolicyAndReview (0.01s)\n--- PASS: TestRevisionStoreMediaFullFilesystemRetainsConfirmedPolicyAndReview (0.01s)\n--- PASS: TestNASBootstrapAdapterNeverImportsLegacyState (0.01s)\nPASS\n'"$done"
verify() { awk -f "$source/support/tests/verify-revisionstore-media-log.awk"; }
printf '%s\n' "$proof" | verify
printf '%s\r\n' "${proof//$'\n'/$'\r\n'}" | verify
negative=0
refused() {
    if printf '%s\n' "$1" | verify; then echo 'Media verifier accepted incomplete proof' >&2; exit 1; fi
    negative=$((negative + 1))
}
for value in '' "$stage" "$done" "${proof/readonly=true/readonly=false}" \
    "${proof/sigkill=14/sigkill=7}" "${proof/normal_unmount=true/normal_unmount=false}" \
    "${proof/scope=qemu-only/scope=product}" "${proof/synthetic_ext4=true/synthetic_ext4=false}" \
    "${proof/snapshot=true/snapshot=false}" "${proof/enospc=true/enospc=false}" "${proof/bootstrap=true/bootstrap=false}" "${proof/--- PASS:/--- SKIP:}" \
    "${proof/--- PASS:/--- FAIL:}" "${proof/TestNASBundleSIGKILLRecovery/ForeignTest}" \
    "${proof/partial-write/foreign}" "${proof/TestRevisionStoreMediaReadOnlyRetainsConfirmedPolicyAndReview/ForeignTest}" \
    "${proof/TestRevisionStoreMediaFullFilesystemRetainsConfirmedPolicyAndReview/ForeignTest}" \
    "${proof/PASS$'\n'/MISSING$'\n'}" "$proof suffix" "$proof"$'\nKernel panic' \
    "$proof"$'\nruntime error:' "$proof"$'\nWARNING: DATA RACE' \
    "$proof"$'\n--- PASS: ForeignTest (0.01s)' "$proof"$'\nPASS'; do refused "$value"; done
while IFS= read -r line; do
    case "$line" in *'--- PASS: '*) ;;
        *) continue ;; esac
    # Every required top-level and stage receipt must occur exactly once.
    refused "${proof/"$line"/}"
    refused "${proof/"$line"/"$line"$'\n'"$line"}"
done <<<"$proof"
swapped=${proof/TestBundleSIGKILLRecovery\/partial-write/temporary-point}
swapped=${swapped/TestBundleSIGKILLRecovery\/full-write/TestBundleSIGKILLRecovery\/partial-write}
swapped=${swapped/temporary-point/TestBundleSIGKILLRecovery\/full-write}
refused "$swapped"
refused "$stage"$'\nPASS\n'"$done"
refused "$stage"$'\n'"$proof"
refused "$done"$'\n'"$proof"
refused "$proof"$'\nPHANTOWD_FOREIGN_READY'
printf 'PHANTOWD_REVISIONSTORE_MEDIA_LOG_CONTROLS_DONE positive=2 negative=%s scope=host-parser-only guest=false\n' "$negative"
