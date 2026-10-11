#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository required}
[ "$#" -eq 1 ] || exit 1
stage='PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true hashes_during_copy=true no_overwrite=true refusals=5 scope=qemu-only'
proof='PHANTOWD_CAPTURE_RUNTIME_PROOF actual_smbd=true module_retained=true original_channel_pair=true stop_before_release=true existing_passdb_refused=true unchanged_passdb=true fd_equal=true authentication=false file_open=false samples=false authority=false scope=qemu-only'
done='PHANTOWD_CAPTURE_RUNTIME_GUEST_DONE'
arm_tests=$'=== RUN   TestServerCaptureClientNoticesRequireCompleteSameOpenSequence\n--- PASS: TestServerCaptureClientNoticesRequireCompleteSameOpenSequence (0.05s)\n=== RUN   TestServerCaptureClientNoticesRefuseDriftUnrequestedReadsAndOtherProtocols\n--- PASS: TestServerCaptureClientNoticesRefuseDriftUnrequestedReadsAndOtherProtocols (0.00s)\n=== RUN   TestServerCaptureClientDedicatedLifecycleRefusesHostNilCopyCancelBusyAndReview\n--- PASS: TestServerCaptureClientDedicatedLifecycleRefusesHostNilCopyCancelBusyAndReview (0.02s)\n=== RUN   TestServerCaptureClientConnectionRefusesAbsentCopiedCanceledAndUnstarted\n--- PASS: TestServerCaptureClientConnectionRefusesAbsentCopiedCanceledAndUnstarted (0.00s)\n=== RUN   TestServerCaptureClientAccumulatedNoticesNeverLatchPartialOrAcceptUnrequestedRead\n--- PASS: TestServerCaptureClientAccumulatedNoticesNeverLatchPartialOrAcceptUnrequestedRead (0.00s)\nPASS'
bare_proof=$proof
proof="$proof"$'\n'"$arm_tests"
negative=0
verify() { awk -f "$source/support/tests/verify-server-capture-runtime-log.awk"; }
refused() {
    if printf '%s\n' "$1" | verify; then echo 'Capture runtime verifier accepted malformed proof' >&2; exit 1; fi
    negative=$((negative + 1))
}
printf '%s\n' "$stage" "$proof" "$done" | verify
printf '%s\r\n' "$stage" "$proof" "$done" | verify
newline=$'\n'
for text in '' "$stage" "$proof" "$done" \
    "$proof$newline$stage$newline$done" "$proof$newline$done" "$stage$newline$done" \
    "$stage$newline$done$newline$proof" "$stage$newline$stage$newline$proof$newline$done" \
    "$stage$newline$proof$newline$proof$newline$done" "$stage$newline$proof$newline$done$newline$done" \
    "$stage$newline$proof$newline$done${newline}PHANTOWD_UNRELATED_SUCCESS" \
    "$stage$newline$proof${newline}PHANTOWD_CAPTURE_RUNTIME_GUEST_FAILED$newline$done" \
    "$stage${newline}prefix $proof$newline$done" "$stage$newline$proof$newline$done suffix" \
    "$stage$newline$proof${newline}Kernel panic$newline$done" \
    "$stage$newline$proof${newline}INTERNAL ERROR$newline$done"; do
    refused "$text"
done
for mutation in 'actual_smbd=true/actual_smbd=false' 'module_retained=true/module_retained=false' \
    'original_channel_pair=true/original_channel_pair=false' 'stop_before_release=true/stop_before_release=false' \
    'existing_passdb_refused=true/existing_passdb_refused=false' 'unchanged_passdb=true/unchanged_passdb=false' \
    'fd_equal=true/fd_equal=false' 'authentication=false/authentication=true' \
    'file_open=false/file_open=true' 'samples=false/samples=true' 'authority=false/authority=true' \
    'scope=qemu-only/scope=product' 'scope=qemu-only/scope=qemu-only unexpected=true'; do
    refused "$stage$newline${proof/${mutation%%\/*}/${mutation#*\/}}$newline$done"
done
refused "$stage$newline$bare_proof$newline$done"
refused "$stage$newline$proof$newline$arm_tests$newline$done"
refused "$stage$newline${proof/=== RUN   TestServerCaptureClientNoticesRequireCompleteSameOpenSequence/=== RUN   OtherTest}$newline$done"
refused "$stage$newline${proof/--- PASS:/--- FAIL:}$newline$done"
refused "$stage$newline${proof/--- PASS:/--- SKIP:}$newline$done"
refused "$stage$newline${proof/(0.05s)/(nans)}$newline$done"
refused "$stage$newline${proof/--- PASS: TestServerCaptureClientAccumulatedNoticesNeverLatchPartialOrAcceptUnrequestedRead (0.00s)/--- PASS: OtherTest (0.00s)}$newline$done"
refused "$stage$newline${proof/=== RUN   TestServerCaptureClientConnectionRefusesAbsentCopiedCanceledAndUnstarted/}$newline$done"
refused "$stage$newline${proof/--- PASS: TestServerCaptureClientConnectionRefusesAbsentCopiedCanceledAndUnstarted (0.00s)/}$newline$done"
printf 'PHANTOWD_CAPTURE_RUNTIME_LOG_CONTROLS_DONE positive=2 negative=%s scope=host-parser-only guest=false\n' "$negative"
