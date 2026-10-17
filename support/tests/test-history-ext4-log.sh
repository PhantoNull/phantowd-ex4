#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository required}
[ "$#" -eq 1 ] || exit 1
verifier="$source/support/tests/verify-history-ext4-log.awk"
expected=$(awk -v selection=1 -f "$verifier" </dev/null)
declared=$(sed -n "s/^    selected='\(.*\)'$/\1/p" "$source/support/tests/history-ext4-init.sh")
[ -n "$expected" ] && [ "$expected" = "$declared" ] || exit 1
stage='PHANTOWD_HISTORY_EXT4_PREPARED synthetic_ext4=true snapshot=true stages=21 admission=false scope=qemu-only'
done='PHANTOWD_HISTORY_EXT4_DONE sigkill=21 original_refs=true first_record_preserved=true runtime_reader=true pending_review=true review=true loss_observer_readonly=true process_boundary=true normal_unmount=true scope=qemu-only'
proof="$stage"$'\n--- PASS: TestHistoryExt4RemountRejectsUnlinkedReadPin (0.01s)\n--- PASS: TestRuntimeHistoryWriterOnExt4 (0.02s)'
for value in normal readonly full process-boundary; do
    proof+=$'\n'"    --- PASS: TestRuntimeHistoryWriterOnExt4/$value (0.01s)"
done
proof+=$'\n--- PASS: TestRuntimeHistoryObserverAfterExt4ProcessLoss (0.02s)'
for role in intent policy receipt; do
    for point in partial-write full-write file-sync file-close before-rename after-rename directory-sync; do
        proof+=$'\n'"    --- PASS: TestRuntimeHistoryObserverAfterExt4ProcessLoss/$role/$point (0.01s)"
    done
done
proof+=$'\nPASS\n'"$done"
verify() { awk -f "$verifier"; }
printf '%s\n' "$proof" | verify
printf '%s\r\n' "${proof//$'\n'/$'\r\n'}" | verify
negative=0
refused() {
    if printf '%s\n' "$1" | verify; then echo 'History ext4 verifier accepted incomplete proof' >&2; exit 1; fi
    negative=$((negative + 1))
}
for value in '' "$stage" "$done" "$proof suffix" "$proof"$'\nPASS' \
    "$proof"$'\nKernel panic' "$proof"$'\nruntime error:' "$proof"$'\nWARNING: DATA RACE' \
    "$proof"$'\n--- PASS: ForeignTest (0.01s)' "$proof"$'\nPHANTOWD_FOREIGN_READY' \
    "${proof/--- PASS:/--- SKIP:}" "${proof/--- PASS:/--- FAIL:}" \
    "${proof/PASS$'\n'/MISSING$'\n'}" "${proof/process-boundary/foreign}"; do refused "$value"; done
for field in synthetic_ext4 snapshot original_refs first_record_preserved runtime_reader pending_review review loss_observer_readonly process_boundary normal_unmount; do
    refused "${proof/"$field=true"/"$field=false"}"
done
refused "${proof/admission=false/admission=true}"
refused "${proof/sigkill=21/sigkill=20}"
refused "${proof/stages=21/stages=20}"
refused "${proof/scope=qemu-only/scope=product}"
refused "${proof/"$stage"/}"
refused "${proof/"$done"/}"
refused "$stage"$'\n'"$proof"
refused "$proof"$'\n'"$done"
while IFS= read -r line; do
    case "$line" in *'--- PASS: '*) ;; *) continue ;; esac
    refused "${proof/"$line"/}"
    refused "${proof/"$line"/"$line"$'\n'"$line"}"
done <<<"$proof"
swapped=${proof/intent\/partial-write/temporary-point}
swapped=${swapped/intent\/full-write/intent\/partial-write}
swapped=${swapped/temporary-point/intent\/full-write}
refused "$swapped"
printf 'PHANTOWD_HISTORY_EXT4_LOG_CONTROLS_DONE positive=2 negative=%s scope=host-parser-only guest=false\n' "$negative"
