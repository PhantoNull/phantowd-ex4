#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository required}
[ "$#" -eq 1 ] || exit 1
stage='PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true hashes_during_copy=true no_overwrite=true refusals=5 scope=qemu-only'
done='PHANTOWD_CAPTURE_INPUT_FAULT_GUEST_DONE'
newline=$'\n'
negative=0
verify() { awk -v kind="$kind" -f "$source/support/tests/verify-server-capture-input-fault-log.awk"; }
refused() {
    if printf '%s\n' "$1" | verify; then echo 'Input-fault verifier accepted incomplete proof' >&2; exit 1; fi
    negative=$((negative + 1))
}
for kind in module configuration channel source; do
    proof="PHANTOWD_CAPTURE_INPUT_FAULT_PROOF kind=$kind first_read_matched=true next_read_refused=true zero_frame=true client_stopped=true server_stopped=true review=true originals_retained=true input_restored=true restoration_refused=true stable_review_fds=true unchanged_data=true samples=1 authority=false scope=qemu-only"
    printf '%s\n' "$stage" "$proof" "$done" | verify
    printf '%s\r\n' "$stage" "$proof" "$done" | verify
    for value in '' "$stage" "$proof" "$done" "$stage$newline$done" \
        "$proof$newline$stage$newline$done" "$stage$newline$done$newline$proof" \
        "$stage$newline$proof$newline$proof$newline$done" \
        "$stage$newline$proof${newline}PHANTOWD_CAPTURE_OPEN_GUEST_FAILED$newline$done" \
        "$stage$newline$proof${newline}Kernel panic$newline$done" \
        "$stage$newline$proof${newline}AddressSanitizer$newline$done" \
        "$stage$newline$proof$newline$done suffix"; do refused "$value"; done
    for field in first_read_matched next_read_refused zero_frame client_stopped server_stopped \
        review originals_retained input_restored restoration_refused stable_review_fds unchanged_data; do
        refused "$stage$newline${proof/$field=true/$field=false}$newline$done"
    done
    for replacement in 'samples=1/samples=2' 'authority=false/authority=true' 'scope=qemu-only/scope=product'; do
        refused "$stage$newline${proof/${replacement%%\/*}/${replacement#*\/}}$newline$done"
    done
    refused "$stage$newline${proof/kind=$kind/kind=foreign}$newline$done"
done
kind=unknown
refused "$stage$newline$proof$newline$done"
printf 'PHANTOWD_CAPTURE_INPUT_FAULT_LOG_CONTROLS_DONE positive=8 negative=%s scope=host-parser-only guest=false\n' "$negative"
