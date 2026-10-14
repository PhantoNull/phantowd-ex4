#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository required}
[ "$#" -eq 1 ] || exit 1
stage='PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true hashes_during_copy=true no_overwrite=true refusals=5 scope=qemu-only'
proof='PHANTOWD_CAPTURE_CANCEL_READ_PROOF collection_canceled=true witness_joined=true client_completion_unknown=true client_ack=false zero_frame=true sequence_zero=true queued_bytes=88 queue_unconsumed=true client_stopped=true server_stopped=true review=true originals_retained=true retry_refused=true stable_review_fds=true unchanged_data=true authority=false scope=qemu-only'
done='PHANTOWD_CAPTURE_CANCEL_READ_GUEST_DONE'
newline=$'\n'
negative=0
verify() { awk -f "$source/support/tests/verify-server-capture-cancel-read-log.awk"; }
refused() {
    if printf '%s\n' "$1" | verify; then echo 'Canceled READ verifier accepted incomplete proof' >&2; exit 1; fi
    negative=$((negative + 1))
}
printf '%s\n' "$stage" "$proof" "$done" | verify
printf '%s\r\n' "$stage" "$proof" "$done" | verify
for value in '' "$stage" "$proof" "$done" "$stage$newline$done" \
    "$proof$newline$stage$newline$done" "$stage$newline$done$newline$proof" \
    "$stage$newline$proof$newline$proof$newline$done" \
    "$stage$newline$proof${newline}PHANTOWD_CAPTURE_OPEN_GUEST_FAILED$newline$done" \
    "$stage$newline$proof${newline}Kernel panic$newline$done" \
    "$stage$newline$proof${newline}AddressSanitizer$newline$done" \
    "$stage$newline$proof$newline$done suffix"; do refused "$value"; done
for field in collection_canceled witness_joined client_completion_unknown zero_frame sequence_zero queue_unconsumed client_stopped server_stopped \
    review originals_retained retry_refused stable_review_fds unchanged_data; do
    refused "$stage$newline${proof/$field=true/$field=false}$newline$done"
done
for mutation in 'client_ack=false/client_ack=true' 'queued_bytes=88/queued_bytes=0' \
    'queued_bytes=88/queued_bytes=89' 'authority=false/authority=true' 'scope=qemu-only/scope=product'; do
    refused "$stage$newline${proof/${mutation%%\/*}/${mutation#*\/}}$newline$done"
done
printf 'PHANTOWD_CAPTURE_CANCEL_READ_LOG_CONTROLS_DONE positive=2 negative=%s scope=host-parser-only guest=false\n' "$negative"
