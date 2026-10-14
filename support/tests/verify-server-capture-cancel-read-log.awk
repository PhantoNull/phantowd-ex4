# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
BEGIN {
    stage = "PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true hashes_during_copy=true no_overwrite=true refusals=5 scope=qemu-only"
    proof = "PHANTOWD_CAPTURE_CANCEL_READ_PROOF collection_canceled=true witness_joined=true client_completion_unknown=true client_ack=false zero_frame=true sequence_zero=true queued_bytes=88 queue_unconsumed=true client_stopped=true server_stopped=true review=true originals_retained=true retry_refused=true stable_review_fds=true unchanged_data=true authority=false scope=qemu-only"
    done = "PHANTOWD_CAPTURE_CANCEL_READ_GUEST_DONE"
}
{ sub(/\r$/, "") }
/PHANTOWD_/ {
    if (state == 0 && $0 == stage) { state = 1; next }
    if (state == 1 && $0 == proof) { state = 2; next }
    if (state == 2 && $0 == done) { state = 3; next }
    refused = 1
}
/Kernel panic|INTERNAL ERROR|AddressSanitizer|runtime error:/ { refused = 1 }
END { if (state != 3 || refused) exit 1 }
