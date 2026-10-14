# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
BEGIN {
    if (kind != "module" && kind != "configuration" && kind != "channel" && kind != "source" && kind != "source-root") { refused = 1 }
    stage = "PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true hashes_during_copy=true no_overwrite=true refusals=5 scope=qemu-only"
    proof = "PHANTOWD_CAPTURE_INPUT_FAULT_PROOF kind=" kind " first_read_matched=true next_read_refused=true zero_frame=true client_stopped=true server_stopped=true review=true originals_retained=true input_restored=true restoration_refused=true stable_review_fds=true unchanged_data=true samples=1 authority=false scope=qemu-only"
    done = "PHANTOWD_CAPTURE_INPUT_FAULT_GUEST_DONE"
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
