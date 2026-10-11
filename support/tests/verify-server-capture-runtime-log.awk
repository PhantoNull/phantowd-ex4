# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
BEGIN {
    stage = "PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true hashes_during_copy=true no_overwrite=true refusals=5 scope=qemu-only"
    proof = "PHANTOWD_CAPTURE_RUNTIME_PROOF actual_smbd=true module_retained=true original_channel_pair=true stop_before_release=true existing_passdb_refused=true unchanged_passdb=true fd_equal=true authentication=false file_open=false samples=false authority=false scope=qemu-only"
    done = "PHANTOWD_CAPTURE_RUNTIME_GUEST_DONE"
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
