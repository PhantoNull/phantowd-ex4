# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
BEGIN {
    stage = "PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true hashes_during_copy=true no_overwrite=true refusals=5 scope=qemu-only"
    proof = "PHANTOWD_CAPTURE_OPEN_PROOF authenticated_client=true actual_open_close=true complete_client_inputs=true module_retained=true original_channel_pair=true status_worker_local=true tcp_namespaces=true stop_before_release=true unchanged_data=true fd_equal=true reads=false samples=false worker_binding=false authority=false scope=qemu-only"
    done = "PHANTOWD_CAPTURE_OPEN_GUEST_DONE"
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
