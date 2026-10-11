# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
BEGIN {
    stage = "PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true hashes_during_copy=true no_overwrite=true refusals=5 scope=qemu-only"
    proof = "PHANTOWD_SERVER_OBSERVER_DAEMON_PROOF actual_smbd=true negotiate_smb302=true endpoint_retained=true stop_before_release=true restart_refused=true scope=qemu-only"
    done = "PHANTOWD_SERVER_OBSERVER_DAEMON_GUEST_DONE"
    drift = "PHANTOWD_SERVER_OBSERVER_DAEMON_DRIFT_PROOF actual_smbd=true original_endpoint_drift=true stop_verified=true originals_retained=true restoration_refused=true scope=qemu-only"
    binding = "PHANTOWD_SERVER_OBSERVER_CODE_BINDING_PROOF complete_original_census=true caller_close=true foreign_root_refused=true identical_copy_refused=true originals_retained=true restoration_refused=true released=true scope=qemu-only"
    runtime = "PHANTOWD_SERVER_OBSERVER_RUNTIME_PROOF actual_smbd=true complete_code_retained=true original_channel_pair=true receiver_drift_stopped=true live_code_cover_stopped=true originals_retained=true restoration_refused=true stop_before_release=true scope=qemu-only"
}
{ sub(/\r$/, "") }
/PHANTOWD_/ {
    if (state == 0 && $0 == stage) { state = 1; next }
    if (state == 1 && $0 == binding) { state = 2; next }
    if (state == 2 && $0 == proof) { state = 3; next }
    if (state == 3 && $0 == drift) { state = 4; next }
    if (state == 4 && $0 == runtime) { state = 5; next }
    if (state == 5 && $0 == done) { state = 6; next }
    refused = 1
}
END { if (state != 6 || refused) exit 1 }
