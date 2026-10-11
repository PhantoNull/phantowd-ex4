#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository required}
[ "$#" -eq 1 ] || exit 1
stage='PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true hashes_during_copy=true no_overwrite=true refusals=5 scope=qemu-only'
proof='PHANTOWD_SERVER_OBSERVER_DAEMON_PROOF actual_smbd=true negotiate_smb302=true endpoint_retained=true stop_before_release=true restart_refused=true scope=qemu-only'
done='PHANTOWD_SERVER_OBSERVER_DAEMON_GUEST_DONE'
drift='PHANTOWD_SERVER_OBSERVER_DAEMON_DRIFT_PROOF actual_smbd=true original_endpoint_drift=true stop_verified=true originals_retained=true restoration_refused=true scope=qemu-only'
binding='PHANTOWD_SERVER_OBSERVER_CODE_BINDING_PROOF complete_original_census=true caller_close=true foreign_root_refused=true identical_copy_refused=true originals_retained=true restoration_refused=true released=true scope=qemu-only'
runtime='PHANTOWD_SERVER_OBSERVER_RUNTIME_PROOF actual_smbd=true complete_code_retained=true original_channel_pair=true receiver_drift_stopped=true live_code_cover_stopped=true originals_retained=true restoration_refused=true stop_before_release=true scope=qemu-only'
verify() { awk -f "$source/support/tests/verify-server-observer-daemon-log.awk"; }
refused() { if verify; then echo 'Observer daemon verifier accepted malformed proof' >&2; exit 1; fi; }
printf '%s\n' "$stage" "$binding" "$proof" "$drift" "$runtime" "$done" | verify
printf '%s\r\n' "$stage" "$binding" "$proof" "$drift" "$runtime" "$done" | verify
printf '' | refused
printf '%s\n' "$stage" | refused
printf '%s\n' "$stage" "$binding" "$proof" | refused
printf '%s\n' "$stage" "$binding" "$proof" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$binding" "$drift" "$runtime" "$done" | refused
printf '%s\n' "$binding" "$proof" "$drift" "$runtime" "$done" | refused
printf '%s\n' "$runtime" "$done" "$stage" "$binding" "$proof" "$drift" | refused
printf '%s\n' "$stage" "$binding" "$drift" "$proof" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$binding" "$proof" "$runtime" "$done" "$drift" | refused
printf '%s\n' "$stage" "$stage" "$binding" "$proof" "$drift" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$binding" "$proof" "$proof" "$drift" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$binding" "$proof" "$drift" "$drift" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$binding" "$proof" "$drift" "$runtime" "$done" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$binding" 'PHANTOWD_SERVER_OBSERVER_DAEMON_GUEST_FAILED' "$proof" "$drift" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$binding" "prefix $proof" "$drift" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$binding" "$proof suffix" "$drift" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$binding" "$proof" "$drift" "$runtime" "$done" 'PHANTOWD_UNRELATED_SUCCESS' | refused
printf '%s\n' "$stage" "$binding" "$proof" "$drift" "$runtime" "$done" "$stage" | refused
printf '%s\n' "$stage" "$binding" "$proof" "prefix $drift" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$binding" "$proof" "$drift suffix" "$runtime" "$done" | refused
for mutation in 'actual_smbd=true/actual_smbd=false' 'negotiate_smb302=true/negotiate_smb302=false' \
    'endpoint_retained=true/endpoint_retained=false' 'stop_before_release=true/stop_before_release=false' \
    'restart_refused=true/restart_refused=false' 'scope=qemu-only/scope=product'; do
    printf '%s\n' "$stage" "$binding" "${proof/${mutation%%\/*}/${mutation#*\/}}" "$drift" "$runtime" "$done" | refused
done
for mutation in 'actual_smbd=true/actual_smbd=false' 'original_endpoint_drift=true/original_endpoint_drift=false' \
    'stop_verified=true/stop_verified=false' 'originals_retained=true/originals_retained=false' \
    'restoration_refused=true/restoration_refused=false' 'scope=qemu-only/scope=product'; do
    printf '%s\n' "$stage" "$binding" "$proof" "${drift/${mutation%%\/*}/${mutation#*\/}}" "$runtime" "$done" | refused
done
printf '%s\n' "$stage" "$proof" "$drift" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$binding" "$binding" "$proof" "$drift" "$runtime" "$done" | refused
printf '%s\n' "$binding" "$stage" "$proof" "$drift" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$proof" "$binding" "$drift" "$runtime" "$done" | refused
printf '%s\n' "$stage" "prefix $binding" "$proof" "$drift" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$binding suffix" "$proof" "$drift" "$runtime" "$done" | refused
for mutation in 'complete_original_census=true/complete_original_census=false' 'caller_close=true/caller_close=false' \
    'foreign_root_refused=true/foreign_root_refused=false' 'identical_copy_refused=true/identical_copy_refused=false' \
    'originals_retained=true/originals_retained=false' 'restoration_refused=true/restoration_refused=false' \
    'released=true/released=false' 'scope=qemu-only/scope=product'; do
    printf '%s\n' "$stage" "${binding/${mutation%%\/*}/${mutation#*\/}}" "$proof" "$drift" "$runtime" "$done" | refused
done
printf '%s\n' "$stage" "$binding" "$proof" "$drift" "$done" | refused
printf '%s\n' "$stage" "$binding" "$proof" "$drift" "$runtime" "$runtime" "$done" | refused
printf '%s\n' "$stage" "$binding" "$runtime" "$proof" "$drift" "$done" | refused
printf '%s\n' "$stage" "$binding" "$proof" "$drift" "$done" "$runtime" | refused
printf '%s\n' "$stage" "$binding" "$proof" "$drift" "prefix $runtime" "$done" | refused
printf '%s\n' "$stage" "$binding" "$proof" "$drift" "$runtime suffix" "$done" | refused
for mutation in 'actual_smbd=true/actual_smbd=false' 'complete_code_retained=true/complete_code_retained=false' \
    'original_channel_pair=true/original_channel_pair=false' 'receiver_drift_stopped=true/receiver_drift_stopped=false' \
    'live_code_cover_stopped=true/live_code_cover_stopped=false' \
    'originals_retained=true/originals_retained=false' 'restoration_refused=true/restoration_refused=false' \
    'stop_before_release=true/stop_before_release=false' 'scope=qemu-only/scope=product'; do
    printf '%s\n' "$stage" "$binding" "$proof" "$drift" "${runtime/${mutation%%\/*}/${mutation#*\/}}" "$done" | refused
done
echo 'PHANTOWD_SERVER_OBSERVER_DAEMON_LOG_CONTROLS_DONE positive=2 negative=61 scope=host-parser-only guest=false'
