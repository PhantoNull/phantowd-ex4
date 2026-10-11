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
verify() { awk -f "$source/support/tests/verify-server-observer-daemon-log.awk"; }
refused() { if verify; then echo 'Observer daemon verifier accepted malformed proof' >&2; exit 1; fi; }
printf '%s\n' "$stage" "$proof" "$drift" "$done" | verify
printf '%s\r\n' "$stage" "$proof" "$drift" "$done" | verify
printf '' | refused
printf '%s\n' "$stage" | refused
printf '%s\n' "$stage" "$proof" | refused
printf '%s\n' "$stage" "$proof" "$done" | refused
printf '%s\n' "$stage" "$drift" "$done" | refused
printf '%s\n' "$proof" "$drift" "$done" | refused
printf '%s\n' "$done" "$stage" "$proof" "$drift" | refused
printf '%s\n' "$stage" "$drift" "$proof" "$done" | refused
printf '%s\n' "$stage" "$proof" "$done" "$drift" | refused
printf '%s\n' "$stage" "$stage" "$proof" "$drift" "$done" | refused
printf '%s\n' "$stage" "$proof" "$proof" "$drift" "$done" | refused
printf '%s\n' "$stage" "$proof" "$drift" "$drift" "$done" | refused
printf '%s\n' "$stage" "$proof" "$drift" "$done" "$done" | refused
printf '%s\n' "$stage" 'PHANTOWD_SERVER_OBSERVER_DAEMON_GUEST_FAILED' "$proof" "$drift" "$done" | refused
printf '%s\n' "$stage" "prefix $proof" "$drift" "$done" | refused
printf '%s\n' "$stage" "$proof suffix" "$drift" "$done" | refused
printf '%s\n' "$stage" "$proof" "$drift" "$done" 'PHANTOWD_UNRELATED_SUCCESS' | refused
printf '%s\n' "$stage" "$proof" "$drift" "$done" "$stage" | refused
printf '%s\n' "$stage" "$proof" "prefix $drift" "$done" | refused
printf '%s\n' "$stage" "$proof" "$drift suffix" "$done" | refused
for mutation in 'actual_smbd=true/actual_smbd=false' 'negotiate_smb302=true/negotiate_smb302=false' \
    'endpoint_retained=true/endpoint_retained=false' 'stop_before_release=true/stop_before_release=false' \
    'restart_refused=true/restart_refused=false' 'scope=qemu-only/scope=product'; do
    printf '%s\n' "$stage" "${proof/${mutation%%\/*}/${mutation#*\/}}" "$drift" "$done" | refused
done
for mutation in 'actual_smbd=true/actual_smbd=false' 'original_endpoint_drift=true/original_endpoint_drift=false' \
    'stop_verified=true/stop_verified=false' 'originals_retained=true/originals_retained=false' \
    'restoration_refused=true/restoration_refused=false' 'scope=qemu-only/scope=product'; do
    printf '%s\n' "$stage" "$proof" "${drift/${mutation%%\/*}/${mutation#*\/}}" "$done" | refused
done
echo 'PHANTOWD_SERVER_OBSERVER_DAEMON_LOG_CONTROLS_DONE positive=2 negative=32 scope=host-parser-only guest=false'
