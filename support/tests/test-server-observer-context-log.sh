#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository required}
[ "$#" -eq 1 ] || exit 1
ready='PHANTOWD_SERVER_OBSERVER_CONTEXT_PROOF original_sender=true kernel_child_credentials=true sole_endpoint=true isolated_root=true original_inputs_after_stop=true scope=qemu-only'
done='PHANTOWD_SERVER_OBSERVER_CONTEXT_GUEST_DONE'
verify() { awk -f "$source/support/tests/verify-server-observer-context-log.awk"; }
refused() { if verify; then echo 'Observer context verifier accepted malformed proof' >&2; exit 1; fi; }
printf '%s\n' "$ready" "$done" | verify
printf '%s\r\n' "$ready" "$done" | verify
printf '' | refused
printf '%s\n' "$ready" | refused
printf '%s\n' "$done" | refused
printf '%s\n' "$done" "$ready" | refused
printf '%s\n' "$ready" "$ready" "$done" | refused
printf '%s\n' "$ready" "$done" "$done" | refused
printf '%s\n' "$ready" 'PHANTOWD_SERVER_OBSERVER_CONTEXT_GUEST_FAILED' "$done" | refused
printf '%s\n' "prefix $ready" "$done" | refused
printf '%s\n' "$ready suffix" "$done" | refused
printf '%s\n' "$ready" "$done" 'PHANTOWD_UNRELATED_SUCCESS' | refused
for mutation in 'original_sender=true/original_sender=false' 'kernel_child_credentials=true/kernel_child_credentials=false' \
    'sole_endpoint=true/sole_endpoint=false' 'isolated_root=true/isolated_root=false' \
    'original_inputs_after_stop=true/original_inputs_after_stop=false' 'scope=qemu-only/scope=product'; do
    printf '%s\n' "${ready/${mutation%%\/*}/${mutation#*\/}}" "$done" | refused
done
echo 'PHANTOWD_SERVER_OBSERVER_CONTEXT_LOG_CONTROLS_DONE positive=2 negative=16 scope=host-parser-only guest=false'
