#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository required}
[ "$#" -eq 1 ] || exit 1
ready='PHANTOWD_PENDING_HANDLE_SOURCE_READY refusals=36 real_idr=true reused_fnum_distinct=true getters=mocked dso_early_refusals=3 network=false server=false authority=false scope=qemu-only'
done='PHANTOWD_PENDING_HANDLE_SOURCE_GUEST_DONE'
verify() { awk -f "$source/support/tests/verify-pending-handle-observer-log.awk"; }
refused() { if verify; then echo 'Handle observer verifier accepted malformed proof' >&2; exit 1; fi; }
printf '%s\n' "$ready" "$done" | verify
printf '%s\r\n' "$ready" "$done" | verify
printf '' | refused
printf '%s\n' "$ready" | refused
printf '%s\n' "$done" | refused
printf '%s\n' "$done" "$ready" | refused
printf '%s\n' "$ready" "$ready" "$done" | refused
printf '%s\n' "$ready" "$done" "$done" | refused
printf '%s\n' "$ready" 'PHANTOWD_PENDING_HANDLE_SOURCE_GUEST_FAILED' "$done" | refused
printf '%s\n' "prefix $ready" "$done" | refused
printf '%s\n' "$ready suffix" "$done" | refused
printf '%s\n' "$ready" "$done" 'PHANTOWD_UNRELATED_SUCCESS' | refused
for mutation in 'refusals=36/refusals=35' 'real_idr=true/real_idr=false' \
    'reused_fnum_distinct=true/reused_fnum_distinct=false' 'getters=mocked/getters=real' \
    'dso_early_refusals=3/dso_early_refusals=0' 'network=false/network=true' \
    'server=false/server=true' 'authority=false/authority=true' 'scope=qemu-only/scope=product'; do
    printf '%s\n' "${ready/${mutation%%\/*}/${mutation#*\/}}" "$done" | refused
done
printf '%s\n' 'PHANTOWD_PENDING_HANDLE_LOG_CONTROLS_DONE positive=2 negative=19 scope=host-parser-only guest=false'
