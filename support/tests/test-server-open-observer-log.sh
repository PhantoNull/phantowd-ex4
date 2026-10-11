#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository required}
[ "$#" -eq 1 ] || exit 1
ready='PHANTOWD_SERVER_OPEN_SOURCE_READY refusals=65 dso_refusals=65 real_fd=true real_getters=true synthetic_open=true active_worker=false authority=false scope=qemu-only'
done='PHANTOWD_SERVER_OPEN_SOURCE_GUEST_DONE'
verify() { awk -f "$source/support/tests/verify-server-open-observer-log.awk"; }
refused() { if verify; then echo 'Server observer verifier accepted malformed proof' >&2; exit 1; fi; }
printf '%s\n' "$ready" "$done" | verify
printf '%s\r\n' "$ready" "$done" | verify
printf '' | refused
printf '%s\n' "$ready" | refused
printf '%s\n' "$done" | refused
printf '%s\n' "$done" "$ready" | refused
printf '%s\n' "$ready" "$ready" "$done" | refused
printf '%s\n' "$ready" "$done" "$done" | refused
printf '%s\n' "$ready" 'PHANTOWD_SERVER_OPEN_SOURCE_GUEST_FAILED' "$done" | refused
printf '%s\n' "prefix $ready" "$done" | refused
printf '%s\n' "$ready suffix" "$done" | refused
printf '%s\n' "$ready" "$done" 'PHANTOWD_UNRELATED_SUCCESS' | refused
printf '%s\n' "$ready" 'PHANTOWD_SERVER_OPEN_SOURCE_ASSERT_FAILED line=1' "$done" | refused
for mutation in 'refusals=65/refusals=64' 'dso_refusals=65/dso_refusals=64' \
    'real_fd=true/real_fd=false' 'real_getters=true/real_getters=false' \
    'synthetic_open=true/synthetic_open=false' 'active_worker=false/active_worker=true' \
    'authority=false/authority=true' 'scope=qemu-only/scope=product'; do
    printf '%s\n' "${ready/${mutation%%\/*}/${mutation#*\/}}" "$done" | refused
done
printf '%s\n' 'PHANTOWD_SERVER_OPEN_LOG_CONTROLS_DONE positive=2 negative=19 scope=host-parser-only guest=false'
