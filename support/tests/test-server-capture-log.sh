#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository required}
[ "$#" -eq 1 ] || exit 1
ready='PHANTOWD_SERVER_CAPTURE_READY sync=true async=true paired_frames=true credentials=true cases=20 sticky_refusal=true unchanged_data=true fd_equal=true uid=65534 caps=0 nnp=true synthetic_open=true active_worker=false authority=false scope=qemu-only'
done='PHANTOWD_SERVER_CAPTURE_GUEST_DONE'
verify() { awk -f "$source/support/tests/verify-server-capture-log.awk"; }
refused() { if verify; then echo 'Capture verifier accepted malformed proof' >&2; exit 1; fi; }
printf '%s\n' "$ready" "$done" | verify
printf '%s\r\n' "$ready" "$done" | verify
printf '' | refused
printf '%s\n' "$ready" | refused
printf '%s\n' "$done" | refused
printf '%s\n' "$done" "$ready" | refused
printf '%s\n' "$ready" "$ready" "$done" | refused
printf '%s\n' "$ready" "$done" "$done" | refused
printf '%s\n' "$ready" 'PHANTOWD_SERVER_CAPTURE_GUEST_FAILED' "$done" | refused
printf '%s\n' "$ready" 'PHANTOWD_SERVER_CAPTURE_ASSERT_FAILED' "$done" | refused
printf '%s\n' "prefix $ready" "$done" | refused
printf '%s\n' "$ready suffix" "$done" | refused
printf '%s\n' "$ready" "$done" 'PHANTOWD_UNRELATED_SUCCESS' | refused
printf '%s\n' "$ready" "prefix $done" | refused
printf '%s\n' "$ready" "$done suffix" | refused
printf '%s\n' "$ready" 'PANIC' "$done" | refused
for mutation in 'sync=true/sync=false' 'async=true/async=false' \
    'paired_frames=true/paired_frames=false' 'credentials=true/credentials=false' \
    'cases=20/cases=19' 'sticky_refusal=true/sticky_refusal=false' \
    'unchanged_data=true/unchanged_data=false' 'fd_equal=true/fd_equal=false' \
    'uid=65534/uid=0' 'caps=0/caps=1' 'nnp=true/nnp=false' \
    'synthetic_open=true/synthetic_open=false' 'active_worker=false/active_worker=true' \
    'authority=false/authority=true' 'scope=qemu-only/scope=product' \
    'scope=qemu-only/scope=qemu-only unexpected=true'; do
    printf '%s\n' "${ready/${mutation%%\/*}/${mutation#*\/}}" "$done" | refused
done
echo 'PHANTOWD_SERVER_CAPTURE_LOG_CONTROLS_DONE positive=2 negative=30 scope=host-parser-only guest=false'
