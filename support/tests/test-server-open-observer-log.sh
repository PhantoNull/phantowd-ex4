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
wire='PHANTOWD_SERVER_OPEN_WIRE_READY frames=2 c_to_go=true bounded=true synthetic_open=true active_worker=false proof=false scope=qemu-only'
packet='PHANTOWD_SERVER_OPEN_PACKET_READY frames=2 kernel_credentials=true original_pair=true synthetic_open=true active_worker=false proof=false scope=qemu-only'
real='PHANTOWD_SERVER_OPEN_REAL_IDS_READY frames=2 real_ids=true effective_ids=false permitted_override=true producer_settled=true active_worker=false proof=false scope=qemu-only'
wire_verify() { awk -v wire=1 -f "$source/support/tests/verify-server-open-observer-log.awk"; }
wire_refused() { if wire_verify; then echo 'Wire verifier accepted malformed proof' >&2; exit 1; fi; }
printf '%s\n' "$ready" "$wire" "$packet" "$real" "$done" | wire_verify
printf '%s\r\n' "$ready" "$wire" "$packet" "$real" "$done" | wire_verify
printf '' | wire_refused
printf '%s\n' "$ready" "$real" "$done" | wire_refused
printf '%s\n' "$wire" "$packet" "$real" "$done" | wire_refused
printf '%s\n' "$ready" "$wire" "$packet" "$real" | wire_refused
printf '%s\n' "$wire" "$ready" "$packet" "$real" "$done" | wire_refused
printf '%s\n' "$ready" "$wire" "$wire" "$packet" "$real" "$done" | wire_refused
printf '%s\n' "$ready" "$wire" "$packet" "$real" "$done" "$wire" | wire_refused
printf '%s\n' "$ready" "$wire" 'PHANTOWD_SERVER_OPEN_SOURCE_GUEST_FAILED' "$packet" "$real" "$done" | wire_refused
for mutation in 'frames=2/frames=1' 'c_to_go=true/c_to_go=false' 'bounded=true/bounded=false' \
    'synthetic_open=true/synthetic_open=false' 'active_worker=false/active_worker=true' \
    'proof=false/proof=true' 'scope=qemu-only/scope=product'; do
    printf '%s\n' "$ready" "${wire/${mutation%%\/*}/${mutation#*\/}}" "$packet" "$real" "$done" | wire_refused
done
printf '%s\n' "$ready" "$wire" "$real" "$done" | wire_refused
printf '%s\n' "$ready" "$packet" "$real" "$done" | wire_refused
printf '%s\n' "$ready" "$packet" "$wire" "$real" "$done" | wire_refused
printf '%s\n' "$ready" "$wire" "$packet" "$packet" "$real" "$done" | wire_refused
printf '%s\n' "$ready" "$wire" "$packet" "$real" "$done" "$packet" | wire_refused
printf '%s\n' "$ready" "$wire" "prefix $packet" "$real" "$done" | wire_refused
printf '%s\n' "$ready" "$wire" "$packet suffix" "$real" "$done" | wire_refused
for mutation in 'frames=2/frames=1' 'kernel_credentials=true/kernel_credentials=false' \
    'original_pair=true/original_pair=false' 'synthetic_open=true/synthetic_open=false' \
    'active_worker=false/active_worker=true' 'proof=false/proof=true' 'scope=qemu-only/scope=product'; do
    printf '%s\n' "$ready" "$wire" "${packet/${mutation%%\/*}/${mutation#*\/}}" "$real" "$done" | wire_refused
done
printf '%s\n' "$ready" "$wire" "$packet" "$done" | wire_refused
printf '%s\n' "$ready" "$wire" "$real" "$done" | wire_refused
printf '%s\n' "$ready" "$wire" "$real" "$packet" "$done" | wire_refused
printf '%s\n' "$ready" "$wire" "$packet" "$real" "$real" "$done" | wire_refused
printf '%s\n' "$ready" "$wire" "$packet" "$real" "$done" "$real" | wire_refused
printf '%s\n' "$ready" "$wire" "$packet" "prefix $real" "$done" | wire_refused
printf '%s\n' "$ready" "$wire" "$packet" "$real suffix" "$done" | wire_refused
for mutation in 'frames=2/frames=1' 'real_ids=true/real_ids=false' \
    'effective_ids=false/effective_ids=true' 'permitted_override=true/permitted_override=false' \
    'producer_settled=true/producer_settled=false' \
    'active_worker=false/active_worker=true' 'proof=false/proof=true' 'scope=qemu-only/scope=product'; do
    printf '%s\n' "$ready" "$wire" "$packet" "${real/${mutation%%\/*}/${mutation#*\/}}" "$done" | wire_refused
done
printf '%s\n' 'PHANTOWD_SERVER_OPEN_WIRE_LOG_CONTROLS_DONE positive=2 negative=44 scope=host-parser-only guest=false'
