#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository source required}
[ "$#" -eq 1 ] || exit 1
verifier="$source/support/tests/verify-pending-client-inputs-log.awk"
ready='PHANTOWD_PENDING_INPUTS_READY complete_root=true complete_bootstrap=true fixed_documents=true original_pins=true caller_duplicate_closed=true late_rechecked=true mismatches=2 canceled_refused=true released_refused=true no_fd_leak=true execution=false scope=qemu-only'
guest=PHANTOWD_PENDING_INPUTS_GUEST_DONE
owner='PHANTOWD_PENDING_OWNER_READY complete_inputs=true adapter_bound=true constructor_refused=true caller_duplicate_closed=true late_rechecked=true copied_refused=true canceled_refused=true busy_refused=true released_refused=true no_fd_leak=true execution=false scope=qemu-only'
loss='PHANTOWD_PENDING_OWNER_INPUT_LOSS_READY real_constructor=true never_started=true lost_pin_closed=true close_refused=true review_retained=true unattempted_retained=true repeated_refused=true review_fd_count_equal=true unrelated_kept=true client_executed=false scope=qemu-only'
disposed='PHANTOWD_PENDING_OWNER_INPUT_LOSS_PROCESS_READY exit0=true child_reaped=true parent_fd_count_equal=true client_executed=false scope=qemu-only'
good=$(printf '%s\n%s\n%s\n%s\n%s' "$ready" "$owner" "$loss" "$disposed" "$guest")
check() {
    expected=$1
    status=0
    printf '%s\n' "$2" | awk -f "$verifier" || status=$?
    [ "$status" -eq "$expected" ] || exit 1
}
check 0 "$good"
printf '%s\r\n%s\r\n%s\r\n%s\r\n%s\r\n' "$ready" "$owner" "$loss" "$disposed" "$guest" | awk -f "$verifier"
check 1 ''
check 1 "$ready"
check 1 "$guest"
check 1 "$(printf '%s\n%s' "$ready" "$guest")"
check 1 "$(printf '%s\n%s' "$owner" "$guest")"
check 1 "$(printf '%s\n%s' "$good" "$owner")"
check 1 "$(printf '%s\n%s\n%s' "$owner" "$ready" "$guest")"
check 1 "$(printf '%s\n%s\n%s' "$ready" "$guest" "$owner")"
check 1 "${good/constructor_refused=true/constructor_refused=false}"
check 1 "$(printf '%s\n%s' "$good" "$guest")"
check 1 "$(printf '%s\n%s' "$good" "$ready")"
check 1 "$(printf '%s\n%s' "$good" PHANTOWD_PENDING_INPUTS_GUEST_FAILED)"
check 1 "$(printf '%s\n%s' "$good" PHANTOWD_PENDING_UNKNOWN)"
check 1 "${good/original_pins=true/original_pins=false}"
check 1 "${good/execution=false/execution=true}"
check 1 "$(printf '%s extra=true\n%s' "$ready" "$guest")"
check 1 "$(printf '%s\r\r\n%s' "$ready" "$guest")"
check 1 "$(printf '%s\n%s\n%s' "$ready" "$owner" "$guest")"
check 1 "$(printf '%s\n%s\n%s\n%s' "$ready" "$owner" "$loss" "$guest")"
check 1 "$(printf '%s\n%s\n%s\n%s' "$ready" "$owner" "$disposed" "$guest")"
check 1 "$(printf '%s\n%s\n%s\n%s\n%s' "$ready" "$owner" "$disposed" "$loss" "$guest")"
check 1 "$(printf '%s\n%s' "$good" "$loss")"
check 1 "$(printf '%s\n%s' "$good" "$disposed")"
for field in real_constructor never_started lost_pin_closed close_refused \
    review_retained unattempted_retained repeated_refused review_fd_count_equal \
    unrelated_kept exit0 child_reaped parent_fd_count_equal; do
    check 1 "${good/$field=true/$field=false}"
done
check 1 "${good/client_executed=false/client_executed=true}"
check 1 "${good/complete_inputs=true/complete_inputs=false}"
printf '%s\n' 'PHANTOWD_PENDING_INPUTS_LOG_CONTROLS_DONE scope=host-parser-only guest=false'
