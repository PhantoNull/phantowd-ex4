#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository source required}
[ "$#" -eq 1 ] || exit 1
verifier="$source/support/tests/verify-pending-client-inputs-log.awk"
ready='PHANTOWD_PENDING_INPUTS_READY complete_root=true complete_bootstrap=true fixed_documents=true original_pins=true caller_duplicate_closed=true late_rechecked=true mismatches=2 canceled_refused=true released_refused=true no_fd_leak=true execution=false scope=qemu-only'
guest=PHANTOWD_PENDING_INPUTS_GUEST_DONE
good=$(printf '%s\n%s' "$ready" "$guest")
check() {
    expected=$1
    status=0
    printf '%s\n' "$2" | awk -f "$verifier" || status=$?
    [ "$status" -eq "$expected" ] || exit 1
}
check 0 "$good"
printf '%s\r\n%s\r\n' "$ready" "$guest" | awk -f "$verifier"
check 1 ''
check 1 "$ready"
check 1 "$guest"
check 1 "$(printf '%s\n%s' "$good" "$guest")"
check 1 "$(printf '%s\n%s' "$good" "$ready")"
check 1 "$(printf '%s\n%s' "$good" PHANTOWD_PENDING_INPUTS_GUEST_FAILED)"
check 1 "$(printf '%s\n%s' "$good" PHANTOWD_PENDING_UNKNOWN)"
check 1 "${good/original_pins=true/original_pins=false}"
check 1 "${good/execution=false/execution=true}"
check 1 "$(printf '%s extra=true\n%s' "$ready" "$guest")"
check 1 "$(printf '%s\r\r\n%s' "$ready" "$guest")"
printf '%s\n' 'PHANTOWD_PENDING_INPUTS_LOG_CONTROLS_DONE scope=host-parser-only guest=false'
