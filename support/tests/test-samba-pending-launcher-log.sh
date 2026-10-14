#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
source=${1:?repository source required}
[ "$#" -eq 1 ] || exit 1
verifier="$source/support/tests/verify-samba-pending-launcher-log.awk"
boundary='PHANTOWD_PENDING_LAUNCHER_BOUNDARY_DONE private_namespace=true readonly_root=true caps_zero=true ids_65534=true nnp=true pipe_control=true original_exec=true refusals=3 stopped_reaped=true originals_closed_after_stop=true smb=false scope=qemu-only'
guest=PHANTOWD_PENDING_LAUNCHER_GUEST_DONE
good=$(printf '%s\n%s' "$boundary" "$guest")
check() {
    expected=$1
    status=0
    printf '%s\n' "$2" | awk -f "$verifier" || status=$?
    [ "$status" -eq "$expected" ] || exit 1
}
check 0 "$good"
printf '%s\r\n%s\r\n' "$boundary" "$guest" | awk -f "$verifier"
check 1 ''
check 1 "$boundary"
check 1 "$guest"
check 1 "$(printf '%s\n%s' "$good" "$guest")"
check 1 "$(printf '%s\n%s' "$good" "$boundary")"
check 1 "$(printf '%s\n%s' "$good" PHANTOWD_PENDING_LAUNCHER_GUEST_FAILED)"
check 1 "$(printf '%s\n%s' "$good" PHANTOWD_PENDING_UNKNOWN)"
check 1 "${good/caps_zero=true/caps_zero=false}"
check 1 "${good/smb=false/smb=true}"
check 1 "$(printf '%s extra=true\n%s' "$boundary" "$guest")"
check 1 "$(printf '%s\r\r\n%s' "$boundary" "$guest")"
printf '%s\n' 'PHANTOWD_PENDING_LAUNCHER_LOG_CONTROLS_DONE scope=host-parser-only guest=false'
