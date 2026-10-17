#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Standard smoke executes the pure policy model before and after API restart.
set -eu
[ "$#" -eq 1 ] || exit 1
log_file=$1
[ -f "$log_file" ] && [ ! -L "$log_file" ] || exit 1
[ "$(wc -c <"$log_file")" -le 1048576 ] || exit 1
marker='PHANTOWD_NAS_POLICY_EDIT_READY cases=7 coherent_revision=true detached=true cross_protocol_preserved=true publication=false scope=synthetic-policy-only'
rows=$(sed 's/\r$//' "$log_file" | grep -c '^PHANTOWD_NAS_POLICY_EDIT_READY' || true)
exact=$(sed 's/\r$//' "$log_file" | grep -Fxc "$marker" || true)
[ "$rows" -eq 2 ] && [ "$exact" -eq 2 ]
