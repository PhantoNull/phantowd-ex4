#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Standard smoke executes the pure policy model before and after API restart.
set -eu
[ "$#" -eq 1 ] || exit 1
log_file=$1
[ -f "$log_file" ] && [ ! -L "$log_file" ] || exit 1
[ "$(wc -c <"$log_file")" -le 1048576 ] || exit 1
for marker in \
    'PHANTOWD_NAS_POLICY_EDIT_READY cases=7 coherent_revision=true detached=true cross_protocol_preserved=true publication=false scope=synthetic-policy-only' \
    'PHANTOWD_POLICY_VIEW_WRITER_READY commits=3 stale_refused=true cross_protocol_preserved=true uncertainty_fenced=true original_locks=true product=false scope=temporary-qemu-only' \
    'PHANTOWD_POLICY_EPOCH_RECORD_READY cases=8 exact_binding=true declarations_only=true admission=false scope=synthetic-memory-only'; do
    prefix=${marker%% *}
    rows=$(sed 's/\r$//' "$log_file" | grep -c "^$prefix" || true)
    exact=$(sed 's/\r$//' "$log_file" | grep -Fxc "$marker" || true)
    if [ "$rows" -ne 2 ] || [ "$exact" -ne 2 ]; then exit 1; fi
done
