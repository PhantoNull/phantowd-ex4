#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
verify=$script_dir/verify-nas-policy-edit.sh
scratch=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-policy-edit-receipt.XXXXXX")
trap 'rm -f "$scratch/log" "$scratch/link"; rmdir "$scratch"' EXIT HUP INT TERM
marker='PHANTOWD_NAS_POLICY_EDIT_READY cases=7 coherent_revision=true detached=true cross_protocol_preserved=true publication=false scope=synthetic-policy-only'
for count in 0 1 2 3; do
    : >"$scratch/log"
    index=0
    while [ "$index" -lt "$count" ]; do
        printf '%s\n' "$marker" >>"$scratch/log"
        index=$((index + 1))
    done
    if sh "$verify" "$scratch/log"; then [ "$count" -eq 2 ]; else [ "$count" -ne 2 ]; fi
done
printf '%s\r\n%s\r\n' "$marker" "$marker" >"$scratch/log"
sh "$verify" "$scratch/log"
for changed in "${marker}extra" "${marker%only}other" 'PHANTOWD_NAS_POLICY_EDIT_READY_LOOKALIKE'; do
    printf '%s\n%s\n' "$marker" "$changed" >"$scratch/log"
    if sh "$verify" "$scratch/log"; then exit 1; fi
done
printf '%s\n%s\n%s\n' "$marker" "$marker" 'PHANTOWD_NAS_POLICY_EDIT_READY extra' >"$scratch/log"
if sh "$verify" "$scratch/log"; then exit 1; fi
printf '%s\n%s\n' "$marker" "$marker" >"$scratch/log"
ln -s "$scratch/log" "$scratch/link"
if sh "$verify" "$scratch/link"; then exit 1; fi
truncate -s 1048577 "$scratch/log"
if sh "$verify" "$scratch/log"; then exit 1; fi
printf 'NAS policy edit receipt controls passed: exact_restart_pair=true incomplete_repeated_changed_refused=true bounded_regular_log=true\n'
