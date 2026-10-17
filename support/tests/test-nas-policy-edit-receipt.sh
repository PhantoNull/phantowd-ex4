#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
verify=$script_dir/verify-nas-policy-edit.sh
scratch=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-policy-edit-receipt.XXXXXX")
trap 'rm -f "$scratch/log" "$scratch/link"; rmdir "$scratch"' EXIT HUP INT TERM
marker='PHANTOWD_NAS_POLICY_EDIT_READY cases=7 coherent_revision=true detached=true cross_protocol_preserved=true publication=false scope=synthetic-policy-only'
writer='PHANTOWD_POLICY_VIEW_WRITER_READY commits=3 stale_refused=true cross_protocol_preserved=true uncertainty_fenced=true original_locks=true product=false scope=temporary-qemu-only'
for which in model writer; do
    selected=$marker
    other=$writer
    if [ "$which" = writer ]; then selected=$writer; other=$marker; fi
for count in 0 1 2 3; do
    printf '%s\n%s\n' "$other" "$other" >"$scratch/log"
    index=0
    while [ "$index" -lt "$count" ]; do
        printf '%s\n' "$selected" >>"$scratch/log"
        index=$((index + 1))
    done
    if sh "$verify" "$scratch/log"; then [ "$count" -eq 2 ]; else [ "$count" -ne 2 ]; fi
done
printf '%s\r\n%s\r\n%s\r\n%s\r\n' "$selected" "$selected" "$other" "$other" >"$scratch/log"
sh "$verify" "$scratch/log"
for changed in "${selected}extra" "${selected%only}other" "${selected%% *}_LOOKALIKE"; do
    printf '%s\n%s\n%s\n%s\n' "$selected" "$changed" "$other" "$other" >"$scratch/log"
    if sh "$verify" "$scratch/log"; then exit 1; fi
done
printf '%s\n%s\n%s\n%s\n%s\n' "$selected" "$selected" "$other" "$other" "${selected%% *} extra" >"$scratch/log"
if sh "$verify" "$scratch/log"; then exit 1; fi
done
printf '%s\n%s\n%s\n%s\n' "$marker" "$marker" "$writer" "$writer" >"$scratch/log"
ln -s "$scratch/log" "$scratch/link"
if sh "$verify" "$scratch/link"; then exit 1; fi
truncate -s 1048577 "$scratch/log"
if sh "$verify" "$scratch/log"; then exit 1; fi
printf 'NAS policy edit receipt controls passed: exact_model_writer_pairs=true incomplete_repeated_changed_refused=true bounded_regular_log=true\n'
