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
epoch='PHANTOWD_POLICY_EPOCH_RECORD_READY cases=8 exact_binding=true declarations_only=true admission=false scope=synthetic-memory-only'
journal='PHANTOWD_POLICY_EPOCH_JOURNAL_READY scenarios=3 fresh_only=true actual_store_lock=true exact_readback=true uncertainty_fenced=true private_copies=true declarations_only=true admission=false scope=temporary-qemu-only'
session='PHANTOWD_POLICY_SESSION_WRITER_READY scenarios=5 original_locks=true opening_required=true unified_history=true checkpoint_bound=true closure_serialized=true uncertainty_fenced=true close_does_not_seal=true product=false scope=temporary-qemu-only'
session_fs='PHANTOWD_POLICY_SESSION_FS_READY scenarios=10 original_locks=4 checkpoint_bound=true pending_metadata_only=true restored_refused=true readonly=true admission=false scope=temporary-qemu-only'
credentials='PHANTOWD_CREDENTIAL_STATE_FS_READY profiles=2 scenarios=10 root_only_chap=true values_redacted=true legacy_preserved=true pending_metadata_only=true original_lock=true readonly=true admission=false scope=temporary-qemu-only'
identity='PHANTOWD_IDENTITY_DOCUMENT_READY cases=8 complete_links=true malformed_not_hidden=true values_redacted=true readonly=true recovery=false admission=false scope=synthetic-memory-only'
identity_fs='PHANTOWD_IDENTITY_STATE_FS_READY cases=8 original_locks=true complete_roster=true pending_metadata_only=true restored_refused=true readonly=true recovery=false admission=false scope=temporary-qemu-only'
others() {
    for row in "$marker" "$writer" "$epoch" "$journal" "$session" "$session_fs" "$credentials" "$identity" "$identity_fs"; do
        if [ "$row" != "$selected" ]; then printf '%s\n%s\n' "$row" "$row"; fi
    done
}
for selected in "$marker" "$writer" "$epoch" "$journal" "$session" "$session_fs" "$credentials" "$identity" "$identity_fs"; do
for count in 0 1 2 3; do
    others >"$scratch/log"
    index=0
    while [ "$index" -lt "$count" ]; do
        printf '%s\n' "$selected" >>"$scratch/log"
        index=$((index + 1))
    done
    if sh "$verify" "$scratch/log"; then [ "$count" -eq 2 ]; else [ "$count" -ne 2 ]; fi
done
printf '%s\r\n' "$marker" "$marker" "$writer" "$writer" "$epoch" "$epoch" "$journal" "$journal" "$session" "$session" "$session_fs" "$session_fs" "$credentials" "$credentials" "$identity" "$identity" "$identity_fs" "$identity_fs" >"$scratch/log"
sh "$verify" "$scratch/log"
for changed in "${selected}extra" "${selected%only}other" "${selected%% *}_LOOKALIKE"; do
    others >"$scratch/log"
    printf '%s\n%s\n' "$selected" "$changed" >>"$scratch/log"
    if sh "$verify" "$scratch/log"; then exit 1; fi
done
others >"$scratch/log"
printf '%s\n%s\n%s\n' "$selected" "$selected" "${selected%% *} extra" >>"$scratch/log"
if sh "$verify" "$scratch/log"; then exit 1; fi
done
printf '%s\n' "$marker" "$marker" "$writer" "$writer" "$epoch" "$epoch" "$journal" "$journal" "$session" "$session" "$session_fs" "$session_fs" "$credentials" "$credentials" "$identity" "$identity" "$identity_fs" "$identity_fs" >"$scratch/log"
ln -s "$scratch/log" "$scratch/link"
if sh "$verify" "$scratch/link"; then exit 1; fi
truncate -s 1048577 "$scratch/log"
if sh "$verify" "$scratch/log"; then exit 1; fi
printf 'NAS policy edit receipt controls passed: exact_model_writer_epoch_journal_session_fs_credentials_identity_fs_pairs=true incomplete_repeated_changed_refused=true bounded_regular_log=true\n'
