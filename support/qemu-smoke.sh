#!/bin/sh
set -eu

images_dir="${1:?usage: qemu-smoke.sh IMAGES_DIR [LOG_FILE [EXPECTED_KERNEL]]}"
log_file="${2:-$images_dir/qemu-smoke.log}"
expected_kernel="${3:-}"
qemu_binary="${QEMU_SYSTEM_ARM:-qemu-system-arm}"
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
smoke_timeout=${PHANTOWD_QEMU_SMOKE_TIMEOUT_SECONDS:-240}
case "$smoke_timeout" in
    ''|*[!0-9]*|0*)
        echo 'QEMU smoke timeout must be 1..300 canonical whole seconds' >&2
        exit 1
        ;;
esac
if [ "${#smoke_timeout}" -gt 3 ] || [ "$smoke_timeout" -gt 300 ]; then
    echo 'QEMU smoke timeout must be 1..300 canonical whole seconds' >&2
    exit 1
fi

ready_marker='PHANTOWD_QEMU_READY target=qemu-armv5 kernel='
if [ -n "$expected_kernel" ]; then
    ready_marker="$ready_marker$expected_kernel"
fi

for required in zImage versatile-pb.dtb rootfs.ext2; do
    if [ ! -f "$images_dir/$required" ]; then
        echo "Missing QEMU artifact: $images_dir/$required" >&2
        exit 1
    fi
done

fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-qemu-data.XXXXXX")
qemu_pid=
cleanup() {
    # shellcheck disable=SC2317 # invoked through trap
    if [ -n "$qemu_pid" ]; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    # Exact regular file in a freshly created private temporary directory.
    # shellcheck disable=SC2317 # invoked through trap
    rm -f "$fixture_dir/data.ext2" "$fixture_dir/clone.ext2" "$fixture_dir/collision.raw" \
        "$fixture_dir/collision-clone.raw" \
        "$fixture_dir/md-member-a.raw" "$fixture_dir/md-member-b.raw"
    # shellcheck disable=SC2317 # invoked through trap
    rmdir "$fixture_dir"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
truncate -s 16M "$fixture_dir/data.ext2"
mkfs.ext2 -q -F -U 11111111-2222-3333-4444-555555555555 \
    -L PHANTOWD-TEST "$fixture_dir/data.ext2"
# A separate virtual device with the SAME filesystem UUID exercises ambiguity.
# Both files are disposable; the clone is presented read-only to the guest.
cp "$fixture_dir/data.ext2" "$fixture_dir/clone.ext2"
# A separate read-only virtual block node intentionally duplicates the root
# disk's VPD serial but has its own WWN. Its GPT is used only to verify parser
# output against the kernel's complete partition-child inventory.
python3 "$script_dir/make-qemu-gpt-fixture.py" "$fixture_dir/collision.raw"
# A second independent device is an exact GPT clone with distinct VPD identity.
# Both GPT disks stay read-only and are never mounted by the GPT observation.
cp "$fixture_dir/collision.raw" "$fixture_dir/collision-clone.raw"
# These blank backing files are used only to create a disposable RAID1 in the
# snapshot-mode guest. mdadm/mkfs writes are discarded with QEMU's overlays.
truncate -s 32M "$fixture_dir/md-member-a.raw" "$fixture_dir/md-member-b.raw"

: > "$log_file"
"$qemu_binary" \
    -M versatilepb \
    -cpu arm926 \
    -m 256M \
    -kernel "$images_dir/zImage" \
    -dtb "$images_dir/versatile-pb.dtb" \
    -drive "file=$images_dir/rootfs.ext2,if=none,id=rootdisk,format=raw" \
    -device lsi53c895a,id=scsi0 \
    -device "scsi-hd,bus=scsi0.0,drive=rootdisk,serial=PHANTOWD-QEMU-SERIAL-01,wwn=0x500f000000000001" \
    -drive "file=$fixture_dir/data.ext2,if=none,id=testdisk,format=raw" \
    -device "scsi-hd,bus=scsi0.0,drive=testdisk,serial=PHANTOWD-QEMU-DATA-01,wwn=0x500f000000000002" \
    -drive "file=$fixture_dir/clone.ext2,if=none,id=clonedisk,format=raw,readonly=on" \
    -device "scsi-hd,bus=scsi0.0,drive=clonedisk,serial=PHANTOWD-QEMU-CLONE-01,wwn=0x500f000000000003" \
    -drive "file=$fixture_dir/collision.raw,if=none,id=collisiondisk,format=raw,readonly=on" \
    -device "scsi-hd,bus=scsi0.0,drive=collisiondisk,serial=PHANTOWD-QEMU-SERIAL-01,wwn=0x500f000000000001" \
    -drive "file=$fixture_dir/md-member-a.raw,if=none,id=mdmembera,format=raw,snapshot=on" \
    -device "scsi-hd,bus=scsi0.0,drive=mdmembera,serial=PHANTOWD-QEMU-MD-A,wwn=0x500f000000000004" \
    -drive "file=$fixture_dir/md-member-b.raw,if=none,id=mdmemberb,format=raw,snapshot=on" \
    -device "scsi-hd,bus=scsi0.0,drive=mdmemberb,serial=PHANTOWD-QEMU-MD-B,wwn=0x500f000000000005" \
    -drive "file=$fixture_dir/collision-clone.raw,if=none,id=collisionclone,format=raw,readonly=on" \
    -device "scsi-hd,bus=scsi0.0,drive=collisionclone,serial=PHANTOWD-GPT-CLONE-01,wwn=0x500f000000000006" \
    -object rng-random,id=rng0,filename=/dev/urandom \
    -device virtio-rng-pci,rng=rng0 \
    -snapshot \
    -append "rootwait root=/dev/sda console=ttyAMA0,115200" \
    -display none \
    -serial stdio \
    -monitor none \
    -no-reboot \
    -netdev user,id=net0,restrict=on \
    -device rtl8139,netdev=net0,romfile= \
    > "$log_file" 2>&1 &
qemu_pid=$!
echo "QEMU smoke budget: timeout_seconds=$smoke_timeout poll_seconds=1"

attempt=0
while [ "$attempt" -lt "$smoke_timeout" ]; do
    if [ "$attempt" -gt 0 ] && [ "$((attempt % 30))" -eq 0 ]; then
        last_marker=$(awk '/^PHANTOWD_/ { line=substr($0, 1, 180) } END { print line }' "$log_file")
        echo "QEMU smoke progress: waited_seconds=$attempt last_marker=$last_marker"
    fi
    if grep -F 'PHANTOWD_QEMU_ERROR' "$log_file" >/dev/null; then
        echo "QEMU reported a boot readiness failure" >&2
        tail -n 80 "$log_file" >&2
        exit 1
    fi

    if grep -F "$ready_marker" "$log_file" >/dev/null; then
        if grep -E 'Kernel panic|PHANTOWD_QEMU_ERROR|PHANTOWD_API_ERROR' "$log_file" >/dev/null; then
            echo "QEMU reported a boot failure" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_API_READY target=qemu-armv5 goarm=5' "$log_file" >/dev/null; then
            echo "Missing ARMv5 diagnostics API assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_STORAGE_COLLISION_READY nodes=2 serial=ambiguous wwn=ambiguous redacted=true read_only=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo "Missing ARMv5 duplicate storage-identity assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_STORAGE_BROKER_READY api_outside_device_group=true broker_nnp_all_threads=true broker_capabilities=none whole_disk_mode=0440 hotplug_rechecked=true nodes=2 serial=ambiguous wwn=ambiguous redacted=true read_only=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo "Missing ARMv5 least-privilege storage broker assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SHARE_POLICY_READY schema=1 scope=synthetic-policy-only' "$log_file" >/dev/null; then
            echo "Missing ARMv5 share-policy validation assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SHARE_STORE_READY revision=2 reopen=true scope=temporary-qemu-only' "$log_file" >/dev/null; then
            echo "Missing ARMv5 share-store revision/reopen assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMB_PREVIEW_READY parser=testparm grants=ro,rw scope=synthetic-config-only' "$log_file" >/dev/null; then
            echo "Missing generated Samba policy parser assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_NETWORK_INVENTORY_READY kernel=true repeated=true routes=true fib_only=true rules=true nexthops=true object_fixture=true address_fixture=true counts_redacted=true json_refused=true apply=false scope=qemu-namespace-only' "$log_file" >/dev/null; then
            echo "Kernel network inventory self-test marker missing" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_NETWORK_POLICY_READY schema=1 dual_stack=true aliases=true conflict_refused=true strict_json=true apply=false scope=synthetic-policy-only' "$log_file" >/dev/null; then
            echo "Desired network policy self-test marker missing" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_NFS_POLICY_READY schema=1 mapping=all-squash scope=synthetic-policy-only' "$log_file" >/dev/null; then
            echo "Missing NFS policy validation assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_FILE_SERVICE_PREVIEW_READY authenticated=true csrf=true applied=false scope=desired-policy-only' "$log_file" >/dev/null; then
            echo "Missing authenticated file-service preview assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_FILE_SERVICE_PLAN_READY snapshot=complete-mounted-owner-set-nonempty roster_lease=all_member_owned descriptor_revoked=true owner_scope=fixture_complete volume_count=1 revisions=bound fresh_check=passed parser=testparm json=false activation=false compatibility=synthetic-ext2 scope=disposable-qemu-only' "$log_file" >/dev/null; then
            echo "Missing internal file-service plan assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_FILE_SERVICE_OWNER_MOUNTED_PLAN_READY identity=owner_observed storage=complete_mounted_owner_set owner_scope=fixture_complete volume_count=1 uid_gid=local_census nfs=read_only identity_stale=true mount_stale=true candidate_only=true auth_mutation=false activation=false http=false scope=disposable-qemu-only' "$log_file" >/dev/null; then
            echo 'Missing combined Owner identity and mounted-storage planner assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_FILE_SERVICE_OWNER_MOUNTED_EXPORTFS_READY target_parser=accepted_and_withdrawn owner_tuple=true read_only=true identity_mapping=true persistent_export=false scope=disposable-qemu-only' "$log_file" >/dev/null; then
            echo 'Missing Owner-mounted NFS exportfs acceptance/withdrawal assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMB_POLICY_IO_READY generated=true writer_uid=1801 reader_ro=true outsider_denied=true unix_denied=true symlink_denied=true process_owner=started-ready-stopped scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing generated Samba effective-access assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_PROCESS_OWNER_REVIEW_READY unexpected_exit=true review_required=true restart_blocked=true group_reaped=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'QEMU did not verify process-owner quarantine after an unexpected exit' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_PROCESS_OWNER_FORCE_STOP_READY sigterm_ignored=true forced_termination=true review_required=true restart_blocked=true group_reaped=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'QEMU did not verify process-owner forced-stop quarantine' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_PROCESS_OWNER_FAILED_START_REVIEW_READY failed_start=true forced_cleanup=true review_persistent=true restart_blocked=true group_reaped=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'QEMU did not verify failed-start review persistence after forced cleanup' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_PROCESS_SET_READY members=2 all_ready=true generation=1 clean_stop=true stop_generation=1 scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'QEMU did not verify all-ready multi-service startup and clean stop' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_PROCESS_SET_ROLLBACK_READY members=2 later_start_failed=true earlier_stopped=true generation=0 review=false scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'QEMU did not verify rollback after a later service failed readiness' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_PROCESS_SET_MEMBER_REVIEW_READY exited_member_review=true healthy_peer_preserved=true restart_blocked=true explicit_stop=true review_persistent=true peers_reaped=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'QEMU did not verify member-level process-set review and peer cleanup' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMB_CREDENTIALS_READY rotated=true old_password_denied=true disabled_denied=true reenabled=true unix_identity_unchanged=true data_preserved=true scope=new-qemu-connections-only' "$log_file" >/dev/null; then
            echo 'Missing Samba credential lifecycle assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_UNIX_IDENTITY_READY exclusions=true partial_detected=true exact_binding=true conflict_refused=true cleanup_verified=true scope=local-qemu-files-only' "$log_file" >/dev/null; then
            echo 'Missing local Unix identity reconciliation assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_IDENTITY_PROVISION_READY durable_intents=true confirmed_group_reopened=true unix_confirmed=true scope=isolated-qemu-backend-only' "$log_file" >/dev/null; then
            echo 'Missing journaled Unix provisioning assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_PASSWORD_TLS_READY changed=true old_login_denied=true new_login=true scope=qemu-loopback-only' "$log_file" >/dev/null; then
            echo 'QEMU password-change HTTPS test did not complete' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SYSTEM_SNAPSHOT_READY schema=1 nonroot=true authenticated=true scope=qemu-loopback-only' "$log_file" >/dev/null; then
            echo 'QEMU authenticated system snapshot assertion did not complete' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_STORAGE_RESPONSE_READY schema=2 broker=true opened=true content_read=false scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'QEMU authenticated read-only storage broker response assertion did not complete' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_GPT_OBSERVATION_READY eligible=6 gpt_disks=2 partitions=2 duplicate_disk_guids=2 duplicate_partuuids=2 summary_only=true normal_refresh_redacted=true auth=true csrf=true manual=true read_only=true no_mount=true no_mutation=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'QEMU explicit authenticated GPT observation or HTTP redaction assertion did not complete' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_IDENTITY_EXEC_READY binary=pinned-busybox typed_commands=true unix_login_locked=true nologin=true home_created=false scope=isolated-qemu-only' "$log_file" >/dev/null; then
            echo 'QEMU typed native identity executor did not complete' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_IDENTITY_CHANNEL_READY peer_uid=65534 server_uid=0 journaled_steps=true stale_replay_denied=true scope=isolated-qemu-only' "$log_file" >/dev/null; then
            echo 'QEMU unprivileged identity channel did not complete' >&2
            exit 1
        fi
        for phase in group user second; do
            if ! grep -F "PHANTOWD_IDENTITY_LISTENER_READY phase=$phase protected=true lease_exclusive=true drained=true scope=isolated-qemu-only" "$log_file" >/dev/null; then
                echo "Protected identity listener lifecycle marker missing: $phase" >&2
                exit 1
            fi
        done
        if ! grep -F 'PHANTOWD_IDENTITY_ROUTER_READY accounts=2 distinct_ids=true historical_unchanged=true unknown_denied=true scope=isolated-qemu-only' "$log_file" >/dev/null; then
            echo 'QEMU multi-account identity router did not complete' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_M41_OWNER_PASSDB_OBSERVATION_READY owner_locked=true ledger=true native_journals=true samba_journal=true passdb=redacted uid_gid=local_census no_adoption=true journals_unchanged=true auth_mutation=false activation=false http=false scope=disposable-qemu-only' "$log_file" >/dev/null; then
            echo 'ARMv5 Owner-backed read-only identity/passdb observation did not complete' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_M41_OWNER_STORAGE_COHERENT_READY identity=owner_passdb_fingerprint storage=mounted_roster locks=ordered nfs=readonly samba=empty_policy candidate=true activation=false endpoint=false auth_mutation=false scope=disposable-qemu-only' "$log_file" >/dev/null; then
            echo 'ARMv5 M4.1 lock-coherent Owner identity and storage plan did not complete' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMB_DISABLED_PASSWORD_SET_READY replacement_set=true disabled_until_explicit_enable=true obsolete_password_denied=true unix_identity_unchanged=true scope=isolated-qemu-only' "$log_file" >/dev/null; then
            echo 'Samba disabled-password update did not complete safely' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMB_DISABLED_ENROLLMENT_READY owner_lock=true intent_journal=true created_disabled=true empty_credential_denied=true password_set_disabled=true pre_enable_valid_denied=true enable_explicit=true same_sid_revalidated=true post_enable_valid_accepted=true post_enable_empty_denied=true disable_explicit=true disabled_new_auth_denied=true reenable_explicit=true reenabled_auth_accepted=true scope=isolated-qemu-only' "$log_file" >/dev/null; then
            echo 'Samba disabled-account enrollment did not complete safely' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMB_CONNECTION_REVOCATION_READY pre_disable_active_write=true disable_revokes_active_sessions=true target_connections=2 target_sessions_absent=true same_ip_peer_preserved=true peer_session_verified=true fresh_login_denied=true process_generation_available=true generation_targeting=qemu-only stale_generation_nonmatch_safe=true pid_targeting=false open_handles=false durable_reconnect=false scope=isolated-qemu-only' "$log_file" >/dev/null; then
            echo 'Samba active-session revocation characterization did not complete safely' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_IDENTITY_OWNER_READY lease_exclusive=true pending_blocks_reservation=true after_reopen=true scope=isolated-qemu-only' "$log_file" >/dev/null; then
            echo 'QEMU native identity authority did not complete' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_IDENTITY_OWNER_DESIRED_STATE_READY enabled=true disabled=true registry_revisioned=true native_journal_immutable=true smb_journal=false auth_mutation=false service_activation=false http=false scope=qemu-only' "$log_file" >/dev/null; then
            echo 'QEMU native identity-owner desired-state contract did not complete' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_IDENTITY_OWNER_BOOT_READY service_uid=0 socket_mode=0620 api_uid=nonroot config_validated_before_owner_state=true config_missing_rejected=true config_invalid_rejected=true no_side_effects=true process_restart=true drained=true desired_state_roundtrip=true native_journal_immutable=true smb_journal=false service_activation=false runtime=run http=false scope=qemu-only' "$log_file" >/dev/null; then
            echo 'QEMU boot identity-owner service contract did not complete' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SESSION_REVOCATION_READY peers=2 old_sessions_denied=true fresh_login=true scope=panel-sessions-only' "$log_file" >/dev/null; then
            echo 'Missing global panel session revocation assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_MOUNT_GUARD_READY unique_mount_id=true descriptor_pinned=true symlinks_denied=true nested_mount_denied=true overmount_denied=true readonly_change_denied=true lease_revoked_on_identity_failure=true fresh_root_required=true fallback_denied=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing descriptor/mount guard assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_MOUNT_OWNER_READY qualified_before_lease=true identity_change_blocks_new_access=true owner_handles_revoked=true set_lease_identity_loss=true returned_anchor_no_reuse=true ambiguous_mount_no_retry=true ambiguous_unmount_no_retry=true mismatch_no_lease=true target_fd_anchored=true target_replacement_not_used=true late_target_race_pinned_object_only=true late_target_race_quarantined=true source_fd_anchored=true source_replacement_quarantined=true scope=disposable-qemu-only' "$log_file" >/dev/null; then
            echo 'Missing trusted mount-owner lifecycle assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SERVICE_HANDOFF_READY share_subtree_clone=true read_only_enforced=true target_bound=true service_uid=1000 service_gid=1000 exact_groups=true ungranted_uid=65534_denied=true mismatched_group_rejected=true source_replacement_not_used=true source_loss_quarantined=true set_lease_held=true explicit_unmount=true scope=disposable-qemu-only' "$log_file" >/dev/null; then
            echo 'Missing non-root service handoff access-boundary assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_MOUNT_GRAPH_READY backing_members=2 actual_raid1=true readonly_mountinfo=true both_members_attributed=true unrelated_disk_clear=true cleanup=true scope=disposable-qemu-only' "$log_file" >/dev/null; then
            echo 'Missing real disposable RAID1 mount-graph assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_MD_FILESYSTEM_IDENTITY_READY filesystem_to_md=true md_uuid_internal=true members=2 readonly_mount=true conflict_free=true scope=disposable-qemu-only' "$log_file" >/dev/null; then
            echo 'Missing mounted filesystem to MD/member identity assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_M33_M34_PROVIDER_READY source=complete_md_filesystem_identity owner=live_mount_revalidated roster=complete_for_fixture_only uuid=true device_tuple=true read_only=true planner_snapshot=true activation=false http=false scope=disposable-qemu-only' "$log_file" >/dev/null; then
            echo 'Missing M3.3-to-M3.4 trusted mounted-volume provider assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_MOUNTED_EXT_CENSUS_READY namespace_scoped=true roots_from_mountinfo=true rootfs_excluded=true md_members=2 repeated_metadata=true private=true block_opened=false file_data_read=false qualification=false activation=false scope=disposable-qemu-only' "$log_file" >/dev/null; then
            echo 'Missing private complete-scope mounted-ext census assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_M35_TWO_VOLUME_READY distinct_filesystems=true lost_volume_quarantined=true lost_handles_revoked=true healthy_group_lease_survived=true fresh_healthy_owner_lease=true roster_reacquire=all_or_error scope=disposable-qemu-only' "$log_file" >/dev/null; then
            echo 'Missing M3.5 two-volume lease-loss assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_FILESYSTEM_UUID_READY source=kernel-ioctl expected_uuid=true mismatch_denied=true block_device_opened=false scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing kernel filesystem UUID assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_MOUNTED_AMBIGUITY_READY cloned_uuid=true bind_alias_not_clone=true incomplete_scan_refused=true scope=provided-mounted-ext-only' "$log_file" >/dev/null; then
            echo 'Missing mounted filesystem ambiguity assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_MOUNTED_STORAGE_CORRELATION_READY anchors=3 uuid_conflict_entries=3 bind_alias_same_device=true complete_sysfs=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing mounted filesystem to complete storage identity assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_VOLUME_PROBE_READY backend=libblkid unmounted_devices=2 readonly_descriptors=true expected_uuid=true unidentified_not_empty=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing unmounted metadata probe assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_PARTITION_TABLE_READY gpt=true backup_header_offset_gt_2g=true sparse_regular_image=true read_only=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing sparse large-GPT partition-table probe assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_PARTITION_SYSFS_CORRELATION_READY candidates_complete=true table_disks=2 partitions=2 start_size_match=true type_guid_preserved=true generic_type_hint=linux-data mismatch_refused=true cloned_pair=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing parser-to-kernel partition reconciliation assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_PARTITION_IDENTITY_CLASSIFICATION_READY candidates_complete=true observed_gpt_disks=2 coverage=partial cloned_guest_disks=2 duplicate_disk_guid=ambiguous duplicate_partuuid=ambiguous scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing complete-set GPT clone-identity classification assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_VOLUME_SET_READY cloned_uuid=true aliases_deduplicated=true generation_bound=true stale_generation_refused=true unobserved_not_absent=true shuffled_complete_set=true trusted_complete_discovery=true mount_swap_rechecked=true sysfs_rechecked=true observed_opener=true readonly_sources=true all_or_error=true symlink_refused=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing complete QEMU source-set opener assertions' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_VOLUME_COLLISION_READY ext_control=true xfs_control=true invalid_control=true collision_refused=true partial_set_discarded=true hashes_unchanged=true scope=synthetic-regular-images' "$log_file" >/dev/null; then
            echo 'Missing ARMv5 competing-signature refusal assertions' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_UI_READY mode=development assets_verified=true activation=false transport=guest-loopback-only' "$log_file" >/dev/null; then
            echo "Missing loopback-only dashboard assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SYSFS_STORAGE_READY complete=true' "$log_file" >/dev/null; then
            echo 'Missing complete QEMU sysfs storage collector assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMART_SYSFS_CENSUS_READY complete=true leaves=7 mounted_root_included=true ambiguous_vpd_preserved=true device_opened=false command_admitted=false scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing read-only SMART census assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMART_MD_CENSUS_READY complete=true leaves=7 active_md_members=2 mounted_root_included=true device_opened=false command_admitted=false scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing in-use MD member SMART census assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMART_FD_WITNESS_READY active_md_members=2 retained_fd=true caller_close=true mismatch_refused=true review_sticky=true metadata_ioctl=BLKGETDISKSEQ content_read=false smart_command=false scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing retained SMART descriptor-generation assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMART_CENSUS_WITNESS_SET_READY leaves=7 complete=true partial_refused=true rollback_no_leak=true caller_close=true review_pins_retained=true reader_failure_sticky=true explicit_release=true content_read=false smart_command=false scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing complete retained SMART census-set assertion' >&2
            exit 1
        fi
        if ! grep -E 'PHANTOWD_AUTH_READY algorithm=argon2id kdf_concurrency=1 bootstrap=created login_enabled=yes transport=guest-loopback-http state=volatile-qemu session=memory-only kdf_cycle_ms=[0-9]+' "$log_file" >/dev/null; then
            echo "Missing first-account/authentication ARMv5 self-test assertion" >&2
            exit 1
        fi
        if ! grep -E 'PHANTOWD_AUTH_READY algorithm=argon2id kdf_concurrency=1 bootstrap=existing login_enabled=yes transport=guest-loopback-http state=volatile-qemu session=memory-only kdf_cycle_ms=[0-9]+' "$log_file" >/dev/null; then
            echo "Missing persisted-account login after API restart assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_TLS_READY target=qemu-armv5 min_version=1.2 origin_enforced=true scope=loopback-test-only' "$log_file" >/dev/null; then
            echo "Missing ARMv5 TLS handshake and exact-origin assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_AUTH_STATE_READY account_survives=daemon-restart sessions_memory_only=true scope=qemu-loopback-only' "$log_file" >/dev/null; then
            echo "Missing account persistence across API process restart assertion" >&2
            exit 1
        fi
        if ! grep -E 'PHANTOWD_NFS_RESOURCE userspace_daemons=rpcbind,rpc.statd,rpc.mountd rss_kib=[0-9]+' "$log_file" >/dev/null; then
            echo "Missing NFS userspace resource measurement" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_NFS_SMOKE_READY protocol=nfs3 transport=tcp scope=qemu-loopback-only' "$log_file" >/dev/null; then
            echo "Missing loopback-only NFSv3/TCP integration assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_NFS_POLICY_IO_READY generated=exportfs plan_parser=accepted-and-withdrawn rw=sync-verified ro=EROFS uid=101000 gid=101000 denied_client=true mount_guard=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo "Missing generated NFS policy access/mapping/mount-guard assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMB_LISTENER_READY address=127.0.0.1:445 smb1=disabled netbios=nmbd-disabled' "$log_file" >/dev/null; then
            echo "Missing loopback-only SMB listener and NetBIOS-disabled assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMB_SMOKE_READY client_max_protocol=SMB3_11 server_min_protocol=SMB3_00 server_max_protocol=SMB3_11 transport=tcp scope=qemu-loopback-only' "$log_file" >/dev/null; then
            echo "Missing loopback-only SMB3 integration assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMB_READONLY_READY denied_write=confirmed scope=qemu-loopback-only' "$log_file" >/dev/null; then
            echo "Missing SMB read-only authorization assertion" >&2
            exit 1
        fi
        if ! grep -E 'PHANTOWD_SMB_RESOURCE userspace_daemons=smbd rss_kib=[0-9]+' "$log_file" >/dev/null; then
            echo "Missing SMB userspace resource measurement" >&2
            exit 1
        fi
        echo "QEMU ARMv5 smoke test passed"
        exit 0
    fi

    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        echo "QEMU exited before the readiness marker" >&2
        tail -n 80 "$log_file" >&2
        exit 1
    fi

    attempt=$((attempt + 1))
    sleep 1
done

echo "Timed out waiting for the QEMU readiness marker: timeout_seconds=$smoke_timeout" >&2
tail -n 80 "$log_file" >&2
exit 1
