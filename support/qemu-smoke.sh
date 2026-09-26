#!/bin/sh
set -eu

images_dir="${1:?usage: qemu-smoke.sh IMAGES_DIR [LOG_FILE [EXPECTED_KERNEL]]}"
log_file="${2:-$images_dir/qemu-smoke.log}"
expected_kernel="${3:-}"
qemu_binary="${QEMU_SYSTEM_ARM:-qemu-system-arm}"

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
    rm -f "$fixture_dir/data.ext2" "$fixture_dir/clone.ext2"
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

attempt=0
while [ "$attempt" -lt 120 ]; do
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
        if ! grep -F 'PHANTOWD_NFS_POLICY_READY schema=1 mapping=all-squash scope=synthetic-policy-only' "$log_file" >/dev/null; then
            echo "Missing NFS policy validation assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_FILE_SERVICE_PREVIEW_READY authenticated=true csrf=true applied=false scope=desired-policy-only' "$log_file" >/dev/null; then
            echo "Missing authenticated file-service preview assertion" >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_SMB_POLICY_IO_READY generated=true writer_uid=1801 reader_ro=true outsider_denied=true unix_denied=true symlink_denied=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing generated Samba effective-access assertion' >&2
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
        if ! grep -F 'PHANTOWD_SESSION_REVOCATION_READY peers=2 old_sessions_denied=true fresh_login=true scope=panel-sessions-only' "$log_file" >/dev/null; then
            echo 'Missing global panel session revocation assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_MOUNT_GUARD_READY unique_mount_id=true descriptor_pinned=true symlinks_denied=true nested_mount_denied=true overmount_denied=true readonly_change_denied=true fallback_denied=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing descriptor/mount guard assertion' >&2
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
        if ! grep -F 'PHANTOWD_VOLUME_PROBE_READY backend=libblkid unmounted_devices=2 readonly_descriptors=true expected_uuid=true unidentified_not_empty=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
            echo 'Missing unmounted metadata probe assertion' >&2
            exit 1
        fi
        if ! grep -F 'PHANTOWD_VOLUME_SET_READY cloned_uuid=true aliases_deduplicated=true unobserved_not_absent=true scope=provided-descriptors-only' "$log_file" >/dev/null; then
            echo 'Missing unmounted probe-set identity assertions' >&2
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
        if ! grep -F 'PHANTOWD_NFS_POLICY_IO_READY generated=exportfs rw=sync-verified ro=EROFS uid=101000 gid=101000 denied_client=true mount_guard=true scope=qemu-fixture-only' "$log_file" >/dev/null; then
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

echo "Timed out waiting for the QEMU readiness marker" >&2
tail -n 80 "$log_file" >&2
exit 1
