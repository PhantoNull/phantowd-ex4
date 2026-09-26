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

cleanup() {
    # shellcheck disable=SC2317 # invoked through trap
    kill "$qemu_pid" 2>/dev/null || true
    # shellcheck disable=SC2317 # invoked through trap
    wait "$qemu_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

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
        if ! grep -F 'PHANTOWD_UI_READY mode=development read_only=true transport=guest-loopback-only' "$log_file" >/dev/null; then
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
