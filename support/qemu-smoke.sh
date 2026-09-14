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
    -drive "file=$images_dir/rootfs.ext2,if=scsi,format=raw" \
    -snapshot \
    -append "rootwait root=/dev/sda console=ttyAMA0,115200" \
    -display none \
    -serial stdio \
    -monitor none \
    -no-reboot \
    -netdev user,id=net0 \
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
    if grep -F "$ready_marker" "$log_file" >/dev/null; then
        if grep -E 'Kernel panic|PHANTOWD_QEMU_ERROR' "$log_file" >/dev/null; then
            echo "QEMU reported a boot failure" >&2
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
