#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Two independent kernels; only a NEW regular-file data disk persists.
set -eu
images=${1:?images directory}
log=${2:?output log}
qemu=${QEMU_SYSTEM_ARM:-qemu-system-arm}
case "$images" in *[!a-zA-Z0-9_./:-]*) echo 'Unsupported image path' >&2; exit 1 ;; esac
for file in rootfs.ext2 zImage versatile-pb.dtb; do
    [ -f "$images/$file" ] && [ ! -L "$images/$file" ] || exit 1
done
workspace=$(mktemp -d /tmp/phantowd-state-reboot.XXXXXX)
qemu_pid=
cleanup() {
    if [ -n "$qemu_pid" ]; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    # Only explicit files in this invocation's newly allocated directory.
    rm -f "$workspace/state.ext2" "$workspace/seed.log" "$workspace/verify.log"
    rmdir "$workspace"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
truncate -s 16M "$workspace/state.ext2"
mkfs.ext2 -q -F -U 11111111-2222-3333-4444-555555555555 "$workspace/state.ext2"
: > "$log"
for phase in seed verify; do
    "$qemu" -M versatilepb -cpu arm926 -m 256M \
        -kernel "$images/zImage" -dtb "$images/versatile-pb.dtb" \
        -drive "file=$images/rootfs.ext2,if=none,id=rootdisk,format=raw,snapshot=on" \
        -device lsi53c895a,id=scsi0 \
        -device scsi-hd,bus=scsi0.0,drive=rootdisk,serial=PHANTOWD-QEMU-SERIAL-01,wwn=0x500f000000000001 \
        -drive "file=$workspace/state.ext2,if=none,id=statedisk,format=raw,cache=writethrough" \
        -device scsi-hd,bus=scsi0.0,drive=statedisk,serial=PHANTOWD-QEMU-DATA-01,wwn=0x500f000000000002 \
        -object rng-random,id=rng0,filename=/dev/urandom \
        -device virtio-rng-pci,rng=rng0 \
        -append "rootwait root=/dev/sda ro console=ttyAMA0,115200 init=/usr/lib/phantowd/qemu-state-init.sh phantowd.state=$phase" \
        -display none -serial stdio -monitor none -no-reboot -nic none \
        > "$workspace/$phase.log" 2>&1 &
    qemu_pid=$!
    attempt=0
    while kill -0 "$qemu_pid" 2>/dev/null && [ "$attempt" -lt 60 ]; do
        sleep 1
        attempt=$((attempt + 1))
    done
    if kill -0 "$qemu_pid" 2>/dev/null; then
        cat "$workspace/$phase.log" >> "$log"
        echo 'State reboot QEMU timed out' >&2
        exit 1
    fi
    status=0
    wait "$qemu_pid" || status=$?
    qemu_pid=
    cat "$workspace/$phase.log" >> "$log"
    [ "$status" -eq 0 ] || exit 1
    if grep -E 'PHANTOWD_STATE_ERROR|PHANTOWD_API_ERROR|Kernel panic' "$workspace/$phase.log"; then
        exit 1
    fi
    grep -F "PHANTOWD_STATE_BOOT_READY phase=$phase scope=disposable-qemu-only" "$workspace/$phase.log" >/dev/null
    grep -F 'reboot: Restarting system' "$workspace/$phase.log" >/dev/null
done
grep -F 'PHANTOWD_SHARE_READ_READY authenticated=true backend=sharestore after_reboot=true mutation=false scope=qemu-handler-dispatch-only' "$log" >/dev/null
grep -F 'PHANTOWD_SERVICE_STATE_READY protocols=smb,nfs atomic_revision=true after_reboot=true activation=false scope=disposable-qemu-only' "$log" >/dev/null
grep -F 'PHANTOWD_SERVICE_HTTP_READY protocols=http,https authenticated=true csrf=true stale_write_denied=true after_reboot=true activation=false scope=disposable-qemu-only' "$log" >/dev/null
grep -F 'PHANTOWD_SERVICE_IDENTITIES_READY after_reboot=true retired_ids_reserved=true stale_writer_denied=true share_binding=true provisioned=false scope=disposable-qemu-only' "$log" >/dev/null
grep -F 'PHANTOWD_SMB_REBOOT_READY unix_preserved=true rotated_password_retained=true disabled_retained=true explicit_enable=true obsolete_password_denied=true data_preserved=true scope=clean-qemu-reboot-only' "$log" >/dev/null
echo 'PHANTOWD_STATE_REBOOT_READY boots=2 committed_policy=true pending_not_promoted=true corrupt_refused=true stale_writer_denied=true scope=clean-qemu-reboot-only' | tee -a "$log"
