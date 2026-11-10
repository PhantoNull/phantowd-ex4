#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
images=${1:?verified image directory required}
log=${2:?log file required}
status=0
timeout --signal=TERM --kill-after=5 90 qemu-system-arm \
    -M versatilepb -cpu arm926 -m 256M -display none -serial stdio -monitor none -no-reboot -nic none \
    -kernel "$images/zImage" -dtb "$images/versatile-pb.dtb" \
    -drive "file=$images/rootfs.ext2,format=raw,if=scsi,readonly=on" \
    -object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0 \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 init=/usr/lib/phantowd/qemu-nas-policy-boot-init.sh' \
    >"$log" 2>&1 || status=$?
expected=$(cat <<'EOF'
PHANTOWD_NAS_BOOT_BEFORE_PROVIDER_READY init_exit_nonzero=true api_started=false
PHANTOWD_NAS_PROVIDER_READY root=true directory_mode=0710 socket_mode=0660 runtime=run scope=qemu-only
PHANTOWD_NAS_PROVIDER_INIT_READY before_api=true runtime=run
PHANTOWD_NAS_BOOT_MISSING_READY standard_main=true exit_nonzero=true no_fallback=true
PHANTOWD_NAS_BOOT_API_READY init=true nonroot=true https=verified authenticated=true config=provider scope=qemu-only
PHANTOWD_NAS_BOOT_DONE
EOF
)
if [ "$status" -ne 0 ] || [ "$(grep '^PHANTOWD_NAS_' "$log" | tr -d '\r')" != "$expected" ]; then
    tail -n 80 "$log" >&2
    exit 1
fi
