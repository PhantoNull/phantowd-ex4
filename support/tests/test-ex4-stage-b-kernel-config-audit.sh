#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PhantoWD EX4 contributors

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
audit="$repo_root/support/container/audit-ex4-stage-b-kernel-config.sh"
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-kconfig-audit.XXXXXX")
trap 'rm -f "$temp_dir"/*; rmdir "$temp_dir"' EXIT HUP INT TERM

cat > "$temp_dir/valid-b3.config" <<'EOF'
CONFIG_MACH_KIRKWOOD=y
CONFIG_CPU_FEROCEON=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SERIAL_OF_PLATFORM=y
CONFIG_DEVTMPFS=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_ARM_APPENDED_DTB=y
CONFIG_ARM_ATAG_DTB_COMPAT=y
CONFIG_CMDLINE_FORCE=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_NET=y
CONFIG_INET=y
CONFIG_NETDEVICES=y
CONFIG_ETHERNET=y
CONFIG_NET_VENDOR_MARVELL=y
CONFIG_MV643XX_ETH=y
CONFIG_MVMDIO=y
CONFIG_PHYLIB=y
CONFIG_OF_MDIO=y
CONFIG_NET_RX_BUSY_POLL=y
CONFIG_NET_SELFTESTS=y
CONFIG_THERMAL=y
CONFIG_THERMAL_OF=y
CONFIG_KIRKWOOD_THERMAL=y
CONFIG_CMDLINE="console=ttyS0,115200n8 rdinit=/init panic=-1"
CONFIG_INITRAMFS_SOURCE="${BR_BINARIES_DIR}/rootfs.cpio"
# CONFIG_NFS_FS is not set
# CONFIG_NET_PKTGEN is not set
EOF

cat > "$temp_dir/valid-b2.config" <<'EOF'
CONFIG_MACH_KIRKWOOD=y
CONFIG_CPU_FEROCEON=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SERIAL_OF_PLATFORM=y
CONFIG_DEVTMPFS=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_ARM_APPENDED_DTB=y
CONFIG_ARM_ATAG_DTB_COMPAT=y
CONFIG_CMDLINE_FORCE=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_NET=y
CONFIG_INET=y
CONFIG_NETDEVICES=y
CONFIG_ETHERNET=y
CONFIG_NET_VENDOR_MARVELL=y
CONFIG_MV643XX_ETH=y
CONFIG_MVMDIO=y
CONFIG_PHYLIB=y
CONFIG_OF_MDIO=y
CONFIG_NET_RX_BUSY_POLL=y
CONFIG_NET_SELFTESTS=y
CONFIG_CMDLINE="console=ttyS0,115200n8 rdinit=/init panic=-1"
CONFIG_INITRAMFS_SOURCE="${BR_BINARIES_DIR}/rootfs.cpio"
# CONFIG_THERMAL is not set
# CONFIG_KIRKWOOD_THERMAL is not set
EOF

sh "$audit" b3 "$temp_dir/valid-b3.config" >/dev/null
sh "$audit" b2 "$temp_dir/valid-b2.config" >/dev/null

cp "$temp_dir/valid-b3.config" "$temp_dir/unexpected-vendor.config"
printf '%s\n' 'CONFIG_NET_VENDOR_REALTEK=y' >> "$temp_dir/unexpected-vendor.config"
if sh "$audit" b3 "$temp_dir/unexpected-vendor.config" >/dev/null 2>&1; then
    echo 'kernel-config audit accepted a non-Marvell network vendor' >&2
    exit 1
fi

cp "$temp_dir/valid-b3.config" "$temp_dir/packet-generator.config"
printf '%s\n' 'CONFIG_NET_PKTGEN=y' >> "$temp_dir/packet-generator.config"
if sh "$audit" b3 "$temp_dir/packet-generator.config" >/dev/null 2>&1; then
    echo 'kernel-config audit accepted the packet generator' >&2
    exit 1
fi

cp "$temp_dir/valid-b3.config" "$temp_dir/ptp-classifier.config"
printf '%s\n' 'CONFIG_PTP_1588_CLOCK=y' \
    'CONFIG_NET_PTP_CLASSIFY=y' >> "$temp_dir/ptp-classifier.config"
if sh "$audit" b3 "$temp_dir/ptp-classifier.config" >/dev/null 2>&1; then
    echo 'kernel-config audit accepted the unused PTP classifier' >&2
    exit 1
fi

cp "$temp_dir/valid-b3.config" "$temp_dir/missing-driver.config"
sed '/CONFIG_MV643XX_ETH=y/d' "$temp_dir/valid-b3.config" > \
    "$temp_dir/missing-driver.config"
if sh "$audit" b3 "$temp_dir/missing-driver.config" >/dev/null 2>&1; then
    echo 'kernel-config audit accepted a missing EX4 Ethernet driver' >&2
    exit 1
fi

printf 'Stage B kernel-config audit tests passed\n'
