#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PhantoWD EX4 contributors

set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <b2|b3> <resolved-linux-config>" >&2
    exit 2
fi

stage=$1
kernel_config=$2
case "$stage" in
    b2|b3) ;;
    *) echo "unsupported Stage B kernel-config audit stage: $stage" >&2; exit 2 ;;
esac
test -s "$kernel_config"

assert_enabled() {
    grep -Fx "CONFIG_$1=y" "$kernel_config" >/dev/null || {
        echo "Required Stage B kernel option is missing: CONFIG_$1" >&2
        exit 1
    }
}

assert_disabled() {
    if grep -Eq "^CONFIG_$1=(y|m)$" "$kernel_config"; then
        echo "Forbidden Stage B kernel option is enabled: CONFIG_$1" >&2
        exit 1
    fi
}

for option in MACH_KIRKWOOD CPU_FEROCEON SERIAL_8250 SERIAL_8250_CONSOLE \
    SERIAL_OF_PLATFORM DEVTMPFS PROC_FS SYSFS TMPFS ARM_APPENDED_DTB \
    ARM_ATAG_DTB_COMPAT CMDLINE_FORCE BLK_DEV_INITRD NET INET NETDEVICES \
    ETHERNET NET_VENDOR_MARVELL MV643XX_ETH MVMDIO PHYLIB OF_MDIO \
    NET_RX_BUSY_POLL NET_SELFTESTS; do
    assert_enabled "$option"
done

if [ "$stage" = b2 ]; then
    assert_disabled THERMAL THERMAL_OF KIRKWOOD_THERMAL
else
    for option in THERMAL THERMAL_OF KIRKWOOD_THERMAL; do
        assert_enabled "$option"
    done
    assert_disabled THERMAL_HWMON THERMAL_MMIO
fi

for option in MODULES BLOCK MTD USB_SUPPORT MMC SCSI ATA MD BLK_DEV_DM \
    I2C SPI RTC_CLASS WATCHDOG SOUND KEXEC CPU_FREQ CPU_IDLE SUSPEND PM \
    DEVMEM DEVPORT PCI_MVEBU HWMON DMADEVICES IPV6 NETFILTER \
    PACKET UNIX WIRELESS WLAN NET_DSA PTP_1588_CLOCK NET_PTP_CLASSIFY \
    NET_SWITCHDEV NET_PKTGEN NETWORK_FILESYSTEMS IP_PNP NFS_FS ROOT_NFS \
    SUNRPC; do
    assert_disabled "$option"
done

# These are derived Kconfig symbols in the pinned non-RT profile: busy-poll
# core defaults on for non-PREEMPT_RT kernels, while NET_SELFTESTS follows
# PHYLIB. They cannot be disabled independently without changing that profile.

unexpected_network_vendors="$(
    grep -E '^CONFIG_NET_VENDOR_[A-Z0-9_]+=y$' "$kernel_config" |
        grep -Fxv 'CONFIG_NET_VENDOR_MARVELL=y' || true
)"
if [ -n "$unexpected_network_vendors" ]; then
    echo 'Kernel config enabled network vendors outside the EX4 allowlist:' >&2
    printf '%s\n' "$unexpected_network_vendors" >&2
    exit 1
fi

grep -Fx 'CONFIG_CMDLINE="console=ttyS0,115200n8 rdinit=/init panic=-1"' \
    "$kernel_config" >/dev/null
# shellcheck disable=SC2016
grep -Fx 'CONFIG_INITRAMFS_SOURCE="${BR_BINARIES_DIR}/rootfs.cpio"' \
    "$kernel_config" >/dev/null

printf 'Stage %s kernel configuration audit passed\n' "$stage"
