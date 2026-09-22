#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PhantoWD EX4 contributors

set -eu

external_dir="${PHANTOWD_EXTERNAL_DIR:-/external}"
workspace_dir="${PHANTOWD_WORKSPACE_DIR:-/workspace}"

# shellcheck disable=SC1091
. "$external_dir/versions.env"

buildroot_source="$workspace_dir/buildroot-$BUILDROOT_VERSION"
download_dir="$workspace_dir/dl"
stage_a_dir="$external_dir/board/wd/ex4/stage-a"
stage_b_dir="$external_dir/board/wd/ex4/stage-b"
stage_b2_dir="$external_dir/board/wd/ex4/stage-b2"
config_file="$external_dir/configs/phantowd_ex4_stage_b2_defconfig"
fragment_file="$stage_b_dir/linux.fragment"
busybox_fragment="$stage_b2_dir/busybox.fragment"
dts_file="$stage_b2_dir/kirkwood-wd-mycloud-ex4-stage-b2.dts"
init_file="$stage_b2_dir/rootfs-overlay/init"
release_file="$stage_b2_dir/rootfs-overlay/etc/phantowd-release"

test -f "$buildroot_source/.phantowd-source-ready"
test -s "$download_dir/linux/linux-$LINUX_VERSION.tar.xz"
grep -Fx "BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE=\"$LINUX_VERSION\"" "$config_file" >/dev/null
grep -Fx 'BR2_PACKAGE_HOST_UBOOT_TOOLS=y' "$config_file" >/dev/null
grep -F 'board/wd/ex4/stage-a/linux.fragment' "$config_file" >/dev/null
grep -F 'board/wd/ex4/stage-b/linux.fragment' "$config_file" >/dev/null
grep -F 'board/wd/ex4/stage-b2/busybox.fragment' "$config_file" >/dev/null
grep -Fx '#include "marvell/kirkwood.dtsi"' "$dts_file" >/dev/null
grep -Fx '#include "marvell/kirkwood-6282.dtsi"' "$dts_file" >/dev/null
grep -Fx "PHANTOWD_KERNEL_VERSION=$LINUX_VERSION" "$release_file" >/dev/null
grep -Fx 'PHANTOWD_NETWORK_MODE=link-observation-only' "$release_file" >/dev/null

assert_dts_status() {
    node="$1"
    expected="$2"
    awk -v declaration="&$node {" -v expected="$expected" '
        $0 == declaration { inside = 1; seen = 1; next }
        inside && $0 ~ "status = \\\"" expected "\\\";" { matched = 1 }
        inside && $0 == "};" { exit !(seen && matched) }
        END { if (!(seen && matched)) exit 1 }
    ' "$dts_file" || {
        echo "DTS node &$node is not explicitly status=$expected" >&2
        exit 1
    }
}

for node in uart0 eth0 eth1 mdio; do assert_dts_status "$node" okay; done
for node in uart1 gpio0 gpio1 nand crypto_sram sata sata_phy0 sata_phy1 \
    sdio usb0 pciec pcie0 pcie1 i2c0 i2c1 spi0 rtc thermal wdt \
    cesa dma0 dma1 audio0; do
    assert_dts_status "$node" disabled
done
grep -F 'phy-handle = <&ethphy0>;' "$dts_file" >/dev/null
grep -F 'ethphy0: ethernet-phy@0 {' "$dts_file" >/dev/null
grep -F 'phy-handle = <&ethphy1>;' "$dts_file" >/dev/null
grep -F 'ethphy1: ethernet-phy@1 {' "$dts_file" >/dev/null
grep -Fx 'CONFIG_IFCONFIG=y' "$busybox_fragment" >/dev/null

input_hash="$(
    sha256sum "$config_file" "$stage_a_dir/linux.fragment" \
        "$stage_a_dir/busybox.config" "$stage_a_dir/post-build.sh" \
        "$fragment_file" "$busybox_fragment" "$dts_file" "$init_file" \
        "$release_file" |
        sha256sum | cut -c1-16
)"
output_dir="$workspace_dir/stage-b2/$BUILDROOT_VERSION-$input_hash"

make -C "$buildroot_source" BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" O="$output_dir" \
    phantowd_ex4_stage_b2_defconfig
make -C "$buildroot_source" BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" O="$output_dir" \
    -j"$(getconf _NPROCESSORS_ONLN)"

kernel_config="$output_dir/build/linux-$LINUX_VERSION/.config"
dtb="$output_dir/images/kirkwood-wd-mycloud-ex4-stage-b2.dtb"
zimage="$output_dir/images/zImage"
cpio="$output_dir/images/rootfs.cpio"
test -s "$kernel_config"
test -s "$dtb"
test -s "$zimage"
test -s "$cpio"
test -x "$output_dir/target/init"
test ! -e "$output_dir/target/etc/network"

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
    ETHERNET NET_VENDOR_MARVELL MV643XX_ETH MVMDIO PHYLIB OF_MDIO; do
    assert_enabled "$option"
done
for option in MODULES BLOCK MTD USB_SUPPORT MMC SCSI ATA MD BLK_DEV_DM \
    I2C SPI RTC_CLASS WATCHDOG SOUND KEXEC CPU_FREQ CPU_IDLE SUSPEND PM \
    DEVMEM DEVPORT PCI_MVEBU HWMON THERMAL DMADEVICES IPV6 NETFILTER \
    PACKET UNIX WIRELESS WLAN NET_DSA; do
    assert_disabled "$option"
done
grep -Fx 'CONFIG_CMDLINE="console=ttyS0,115200n8 rdinit=/init panic=-1"' \
    "$kernel_config" >/dev/null
# shellcheck disable=SC2016
grep -Fx 'CONFIG_INITRAMFS_SOURCE="${BR_BINARIES_DIR}/rootfs.cpio"' \
    "$kernel_config" >/dev/null

# Stage B2 adds only ifconfig to Stage A's exact minimal BusyBox surface.
busybox_build_dir="$(find "$output_dir/build" -maxdepth 1 -type d \
    -name 'busybox-*' -print -quit)"
test -n "$busybox_build_dir"
test -s "$busybox_build_dir/.config"
grep '=y$' "$busybox_build_dir/.config" | sort > \
    "$output_dir/busybox-enabled.actual"
cat > "$output_dir/busybox-enabled.expected" <<'EOF'
CONFIG_ASH=y
CONFIG_ASH_ECHO=y
CONFIG_ASH_INTERNAL_GLOB=y
CONFIG_ASH_TEST=y
CONFIG_BASH_IS_NONE=y
CONFIG_FEATURE_BUFFERS_USE_MALLOC=y
CONFIG_HALT=y
CONFIG_HAVE_DOT_CONFIG=y
CONFIG_IFCONFIG=y
CONFIG_INSTALL_APPLET_SYMLINKS=y
CONFIG_LFS=y
CONFIG_MOUNT=y
CONFIG_NO_DEBUG_LIB=y
CONFIG_SHELL_ASH=y
CONFIG_SH_IS_ASH=y
CONFIG_SLEEP=y
CONFIG_TRY_LOOP_CONFIGURE=y
CONFIG_UNAME=y
EOF
if ! cmp -s "$output_dir/busybox-enabled.expected" \
    "$output_dir/busybox-enabled.actual"; then
    echo 'Stage B BusyBox gained an unaudited option:' >&2
    diff -u "$output_dir/busybox-enabled.expected" \
        "$output_dir/busybox-enabled.actual" >&2 || true
    exit 1
fi

for path in bin/ash bin/mount bin/sh bin/sleep bin/uname sbin/halt \
    sbin/ifconfig; do
    test -x "$output_dir/target/$path" || {
        echo "Required Stage B BusyBox applet is missing: $path" >&2
        exit 1
    }
done
test -x "$output_dir/target/bin/busybox"
test -x "$output_dir/target/lib/ld-linux.so.3"
test -x "$output_dir/target/lib/libc.so.6"
test ! -e "$output_dir/target/sbin/ip"
test ! -e "$output_dir/target/bin/ping"

"$output_dir/host/bin/arm-buildroot-linux-gnueabi-readelf" -d \
    "$output_dir/target/bin/busybox" |
    sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' | sort > \
    "$output_dir/busybox-needed.actual"
cat > "$output_dir/busybox-needed.expected" <<'EOF'
ld-linux.so.3
libc.so.6
EOF
if ! cmp -s "$output_dir/busybox-needed.expected" \
    "$output_dir/busybox-needed.actual"; then
    echo 'Stage B BusyBox gained an unexpected dynamic dependency:' >&2
    diff -u "$output_dir/busybox-needed.expected" \
        "$output_dir/busybox-needed.actual" >&2 || true
    exit 1
fi

find "$output_dir/target/lib" -maxdepth 1 \
    \( -type f -o -type l \) -print | sort > "$output_dir/libraries.actual"
cat > "$output_dir/libraries.expected" <<EOF
$output_dir/target/lib/ld-linux.so.3
$output_dir/target/lib/libc.so.6
EOF
if ! cmp -s "$output_dir/libraries.expected" "$output_dir/libraries.actual"; then
    echo 'Stage B root filesystem contains unexpected shared libraries:' >&2
    diff -u "$output_dir/libraries.expected" \
        "$output_dir/libraries.actual" >&2 || true
    exit 1
fi

executables="$output_dir/executables.actual"
find "$output_dir/target" -xdev -type f -perm /111 -print | sort > "$executables"
cat > "$output_dir/executables.expected" <<EOF
$output_dir/target/bin/busybox
$output_dir/target/init
$output_dir/target/lib/ld-linux.so.3
$output_dir/target/lib/libc.so.6
EOF
if ! cmp -s "$output_dir/executables.expected" "$executables"; then
    echo 'Stage B root filesystem contains unexpected executable files:' >&2
    diff -u "$output_dir/executables.expected" "$executables" >&2 || true
    exit 1
fi

find "$output_dir/target" -xdev -type l -print | while IFS= read -r path; do
    link_target="$(readlink "$path")"
    case "$link_target" in
        *busybox)
            relative_path="${path#"$output_dir/target/"}"
            case "$relative_path" in
                bin/ash|bin/mount|bin/sh|bin/sleep|bin/uname|sbin/halt|sbin/ifconfig) ;;
                *)
                    echo "Unexpected Stage B BusyBox applet: $relative_path" >&2
                    exit 1
                    ;;
            esac
            ;;
    esac
done

busybox_archive_mode="$(
    "$output_dir/host/bin/cpio" -itv --quiet < "$cpio" |
        awk '$1 ~ /^-/ && ($NF == "bin/busybox" || $NF == "./bin/busybox") {
            print $1
        }'
)"
if [ "$busybox_archive_mode" != '-rwxr-xr-x' ]; then
    echo "Unexpected initramfs BusyBox mode: $busybox_archive_mode" >&2
    exit 1
fi

appended="$output_dir/zImage-with-appended-dtb.compile-only"
cat "$zimage" "$dtb" > "$appended"
zimage_size="$(wc -c < "$zimage" | tr -d '[:space:]')"
dtb_size="$(wc -c < "$dtb" | tr -d '[:space:]')"
appended_size="$(wc -c < "$appended" | tr -d '[:space:]')"
test "$appended_size" -eq "$((zimage_size + dtb_size))"
cmp -n "$zimage_size" "$zimage" "$appended"
test "$(dd if="$appended" bs=1 skip="$zimage_size" count=4 \
    status=none | od -An -tx1 | tr -d '[:space:]')" = 'd00dfeed'

mkimage="$output_dir/host/bin/mkimage"
test -x "$mkimage"
wrapped="$output_dir/uImage-stage-b2.compile-only"
SOURCE_DATE_EPOCH=0 "$mkimage" -A arm -O linux -T kernel -C none \
    -a 0x00008000 -e 0x00008000 \
    -n 'PhantoWD EX4 Stage B2' -d "$appended" "$wrapped"
wrapped_size="$(wc -c < "$wrapped" | tr -d '[:space:]')"
test "$wrapped_size" -eq "$((appended_size + 64))"
test "$wrapped_size" -le 5242880
SOURCE_DATE_EPOCH=0 "$mkimage" -A arm -O linux -T kernel -C none \
    -a 0x00008000 -e 0x00008000 \
    -n 'PhantoWD EX4 Stage B2' -d "$appended" \
    "$output_dir/uImage-stage-b2-second-build.actual" >/dev/null
cmp "$wrapped" "$output_dir/uImage-stage-b2-second-build.actual"
dd if="$wrapped" of="$output_dir/uimage-payload.actual" \
    bs=64 skip=1 status=none
cmp "$appended" "$output_dir/uimage-payload.actual"
"$mkimage" -l "$wrapped" > "$output_dir/uimage-header.actual"
grep -Fx 'Image Type:   ARM Linux Kernel Image (uncompressed)' \
    "$output_dir/uimage-header.actual" >/dev/null
grep -Fx 'Load Address: 00008000' "$output_dir/uimage-header.actual" >/dev/null
grep -Fx 'Entry Point:  00008000' "$output_dir/uimage-header.actual" >/dev/null

artifact_dir="$external_dir/artifacts/ex4-stage-b2-compile-only"
install -d -m 0755 "$artifact_dir"
install -m 0644 "$zimage" "$artifact_dir/zImage"
install -m 0644 "$dtb" "$artifact_dir/kirkwood-wd-mycloud-ex4-stage-b2.dtb"
install -m 0644 "$appended" "$artifact_dir/zImage-with-appended-dtb.compile-only"
install -m 0644 "$wrapped" "$artifact_dir/uImage-stage-b2.compile-only"
install -m 0644 "$kernel_config" "$artifact_dir/linux.config"
install -m 0644 "$cpio" "$artifact_dir/rootfs.cpio"
cat > "$artifact_dir/COMPILE-ONLY.txt" <<'EOF'
Stage B2 is a NON-FLASHABLE research artifact. Do not boot it before a separate
physical safety review. It adds Ethernet 1 and a second candidate MDIO PHY to
Stage B. A fixed init script briefly raises both interfaces to observe link
carrier, then lowers them and halts. There is no DHCP, IP configuration,
SSH server, storage, MTD or NAND writer. Link negotiation is expected; do not
assume the interfaces are electrically passive. The prior Stage B boot does
not qualify Stage B2 PHY mapping, cooling or recovery.
EOF
cat > "$artifact_dir/UIMAGE-RESEARCH-MANIFEST.txt" <<EOF
format=legacy-uimage
status=compile-only
flashable=no
hardware_validated=no
target=wd-my-cloud-ex4
stage=B2-dual-ethernet-link-observation
network_mode=link-observation-only
storage_enabled=no
payload_bytes=$appended_size
payload_sha256=$(sha256sum "$appended" | awk '{print $1}')
wrapped_bytes=$wrapped_size
wrapped_sha256=$(sha256sum "$wrapped" | awk '{print $1}')
timestamp_unix=0
load_address=0x00008000
entry_point=0x00008000
approved_boot_command=no
EOF
(
    cd "$artifact_dir"
    sha256sum zImage kirkwood-wd-mycloud-ex4-stage-b2.dtb \
        zImage-with-appended-dtb.compile-only uImage-stage-b2.compile-only \
        linux.config rootfs.cpio COMPILE-ONLY.txt \
        UIMAGE-RESEARCH-MANIFEST.txt > SHA256SUMS
)
printf 'EX4 Stage B2 compile passed. Non-flashable artifact: %s\n' "$artifact_dir"
