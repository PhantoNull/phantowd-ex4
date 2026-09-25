#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PhantoWD EX4 contributors

set -eu

external_dir="${PHANTOWD_EXTERNAL_DIR:-/external}"
workspace_dir="${PHANTOWD_WORKSPACE_DIR:-/workspace}"
stage="${PHANTOWD_EX4_STAGE:-b2}"

case "$stage" in
    b2)
        stage_label='Stage B2'
        network_mode='link-observation-only'
        thermal_status=disabled
        ;;
    b3)
        stage_label='Stage B3'
        network_mode='dual-link-and-internal-thermal-observation-only'
        thermal_status=okay
        ;;
    *)
        echo "Unsupported EX4 research stage: $stage" >&2
        exit 2
        ;;
esac

# shellcheck disable=SC1091
. "$external_dir/versions.env"

buildroot_source="$workspace_dir/buildroot-$BUILDROOT_VERSION"
download_dir="$workspace_dir/dl"
stage_a_dir="$external_dir/board/wd/ex4/stage-a"
stage_b_dir="$external_dir/board/wd/ex4/stage-b"
stage_b2_dir="$external_dir/board/wd/ex4/stage-b2"
stage_dir="$external_dir/board/wd/ex4/stage-$stage"
config_file="$external_dir/configs/phantowd_ex4_stage_${stage}_defconfig"
fragment_file="$stage_b_dir/linux.fragment"
stage_fragment="$stage_dir/linux.fragment"
stage_b2_fragment="$stage_b2_dir/linux.fragment"
busybox_fragment="$stage_dir/busybox.fragment"
dts_file="$stage_dir/kirkwood-wd-mycloud-ex4-stage-$stage.dts"
init_file="$stage_dir/rootfs-overlay/init"
release_file="$stage_dir/rootfs-overlay/etc/phantowd-release"
mac_policy_file="$stage_dir/rootfs-overlay/usr/lib/phantowd/stage-b3/mac-policy.sh"
kernel_config_audit="$external_dir/support/container/audit-ex4-stage-b-kernel-config.sh"

test -f "$buildroot_source/.phantowd-source-ready"
test -s "$download_dir/linux/linux-$LINUX_VERSION.tar.xz"
grep -Fx "BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE=\"$LINUX_VERSION\"" "$config_file" >/dev/null
grep -Fx 'BR2_PACKAGE_HOST_UBOOT_TOOLS=y' "$config_file" >/dev/null
grep -F 'board/wd/ex4/stage-a/linux.fragment' "$config_file" >/dev/null
grep -F 'board/wd/ex4/stage-b/linux.fragment' "$config_file" >/dev/null
grep -F 'board/wd/ex4/stage-b2/linux.fragment' "$config_file" >/dev/null
grep -F "board/wd/ex4/stage-$stage/linux.fragment" "$config_file" >/dev/null
grep -F "board/wd/ex4/stage-$stage/busybox.fragment" "$config_file" >/dev/null
grep -Fx '#include "marvell/kirkwood.dtsi"' "$dts_file" >/dev/null
grep -Fx '#include "marvell/kirkwood-6282.dtsi"' "$dts_file" >/dev/null
grep -Fx "PHANTOWD_KERNEL_VERSION=$LINUX_VERSION" "$release_file" >/dev/null
grep -Fx "PHANTOWD_NETWORK_MODE=$network_mode" "$release_file" >/dev/null
test -s "$kernel_config_audit"

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
assert_dts_status thermal "$thermal_status"
for node in uart1 gpio0 gpio1 nand crypto_sram sata sata_phy0 sata_phy1 \
    sdio usb0 pciec pcie0 pcie1 i2c0 i2c1 spi0 rtc wdt \
    cesa dma0 dma1 audio0; do
    assert_dts_status "$node" disabled
done
grep -F 'phy-handle = <&ethphy0>;' "$dts_file" >/dev/null
grep -F 'ethphy0: ethernet-phy@0 {' "$dts_file" >/dev/null
grep -F 'phy-handle = <&ethphy1>;' "$dts_file" >/dev/null
grep -F 'ethphy1: ethernet-phy@1 {' "$dts_file" >/dev/null
grep -Fx 'CONFIG_IFCONFIG=y' "$busybox_fragment" >/dev/null
grep -Fx 'CONFIG_INET=y' "$stage_b2_fragment" >/dev/null
grep -Fx '# CONFIG_IP_PNP is not set' "$stage_fragment" >/dev/null
grep -Fx '# CONFIG_NFS_FS is not set' "$stage_b2_fragment" >/dev/null
if [ "$stage" = b3 ]; then
    test -s "$mac_policy_file"
    sh "$external_dir/support/tests/test-stage-b3-mac-policy.sh" \
        "$mac_policy_file"
fi

if [ "$stage" = b3 ]; then
    input_hash="$(
        sha256sum "$config_file" "$stage_a_dir/linux.fragment" \
            "$stage_a_dir/busybox.config" "$stage_a_dir/post-build.sh" \
            "$fragment_file" "$stage_b2_fragment" "$stage_fragment" \
            "$busybox_fragment" "$dts_file" "$init_file" \
            "$mac_policy_file" "$release_file" |
            sha256sum | cut -c1-16
    )"
else
    input_hash="$(
        sha256sum "$config_file" "$stage_a_dir/linux.fragment" \
            "$stage_a_dir/busybox.config" "$stage_a_dir/post-build.sh" \
            "$fragment_file" "$stage_b2_fragment" "$stage_fragment" \
            "$busybox_fragment" "$dts_file" "$init_file" "$release_file" |
            sha256sum | cut -c1-16
    )"
fi
output_dir="$workspace_dir/stage-$stage/$BUILDROOT_VERSION-$input_hash"

kernel_config="$output_dir/build/linux-$LINUX_VERSION/.config"

make -C "$buildroot_source" BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" O="$output_dir" \
    "phantowd_ex4_stage_${stage}_defconfig"
# Configure and audit the final Kconfig result before paying for a kernel build.
make -C "$buildroot_source" BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" O="$output_dir" linux-configure
test -s "$kernel_config"
sh "$kernel_config_audit" "$stage" "$kernel_config"

make -C "$buildroot_source" BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" O="$output_dir" \
    -j"$(getconf _NPROCESSORS_ONLN)"

dtb="$output_dir/images/kirkwood-wd-mycloud-ex4-stage-$stage.dtb"
zimage="$output_dir/images/zImage"
cpio="$output_dir/images/rootfs.cpio"
test -s "$kernel_config"
test -s "$dtb"
test -s "$zimage"
test -s "$cpio"
test -x "$output_dir/target/init"
test ! -e "$output_dir/target/etc/network"
sh "$kernel_config_audit" "$stage" "$kernel_config"

# These stages add only ifconfig to Stage A's exact minimal BusyBox surface.
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
wrapped="$output_dir/uImage-stage-$stage.compile-only"
SOURCE_DATE_EPOCH=0 "$mkimage" -A arm -O linux -T kernel -C none \
    -a 0x00008000 -e 0x00008000 \
    -n "PhantoWD EX4 $stage_label" -d "$appended" "$wrapped"
wrapped_size="$(wc -c < "$wrapped" | tr -d '[:space:]')"
test "$wrapped_size" -eq "$((appended_size + 64))"
test "$wrapped_size" -le 5242880
SOURCE_DATE_EPOCH=0 "$mkimage" -A arm -O linux -T kernel -C none \
    -a 0x00008000 -e 0x00008000 \
    -n "PhantoWD EX4 $stage_label" -d "$appended" \
    "$output_dir/uImage-stage-$stage-second-build.actual" >/dev/null
cmp "$wrapped" "$output_dir/uImage-stage-$stage-second-build.actual"
dd if="$wrapped" of="$output_dir/uimage-payload.actual" \
    bs=64 skip=1 status=none
cmp "$appended" "$output_dir/uimage-payload.actual"
"$mkimage" -l "$wrapped" > "$output_dir/uimage-header.actual"
grep -Fx 'Image Type:   ARM Linux Kernel Image (uncompressed)' \
    "$output_dir/uimage-header.actual" >/dev/null
grep -Fx 'Load Address: 00008000' "$output_dir/uimage-header.actual" >/dev/null
grep -Fx 'Entry Point:  00008000' "$output_dir/uimage-header.actual" >/dev/null

artifact_dir="$external_dir/artifacts/ex4-stage-$stage-compile-only"
install -d -m 0755 "$artifact_dir"
install -m 0644 "$zimage" "$artifact_dir/zImage"
install -m 0644 "$dtb" "$artifact_dir/kirkwood-wd-mycloud-ex4-stage-$stage.dtb"
install -m 0644 "$appended" "$artifact_dir/zImage-with-appended-dtb.compile-only"
install -m 0644 "$wrapped" "$artifact_dir/uImage-stage-$stage.compile-only"
install -m 0644 "$kernel_config" "$artifact_dir/linux.config"
install -m 0644 "$cpio" "$artifact_dir/rootfs.cpio"
if [ "$stage" = b2 ]; then
    cat > "$artifact_dir/COMPILE-ONLY.txt" <<'EOF'
Stage B2 is a NON-FLASHABLE research artifact. It raises both Ethernet
interfaces briefly to observe link carrier, then lowers them and halts. There
is no DHCP, IP configuration, SSH server, storage, MTD or NAND writer. Link
negotiation is expected; do not assume the interfaces are electrically passive.
EOF
else
    cat > "$artifact_dir/COMPILE-ONLY.txt" <<'EOF'
Stage B3 is a NON-FLASHABLE research artifact. A physical trial requires a
separately reviewed procedure and per-unit MAC values entered into U-Boot RAM
only; never save those environment changes. It reports MAC handoff status,
warns on placeholders, and fails closed if the two interface MACs are equal.
It raises both Ethernet interfaces together, samples both links at two-second
intervals, then lowers both interfaces and halts. The SoC thermal sensor is
sampled over serial; it is observational only and has no fan or shutdown
policy. There is no IP configuration, DHCP, network service, storage, MTD or
NAND writer. Do not install or use with data-bearing disks.
EOF
fi
cat > "$artifact_dir/UIMAGE-RESEARCH-MANIFEST.txt" <<EOF
format=legacy-uimage
status=compile-only
flashable=no
hardware_validated=no
target=wd-my-cloud-ex4
stage=$stage-dual-link-mac-and-thermal-observation
network_mode=$network_mode
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
    sha256sum zImage "kirkwood-wd-mycloud-ex4-stage-$stage.dtb" \
        zImage-with-appended-dtb.compile-only "uImage-stage-$stage.compile-only" \
        linux.config rootfs.cpio COMPILE-ONLY.txt \
        UIMAGE-RESEARCH-MANIFEST.txt > SHA256SUMS
)
printf 'EX4 %s compile passed. Non-flashable artifact: %s\n' "$stage_label" "$artifact_dir"
