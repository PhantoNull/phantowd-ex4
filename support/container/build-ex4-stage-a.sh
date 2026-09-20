#!/bin/sh
set -eu

external_dir="${PHANTOWD_EXTERNAL_DIR:-/external}"
workspace_dir="${PHANTOWD_WORKSPACE_DIR:-/workspace}"

# shellcheck disable=SC1091
. "$external_dir/versions.env"

buildroot_source="$workspace_dir/buildroot-$BUILDROOT_VERSION"
download_dir="$workspace_dir/dl"
config_file="$external_dir/configs/phantowd_ex4_stage_a_defconfig"
fragment_file="$external_dir/board/wd/ex4/stage-a/linux.fragment"
dts_file="$external_dir/board/wd/ex4/stage-a/kirkwood-wd-mycloud-ex4-stage-a.dts"
init_file="$external_dir/board/wd/ex4/stage-a/rootfs-overlay/init"
release_file="$external_dir/board/wd/ex4/stage-a/rootfs-overlay/etc/phantowd-release"
post_build_file="$external_dir/board/wd/ex4/stage-a/post-build.sh"

test -f "$buildroot_source/.phantowd-source-ready"
test -s "$download_dir/linux/linux-$LINUX_VERSION.tar.xz"
grep -F "BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE=\"$LINUX_VERSION\"" \
    "$config_file" >/dev/null
grep -Fx 'BR2_LINUX_KERNEL_NEEDS_HOST_OPENSSL=y' "$config_file" >/dev/null
grep -Fx '#include "marvell/kirkwood.dtsi"' "$dts_file" >/dev/null
grep -Fx '#include "marvell/kirkwood-6282.dtsi"' "$dts_file" >/dev/null
grep -F "PHANTOWD_KERNEL_VERSION=$LINUX_VERSION" "$release_file" >/dev/null

assert_dts_status() {
    node="$1"
    expected="$2"
    awk -v declaration="&$node {" -v expected="$expected" '
        $0 == declaration {
            inside = 1
            seen = 1
            next
        }
        inside && $0 ~ "status = \\\"" expected "\\\";" {
            matched = 1
        }
        inside && $0 == "};" {
            exit !(seen && matched)
        }
        END {
            if (!(seen && matched))
                exit 1
        }
    ' "$dts_file" || {
        echo "DTS node &$node is not explicitly status=$expected" >&2
        exit 1
    }
}

assert_dts_status uart0 okay
for node in uart1 gpio0 gpio1 nand crypto_sram sata sata_phy0 sata_phy1 \
    sdio usb0 pciec pcie0 pcie1 eth0 eth1 mdio i2c0 i2c1 spi0 rtc \
    thermal wdt cesa dma0 dma1 audio0; do
    assert_dts_status "$node" disabled
done

input_hash="$(
    sha256sum "$config_file" "$fragment_file" "$dts_file" "$init_file" \
        "$release_file" "$post_build_file" | sha256sum | cut -c1-16
)"
output_dir="$workspace_dir/stage-a/$BUILDROOT_VERSION-$input_hash"

make -C "$buildroot_source" \
    BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" \
    O="$output_dir" \
    phantowd_ex4_stage_a_defconfig

make -C "$buildroot_source" \
    BR2_EXTERNAL="$external_dir" \
    BR2_DL_DIR="$download_dir" \
    O="$output_dir" \
    -j"$(getconf _NPROCESSORS_ONLN)"

kernel_config="$output_dir/build/linux-$LINUX_VERSION/.config"
dtb="$output_dir/images/kirkwood-wd-mycloud-ex4-stage-a.dtb"
zimage="$output_dir/images/zImage"

test -s "$kernel_config"
test -s "$dtb"
test -s "$zimage"
test -x "$output_dir/target/init"
test ! -x "$output_dir/target/etc/phantowd-release"

assert_enabled() {
    grep -Fx "CONFIG_$1=y" "$kernel_config" >/dev/null || {
        echo "Required kernel option is not built in: CONFIG_$1" >&2
        exit 1
    }
}

assert_disabled() {
    if grep -Eq "^CONFIG_$1=(y|m)$" "$kernel_config"; then
        echo "Forbidden kernel option is enabled: CONFIG_$1" >&2
        exit 1
    fi
}

for option in MACH_KIRKWOOD CPU_FEROCEON SERIAL_8250 \
    SERIAL_8250_CONSOLE SERIAL_OF_PLATFORM DEVTMPFS PROC_FS SYSFS TMPFS \
    CMDLINE_FORCE EXPERT PCI BLK_DEV_INITRD GPIOLIB GPIO_MVEBU \
    SERIAL_8250_FSL SERIAL_MCTRL_GPIO GENERIC_PHY PHY_MVEBU_SATA; do
    assert_enabled "$option"
done

for option in MODULES BLOCK MTD NET USB_SUPPORT MMC SCSI ATA MD \
    BLK_DEV_DM I2C SPI RTC_CLASS WATCHDOG SOUND KEXEC CGROUPS NAMESPACES \
    FHANDLE PERF_EVENTS COREDUMP VT UNIX98_PTYS LEGACY_PTYS MAGIC_SYSRQ \
    DEBUG_FS BPF_SYSCALL CPU_FREQ CPU_IDLE SUSPEND PM KPROBES PROFILING \
    DEVMEM DEVPORT SERIAL_8250_DMA SERIAL_8250_PCI SERIAL_8250_EXAR \
    SERIAL_8250_DW SERIAL_8250_PERICOM PCI_MVEBU PCIEASPM FW_LOADER \
    SRAM SERIO HW_RANDOM \
    POWER_RESET POWER_SUPPLY HWMON THERMAL MFD REGULATOR NEW_LEDS \
    DMADEVICES VIRTIO_MENU STAGING IOMMU_SUPPORT WPCM450_SOC EXTCON MEMORY \
    IIO PWM RESET_CONTROLLER PHY_MVEBU_A3700_UTMI NVMEM CONFIGFS_FS \
    MISC_FILESYSTEMS NLS KEYS CRYPTO; do
    assert_disabled "$option"
done

grep -Fx 'CONFIG_CMDLINE="console=ttyS0,115200n8 rdinit=/init panic=-1"' \
    "$kernel_config" >/dev/null
# shellcheck disable=SC2016 # The Buildroot variable must remain literal.
grep -Fx 'CONFIG_INITRAMFS_SOURCE="${BR_BINARIES_DIR}/rootfs.cpio"' \
    "$kernel_config" >/dev/null

for forbidden in fw_setenv flash_erase flash_eraseall nanddump nandwrite \
    mdadm mount.nfs ntfs-3g ssh sshd; do
    if find "$output_dir/target" -xdev \
        \( -type f -o -type l \) -name "$forbidden" -print -quit |
        grep -q .; then
        echo "Forbidden Stage A userspace path found: $forbidden" >&2
        exit 1
    fi
done

artifact_dir="$external_dir/artifacts/ex4-stage-a-compile-only"
install -d -m 0755 "$artifact_dir"
install -m 0644 "$zimage" "$artifact_dir/zImage"
install -m 0644 "$dtb" \
    "$artifact_dir/kirkwood-wd-mycloud-ex4-stage-a.dtb"
install -m 0644 "$kernel_config" "$artifact_dir/linux.config"
install -m 0644 "$output_dir/images/rootfs.cpio" "$artifact_dir/rootfs.cpio"
cat > "$artifact_dir/COMPILE-ONLY.txt" <<'EOF'
COMPILE-ONLY SAFETY ARTIFACT — DO NOT FLASH OR BOOT YET

This image has no block layer, MTD, network, USB, MMC, SCSI, ATA, mdraid,
device mapper, I2C, SPI, RTC, watchdog, sound, modules, kexec, CPU frequency or
idle transitions, direct physical-memory access, or optional hardware classes.
Mainline MACH_KIRKWOOD forces the unused PCI core plus generic GPIO/SATA-PHY
support to remain compiled in; the PCIe host driver is absent and the DTB
disables PCIe, both GPIO controllers and both SATA PHY nodes. ARM also retains
two inert 8250 support helpers. The DTB enables only the primary serial console
beyond mandatory core SoC infrastructure.

The CPIO is embedded in zImage; the separate rootfs.cpio is retained for static
inspection only. No legacy uImage wrapper or verified U-Boot load/entry address
is provided. These files are not direct TFTP/bootm inputs.

Compilation and static assertions do not prove RAM addresses, U-Boot command
compatibility, clocks, pinmux, console input, thermal behavior, halt behavior,
or recovery on physical WD My Cloud EX4 hardware. Do not boot it until the
two-way serial, data-backup, disk-removal and reviewed TFTP gates pass.
EOF
(
    cd "$artifact_dir"
    sha256sum zImage kirkwood-wd-mycloud-ex4-stage-a.dtb \
        linux.config rootfs.cpio > SHA256SUMS
)

printf 'EX4 Stage A compile passed. Do-not-boot artifact: %s\n' "$artifact_dir"
