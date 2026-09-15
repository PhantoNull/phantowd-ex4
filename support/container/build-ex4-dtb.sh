#!/bin/sh
set -eu

external_dir="${PHANTOWD_EXTERNAL_DIR:-/external}"
workspace_dir="${PHANTOWD_WORKSPACE_DIR:-/workspace}"

# This file is maintained by the project and contains no executable secrets.
# shellcheck disable=SC1091
. "$external_dir/versions.env"

config_file="$external_dir/configs/phantowd_qemu_armv5_defconfig"
config_hash="$(sha256sum "$config_file" | cut -c1-16)"
qemu_output="$workspace_dir/output/$BUILDROOT_VERSION-$config_hash"
cross_prefix="$qemu_output/host/bin/arm-buildroot-linux-gnueabi-"
linux_archive="$workspace_dir/dl/linux/linux-$LINUX_VERSION.tar.xz"
patch_file="$external_dir/board/wd/ex4/patches/linux/0001-arm-dts-marvell-add-wd-my-cloud-ex4-baseline.patch"

if [ ! -x "${cross_prefix}gcc" ]; then
    echo "The pinned ARMv5 toolchain is missing; run build-qemu.sh first." >&2
    exit 1
fi

PATH="$qemu_output/host/bin:$PATH"
export PATH

printf '%s  %s\n' "$LINUX_ARCHIVE_SHA256" "$linux_archive" |
    sha256sum --check --status

patch_hash="$(sha256sum "$patch_file" | cut -c1-16)"
source_dir="$workspace_dir/ex4-dtb/linux-$LINUX_VERSION-$patch_hash"
output_dir="$workspace_dir/ex4-dtb/output-$LINUX_VERSION-$patch_hash"

if [ ! -f "$source_dir/.phantowd-patched" ]; then
    source_stage="$source_dir.extracting"
    if [ -e "$source_stage" ]; then
        echo "Incomplete Linux extraction exists at $source_stage" >&2
        exit 1
    fi
    mkdir -p "$source_stage"
    tar --extract --xz --file "$linux_archive" \
        --directory "$source_stage" --strip-components=1
    patch --directory="$source_stage" --strip=1 --forward < "$patch_file"
    touch "$source_stage/.phantowd-patched"
    mkdir -p "$(dirname "$source_dir")"
    mv "$source_stage" "$source_dir"
fi

make -C "$source_dir" \
    O="$output_dir" \
    ARCH=arm \
    CROSS_COMPILE="$cross_prefix" \
    multi_v5_defconfig

make -C "$source_dir" \
    O="$output_dir" \
    ARCH=arm \
    CROSS_COMPILE="$cross_prefix" \
    -j"$(getconf _NPROCESSORS_ONLN)" \
    dtbs

dtb="$output_dir/arch/arm/boot/dts/marvell/kirkwood-wd-mycloud-ex4.dtb"
test -s "$dtb"

artifact_dir="$external_dir/artifacts/ex4-dtb-research"
install -d -m 0755 "$artifact_dir"
install -m 0644 "$dtb" "$artifact_dir/kirkwood-wd-mycloud-ex4.dtb"
cat > "$artifact_dir/NON-FLASHABLE.txt" <<'EOF'
RESEARCH ARTIFACT ONLY — DO NOT FLASH OR BOOT ON A PRODUCTION NAS

This device tree has passed compile-time checks against the pinned Linux
source. It has not passed EX4 hardware validation, peripheral qualification,
thermal fail-safe testing, recovery testing, or any NAND/ECC qualification.
EOF
(
    cd "$artifact_dir"
    sha256sum kirkwood-wd-mycloud-ex4.dtb > SHA256SUMS
)

printf 'EX4 DTB compile passed. Non-flashable artifact: %s\n' "$artifact_dir"
