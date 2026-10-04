#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Compile-only prerequisite. Caller provides bounded, disposable tmpfs.
set -eu
source_dir=${1:?source checkout required}
archive=${2:?pinned Linux archive required}
base_config=${3:?QEMU kernel configuration required}
host=${4:?existing Buildroot host toolchain required}
output=${5:?fresh tmpfs output directory required}
for input in "$source_dir" "$archive" "$base_config" "$host" "$output"; do
    case "$input" in /*) ;; *) echo 'Absolute research input required' >&2; exit 1 ;; esac
    case "$input" in *[!a-zA-Z0-9_./-]*) echo 'Unsupported research input path' >&2; exit 1 ;; esac
done
[ -f "$archive" ] && [ ! -L "$archive" ]
[ -f "$base_config" ] && [ ! -L "$base_config" ]
[ -d "$output" ] && [ ! -L "$output" ]
[ -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ] || {
    echo 'Fresh empty research output required' >&2; exit 1
}
awk -v target="$output" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || {
    echo 'LIO kernel research output must be tmpfs' >&2; exit 1
}
for tool in arm-buildroot-linux-gnueabi-gcc bison flex; do
    [ -x "$host/bin/$tool" ] || { echo 'Existing kernel tool prerequisite missing' >&2; exit 1; }
done
# shellcheck disable=SC1091 # trusted project version locks
. "$source_dir/versions.env"
archive_hash=$(sha256sum "$archive" | awk '{print $1}')
[ "$archive_hash" = "$LINUX_ARCHIVE_SHA256" ] || { echo 'Pinned Linux hash mismatch' >&2; exit 1; }
config_hash=$(sha256sum "$base_config" | awk '{print $1}')
grep -Fx '# Linux/arm '"$LINUX_VERSION"' Kernel Configuration' "$base_config" >/dev/null
mkdir "$output/source" "$output/build"
tar -xJf "$archive" --strip-components=1 -C "$output/source"
cp "$base_config" "$output/build/.config"
export PATH="$host/bin:$PATH"
export ARCH=arm CROSS_COMPILE="$host/bin/arm-buildroot-linux-gnueabi-"
# Keep this experimental profile separate from every repository defconfig.
for symbol in CONFIGFS_FS TARGET_CORE TCM_FILEIO ISCSI_TARGET CRYPTO_MD5; do
    "$output/source/scripts/config" --file "$output/build/.config" --enable "$symbol"
done
for symbol in TCM_IBLOCK TCM_PSCSI TCM_USER2 LOOPBACK_TARGET ISCSI_TCP ISCSI_BOOT_SYSFS; do
    "$output/source/scripts/config" --file "$output/build/.config" --disable "$symbol"
done
make -C "$output/source" O="$output/build" olddefconfig
python3 "$source_dir/support/container/qemu_lio_inputs.py" "$output/build/.config"
make -C "$output/source" O="$output/build" -j4 zImage dtbs
sha256sum "$output/build/.config" "$output/build/arch/arm/boot/zImage" \
    "$output/build/arch/arm/boot/dts/arm/versatile-pb.dtb"
[ "$(sha256sum "$archive" | awk '{print $1}')" = "$archive_hash" ]
[ "$(sha256sum "$base_config" | awk '{print $1}')" = "$config_hash" ]
echo 'PHANTOWD_LIO_KERNEL_COMPILED scope=tmpfs-research-only guest=false activation=false'
