#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Run inside the pinned Buildroot container. The workspace contains only the
# shared authenticated source/download cache and a disposable RC0 build.
set -eu

[ "$#" -le 1 ] || { echo "Usage: $0 [REPORT_DIRECTORY]" >&2; exit 2; }
reports=${1:-}
if [ -n "$reports" ]; then
    mkdir -p -- "$reports"
    reports=$(CDPATH='' cd -- "$reports" && pwd)
    if [ -e "$reports/comparison" ] || [ -L "$reports/comparison" ]; then
        echo "RC0 report directory already contains a comparison set: $reports" >&2
        exit 2
    fi
fi

external=${PHANTOWD_EXTERNAL_DIR:-/external}
workspace=${PHANTOWD_WORKSPACE_DIR:-/workspace}
# shellcheck disable=SC1091
. "$external/versions.env"

PHANTOWD_REPRO_PHASE=all PHANTOWD_PREPARE_ONLY=1 \
    sh "$external/support/container/build-qemu.sh"
buildroot="$workspace/buildroot-$BUILDROOT_VERSION"
sh "$external/support/container/apply-buildroot-go-maintenance.sh" "$buildroot" \
    "$external/support/buildroot-patches/$BUILDROOT_VERSION/0004-go-1.26.8-maintenance.patch"
sh "$external/support/container/apply-buildroot-samba-json-patch.sh" "$buildroot" \
    "$external/support/buildroot-patches/$BUILDROOT_VERSION/0002-samba4-json-without-ad-dc.patch"
grep -Fx "GO_VERSION = $GO_VERSION" "$buildroot/package/go/go.mk" >/dev/null

output=$(mktemp -d "$workspace/rc0-build.XXXXXX")
trap 'rm -rf -- "$output"' EXIT
trap 'exit 1' INT TERM
jobs=$(python3 -B "$external/support/container/build_jobs.py")
build() {
    make -C "$buildroot" BR2_EXTERNAL="$external" BR2_DL_DIR="$workspace/dl" \
        O="$output" PARALLEL_JOBS="$jobs" "$@"
}
build phantowd_rc0_armv5_defconfig
grep -Fx 'BR2_PACKAGE_PHANTOWD_API=y' "$output/.config" >/dev/null
grep -Fx '# BR2_PACKAGE_PHANTOWD_API_QEMU_SELFTEST is not set' "$output/.config" >/dev/null
grep -Fx '# BR2_TARGET_ENABLE_ROOT_LOGIN is not set' "$output/.config" >/dev/null
grep -Fx '# BR2_TARGET_GENERIC_REMOUNT_ROOTFS_RW is not set' "$output/.config" >/dev/null
grep -Fx 'BR2_TOOLCHAIN_GLIBC_GCONV_LIBS_LIST="IBM850"' "$output/.config" >/dev/null
grep -Fx 'BR2_PACKAGE_NFS_UTILS_RPC_NFSD=y' "$output/.config" >/dev/null
grep -Fx 'BR2_PACKAGE_RPCBIND=y' "$output/.config" >/dev/null
grep -Fx 'BR2_PACKAGE_SAMBA4=y' "$output/.config" >/dev/null
grep -Fx 'BR2_PACKAGE_JANSSON=y' "$output/.config" >/dev/null
if grep -Fx 'BR2_PACKAGE_SAMBA4_AD_DC=y' "$output/.config" >/dev/null; then
    echo 'RC0 Samba must use the standalone file-server profile' >&2
    exit 1
fi
build all
kernel_config="$output/build/linux-$LINUX_VERSION/.config"
for expected in 'CONFIG_MD=y' 'CONFIG_BLK_DEV_MD=y' 'CONFIG_MD_RAID1=y' '# CONFIG_MD_AUTODETECT is not set' \
    'CONFIG_NFSD=y' '# CONFIG_NFSD_V4 is not set' 'CONFIG_NFS_FS=y' 'CONFIG_NFS_V3=y' 'CONFIG_8139CP=y' \
    'CONFIG_NF_TABLES=y' 'CONFIG_NF_TABLES_INET=y'; do
    grep -Fx "$expected" "$kernel_config" >/dev/null
done
evidence=${reports:-$output}
# Use the e2fsprogs already compiled for generating the root filesystem.
export PATH="$output/host/sbin:$PATH"
sh "$external/support/qemu-rc0-profile.sh" "$output/images" "$output/host/bin/go" \
    "$evidence/rc0-profile-serial.log"
sh "$external/support/qemu-rc0-management.sh" "$output/images" "$output/host/bin/go" \
    "$evidence/rc0-management"

if [ -n "$reports" ]; then
    comparison="$reports/comparison/rc0-armv5"
    mkdir -p -- "$comparison"
    for artifact in zImage versatile-pb.dtb rootfs.ext2; do
        cp --sparse=always -- "$output/images/$artifact" "$comparison/$artifact"
    done
    install -m 0644 "$output/.config" "$comparison/buildroot.config"
    install -m 0644 "$kernel_config" "$comparison/linux.config"

    schema="$workspace/dl/cyclonedx/spdx-$CYCLONEDX_SPEC_VERSION.schema.json"
    if [ ! -f "$schema" ]; then
        curl --fail --location --proto '=https' --tlsv1.2 \
            --output "$output/spdx.schema.json" \
            "https://raw.githubusercontent.com/CycloneDX/specification/$CYCLONEDX_SPEC_VERSION/schema/spdx.schema.json"
        printf '%s  %s\n' "$CYCLONEDX_SPDX_SCHEMA_SHA256" "$output/spdx.schema.json" | sha256sum --check --status
        mv -- "$output/spdx.schema.json" "$schema"
    fi
    printf '%s  %s\n' "$CYCLONEDX_SPDX_SCHEMA_SHA256" "$schema" | sha256sum --check --status
    grep -Fx "CYCLONEDX_VERSION = \"$CYCLONEDX_SPEC_VERSION\"" "$buildroot/utils/generate-cyclonedx" >/dev/null
    build --no-print-directory show-info > "$comparison/buildroot-show-info.json"
    (
        cd "$buildroot"
        O="$output" BR2_EXTERNAL="$external" BR2_DL_DIR="$workspace/dl" \
            ./utils/generate-cyclonedx \
            --project-name "PhantoWD EX4 RC0 ARMv5" \
            --project-version "dev-buildroot-$BUILDROOT_VERSION-linux-$LINUX_VERSION" \
            < "$comparison/buildroot-show-info.json" > "$output/buildroot-sbom.cdx.json"
    )
    python3 -B "$external/support/container/augment-cyclonedx.py" \
        < "$output/buildroot-sbom.cdx.json" > "$comparison/sbom.cdx.json"
    build legal-info
    install -m 0644 "$output/legal-info/manifest.csv" "$comparison/license-manifest.csv"
    install -m 0644 "$output/legal-info/host-manifest.csv" "$comparison/host-license-manifest.csv"
    (
        cd "$comparison"
        sha256sum zImage versatile-pb.dtb rootfs.ext2 buildroot.config linux.config \
            buildroot-show-info.json sbom.cdx.json license-manifest.csv host-license-manifest.csv > SHA256SUMS
    )
fi
