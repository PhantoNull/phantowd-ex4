#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PhantoWD EX4 contributors

set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck disable=SC1091
. "$repo_root/versions.env"

check_version_lock() {
    config_file="$1"
    release_file="$2"

    grep -Fx "BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE=\"$LINUX_VERSION\"" \
        "$repo_root/$config_file" >/dev/null || {
        printf 'Linux version in %s does not match versions.env (%s)\n' \
            "$config_file" "$LINUX_VERSION" >&2
        return 1
    }

    grep -Fx "PHANTOWD_KERNEL_VERSION=$LINUX_VERSION" \
        "$repo_root/$release_file" >/dev/null || {
        printf 'Linux version in %s does not match versions.env (%s)\n' \
            "$release_file" "$LINUX_VERSION" >&2
        return 1
    }
}

check_kernel_hash_lock() {
    hash_file="$1"
    expected="sha256  $LINUX_ARCHIVE_SHA256  linux-$LINUX_VERSION.tar.xz"

    kernel_entry_count="$(grep -c '^sha256 .* linux-.*\.tar\.xz$' "$repo_root/$hash_file" || true)"
    if [ "$kernel_entry_count" -ne 1 ] ||
        ! grep -Fx "$expected" "$repo_root/$hash_file" >/dev/null; then
        printf 'Linux archive version/hash in %s does not match versions.env (%s, %s)\n' \
            "$hash_file" "$LINUX_VERSION" "$LINUX_ARCHIVE_SHA256" >&2
        return 1
    fi
}

check_kernel_license_hash_lock() {
    patch_file="$repo_root/support/buildroot-patches/$BUILDROOT_VERSION/0001-linux-gpl-text-hash-for-linux-$LINUX_VERSION.patch"
    expected="+sha256  $LINUX_GPL_TEXT_SHA256  LICENSES/preferred/GPL-2.0"

    if [ ! -f "$patch_file" ] || ! grep -Fx "$expected" "$patch_file" >/dev/null; then
        printf 'Buildroot GPL-2.0 hash patch does not match pinned Linux %s source\n' \
            "$LINUX_VERSION" >&2
        return 1
    fi
}

check_version_lock \
    configs/phantowd_qemu_armv5_defconfig \
    board/qemu/armv5/rootfs-overlay/etc/phantowd-release
check_version_lock \
    configs/phantowd_ex4_stage_a_defconfig \
    board/wd/ex4/stage-a/rootfs-overlay/etc/phantowd-release
check_version_lock \
    configs/phantowd_ex4_stage_b_defconfig \
    board/wd/ex4/stage-b/rootfs-overlay/etc/phantowd-release
check_version_lock \
    configs/phantowd_ex4_stage_b2_defconfig \
    board/wd/ex4/stage-b2/rootfs-overlay/etc/phantowd-release
check_version_lock \
    configs/phantowd_ex4_stage_b3_defconfig \
    board/wd/ex4/stage-b3/rootfs-overlay/etc/phantowd-release

check_kernel_hash_lock board/qemu/armv5/patches/linux/linux.hash
check_kernel_hash_lock board/qemu/armv5/patches/linux-headers/linux-headers.hash
check_kernel_license_hash_lock

openssl_patch="$repo_root/support/buildroot-patches/$BUILDROOT_VERSION/0005-libopenssl-$OPENSSL_VERSION-maintenance.patch"
grep -Fx "+LIBOPENSSL_VERSION = $OPENSSL_VERSION" "$openssl_patch" >/dev/null
grep -Fx "+sha256  $OPENSSL_ARCHIVE_SHA256  openssl-$OPENSSL_VERSION.tar.gz" \
    "$openssl_patch" >/dev/null

printf 'All firmware Linux version locks match %s.\n' "$LINUX_VERSION"
printf 'Host OpenSSL version/hash locks match %s.\n' "$OPENSSL_VERSION"
