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

printf 'All firmware Linux version locks match %s.\n' "$LINUX_VERSION"
