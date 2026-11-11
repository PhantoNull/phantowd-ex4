#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Run inside the pinned Buildroot container. The workspace contains only the
# shared authenticated source/download cache and a disposable RC0 build.
set -eu

external=${PHANTOWD_EXTERNAL_DIR:-/external}
workspace=${PHANTOWD_WORKSPACE_DIR:-/workspace}
# shellcheck disable=SC1091
. "$external/versions.env"

PHANTOWD_REPRO_PHASE=all PHANTOWD_PREPARE_ONLY=1 \
    sh "$external/support/container/build-qemu.sh"
buildroot="$workspace/buildroot-$BUILDROOT_VERSION"
sh "$external/support/container/apply-buildroot-go-maintenance.sh" "$buildroot" \
    "$external/support/buildroot-patches/$BUILDROOT_VERSION/0004-go-1.26.8-maintenance.patch"
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
build all
sh "$external/support/qemu-rc0-profile.sh" "$output/images" "$output/host/bin/go" \
    "$output/rc0-profile-serial.log"
