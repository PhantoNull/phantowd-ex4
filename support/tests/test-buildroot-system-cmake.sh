#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

# Test Buildroot's real selection in a fresh, disposable configuration, not
# a cached host-cmake stamp or a command-line override of its dependencies.
[ "$#" -eq 2 ] || {
    echo 'Usage: test-buildroot-system-cmake.sh BUILDROOT_SOURCE EXTERNAL_DIR' >&2
    exit 1
}
buildroot_source=$1
external_dir=$2
[ -f "$buildroot_source/.phantowd-source-ready" ]
[ -f "$external_dir/configs/phantowd_qemu_armv5_defconfig" ]
[ "$(command -v cmake)" = /usr/bin/cmake ] || {
    echo 'Pinned build container must provide /usr/bin/cmake' >&2
    exit 1
}

scratch=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-system-cmake.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 1' HUP INT TERM

if ! make -s -C "$buildroot_source" BR2_EXTERNAL="$external_dir" \
    O="$scratch/output" phantowd_qemu_armv5_defconfig \
    >"$scratch/config.log" 2>&1; then
    tail -n 80 "$scratch/config.log" >&2
    exit 1
fi

minimum=$(sed -n 's/^BR2_HOST_CMAKE_AT_LEAST="\([0-9][0-9]*\.[0-9][0-9]*\)"$/\1/p' \
    "$scratch/output/.config")
[ -n "$minimum" ]
selected=$(sh "$buildroot_source/support/dependencies/check-host-cmake.sh" \
    "$minimum" cmake cmake3)
[ "$selected" = /usr/bin/cmake ]
if sh "$buildroot_source/support/dependencies/check-host-cmake.sh" \
    99.0 cmake cmake3 >"$scratch/unsupported.log"; then
    echo 'Buildroot accepted an unsuitable system CMake' >&2
    exit 1
fi

graph=$(make -s -C "$buildroot_source" BR2_EXTERNAL="$external_dir" \
    O="$scratch/output" printvars \
    VARS='BR2_CMAKE HOST_CCACHE_DEPENDENCIES')
printf '%s\n' "$graph" | grep -Fx 'BR2_CMAKE=/usr/bin/cmake' >/dev/null
dependencies=$(printf '%s\n' "$graph" | \
    sed -n 's/^HOST_CCACHE_DEPENDENCIES=//p')
[ -n "$dependencies" ]
case " $dependencies " in
    *' host-cmake '*)
        echo 'Cache bootstrap still depends on host-cmake' >&2
        exit 1 ;;
esac
printf 'PHANTOWD_SYSTEM_CMAKE_READY minimum=%s selected=/usr/bin/cmake fresh_graph=true unsuitable_refused=true\n' "$minimum"
