#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Offline static ARMv5 fixture only; never a release/package builder.
set -eu
source_dir=${1:?source directory}
archive=${2:?pinned util-linux archive}
compiler=${3:?pinned Buildroot ARM compiler}
destination=${4:?temporary output binary}
patch_dir=${5:?trusted Buildroot util-linux package directory}
compiler_dir=$(dirname "$compiler")
export PATH="$compiler_dir:$PATH"
expected=5c1daf733b04e9859afdc3bd87cc481180ee0f88b5c0946b16fdec931975fb79
printf '%s  %s\n' "$expected" "$archive" | sha256sum -c -
workspace=$(mktemp -d /tmp/phantowd-probe-arm.XXXXXX)
tar -xf "$archive" -C "$workspace"
sh "$source_dir/support/container/patch-volume-probe-fixture.sh" \
    "$workspace/util-linux-2.40.4" "$patch_dir"
cd "$workspace/util-linux-2.40.4"
test "$("$compiler" -dumpmachine)" = arm-buildroot-linux-gnueabi
CC="$compiler" ./configure --host=arm-buildroot-linux-gnueabi \
    --build="$(cc -dumpmachine)" --disable-all-programs --enable-libblkid \
    --disable-shared --enable-static --disable-nls >"$workspace/configure.log" 2>&1 || {
    tail -n 60 "$workspace/configure.log" >&2
    exit 1
}
make -j2 libblkid.la >"$workspace/build.log" 2>&1 || {
    tail -n 60 "$workspace/build.log" >&2
    exit 1
}
mkdir -p "$workspace/include/blkid"
cp libblkid/src/blkid.h "$workspace/include/blkid/blkid.h"
"$compiler" -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 -I"$workspace/include" \
    "$source_dir/src/phantowd-volume-probe/probe.c" .libs/libblkid.a \
    -static -Wl,-z,relro,-z,now -o "$destination"
readelf -h "$destination" | grep -E 'Machine:.*ARM' >/dev/null
readelf -A "$destination" | grep -E 'Tag_CPU_arch: v5TEJ?$' >/dev/null
if readelf -l "$destination" | grep 'INTERP' >/dev/null; then
    echo 'Fast fixture must not depend on uninstalled target libraries' >&2
    exit 1
fi
sha256sum "$destination"
echo 'Static ARMv5 fixture only; clean Buildroot packaging/legal-info remain required.'
