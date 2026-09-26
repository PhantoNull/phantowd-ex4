#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Native, regular-file-only tests in a disposable build container. No devices.
set -eu
source_dir=${1:?source directory}
archive=${2:?verified Buildroot util-linux archive}
patch_dir=${3:?trusted Buildroot util-linux package directory}
host_tools=${4:?pinned Buildroot host tools bin directory}
export PATH="$host_tools:$PATH"
expected=5c1daf733b04e9859afdc3bd87cc481180ee0f88b5c0946b16fdec931975fb79
printf '%s  %s\n' "$expected" "$archive" | sha256sum -c -
workspace=$(mktemp -d /tmp/phantowd-volume-probe.XXXXXX)
tar -xf "$archive" -C "$workspace"
sh "$source_dir/support/container/patch-volume-probe-fixture.sh" \
    "$workspace/util-linux-2.40.4" "$patch_dir"
cd "$workspace/util-linux-2.40.4"
./configure --disable-all-programs --enable-libblkid --disable-shared \
    --enable-static --disable-nls >"$workspace/configure.log" 2>&1 || {
    tail -n 60 "$workspace/configure.log" >&2
    exit 1
}
make -j2 libblkid.la >"$workspace/build.log" 2>&1 || {
    tail -n 60 "$workspace/build.log" >&2
    exit 1
}
mkdir -p "$workspace/include/blkid"
cp libblkid/src/blkid.h "$workspace/include/blkid/blkid.h"
cc -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 -I"$workspace/include" \
    "$source_dir/src/phantowd-volume-probe/probe.c" .libs/libblkid.a \
    -Wl,-z,relro,-z,now -o "$workspace/phantowd-volume-probe"
python3 "$source_dir/src/phantowd-volume-probe/test_probe.py" "$workspace/phantowd-volume-probe"
sha256sum "$workspace/phantowd-volume-probe"
# The container owns /tmp; do not recursively clean any host workspace.
