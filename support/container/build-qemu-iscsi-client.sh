#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Build test-only upstream client in disposable tmpfs; no product package.
set -eu
source_dir=${1:?source checkout required}
archive=${2:?pinned libiscsi archive required}
host=${3:?existing Buildroot host toolchain required}
output=${4:?fresh tmpfs output directory required}
for input in "$source_dir" "$archive" "$host" "$output"; do
    case "$input" in /*) ;; *) exit 1 ;; esac
    case "$input" in *[!a-zA-Z0-9_./-]*) exit 1 ;; esac
done
[ -f "$archive" ] && [ ! -L "$archive" ]
[ -d "$output" ] && [ ! -L "$output" ]
[ -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]
awk -v target="$output" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts
expected=6321d802103f2a363d3afd9a5ae772de0b4052c84fe6a301ecb576b34e853caa
[ "$(sha256sum "$archive" | awk '{print $1}')" = "$expected" ]
tar -xzf "$archive" --strip-components=1 -C "$output"
(cd "$output" && printf '%s\n' \
    '88e3eccc48722b2a0eaff456dda94b8e8e123848d01f631969bec8e3c6c6eb85  COPYING' \
    '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643  LICENCE-GPL-2.txt' \
    'dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551  LICENCE-LGPL-2.1.txt' | sha256sum -c -)
export PATH="$host/bin:$PATH"
export CC="$host/bin/arm-buildroot-linux-gnueabi-gcc"
export AR="$host/bin/arm-buildroot-linux-gnueabi-ar"
export RANLIB="$host/bin/arm-buildroot-linux-gnueabi-ranlib"
export ac_cv_lib_gcrypt_gcry_control=no libiscsi_cv_HAVE_LINUX_ISER=no
(cd "$output" && autoreconf -fi && ./configure --host=arm-buildroot-linux-gnueabi \
    --disable-shared --enable-static --disable-examples --disable-tests \
    --disable-test-tool --disable-manpages --disable-werror && make -C lib -j4)
"$CC" -std=c11 -Wall -Wextra -Werror -O2 -static \
    -I"$output/include" "$source_dir/support/fixtures/iscsi-loopback-client.c" \
    "$output/lib/.libs/libiscsi.a" -o "$output/phantowd-iscsi-fixture-client"
"$host/bin/arm-buildroot-linux-gnueabi-readelf" -h "$output/phantowd-iscsi-fixture-client"
[ "$(sha256sum "$archive" | awk '{print $1}')" = "$expected" ]
sha256sum "$output/phantowd-iscsi-fixture-client"
echo 'PHANTOWD_ISCSI_CLIENT_COMPILED upstream=libiscsi-1.20.0 static=true guest=false scope=synthetic-loopback-only'
