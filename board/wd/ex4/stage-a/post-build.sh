#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PhantoWD EX4 contributors

set -eu

target_dir="$1"

case "$target_dir" in
    */target) ;;
    *)
        echo "Refusing to prune unexpected target directory: $target_dir" >&2
        exit 1
        ;;
esac

test -x "$target_dir/bin/busybox"

# Buildroot's generic skeleton contains network hook scripts even when the
# kernel and BusyBox networking surfaces are disabled. They are not part of
# the Stage A probe and must not enter its initramfs.
rm -rf "$target_dir/etc/network"

# The audited BusyBox binary needs only the ELF interpreter and libc. Remove
# generic shared libraries copied by the internal toolchain so the probe does
# not carry dormant resolver, threading, math, atomic or dlopen surfaces.
rm -f \
    "$target_dir/lib/libanl.so.1" \
    "$target_dir/lib/libatomic.so" \
    "$target_dir/lib/libatomic.so.1" \
    "$target_dir/lib/libatomic.so.1.2.0" \
    "$target_dir/lib/libdl.so.2" \
    "$target_dir/lib/libgcc_s.so" \
    "$target_dir/lib/libgcc_s.so.1" \
    "$target_dir/lib/libm.so.6" \
    "$target_dir/lib/libnss_dns.so.2" \
    "$target_dir/lib/libnss_files.so.2" \
    "$target_dir/lib/libpthread.so.0" \
    "$target_dir/lib/libresolv.so.2" \
    "$target_dir/lib/librt.so.1" \
    "$target_dir/lib/libutil.so.1"

chmod 0755 "$target_dir/bin/busybox"
chmod 0755 "$target_dir/init"
chmod 0644 "$target_dir/etc/phantowd-release"
