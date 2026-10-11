#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Offline source-built metadata reader only; does not install/modify Samba.
set -eu
output=${1:?existing pinned output required}
source=${2:?repository required}
scratch=${3:?new caller-owned tmpfs directory required}
[ "$#" -eq 3 ] || exit 1
case "$output:$source:$scratch" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$output:$source:$scratch" in /*:/*:/*) ;; *) exit 1 ;; esac
[ -d "$scratch" ] && [ ! -L "$scratch" ] || exit 1
awk -v target="$scratch" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || exit 1
for name in server-observer.o server-observer.so server-observer-test.o server-observer-test-reduced.o server-observer-test server-observer.headers server-observer.symbols; do
    [ ! -e "$scratch/$name" ] && [ ! -L "$scratch/$name" ] || exit 1
done
samba="$output/build/samba4-4.22.11"
# This pins sensitive definitions/call paths, not the entire transitive SDK.
(cd "$samba" && sha256sum -c <<'HASHES'
6a2dbcced428e6e9229bd6f351b47193507a909c29b6127d39a588af04a43082  source3/include/vfs.h
58b9619e2f4cad437b3a9537d5b8616bfca7b58fd25481909de20a698ad160d5  source3/smbd/files.c
cd7ef0adf1bad07bfaf6653c89f2fcb88dc7d6a9bc0713e62a5bbddc59ebc291  source3/smbd/smb2_create.c
cf42520cb6fcefe4fe9e40dc3cb37fa17fee5e1ea146908d71043edd481db5a2  source3/smbd/smbXsrv_open.c
beaebbdb3ae76e969eb9d6fe9875ad1893cd6b959e6a3e1a11c022ae98f6bcad  source3/smbd/fd_handle.c
ce2688699579a863fdd4290986df97069e8633944a7c4c3ffc826e7acd263a4b  source3/smbd/fd_handle.h
ee1d3a8f8e89fe56285a3494750bf0eb8f6b28788da70477bd3fa895adc020f3  source3/smbd/globals.h
ad9a516595f7df86fb7ed3bf63613d06fac91cd6bd9644a58591637394641144  source3/smbd/smbd.h
538d7676db4fce03ada27c98895a2c26d068c5b514a90e2a886dc4b6709c943e  source3/librpc/idl/smbXsrv.idl
9731e5d834f39818afb0f090af2e32935a6d136f290bb49a7684068b7013bf4a  bin/default/source3/librpc/gen_ndr/smbXsrv.h
760c3ce262cf5fc254e33d698d00820dc60df324625197c5a9a9e52408a95311  source3/lib/file_id.h
da5e155661dd72f0f7bdb9de11a4e79128c4d59156fba663568e37fa45e1f24f  bin/default/librpc/gen_ndr/file_id.h
d562f9801fc7301cc8128134e837011d80ef17459c03d5809551c09c84f87cd1  bin/default/librpc/gen_ndr/server_id.h
1a3cbb8a9d9d5306ae11fe5cfa86236e35991875953105e3d92a945f2ce701b4  lib/util/dlinklist.h
HASHES
)
compiler="$output/host/bin/arm-buildroot-linux-gnueabi-gcc"
readelf="$output/host/bin/arm-buildroot-linux-gnueabi-readelf"
flags=(-DPHANTOWD_SAMBA_SERVER_OBSERVER_FIXTURE=1 -D_SAMBA_BUILD_=4 -DHAVE_CONFIG_H=1
    -D__STDC_WANT_LIB_EXT1__=1 -D_GNU_SOURCE=1 -D_FILE_OFFSET_BITS=64
    -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -std=c11 -O2 -fPIC -fvisibility=hidden
    -ffunction-sections -fdata-sections -Wall -Werror
    -I"$samba/source3/include" -I"$samba/source3" -I"$samba/bin/default/source3"
    -I"$samba/bin/default/include" -I"$samba/bin/default" -I"$samba"
    -I"$samba/lib/replace" -I"$samba/lib/talloc" -I"$samba/lib/tevent" -I"$samba/lib/tdb/include"
    -I"$samba/lib" -I"$samba/include")
timeout --signal=TERM --kill-after=1 30 "$compiler" "${flags[@]}" \
    -c "$source/support/tests/samba-server-open-observer-fixture.c" -o "$scratch/server-observer.o"
"$compiler" -shared -Wl,--gc-sections,-z,defs,--enable-new-dtags,-rpath,/usr/lib/samba \
    -Wl,-soname,libphantowd-server-open-qemu.so \
    -Wl,-rpath-link,"$output/staging/usr/lib/samba" -L"$output/staging/usr/lib/samba" \
    -o "$scratch/server-observer.so" "$scratch/server-observer.o" -l:libsmbd-base-private-samba.so
timeout --signal=TERM --kill-after=1 30 "$compiler" "${flags[@]}" \
    -c "$source/support/tests/samba-server-open-observer-qemu-test.c" -o "$scratch/server-observer-test.o"
"$output/host/bin/arm-buildroot-linux-gnueabi-ld" -r --gc-sections \
    -u main -u phantowd_qemu_observe_server_open_v1 \
    -o "$scratch/server-observer-test-reduced.o" "$scratch/server-observer-test.o"
"$compiler" -Wl,--gc-sections,-z,defs,--enable-new-dtags,-rpath,/usr/lib/samba \
    -Wl,-rpath-link,"$output/staging/usr/lib/samba" -L"$output/staging/usr/lib/samba" \
    -o "$scratch/server-observer-test" "$scratch/server-observer-test-reduced.o" \
    -lsamba-util -l:libtalloc-private-samba.so -l:libreplace-private-samba.so \
    -l:libgenrand-private-samba.so -l:libsamba-debug-private-samba.so -ldl
for name in server-observer.so server-observer-test; do
    "$readelf" -h -A -d "$scratch/$name" >"$scratch/server-observer.headers"
    grep -Eq 'Class:.*ELF32' "$scratch/server-observer.headers"
    grep -Eq 'Machine:.*ARM' "$scratch/server-observer.headers"
    grep -Eq 'Flags:.*Version5 EABI, soft-float ABI' "$scratch/server-observer.headers"
    grep -F 'Tag_CPU_arch: v5TEJ' "$scratch/server-observer.headers"
    grep -F 'Library runpath: [/usr/lib/samba]' "$scratch/server-observer.headers"
    if grep -F '(RPATH)' "$scratch/server-observer.headers"; then exit 1; fi
done
"$readelf" -d "$scratch/server-observer.so" | grep -F 'Library soname: [libphantowd-server-open-qemu.so]'
"$readelf" --dyn-syms -W "$scratch/server-observer.so" >"$scratch/server-observer.symbols"
awk '
    $5 == "GLOBAL" && $7 != "UND" { if ($8 != "phantowd_qemu_observe_server_open_v1") exit 1; exported++ }
    $5 == "GLOBAL" && $7 == "UND" {
        split($8, name, "@")
        if (name[1] !~ /^(fh_get_refcount|fh_get_gen_id|fsp_get_pathref_fd|fstat64|getpid|memset|__stack_chk_guard|__stack_chk_fail)$/) exit 1
    }
    END { if (exported != 1) exit 1 }
' "$scratch/server-observer.symbols"
sha256sum "$scratch/server-observer.so" "$scratch/server-observer-test"
printf 'PHANTOWD_SERVER_OPEN_BUILD_DONE exports=1 observer_bytes=%s arm_executed=false authority=false scope=compile-only\n' "$(stat -c %s "$scratch/server-observer.so")"
