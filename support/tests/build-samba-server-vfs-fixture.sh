#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Fixture-only loader prerequisite; never modifies the cached SDK/target.
set -eu
output=${1:?pinned output required}
source=${2:?repository required}
scratch=${3:?new tmpfs scratch required}
[ "$#" -eq 3 ] || exit 1
case "$output:$source:$scratch" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$output:$source:$scratch" in /*:/*:/*) ;; *) exit 1 ;; esac
[ -d "$scratch" ] && [ ! -L "$scratch" ] || exit 1
awk -v target="$scratch" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts
for name in phantowd_open_qemu.so vfs-loader-test vfs-module.o vfs-test.o; do
    [ ! -e "$scratch/$name" ] && [ ! -L "$scratch/$name" ] || exit 1
done
samba="$output/build/samba4-4.22.11"
(cd "$samba" && sha256sum -c <<'HASHES'
6a2dbcced428e6e9229bd6f351b47193507a909c29b6127d39a588af04a43082  source3/include/vfs.h
b9d76b679cfa10cc8c634c6ac5bafb963369c766fbe53deb8de62f6a4e93281e  source3/smbd/vfs.c
f3de11b776a3c8cecd214499ca18302265c5cf90224d769638f0b2f660df2e2e  lib/util/modules.c
f4658956fce48e409ee5c2285f3245197215a70a1b7d65dd927cef99f62a383b  lib/util/samba_modules.h
851c5d91e226390b770864f4b2483404df404469e66e776d91428fa2829f7219  lib/util/util_paths.c
a23bc5b6a907fed975315e0512eb3be107dba882899c7b1586633056296e5433  bin/default/include/config.h
HASHES
)
cc="$output/host/bin/arm-buildroot-linux-gnueabi-gcc"
readelf="$output/host/bin/arm-buildroot-linux-gnueabi-readelf"
flags=(-DPHANTOWD_SAMBA_SERVER_VFS_FIXTURE=1 -D_SAMBA_BUILD_=4 -DHAVE_CONFIG_H=1
    -D__STDC_WANT_LIB_EXT1__=1 -D_GNU_SOURCE=1 -D_FILE_OFFSET_BITS=64
    -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -std=c11 -O2 -fPIC -fvisibility=hidden
    -ffunction-sections -fdata-sections -Wall -Werror
    -I"$samba/source3/include" -I"$samba/source3" -I"$samba/bin/default/source3"
    -I"$samba/bin/default/include" -I"$samba/bin/default" -I"$samba"
    -I"$samba/lib/replace" -I"$samba/lib/talloc" -I"$samba/lib/tevent" -I"$samba/lib/tdb/include"
    -I"$samba/lib" -I"$samba/include")
for pair in 'samba-server-vfs-fixture.c vfs-module.o' 'samba-server-vfs-loader-qemu-test.c vfs-test.o'; do
    timeout --signal=TERM --kill-after=1 30 "$cc" "${flags[@]}" \
        -MMD -MF "$scratch/${pair#* }.d" -c "$source/support/tests/${pair%% *}" -o "$scratch/${pair#* }"
done
"$cc" -shared -Wl,--gc-sections,-z,defs,-z,relro,-z,now,--enable-new-dtags,-rpath,/usr/lib/samba \
    -Wl,-soname,phantowd_open_qemu.so \
    -Wl,-rpath-link,"$output/staging/usr/lib/samba" -L"$output/staging/usr/lib/samba" \
    -o "$scratch/phantowd_open_qemu.so" "$scratch/vfs-module.o" -l:libsmbd-base-private-samba.so
"$cc" -Wl,--gc-sections,-z,defs,-z,relro,-z,now,--enable-new-dtags,-rpath,/usr/lib/samba \
    -Wl,-rpath-link,"$output/staging/usr/lib/samba" -L"$output/staging/usr/lib/samba" \
    -o "$scratch/vfs-loader-test" "$scratch/vfs-test.o" \
    -l:libsmbd-base-private-samba.so -l:libsamba-modules-private-samba.so \
    -lsamba-util -l:libtalloc-private-samba.so \
    -l:libreplace-private-samba.so -ldl
for name in phantowd_open_qemu.so vfs-loader-test; do
    "$readelf" -h -A -d "$scratch/$name" >"$scratch/$name.elf"
    grep -Eq 'Class:.*ELF32' "$scratch/$name.elf"
    grep -Eq 'Machine:.*ARM' "$scratch/$name.elf"
    grep -Eq 'Flags:.*Version5 EABI, soft-float ABI' "$scratch/$name.elf"
    grep -Eq 'Tag_CPU_arch: v5TEJ$' "$scratch/$name.elf"
    grep -F 'Library runpath: [/usr/lib/samba]' "$scratch/$name.elf"
    grep -F 'BIND_NOW' "$scratch/$name.elf"
    "$readelf" -W -l "$scratch/$name" >"$scratch/$name.segments"
    grep -F 'GNU_RELRO' "$scratch/$name.segments"
    grep -E 'GNU_STACK.*RW ' "$scratch/$name.segments"
    if grep -E 'GNU_STACK.*RWE' "$scratch/$name.segments"; then exit 1; fi
    if grep -F '(RPATH)' "$scratch/$name.elf"; then exit 1; fi
done
grep -F 'Library soname: [phantowd_open_qemu.so]' "$scratch/phantowd_open_qemu.so.elf"
awk '/\(NEEDED\)/ {
    if ($NF != "[libsmbd-base-private-samba.so]" && $NF != "[libc.so.6]") exit 1
    needed++
} END { if (needed != 2) exit 1 }' "$scratch/phantowd_open_qemu.so.elf"
"$readelf" --dyn-syms -W "$scratch/phantowd_open_qemu.so" >"$scratch/vfs.symbols"
awk '$5 == "GLOBAL" && $7 != "UND" { if ($8 != "samba_init_module") exit 1; exported++ }
    $5 == "GLOBAL" && $7 == "UND" {
        split($8, name, "@")
        if (name[1] !~ /^(smb_register_vfs|__errno_location|__stack_chk_guard|__stack_chk_fail)$/) exit 1
    }
    END { if (exported != 1) exit 1 }' "$scratch/vfs.symbols"
sha256sum "$scratch/phantowd_open_qemu.so" "$scratch/vfs-loader-test"
