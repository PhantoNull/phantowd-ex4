#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Fixture-only capture prerequisite; never modifies the cached SDK/target.
set -eu
output=${1:?pinned output required}
source=${2:?repository required}
scratch=${3:?new tmpfs scratch required}
[ "$#" -eq 3 ] || exit 1
case "$output:$source:$scratch" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$output:$source:$scratch" in /*:/*:/*) ;; *) exit 1 ;; esac
[ -d "$scratch" ] && [ ! -L "$scratch" ] || exit 1
awk -v target="$scratch" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts
for name in phantowd_open_qemu.so capture-test vfs-module.o vfs-test.o; do
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
58b9619e2f4cad437b3a9537d5b8616bfca7b58fd25481909de20a698ad160d5  source3/smbd/files.c
cd7ef0adf1bad07bfaf6653c89f2fcb88dc7d6a9bc0713e62a5bbddc59ebc291  source3/smbd/smb2_create.c
8e59cd178da78d69dc0d371ff3680f44471ecb434e2d96145ba284a0ed9e0b94  source3/smbd/smb2_close.c
c4d5ca76780186ce3be92aaafec9c69735017fa3fd55d6046ccf5488994a8ee2  source3/smbd/open.c
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
31da503521a5133a57f0445a4dfa2427eeb926d7ece4119a01cd20ba4acec5db  lib/util/tevent_unix.h
4b93c1107f9cddbb98784229a164de367b1a6748d469a6307a0fb749630ea117  lib/util/tevent_unix.c
047c4df80d3897ba66bb887403478ea5a3f850fc3f2a7b85e6f937740a7e915d  lib/tevent/tevent_req.c
d918168d4423dc081c35a410eed183882c81ab9b2b108f439d344affd576cc53  lib/tevent/tevent.h
85086eff7d899069119918e4bb5d39797e8471f1e820ce5650d05a3980bb2e81  source3/include/vfs_macros.h
HASHES
)
cc="$output/host/bin/arm-buildroot-linux-gnueabi-gcc"
readelf="$output/host/bin/arm-buildroot-linux-gnueabi-readelf"
flags=(-DPHANTOWD_SAMBA_SERVER_VFS_FIXTURE=1 -DPHANTOWD_SAMBA_SERVER_CAPTURE_FIXTURE=1 -D_SAMBA_BUILD_=4 -DHAVE_CONFIG_H=1
    -D__STDC_WANT_LIB_EXT1__=1 -D_GNU_SOURCE=1 -D_FILE_OFFSET_BITS=64
    -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -std=c11 -O2 -fPIC -fvisibility=hidden
    -ffunction-sections -fdata-sections -Wall -Werror
    -I"$samba/source3/include" -I"$samba/source3" -I"$samba/bin/default/source3"
    -I"$samba/bin/default/include" -I"$samba/bin/default" -I"$samba"
    -I"$samba/lib/replace" -I"$samba/lib/talloc" -I"$samba/lib/tevent" -I"$samba/lib/tdb/include"
    -I"$samba/lib" -I"$samba/include")
for pair in 'samba-server-capture-fixture.c vfs-module.o' 'samba-server-capture-qemu-test.c vfs-test.o'; do
    timeout --signal=TERM --kill-after=1 30 "$cc" "${flags[@]}" \
        -MMD -MF "$scratch/${pair#* }.d" -c "$source/support/tests/${pair%% *}" -o "$scratch/${pair#* }"
done
"$cc" -shared -Wl,--gc-sections,-z,defs,-z,relro,-z,now,--enable-new-dtags,-rpath,/usr/lib/samba \
    -Wl,--version-script,"$source/support/tests/samba-server-capture-fixture.map" \
    -Wl,-soname,phantowd_open_qemu.so \
    -Wl,-rpath-link,"$output/staging/usr/lib/samba" -L"$output/staging/usr/lib/samba" \
    -o "$scratch/phantowd_open_qemu.so" "$scratch/vfs-module.o" -l:libsmbd-base-private-samba.so -l:libtalloc-private-samba.so -l:libtevent-private-samba.so -l:libtevent-util-private-samba.so
"$cc" -Wl,--gc-sections,-z,defs,-z,relro,-z,now,--enable-new-dtags,-rpath,/usr/lib/samba \
    -Wl,-rpath-link,"$output/staging/usr/lib/samba" -L"$output/staging/usr/lib/samba" \
    -o "$scratch/capture-test" "$scratch/vfs-test.o" \
    -l:libsmbd-base-private-samba.so -l:libsamba-modules-private-samba.so \
    -lsamba-util -l:libtalloc-private-samba.so \
    -l:libreplace-private-samba.so -l:libgenrand-private-samba.so -l:libsamba-debug-private-samba.so -l:libtevent-private-samba.so -ldl
for name in phantowd_open_qemu.so capture-test; do
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
grep -F '(NEEDED)' "$scratch/phantowd_open_qemu.so.elf"
awk '/\(NEEDED\)/ {
    if ($NF != "[libsmbd-base-private-samba.so]" && $NF != "[libtalloc-private-samba.so]" && $NF != "[libtevent-private-samba.so]" && $NF != "[libtevent-util-private-samba.so]" && $NF != "[libc.so.6]" && $NF != "[ld-linux.so.3]") exit 1
    needed++
} END { if (needed != 6) exit 1 }' "$scratch/phantowd_open_qemu.so.elf"
"$readelf" --dyn-syms -W "$scratch/phantowd_open_qemu.so" >"$scratch/vfs.symbols"
awk '$5 == "GLOBAL" && $7 != "UND" { if ($8 != "samba_init_module") exit 1; exported++ }
    $5 == "GLOBAL" && $7 == "UND" {
        split($8, name, "@")
        if (name[1] !~ /^(smb_register_vfs|smb_vfs_call_connect|smb_vfs_call_disconnect|smb_vfs_call_pread|smb_vfs_call_pread_send|SMB_VFS_PREAD_RECV|tevent_req_is_unix_error|__tevent_req_create|_tevent_req_data|_tevent_req_callback_data|_tevent_req_done|_tevent_req_error|_tevent_req_set_callback|tevent_req_post|_talloc_reference_loc|_talloc_get_type_abort|__errno_location|__stack_chk_guard|__stack_chk_fail|_talloc_zero|_talloc_free|getsockopt|fstat64|fcntl64|prctl|strcmp|memcmp|memcpy|memset|send|getpid|fh_get_refcount|fh_get_gen_id|fsp_get_pathref_fd)$/) { print "Unexpected capture import: " name[1]; exit 1 }
    }
    END { if (exported != 1) exit 1 }' "$scratch/vfs.symbols"
sha256sum "$scratch/phantowd_open_qemu.so" "$scratch/capture-test"
