#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Offline compile-only helper; never changes source/cache/installed libraries.
set -eu
output=${1:?existing pinned output required}
source=${2:?repository required}
scratch=${3:?caller-owned disposable tmpfs directory required}
[ "$#" -eq 3 ] || exit 1
case "$output:$source:$scratch" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$output:$source:$scratch" in /*:/*:/*) ;; *) exit 1 ;; esac
[ -d "$scratch" ] && [ ! -L "$scratch" ] || exit 1
awk -v target="$scratch" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || exit 1
for name in observer.o observer.so observer-test observer-test.o observer-test-reduced.o observer.headers observer.symbols; do
    [ ! -e "$scratch/$name" ] && [ ! -L "$scratch/$name" ] || exit 1
done
samba="$output/build/samba4-4.22.11"
# The actual private definitions/mapping/getters are pinned, not a guessed ABI.
# These guards do not authenticate the full transitive source/SDK/runtime.
(cd "$samba" && sha256sum -c <<'HASHES'
7f6b03653317cc8cd9de59d9ba0c586e06ee076b77069feb3ccb02e4cabdf142  source3/include/libsmbclient.h
cda60e8264dd67d74890c8ca8765be10b514f3bc855f29541e92cfb029c41163  source3/include/libsmb_internal.h
301a58f9db28d3270274ab0b1c3e7e868381e5e21f479345f892db59edb367dd  source3/include/client.h
ec32b188fb42bc607196f51554016b3469a5c52c07c6293cad3d2b47164ea4c0  source3/libsmb/cli_smb2_fnum.c
986da006dbdee2def8e402d21fa89f7fc82ecf50dbb4ae94d977e5a5e366d954  libcli/smb/smbXcli_base.c
9e1b3f3c4f6a24cce3df8a005242cbb7c445a98b35e38ef5a3fba058c0f5e1eb  libcli/smb/smbXcli_base.h
99fa883cf03d219525056bb9de495e5d2540408727e1842c3dacbdcdf46c8392  lib/util/idtree.c
eaa36a7262e7680bfdf38ab43a302de7a5ee1b18fb5e5a69c693660e5ab407d1  lib/util/idtree.h
HASHES
)
compiler="$output/host/bin/arm-buildroot-linux-gnueabi-gcc"
readelf="$output/host/bin/arm-buildroot-linux-gnueabi-readelf"
flags=(-DPHANTOWD_SAMBA_SOURCE_OBSERVER_FIXTURE=1 -D_SAMBA_BUILD_=4 -DHAVE_CONFIG_H=1
    -D__STDC_WANT_LIB_EXT1__=1 -D_GNU_SOURCE=1 -D_FILE_OFFSET_BITS=64
    -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -std=c11 -O2 -fPIC -fvisibility=hidden
    -ffunction-sections -fdata-sections -Wall -Werror
    -I"$samba/source3/include" -I"$samba/source3" -I"$samba/bin/default/source3"
    -I"$samba/bin/default/include" -I"$samba/bin/default" -I"$samba"
    -I"$samba/lib/replace" -I"$samba/lib/talloc" -I"$samba/lib/tevent"
    -I"$samba/lib" -I"$samba/include")
timeout --signal=TERM --kill-after=1 30 "$compiler" "${flags[@]}" \
    -c "$source/support/tests/samba-pending-handle-observer-fixture.c" -o "$scratch/observer.o"
"$compiler" -shared -Wl,--gc-sections,-z,defs,-rpath,/usr/lib/samba \
    -Wl,-soname,libphantowd-pending-handle-qemu.so \
    -Wl,--version-script="$source/support/tests/samba-pending-handle-observer-fixture.map" \
    -Wl,-rpath-link,"$output/staging/usr/lib/samba" -L"$output/staging/usr/lib/samba" \
    -o "$scratch/observer.so" "$scratch/observer.o" -lsamba-util -l:libcli-smb-common-private-samba.so
timeout --signal=TERM --kill-after=1 30 "$compiler" "${flags[@]}" \
    -c "$source/support/tests/samba-pending-handle-observer-qemu-test.c" -o "$scratch/observer-test.o"
# Resolve only retained relocations before dynamic-library symbol admission.
# Linking the full upstream unit directly produced DSO-missing errors from
# unreachable tevent code, even with final-link GC/version-script enabled.
"$output/host/bin/arm-buildroot-linux-gnueabi-ld" -r --gc-sections \
    -u main -u phantowd_qemu_observe_smb_handle_v1 \
    -o "$scratch/observer-test-reduced.o" "$scratch/observer-test.o"
"$compiler" -Wl,--gc-sections,-z,defs,-rpath,/usr/lib/samba -Wl,-rpath-link,"$output/staging/usr/lib/samba" \
    -Wl,--version-script="$source/support/tests/samba-pending-handle-observer-fixture.map" \
    -L"$output/staging/usr/lib/samba" -o "$scratch/observer-test" \
    "$scratch/observer-test-reduced.o" \
    -lsamba-util -l:libtalloc-private-samba.so -l:libreplace-private-samba.so -ldl
for name in observer.so observer-test; do
    "$readelf" -h -A -d "$scratch/$name" >"$scratch/observer.headers"
    grep -Eq 'Class:.*ELF32' "$scratch/observer.headers"
    grep -Eq 'Machine:.*ARM' "$scratch/observer.headers"
    grep -Eq 'Flags:.*Version5 EABI, soft-float ABI' "$scratch/observer.headers"
    grep -F 'Tag_CPU_arch: v5TEJ' "$scratch/observer.headers"
done
"$readelf" -d "$scratch/observer.so" | grep -F 'Library soname: [libphantowd-pending-handle-qemu.so]'
"$readelf" --dyn-syms -W "$scratch/observer-test" >"$scratch/observer.symbols"
# The positive seam must not bring back unused wire operations/event engines.
if grep -Eq 'smb2cli_(create|read|write|close|ioctl).*|tevent_req_' "$scratch/observer.symbols"; then exit 1; fi
"$readelf" --dyn-syms -W "$scratch/observer.so" >"$scratch/observer.symbols"
awk '
    $5 == "GLOBAL" && $7 != "UND" { if ($8 != "phantowd_qemu_observe_smb_handle_v1") exit 1; exported++ }
    $5 == "GLOBAL" && $7 == "UND" {
        split($8, name, "@")
        if (name[1] !~ /^(smbXcli_conn_protocol|smbXcli_conn_is_connected|smb2cli_session_current_id|smb2cli_tcon_current_id|idr_find|memset)$/) exit 1
    }
    END { if (exported != 1) exit 1 }
' "$scratch/observer.symbols"
sha256sum "$scratch/observer.so" "$scratch/observer-test"
printf 'PHANTOWD_PENDING_HANDLE_BUILD_DONE exports=1 observer_bytes=%s arm_executed=false authority=false scope=compile-only\n' "$(stat -c %s "$scratch/observer.so")"
