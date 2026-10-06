#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Exact fixed public-runtime profile, disposable root snapshot and guest tmpfs.
set -eu
base=${1:?BASE TARGET GO DEBUGFS CC SOURCE [FAILURE_LOG]}
target=${2:?pinned target required}
go_binary=${3:?pinned Go required}
debugfs=${4:?pinned debugfs required}
compiler=${5:?pinned ARM compiler required}
source_dir=${6:?source required}
failure_log=${7:-}
tmpdir=${TMPDIR:-/tmp}
export TMPDIR="$tmpdir"
case "$base:$target:$go_binary:$debugfs:$compiler:$source_dir:$failure_log:$tmpdir" in
    *[!a-zA-Z0-9_./:-]*) exit 1 ;;
esac
case "$tmpdir" in /*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || exit 1
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
[ -d "$target" ] && [ ! -L "$target" ] || exit 1
scratch=$(mktemp -d "$tmpdir/phantowd-samba-root.XXXXXX")
child_pid=
cleanup() {
    if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    # Only this exact newly-created tmpfs directory owns these files.
    rm -f "$scratch/rootfs.ext2" "$scratch/acl.ext4" "$scratch/lab" "$scratch/smbd.json" \
        "$scratch/smbpasswd.json" "$scratch/testparm.json" "$scratch/pdbedit.json" \
        "$scratch/smbstatus.json" "$scratch/smbcontrol.json" \
        "$scratch/streams_xattr.json" "$scratch/ibm850.json" "$scratch/manifest" \
        "$scratch/launcher" "$scratch/charset" "$scratch/bundle" "$scratch/owner" "$scratch/guest.log"
    rm -rf "$scratch/go-cache" "$scratch/go-path"
    rmdir "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
export GOCACHE="$scratch/go-cache" GOPATH="$scratch/go-path"
(cd "$source_dir/tools/phantowd-lab" && \
    "$go_binary" build -trimpath -o "$scratch/lab" ./cmd/phantowd-lab)
"$scratch/lab" inspect-runtime-closure "$target" usr/sbin/smbd >"$scratch/smbd.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/bin/smbpasswd >"$scratch/smbpasswd.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/bin/testparm >"$scratch/testparm.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/lib/samba/vfs/streams_xattr.so >"$scratch/streams_xattr.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/lib/gconv/IBM850.so >"$scratch/ibm850.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/bin/pdbedit >"$scratch/pdbedit.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/bin/smbstatus >"$scratch/smbstatus.json"
"$scratch/lab" inspect-runtime-closure "$target" usr/bin/smbcontrol >"$scratch/smbcontrol.json"
python3 -B "$source_dir/support/tests/samba_root_fixture.py" prepare \
    "$scratch/smbd.json" "$scratch/smbpasswd.json" "$scratch/testparm.json" \
    "$scratch/streams_xattr.json" "$scratch/ibm850.json" "$scratch/pdbedit.json" \
    "$scratch/smbstatus.json" "$scratch/smbcontrol.json" \
    "$target/usr/lib/gconv/gconv-modules" "$scratch/manifest"
"$compiler" -std=c11 -O2 -static -Wall -Wextra -Werror \
    -o "$scratch/launcher" "$source_dir/support/tests/samba-root-launcher-fixture.c"
"$compiler" -std=c11 -O2 -Wall -Wextra -Werror \
    -o "$scratch/charset" "$source_dir/support/tests/samba-charset-fixture.c"
(cd "$source_dir/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    "$go_binary" build -tags=qemu -trimpath -o "$scratch/bundle" ./cmd/qemu-runtime-bundle)
(cd "$source_dir/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    "$go_binary" build -tags=qemu -trimpath -o "$scratch/owner" ./cmd/qemu-samba-owner)
rm -rf "$scratch/go-cache" "$scratch/go-path"
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
# Format only this newly-created regular tmpfs file, never a block-device path.
truncate -s 16M "$scratch/acl.ext4"
[ -f "$scratch/acl.ext4" ] && [ ! -L "$scratch/acl.ext4" ] || exit 1
"$(dirname "$debugfs")/mke2fs" -q -F -t ext4 \
    -U c395f03e-60ea-4ea1-9f47-08fb0aabfa72 \
    -E lazy_itable_init=0,lazy_journal_init=0 "$scratch/acl.ext4"
for pair in "launcher phantowd-samba-root-launcher" \
    "charset phantowd-samba-charset-probe" \
    "bundle phantowd-runtime-bundle-probe" \
    "owner phantowd-samba-owner-probe" \
    "$source_dir/support/tests/samba-root-init.sh phantowd-samba-root-init"; do
    input=${pair%% *}
    output=${pair#* }
    case "$input" in /*) ;; *) input="$scratch/$input" ;; esac
    "$debugfs" -w -R "write $input /usr/sbin/$output" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output mode 0100755" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
done
"$debugfs" -w -R "write $scratch/manifest /usr/lib/phantowd/qemu-samba-root.manifest" "$scratch/rootfs.ext2" >/dev/null 2>&1
timeout --signal=TERM --kill-after=5 180 qemu-system-arm \
    -M versatilepb -cpu arm926 -m 256M -nographic -no-reboot -nic none \
    -object rng-random,id=samba-rng,filename=/dev/urandom \
    -device virtio-rng-pci,rng=samba-rng \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 phantowd_samba_ext4_fixture=1 init=/usr/sbin/phantowd-samba-root-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    -drive "file=$scratch/acl.ext4,format=raw,if=scsi,snapshot=on" \
    >"$scratch/guest.log" 2>&1 &
child_pid=$!
status=0
wait "$child_pid" || status=$?
child_pid=
if [ "$status" -ne 0 ] || ! python3 -B "$source_dir/support/tests/samba_root_fixture.py" verify \
    "$scratch/guest.log"; then
    if [ -n "$failure_log" ]; then
        mkdir -p "$(dirname "$failure_log")"
        cp "$scratch/guest.log" "$failure_log"
    fi
    tail -n 120 "$scratch/guest.log" >&2
    exit 1
fi
[ "$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')" = "$base_hash" ]
echo PHANTOWD_SAMBA_ROOT_BASE_UNCHANGED
