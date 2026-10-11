#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
base=${1:?base artifacts required}
output=${2:?existing output required}
source=${3:?repository required}
[ "$#" -eq 3 ] || exit 1
tmpdir=${TMPDIR:-/tmp}
case "$base:$output:$source:$tmpdir" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$base:$output:$source:$tmpdir" in /*:/*:/*:/*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)
scratch=$(mktemp -d "$tmpdir/phantowd-capture-runtime.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
go="$output/host/bin/go"
cc="$output/host/bin/arm-buildroot-linux-gnueabi-gcc"
target="$output/target"
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
export GOCACHE="$scratch/go-cache" GOPATH="$scratch/go-path"
(cd "$source/tools/phantowd-lab" && timeout --signal=TERM --kill-after=1 30 "$go" build -trimpath -o "$scratch/lab" ./cmd/phantowd-lab)
for entry in usr/sbin/smbd usr/bin/smbpasswd usr/bin/testparm usr/lib/samba/vfs/streams_xattr.so usr/lib/gconv/IBM850.so usr/bin/pdbedit usr/bin/smbstatus usr/bin/smbcontrol; do
    "$scratch/lab" inspect-runtime-closure "$target" "$entry" >"$scratch/${entry##*/}.json"
done
python3 -B "$source/support/tests/samba_root_fixture.py" prepare \
    "$scratch/smbd.json" "$scratch/smbpasswd.json" "$scratch/testparm.json" \
    "$scratch/streams_xattr.so.json" "$scratch/IBM850.so.json" "$scratch/pdbedit.json" \
    "$scratch/smbstatus.json" "$scratch/smbcontrol.json" "$target/usr/lib/gconv/gconv-modules" "$scratch/manifest"
(cd "$source/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    timeout --signal=TERM --kill-after=1 30 "$go" build -tags=qemu -trimpath -o "$scratch/stager" ./cmd/qemu-runtime-bundle)
(cd "$source/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    timeout --signal=TERM --kill-after=1 30 "$go" test -tags=qemu -c -trimpath -o "$scratch/capture-adapter-tests" ./internal/processowner)
mkdir "$scratch/module"
bash "$source/support/tests/build-samba-server-capture-fixture.sh" "$output" "$source" "$scratch/module"
timeout --signal=TERM --kill-after=1 30 "$cc" -static -std=c11 -O2 -Wall -Wextra -Werror -Wno-unused-function \
    -ffunction-sections -fdata-sections -Wl,--gc-sections,-z,relro,-z,now \
    -DPHANTOWD_SAMBA_CAPTURE_BOOTSTRAP_FIXTURE=1 -o "$scratch/bootstrap" "$source/support/tests/samba-server-capture-bootstrap-qemu.c"
# Expected hashes are supplied from independent build outputs before staging.
for pair in "$scratch/bootstrap /usr/sbin/phantowd-server-observer-daemon-bootstrap" \
    "$scratch/module/phantowd_open_qemu.so /usr/lib/samba/vfs/phantowd_open_qemu.so"; do
    printf '%s %s %s\n' "$(sha256sum "${pair%% *}" | cut -d ' ' -f 1)" "${pair#* }" "${pair#* }" >>"$scratch/manifest"
done
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
[ "$(wc -c < "$scratch/rootfs.ext2")" -le 134217728 ] || exit 1
truncate -s 128M "$scratch/rootfs.ext2"
"$output/host/sbin/resize2fs" -f "$scratch/rootfs.ext2" >/dev/null 2>&1
debugfs="$output/host/sbin/debugfs"
for pair in "$scratch/bootstrap /usr/sbin/phantowd-server-observer-daemon-bootstrap" \
    "$scratch/module/phantowd_open_qemu.so /usr/lib/samba/vfs/phantowd_open_qemu.so" \
    "$scratch/stager /usr/sbin/phantowd-runtime-bundle-probe" \
    "$scratch/capture-adapter-tests /usr/sbin/phantowd-capture-adapter-tests" \
    "$scratch/manifest /usr/lib/phantowd/qemu-samba-root.manifest" \
    "$source/support/tests/server-capture-runtime-init.sh /usr/sbin/phantowd-server-capture-runtime-init"; do
    input=${pair%% *}; name=${pair#* }; mode=0100555
    if [ "$name" = /usr/lib/phantowd/qemu-samba-root.manifest ]; then mode=0100644; fi
    [ -f "$input" ] && [ ! -L "$input" ] || exit 1
    "$debugfs" -w -R "write $input $name" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name mode $mode" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -R "dump $name $scratch/readback" "$scratch/rootfs.ext2" >/dev/null 2>&1
    cmp "$input" "$scratch/readback"
    metadata=$("$debugfs" -R "stat $name" "$scratch/rootfs.ext2" 2>/dev/null)
    printf '%s\n' "$metadata" | grep -Eq "^Inode: [0-9]+ +Type: regular +Mode: +${mode#010} +"
    printf '%s\n' "$metadata" | grep -Eq '^User: +0 +Group: +0 +'
    rm "$scratch/readback"
done
for name in readonly writable; do
    truncate -s 16M "$scratch/$name.ext4"
    "$output/host/sbin/mke2fs" -q -F -t ext4 -E lazy_itable_init=0,lazy_journal_init=0 "$scratch/$name.ext4"
done
export TMPDIR="$scratch"
status=0
timeout --signal=TERM --kill-after=2 60 qemu-system-arm -M versatilepb -cpu arm926 -m 256M \
    -object rng-random,id=capture-rng,filename=/dev/urandom -device virtio-rng-pci,rng=capture-rng \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 phantowd_observer_daemon_fixture=1 phantowd_capture_runtime_fixture=1 init=/usr/sbin/phantowd-server-capture-runtime-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    -drive "file=$scratch/readonly.ext4,format=raw,if=scsi,snapshot=on" \
    -drive "file=$scratch/writable.ext4,format=raw,if=scsi,snapshot=on" \
    -display none -serial stdio -monitor none -nic none -no-reboot >"$scratch/guest.log" 2>&1 || status=$?
cat "$scratch/guest.log"
[ "$status" -eq 0 ] || exit 1
awk -f "$source/support/tests/verify-server-capture-runtime-log.awk" "$scratch/guest.log"
[ "$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)" = "$base_hash" ]
echo 'PHANTOWD_CAPTURE_RUNTIME_COMPLETE base_unchanged=true authentication=false file_open=false samples=false authority=false scope=qemu-only'
