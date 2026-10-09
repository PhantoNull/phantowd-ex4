#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Fresh metadata/retention guest; no client, credentials, server or real storage.
set -eu
base=${1:?base artifacts required}
output=${2:?existing pinned output required}
source=${3:?source required}
[ "$#" -eq 3 ] || exit 1
tmpdir=${TMPDIR:-/tmp}
case "$base:$output:$source:$tmpdir" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$base:$output:$source:$tmpdir" in /*:/*:/*:/*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || exit 1
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)
scratch=$(mktemp -d "$tmpdir/phantowd-pending-inputs.XXXXXX")
# Every mutable artifact belongs to this one newly-created tmpfs tree.
trap 'rm -rf "$scratch"' EXIT
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
export GOCACHE="$scratch/cache" GOPATH="$scratch/path"
go_binary="$output/host/bin/go"
compiler="$output/host/bin/arm-buildroot-linux-gnueabi-gcc"
debugfs="$output/host/sbin/debugfs"
(cd "$source/src/phantowd-api" && "$go_binary" build -tags=qemu -trimpath -o "$scratch/host-inputs" ./cmd/qemu-pending-client-inputs)
"$scratch/host-inputs" documents >"$scratch/documents.json"
(cd "$source/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    "$go_binary" build -tags=qemu -trimpath -o "$scratch/arm-inputs" ./cmd/qemu-pending-client-inputs)
(cd "$source/tools/phantowd-lab" && "$go_binary" build -trimpath -o "$scratch/lab" ./cmd/phantowd-lab)
"$scratch/lab" inspect-runtime-closure "$output/target" usr/lib/libsmbclient.so.0 >"$scratch/closure.json"
"$compiler" -std=c11 -O2 -Wall -Wextra -Werror \
    -I"$output/staging/usr/include/samba-4.0" -Wl,-rpath-link,"$output/staging/usr/lib/samba" \
    -o "$scratch/client" "$source/support/tests/samba-pending-write-fixture.c" -lsmbclient
"$compiler" -std=c11 -O2 -static -Wall -Wextra -Werror \
    -o "$scratch/launcher" "$source/support/tests/samba-pending-write-launcher-fixture.c"
python3 -B "$source/support/tests/pending_client_inputs_fixture.py" \
    "$scratch/closure.json" "$scratch/documents.json" "$scratch/client" "$scratch/launcher" "$output/target" "$scratch"
rm -rf "$scratch/cache" "$scratch/path"
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
# Enlarge ONLY this fresh regular tmpfs copy, never a base/device/user disk.
[ -f "$scratch/rootfs.ext2" ] && [ ! -L "$scratch/rootfs.ext2" ] || exit 1
truncate -s 128M "$scratch/rootfs.ext2"
"$output/host/sbin/resize2fs" -f "$scratch/rootfs.ext2" >/dev/null 2>&1
"$debugfs" -w -f "$scratch/stage.commands" "$scratch/rootfs.ext2" >/dev/null 2>&1
for pair in "$scratch/inputs.json /usr/lib/phantowd/qemu-pending-client-inputs.json" \
    "$scratch/arm-inputs /usr/sbin/phantowd-pending-client-inputs" \
    "$source/support/tests/pending-client-inputs-init.sh /usr/sbin/phantowd-pending-client-inputs-init"; do
    input=${pair%% *}
    path=${pair#* }
    "$debugfs" -w -R "write $input $path" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $path mode 0100555" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $path uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $path gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
done
status=0
timeout --signal=TERM --kill-after=2 60 qemu-system-arm -M versatilepb -m 256M \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 init=/usr/sbin/phantowd-pending-client-inputs-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    -display none -serial stdio -monitor none -nic none -no-reboot >"$scratch/guest.log" 2>&1 || status=$?
cat "$scratch/guest.log"
[ "$status" -eq 0 ] || exit 1
awk -f "$source/support/tests/verify-pending-client-inputs-log.awk" "$scratch/guest.log"
[ "$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)" = "$base_hash" ]
printf '%s\n' 'PHANTOWD_PENDING_INPUTS_QEMU_COMPLETE original_plans=true base_unchanged=true client_executed=false service=false full_image=false scope=qemu-only'
