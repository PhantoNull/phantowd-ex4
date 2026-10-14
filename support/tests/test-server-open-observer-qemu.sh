#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Standalone source/getter prerequisite, not an active server or binding proof.
set -eu
base=${1:?base artifacts required}
output=${2:?existing pinned output required}
source=${3:?repository required}
[ "$#" -eq 3 ] || [ "$#" -eq 4 ] || exit 1
mode=${4:-source}
case "$mode" in source|wire) ;; *) exit 1 ;; esac
tmpdir=${TMPDIR:-/tmp}
case "$base:$output:$source:$tmpdir" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
case "$base:$output:$source:$tmpdir" in /*:/*:/*:/*) ;; *) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || exit 1
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)
scratch=$(mktemp -d "$tmpdir/phantowd-server-open-source.XXXXXX")
trap 'rm -f "$scratch/server-observer.o" "$scratch/server-observer.so" "$scratch/server-observer-test.o" "$scratch/server-observer-test-reduced.o" "$scratch/server-observer-test" "$scratch/server-observer.headers" "$scratch/server-observer.symbols" "$scratch/server-wire-test" "$scratch/inserted-wire" "$scratch/inserted-init" "$scratch/rootfs.ext2" "$scratch/guest.log" "$scratch/inserted.so" "$scratch/inserted-test"; rm -rf "$scratch/cache" "$scratch/path"; rmdir "$scratch"' EXIT
bash "$source/support/tests/build-samba-server-open-observer.sh" "$output" "$source" "$scratch"
init="$source/support/tests/server-open-observer-init.sh"
if [ "$mode" = wire ]; then
    export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false'
    export GOCACHE="$scratch/cache" GOPATH="$scratch/path" TMPDIR="$scratch"
    [ "$(grep -c '^GO_VERSION=' "$source/versions.env")" -eq 1 ]
    go_version=$(sed -n 's/^GO_VERSION=//p' "$source/versions.env")
    [ "$("$output/host/bin/go" version)" = "go version go$go_version linux/amd64" ]
    (cd "$source/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
        timeout --signal=TERM --kill-after=2 120 "$output/host/bin/go" test \
        -tags=qemu -trimpath -c -o "$scratch/server-wire-test" ./internal/runtimebundle)
    sha256sum "$scratch/server-wire-test"
    rm -rf "$scratch/cache" "$scratch/path"
    init="$source/support/tests/server-open-wire-init.sh"
fi
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
if [ "$mode" = wire ]; then
    [ -f "$scratch/rootfs.ext2" ] && [ ! -L "$scratch/rootfs.ext2" ] || exit 1
    truncate -s 128M "$scratch/rootfs.ext2"
    "$output/host/sbin/resize2fs" -f "$scratch/rootfs.ext2" >/dev/null 2>&1
fi
debugfs="$output/host/sbin/debugfs"
for pair in "$scratch/server-observer.so /usr/lib/phantowd-server-open-fixture.so" \
    "$scratch/server-observer-test /usr/sbin/phantowd-server-open-source-test" \
    "$init /usr/sbin/phantowd-server-open-source-init"; do
    input=${pair%% *}
    name=${pair#* }
    "$debugfs" -w -R "write $input $name" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name mode 0100555" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field $name gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
done
"$debugfs" -R "dump /usr/lib/phantowd-server-open-fixture.so $scratch/inserted.so" "$scratch/rootfs.ext2" >/dev/null 2>&1
"$debugfs" -R "dump /usr/sbin/phantowd-server-open-source-test $scratch/inserted-test" "$scratch/rootfs.ext2" >/dev/null 2>&1
cmp "$scratch/server-observer.so" "$scratch/inserted.so"
cmp "$scratch/server-observer-test" "$scratch/inserted-test"
"$debugfs" -R "dump /usr/sbin/phantowd-server-open-source-init $scratch/inserted-init" "$scratch/rootfs.ext2" >/dev/null 2>&1
cmp "$init" "$scratch/inserted-init"
if [ "$mode" = wire ]; then
    "$debugfs" -w -R "write $scratch/server-wire-test /usr/sbin/phantowd-server-open-wire-test" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R 'set_inode_field /usr/sbin/phantowd-server-open-wire-test mode 0100555' "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R 'set_inode_field /usr/sbin/phantowd-server-open-wire-test uid 0' "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R 'set_inode_field /usr/sbin/phantowd-server-open-wire-test gid 0' "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -R "dump /usr/sbin/phantowd-server-open-wire-test $scratch/inserted-wire" "$scratch/rootfs.ext2" >/dev/null 2>&1
    cmp "$scratch/server-wire-test" "$scratch/inserted-wire"
fi
status=0
timeout --signal=TERM --kill-after=2 30 qemu-system-arm -M versatilepb -m 256M \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 init=/usr/sbin/phantowd-server-open-source-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    -display none -serial stdio -monitor none -nic none -no-reboot >"$scratch/guest.log" 2>&1 || status=$?
cat "$scratch/guest.log"
[ "$status" -eq 0 ] || exit 1
awk -v wire="$([ "$mode" = wire ] && echo 1 || echo 0)" -f "$source/support/tests/verify-server-open-observer-log.awk" "$scratch/guest.log"
[ "$(sha256sum "$base/rootfs.ext2" | cut -d ' ' -f 1)" = "$base_hash" ]
printf '%s\n' 'PHANTOWD_SERVER_OPEN_SOURCE_COMPLETE base_unchanged=true active_worker=false authority=false full_image=false scope=qemu-only'
