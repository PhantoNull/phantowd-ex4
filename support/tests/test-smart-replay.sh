#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Native producer oracle only, in a bounded no-device disposable container.
set -eu
archive=${1:?verified source archive required}
go_binary=${2:?pinned Go required}
source_dir=${3:?repository required}
tmpdir=${TMPDIR:-/tmp}
case "$archive:$go_binary:$source_dir:$tmpdir" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts
[ -f "$archive" ] && [ ! -L "$archive" ]
expected=e9a61f641ff96ca95319edfb17948cd297d0cd3342736b2c49c99d4716fb993d
[ "$(sha256sum "$archive" | awk '{print $1}')" = "$expected" ]
scratch=$(mktemp -d "$tmpdir/phantowd-smart-replay.XXXXXX")
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT
trap 'exit 1' INT TERM
tar -xzf "$archive" -C "$scratch"
cd "$scratch/smartmontools-7.4"
if ! timeout --signal=TERM --kill-after=5 120 ./configure \
    --with-os-deps=os_generic.o --without-libsystemd --without-libcap-ng \
    --without-selinux >"$scratch/configure.log" 2>&1; then
    tail -n 40 "$scratch/configure.log" >&2
    exit 1
fi
# No native hardware backend, installation, daemon, database update or network.
grep -x 'os_deps = os_generic.o' Makefile >/dev/null
if ! timeout --signal=TERM --kill-after=5 300 make -j2 smartctl >"$scratch/build.log" 2>&1; then
    tail -n 40 "$scratch/build.log" >&2
    exit 1
fi
[ -f os_generic.o ] && [ ! -f os_linux.o ] && [ ! -f smartd ]
mkdir "$scratch/corpus"
python3 -B "$source_dir/support/tests/smart-replay-corpus.py" \
    "$scratch/smartmontools-7.4/smartctl" "$scratch/corpus"
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false -p=2' GOMAXPROCS=2
export GOCACHE="$scratch/go-cache" GOPATH="$scratch/go-path"
export PHANTOWD_SMART_REPLAY_CORPUS="$scratch/corpus"
cd "$source_dir/src/phantowd-api"
timeout --signal=TERM --kill-after=5 120 "$go_binary" vet -tags smartreplay ./internal/smartreport
timeout --signal=TERM --kill-after=5 180 "$go_binary" test -race -tags smartreplay -count=1 -timeout=60s ./internal/smartreport
echo 'PHANTOWD_SMART_REPLAY_READY scope=native-generic-synthetic-only cases=7'
