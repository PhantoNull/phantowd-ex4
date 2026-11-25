#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

[ "$#" -eq 1 ] || exit 2
target=$1
host_go="${HOST_DIR:?}/bin/go"
external=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
[ -x "$host_go" ]
[ -d "$target/usr/lib" ] && [ ! -L "$target/usr/lib" ]
scratch=$(mktemp -d "${BUILD_DIR:?}/rc0-samba-code.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 1' INT TERM
umask 022
(
    cd "$external/tools/phantowd-lab"
    GOCACHE="$scratch/cache" CGO_ENABLED=0 GOPROXY=off GOTOOLCHAIN=local GOWORK=off \
        "$host_go" build -mod=vendor -buildvcs=false -trimpath -o "$scratch/phantowd-lab" ./cmd/phantowd-lab
)
"$scratch/phantowd-lab" stage-samba-code "$target" "$scratch/bundle"
destination="$target/usr/lib/phantowd-samba-code"
if [ -e "$destination" ] || [ -L "$destination" ]; then
    [ -d "$destination" ] && [ ! -L "$destination" ]
    diff -qr --no-dereference -- "$destination" "$scratch/bundle"
    (cd "$destination" && find . -printf '%P %m\n' | LC_ALL=C sort) > "$scratch/current-modes"
    (cd "$scratch/bundle" && find . -printf '%P %m\n' | LC_ALL=C sort) > "$scratch/staged-modes"
    cmp -- "$scratch/current-modes" "$scratch/staged-modes"
else
    mv -T -- "$scratch/bundle" "$destination"
fi
