#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

[ "$#" -eq 1 ] || exit 2
target=$1
for directory in "$target" "$target/etc" "$target/etc/init.d" "$target/etc/phantowd"; do
    [ -d "$directory" ] && [ ! -L "$directory" ] || exit 1
done
profile="$target/etc/phantowd/product-profile"
[ -f "$profile" ] && [ ! -L "$profile" ] && [ "$(cat "$profile")" = rc0 ] || exit 1

# Buildroot installs these template launchers and an empty exports file.
# Keep the tools for the managed runtime and require an empty boot profile.
exports="$target/etc/exports"
for file in "$target/etc/init.d/S30rpcbind" "$target/etc/init.d/S60nfs" "$exports"; do
    [ ! -L "$file" ] && { [ ! -e "$file" ] || [ -f "$file" ]; } || exit 1
done
if [ -s "$exports" ]; then
    echo 'RC0 has an unexpected static NFS export configuration' >&2
    exit 1
fi
rm -f -- "$target/etc/init.d/S30rpcbind" "$target/etc/init.d/S60nfs" "$exports"
