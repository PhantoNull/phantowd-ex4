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

# Keep the packaged tools for use by a managed runtime and remove stock
# launchers and configuration from the default boot profile.
exports="$target/etc/exports"
samba="$target/etc/samba"
[ ! -L "$samba" ] && { [ ! -e "$samba" ] || [ -d "$samba" ]; } || exit 1
for file in "$target/etc/init.d/S30rpcbind" "$target/etc/init.d/S60nfs" \
    "$target/etc/init.d/S91smb" "$exports" "$samba/smb.conf"; do
    [ ! -L "$file" ] && { [ ! -e "$file" ] || [ -f "$file" ]; } || exit 1
done
if [ -s "$exports" ]; then
    echo 'RC0 has an unexpected static NFS export configuration' >&2
    exit 1
fi
rm -f -- "$target/etc/init.d/S30rpcbind" "$target/etc/init.d/S60nfs" \
    "$target/etc/init.d/S91smb" "$exports" "$samba/smb.conf"
