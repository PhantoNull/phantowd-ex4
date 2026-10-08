#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

# Caller owns and serializes an authenticated Buildroot 2025.02.18 source tree.
# Refuse unknown bytes before patching; never delete package/CWD file globs.
source_dir=${1:?usage: apply-buildroot-download-cleanup.sh BUILDROOT_SOURCE PATCH}
patch_file=${2:?version-pinned archive cleanup patch required}
helper="$source_dir/support/download/helpers"
for directory in "$source_dir" "$source_dir/support" "$source_dir/support/download"; do
    [ -d "$directory" ] && [ ! -L "$directory" ] || exit 1
done
for file in "$helper" "$patch_file"; do
    [ -f "$file" ] && [ ! -L "$file" ] || exit 1
done
patch_digest=$(sha256sum -- "$patch_file")
[ "${patch_digest%% *}" = 4845cc2cc19a1c0009c87395f3d721ffba8ee796911c682e073c75e6e4b5932f ] || {
    echo 'Unexpected Buildroot archive cleanup patch bytes' >&2
    exit 1
}
original=2a2e6190b448ee6bb2881811a6f4785ff790ebb37291c933115a9a6eb314f75b
patched=c6245bb5e1899a485ce5c13fa29b8f29e5bbf99e1cc15f22f05d997ec524db47
helper_digest=$(sha256sum -- "$helper")
case "${helper_digest%% *}" in
    "$original")
        patch --directory "$source_dir" --strip=1 --fuzz=0 --forward --batch \
            --no-backup-if-mismatch --dry-run < "$patch_file" >/dev/null
        patch --directory "$source_dir" --strip=1 --fuzz=0 --forward --batch \
            --no-backup-if-mismatch < "$patch_file" >&2
        result=applied
        ;;
    "$patched") result=already-applied ;;
    *) echo 'Unknown Buildroot archive helper bytes; refusing patch' >&2; exit 1 ;;
esac
helper_digest=$(sha256sum -- "$helper")
[ "${helper_digest%% *}" = "$patched" ]
printf '%s\n' "$result"
