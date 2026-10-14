#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

# The caller serializes an authenticated Buildroot source tree. This helper
# recognizes two complete states, not individual files or a best-effort retry.
[ "$#" = 2 ] || exit 1
source_dir=$1
patch_file=$2
for directory in "$source_dir" "$source_dir/package" "$source_dir/package/go"; do
    [ -d "$directory" ] && [ ! -L "$directory" ] || exit 1
done
make_file="$source_dir/package/go/go.mk"
hash_file="$source_dir/package/go/go.hash"
for file in "$make_file" "$hash_file" "$patch_file"; do
    [ -f "$file" ] && [ ! -L "$file" ] || exit 1
done
digest() {
    checksum=$(sha256sum -- "$1")
    printf '%s\n' "${checksum%% *}"
}
[ "$(digest "$patch_file")" = f0db70a80d256011a98c014a64787e38daeca54229d0edebe4c6297c44cbe014 ] || {
    echo 'Unknown Buildroot Go maintenance patch bytes' >&2
    exit 1
}
original_make=e8317542fe0b1eeda5654e6c3bb37c62b42e45004eb0a7a6ebc05408f540b3d1
original_hash=3309fcb7fd8818a029b2e8d1b7f9051d501c0c44cc1a73d47a42421cb258ef37
patched_make=6168d0cfa8f4d0ad9ad021afcbc2f52e36ce8dfd6814b5fddca6946375f60bc2
patched_hash=bab632d7977da6cc98c7fd88ea752d2cbe32954b1df37a88a4d3cd20ad5cada2
make_digest=$(digest "$make_file")
hash_digest=$(digest "$hash_file")
if [ "$make_digest" = "$original_make" ] && [ "$hash_digest" = "$original_hash" ]; then
    patch --directory "$source_dir" --strip=1 --fuzz=0 --forward --batch \
        --no-backup-if-mismatch --dry-run < "$patch_file" >/dev/null
    patch --directory "$source_dir" --strip=1 --fuzz=0 --forward --batch \
        --no-backup-if-mismatch < "$patch_file" >&2
    result=applied
elif [ "$make_digest" = "$patched_make" ] && [ "$hash_digest" = "$patched_hash" ]; then
    result=already-applied
else
    echo 'Unknown or mixed Buildroot Go recipe; refusing maintenance patch' >&2
    exit 1
fi
[ "$(digest "$make_file")" = "$patched_make" ]
[ "$(digest "$hash_file")" = "$patched_hash" ]
printf '%s\n' "$result"
