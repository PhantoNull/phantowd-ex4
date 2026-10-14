#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

# The caller serializes an authenticated Buildroot source tree. Never repair
# individual files or retry an interrupted/mixed maintenance application.
[ "$#" = 2 ] || exit 1
source_dir=$1
patch_file=$2
for directory in "$source_dir" "$source_dir/package" "$source_dir/package/libopenssl"; do
    [ -d "$directory" ] && [ ! -L "$directory" ] || exit 1
done
make_file="$source_dir/package/libopenssl/libopenssl.mk"
hash_file="$source_dir/package/libopenssl/libopenssl.hash"
for file in "$make_file" "$hash_file" "$patch_file"; do
    [ -f "$file" ] && [ ! -L "$file" ] || exit 1
done
digest() {
    checksum=$(sha256sum -- "$1")
    printf '%s\n' "${checksum%% *}"
}
[ "$(digest "$patch_file")" = 5fc0de889c20a34bec416883a6a9f03be7bb8193fd4b0d8c0f60bfbb56f9e031 ] || {
    echo 'Unknown Buildroot OpenSSL maintenance patch bytes' >&2
    exit 1
}
patch_count=0
for input in "$source_dir/package/libopenssl/"*.patch; do
    [ -f "$input" ] && [ ! -L "$input" ] || exit 1
    case "${input##*/}" in
        0001-Reproducible-build-do-not-leak-compiler-path.patch)
            expected=b1bb9ac225e6ec158539bb50ddfa7c14219baf4a4d2e47b700ef945d9e8fbbf7 ;;
        0002-Configure-use-ELFv2-ABI-on-some-ppc64-big-endian-sys.patch)
            expected=af045e410ef51971e658629e97dddc808a79c933f4b1c9bda63aaa367a455b77 ;;
        0003-Revert-Fix-static-builds.patch)
            expected=e34917c7138d94737a0788ad268cbbfc22a72deaed28b1f72dd2c1d492ef0548 ;;
        0004-Serialize-install-process-to-avoid-multiple-make-dep.patch)
            expected=3d9967848a83e7cce532e9be51189912746369daa7590398228ae8b22658867a ;;
        *) echo 'Unknown Buildroot OpenSSL upstream patch roster' >&2; exit 1 ;;
    esac
    [ "$(digest "$input")" = "$expected" ] || exit 1
    patch_count=$((patch_count + 1))
done
[ "$patch_count" = 4 ] || exit 1
original_make=3b992b3ce475793ed09fd29e507a114adc2e372cf5fef969eef01bc868f7f6b5
original_hash=f23986b9fef3bbf963ac9008e218ed5c630d7a7f177866d3892d307e897f22f0
patched_make=80be96cc7fff539c3426fb42a64555a165c893ae9e14b76b6c2912de5f7d475a
patched_hash=372d49e1a794fe661e22cdafec8c952d601777da229c74a46d000dce51ce995b
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
    echo 'Unknown or mixed Buildroot OpenSSL recipe; refusing maintenance patch' >&2
    exit 1
fi
[ "$(digest "$make_file")" = "$patched_make" ]
[ "$(digest "$hash_file")" = "$patched_hash" ]
printf '%s\n' "$result"
