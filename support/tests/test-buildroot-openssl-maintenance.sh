#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

source_dir=${1:?usage: test-buildroot-openssl-maintenance.sh BUILDROOT_SOURCE}
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
patch_file="$repo_root/support/buildroot-patches/2025.02.18/0005-libopenssl-3.5.9-maintenance.patch"
helper="$repo_root/support/container/apply-buildroot-openssl-maintenance.sh"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-openssl-maintenance.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
trap 'exit 1' HUP INT TERM

mkdir -p "$temporary/package/libopenssl"
cp "$source_dir/package/libopenssl/libopenssl.mk" \
    "$source_dir/package/libopenssl/libopenssl.hash" \
    "$source_dir/package/libopenssl/"*.patch "$temporary/package/libopenssl/"
if grep -Fx 'LIBOPENSSL_VERSION = 3.5.9' "$temporary/package/libopenssl/libopenssl.mk" >/dev/null; then
    patch --directory "$temporary" --strip=1 --fuzz=0 --reverse --batch \
        < "$patch_file" >/dev/null
fi
mkdir "$temporary/original"
cp "$temporary/package/libopenssl/"* "$temporary/original/"

first=$(sh "$helper" "$temporary" "$patch_file")
second=$(sh "$helper" "$temporary" "$patch_file")
[ "$first" = applied ]
[ "$second" = already-applied ]
grep -Fx 'LIBOPENSSL_VERSION = 3.5.9' "$temporary/package/libopenssl/libopenssl.mk" >/dev/null
grep -Fx 'sha256  603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a  openssl-3.5.9.tar.gz' \
    "$temporary/package/libopenssl/libopenssl.hash" >/dev/null
grep -Fx 'sha256  7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a  LICENSE.txt' \
    "$temporary/package/libopenssl/libopenssl.hash" >/dev/null
printf 'Buildroot OpenSSL maintenance coherent patch and idempotence passed\n'

# A recipe/version match cannot authorize changed upstream patch inputs.
snapshot() {
    (cd "$temporary" && {
        find package -printf '%y %p %l\n' | LC_ALL=C sort
        find package -type f -exec sha256sum -- {} + | LC_ALL=C sort
    })
}
printf '\nunknown patch bytes\n' >> "$temporary/package/libopenssl/0001-Reproducible-build-do-not-leak-compiler-path.patch"
before=$(snapshot)
if sh "$helper" "$temporary" "$patch_file" >/dev/null 2>&1; then
    echo 'OpenSSL maintenance accepted changed upstream patch inputs' >&2
    exit 1
fi
[ "$before" = "$(snapshot)" ]
printf 'Buildroot OpenSSL changed-patch no-effect refusal passed\n'

fresh_case() {
    rm -rf -- "$temporary/case"
    mkdir -p "$temporary/case/package/libopenssl"
    cp "$temporary/original/"* "$temporary/case/package/libopenssl/"
}
case_snapshot() {
    (cd "$temporary/case" && {
        find . -printf '%y %m %p %l\n' | LC_ALL=C sort
        find . -type f -exec sha256sum -- {} + | LC_ALL=C sort
    })
}
refuse_without_changes() {
    before=$(case_snapshot)
    if sh "$helper" "$temporary/case" "$1" >/dev/null 2>&1; then
        echo "OpenSSL maintenance accepted an invalid case: $2" >&2
        exit 1
    fi
    [ "$before" = "$(case_snapshot)" ] || {
        echo "OpenSSL maintenance modified a refused case: $2" >&2
        exit 1
    }
}
for file in libopenssl.mk libopenssl.hash; do
    fresh_case
    cp "$temporary/package/libopenssl/$file" "$temporary/case/package/libopenssl/$file"
    refuse_without_changes "$patch_file" "mixed-$file"
    fresh_case
    printf '\nunknown bytes\n' >> "$temporary/case/package/libopenssl/$file"
    refuse_without_changes "$patch_file" "unknown-$file"
    fresh_case
    mv "$temporary/case/package/libopenssl/$file" "$temporary/case/package/libopenssl/$file.real"
    ln -s "$file.real" "$temporary/case/package/libopenssl/$file"
    refuse_without_changes "$patch_file" "symlink-$file"
    fresh_case
    rm "$temporary/case/package/libopenssl/$file"
    refuse_without_changes "$patch_file" "missing-$file"
done
for input in "$temporary/original/"*.patch; do
    name=${input##*/}
    fresh_case
    printf '\nunknown bytes\n' >> "$temporary/case/package/libopenssl/$name"
    refuse_without_changes "$patch_file" "changed-$name"
    fresh_case
    rm "$temporary/case/package/libopenssl/$name"
    refuse_without_changes "$patch_file" "missing-$name"
    fresh_case
    mv "$temporary/case/package/libopenssl/$name" "$temporary/case/package/libopenssl/$name.real"
    ln -s "$name.real" "$temporary/case/package/libopenssl/$name"
    refuse_without_changes "$patch_file" "symlink-$name"
done
fresh_case
cp "$temporary/original/0001-Reproducible-build-do-not-leak-compiler-path.patch" \
    "$temporary/case/package/libopenssl/0005-unknown.patch"
refuse_without_changes "$patch_file" extra-upstream-patch
fresh_case
mv "$temporary/case/package/libopenssl" "$temporary/case/package/libopenssl-real"
ln -s libopenssl-real "$temporary/case/package/libopenssl"
refuse_without_changes "$patch_file" symlink-package-directory
fresh_case
cp "$patch_file" "$temporary/unknown.patch"
printf '\nunknown patch bytes\n' >> "$temporary/unknown.patch"
refuse_without_changes "$temporary/unknown.patch" unknown-maintenance-patch
ln -s "$patch_file" "$temporary/link.patch"
refuse_without_changes "$temporary/link.patch" symlink-maintenance-patch
refuse_without_changes "$temporary/missing.patch" missing-maintenance-patch
printf 'Buildroot OpenSSL mixed/unknown/missing/symlink/patch-roster no-effect refusals passed\n'
