#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

source_dir=${1:?usage: test-buildroot-go-maintenance.sh BUILDROOT_SOURCE}
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
patch_file="$repo_root/support/buildroot-patches/2025.02.18/0004-go-1.26.8-maintenance.patch"
helper="$repo_root/support/container/apply-buildroot-go-maintenance.sh"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-go-maintenance.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM

mkdir -p "$temporary/package/go"
cp "$source_dir/package/go/go.mk" "$temporary/package/go/go.mk"
cp "$source_dir/package/go/go.hash" "$temporary/package/go/go.hash"
if grep -Fx 'GO_VERSION = 1.26.8' "$temporary/package/go/go.mk" >/dev/null; then
    patch --directory "$temporary" --strip=1 --fuzz=0 --reverse --batch \
        < "$patch_file" >/dev/null
fi
mkdir "$temporary/original"
cp "$temporary/package/go/go.mk" "$temporary/package/go/go.hash" "$temporary/original/"

first=$(sh "$helper" "$temporary" "$patch_file")
second=$(sh "$helper" "$temporary" "$patch_file")
[ "$first" = applied ]
[ "$second" = already-applied ]
grep -Fx 'GO_VERSION = 1.26.8' "$temporary/package/go/go.mk" >/dev/null
[ "$(grep -c 'go1.26.8.*tar.gz$' "$temporary/package/go/go.hash")" = 7 ]
grep -Fx 'sha256  911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad  LICENSE' \
    "$temporary/package/go/go.hash" >/dev/null

fresh_case() {
    rm -rf -- "$temporary/case"
    mkdir -p "$temporary/case/package/go"
    cp "$temporary/original/go.mk" "$temporary/original/go.hash" "$temporary/case/package/go/"
}
snapshot() {
    (cd "$temporary/case" && {
        find . -printf '%y %p %l\n' | LC_ALL=C sort
        find . -type f -exec sha256sum -- {} + | LC_ALL=C sort
    })
}
refuse_without_changes() {
    before=$(snapshot)
    if sh "$helper" "$temporary/case" "$1" >/dev/null 2>&1; then
        echo "Go maintenance accepted an invalid case: $2" >&2
        exit 1
    fi
    [ "$before" = "$(snapshot)" ] || {
        echo "Go maintenance modified a refused case: $2" >&2
        exit 1
    }
}
for file in go.mk go.hash; do
    fresh_case
    cp "$temporary/package/go/$file" "$temporary/case/package/go/$file"
    refuse_without_changes "$patch_file" "mixed-$file"
    fresh_case
    printf '\nunknown bytes\n' >> "$temporary/case/package/go/$file"
    refuse_without_changes "$patch_file" "unknown-$file"
    fresh_case
    mv "$temporary/case/package/go/$file" "$temporary/case/package/go/$file.real"
    ln -s "$file.real" "$temporary/case/package/go/$file"
    refuse_without_changes "$patch_file" "symlink-$file"
    fresh_case
    rm "$temporary/case/package/go/$file"
    refuse_without_changes "$patch_file" "missing-$file"
done
fresh_case
mv "$temporary/case/package/go" "$temporary/case/package/go-real"
ln -s go-real "$temporary/case/package/go"
refuse_without_changes "$patch_file" symlink-package-directory
fresh_case
cp "$patch_file" "$temporary/unknown.patch"
printf '\nunknown patch bytes\n' >> "$temporary/unknown.patch"
refuse_without_changes "$temporary/unknown.patch" unknown-patch
ln -s "$patch_file" "$temporary/link.patch"
refuse_without_changes "$temporary/link.patch" symlink-patch
refuse_without_changes "$temporary/missing.patch" missing-patch
printf 'Buildroot Go maintenance coherent patch, idempotence and no-effect refusals passed\n'
