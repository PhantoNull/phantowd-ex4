#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -euo pipefail

buildroot=${1:?usage: test-buildroot-download-patch.sh BUILDROOT_SOURCE}
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
patch_file="$repo/support/buildroot-patches/2025.02.18/0003-download-remove-archive-temporary-marker.patch"
applier="$repo/support/container/apply-buildroot-download-cleanup.sh"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-download-patch.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 1' HUP INT TERM
mkdir -p "$scratch/tree/support/download" "$scratch/original" \
    "$scratch/input" "$scratch/cwd" "$scratch/output"
helper="$scratch/tree/support/download/helpers"
cp "$buildroot/support/download/helpers" "$helper"
# The persistent cache may already contain the qualified one-line patch.
digest=$(sha256sum "$helper")
if [[ "${digest%% *}" == c6245bb5e1899a485ce5c13fa29b8f29e5bbf99e1cc15f22f05d997ec524db47 ]]; then
    patch --directory "$scratch/tree" --strip=1 --fuzz=0 --reverse --batch \
        --no-backup-if-mismatch <"$patch_file" >/dev/null
fi
digest=$(sha256sum "$helper")
[[ "${digest%% *}" == 2a2e6190b448ee6bb2881811a6f4785ff790ebb37291c933115a9a6eb314f75b ]]
cp "$helper" "$scratch/original/helpers"
[[ "$(sh "$applier" "$scratch/tree" "$patch_file")" == applied ]]
after=$(sha256sum "$helper")
[[ "$(sh "$applier" "$scratch/tree" "$patch_file")" == already-applied ]]
[[ "$(sha256sum "$helper")" == "$after" ]]
[[ "$(find "$scratch/tree" -type f -printf '%P\n')" == support/download/helpers ]]
bash "$repo/support/tests/test-buildroot-download-cleanup.sh" "$helper"
# Byte-for-byte differential with the actual unmodified upstream producer.
printf 'same archive input\n' >"$scratch/input/file"
for variant in original patched; do
    selected="$helper"
    [[ "$variant" != original ]] || selected="$scratch/original/helpers"
    (
        cd "$scratch/cwd"
        # shellcheck disable=SC1090
        source "$selected"
        export TAR=tar
        mk_tar_gz "$scratch/input" 'fixture-1.0' \
            '1970-01-01T00:00:00Z' "$scratch/output/$variant.tar.gz"
    )
done
cmp "$scratch/output/original.tar.gz" "$scratch/output/patched.tar.gz"
# Original producer residue is owned by this tmpfs fixture and trap, not by
# the applier. Unknown/missing/aliased inputs must fail without mutation.
printf '\n# unknown helper modification\n' >>"$helper"
unknown=$(sha256sum "$helper")
if sh "$applier" "$scratch/tree" "$patch_file" >/dev/null 2>&1; then exit 1; fi
[[ "$(sha256sum "$helper")" == "$unknown" ]]
cp "$scratch/original/helpers" "$helper"
original=$(sha256sum "$helper")
cp "$patch_file" "$scratch/modified.patch"
printf '\n# changed patch\n' >>"$scratch/modified.patch"
if sh "$applier" "$scratch/tree" "$scratch/modified.patch" >/dev/null 2>&1; then exit 1; fi
[[ "$(sha256sum "$helper")" == "$original" ]]
ln -s "$patch_file" "$scratch/alias.patch"
if sh "$applier" "$scratch/tree" "$scratch/alias.patch" >/dev/null 2>&1; then exit 1; fi
[[ "$(sha256sum "$helper")" == "$original" ]]
mv "$helper" "$scratch/retained-helper"
ln -s "$scratch/retained-helper" "$helper"
if sh "$applier" "$scratch/tree" "$patch_file" >/dev/null 2>&1; then exit 1; fi
[[ "$(sha256sum "$scratch/retained-helper")" == "${original%% *}  $scratch/retained-helper" ]]
rm "$helper"
if sh "$applier" "$scratch/tree" "$patch_file" >/dev/null 2>&1; then exit 1; fi
cp "$scratch/retained-helper" "$helper"
mv "$scratch/tree/support/download" "$scratch/retained-download"
ln -s "$scratch/retained-download" "$scratch/tree/support/download"
if sh "$applier" "$scratch/tree" "$patch_file" >/dev/null 2>&1; then exit 1; fi
[[ "$(sha256sum "$scratch/retained-download/helpers")" == "${original%% *}  $scratch/retained-download/helpers" ]]
printf 'Buildroot archive patch idempotence, unchanged archive bytes and refusals passed\n'
