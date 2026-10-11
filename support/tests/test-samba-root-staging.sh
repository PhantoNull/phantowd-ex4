#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Actual pinned debugfs writes, only to newly-created tmpfs regular images.
set -eu
[ "$#" -eq 2 ] || exit 1
debugfs=$1 source_dir=$2
awk '$2 == "/tmp" && $3 == "tmpfs" { found = 1 } END { exit !found }' /proc/mounts || exit 1
scratch=$(mktemp -d /tmp/phantowd-samba-staging.XXXXXX)
trap 'rm -f "$scratch/image.ext2" "$scratch/input" "$scratch/check"; rmdir "$scratch"' EXIT
stage="$source_dir/support/tests/stage-samba-root-file.sh"
truncate -s 4M "$scratch/image.ext2"
"$(dirname "$debugfs")/mke2fs" -q -F -t ext2 "$scratch/image.ext2"
"$debugfs" -w -R 'mkdir /usr' "$scratch/image.ext2" >/dev/null 2>&1
"$debugfs" -w -R 'mkdir /usr/sbin' "$scratch/image.ext2" >/dev/null 2>&1
truncate -s 64K "$scratch/input"
for destination in phantowd-samba-root-init phantowd-runtime-metadata-tests phantowd-runtime-owner-init; do
    sh "$stage" "$debugfs" "$scratch/image.ext2" "$scratch/input" \
        "/usr/sbin/$destination" "$scratch/check" 0100755
done
printf 'changed' >"$scratch/input"
if sh "$stage" "$debugfs" "$scratch/image.ext2" "$scratch/input" \
    /usr/sbin/phantowd-samba-root-init "$scratch/check" 0100755; then
    echo 'Samba staging accepted stale existing bytes' >&2
    exit 1
fi
# debugfs can report allocation failure while returning zero. An incomplete
# oversized file must refuse at the real staging boundary, not at guest boot.
# Nonzero data must consume blocks; sparse all-zero input is not exhaustion.
dd if=/dev/zero bs=1048576 count=5 2>/dev/null | tr '\000' x >"$scratch/input"
if sh "$stage" "$debugfs" "$scratch/image.ext2" "$scratch/input" \
    /usr/sbin/phantowd-samba-owner-probe "$scratch/check" 0100755; then
    echo 'Samba staging accepted an incomplete image file' >&2
    exit 1
fi
echo 'PHANTOWD_SAMBA_STAGING_TEST_READY exact_copy=true stale_bytes_refused=true exhausted_image_refused=true scope=host-tmpfs-only'
