#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Differential boot on temporary image copies, never the supplied base image.
set -eu

base=${1:?usage: test-qemu-md-v10-init-mode.sh BASE GO_BINARY SOURCE DEBUGFS}
go_binary=${2:?pinned Go required}
source_dir=${3:?source directory required}
debugfs=${4:?pinned debugfs required}
scratch=$(mktemp -d /tmp/phantowd-init-mode.XXXXXX)
trap 'rm -f "$scratch/rootfs.ext2" "$scratch/zImage" "$scratch/versatile-pb.dtb" "$scratch/denied.log" "$scratch/allowed.log"; rmdir "$scratch"' EXIT

base_hash=$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')
for file in rootfs.ext2 zImage versatile-pb.dtb; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
    cp "$base/$file" "$scratch/$file"
done
# Model a Linux checkout of the historical 100644 Git entry. Root must not
# bypass the missing execute bits, even though the script itself is valid.
"$debugfs" -w -R 'set_inode_field /usr/lib/phantowd/qemu-md-v10-init.sh mode 0100644' "$scratch/rootfs.ext2" >/dev/null 2>&1
status=0
TMPDIR="$scratch" sh "$source_dir/support/qemu-md-v10-fixture.sh" \
    "$scratch" "$go_binary" "$source_dir" "$scratch/denied.log" || status=$?
[ "$status" -eq 1 ]
grep -F 'error -13' "$scratch/denied.log" >/dev/null
grep -F 'Kernel panic' "$scratch/denied.log" >/dev/null
echo 'PHANTOWD_INIT_MODE_DENIED mode=0644 errno=EACCES guest_panic=true'

# Change only the inode mode: identical kernel, script and userspace.
"$debugfs" -w -R 'set_inode_field /usr/lib/phantowd/qemu-md-v10-init.sh mode 0100755' "$scratch/rootfs.ext2" >/dev/null 2>&1
TMPDIR="$scratch" sh "$source_dir/support/qemu-md-v10-fixture.sh" \
    "$scratch" "$go_binary" "$source_dir" "$scratch/allowed.log"
grep -F 'PHANTOWD_MD_V10_M34_OWNER_READY' "$scratch/allowed.log" >/dev/null
[ "$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')" = "$base_hash" ]
echo 'PHANTOWD_INIT_MODE_ALLOWED mode=0755 md_v10_owner=true base_unchanged=true'
