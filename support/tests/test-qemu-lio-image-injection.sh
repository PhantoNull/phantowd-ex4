#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Real image injection, fake guest/validator: no kernel compile or guest boot.
set -eu
source_dir=${1:?source checkout required}
scratch=${TMPDIR:-/tmp}
tmpfs() {
    awk -v target="$1" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found=1 } END { exit !found }' /proc/mounts
}
if ! tmpfs "$scratch"; then scratch=/dev/shm; fi
tmpfs "$scratch"
work=$(mktemp -d "$scratch/phantowd-lio-injection.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir "$work/base" "$work/bin"
truncate -s 12M "$work/base/rootfs.ext2"
mkfs.ext2 -q -F -b 1024 "$work/base/rootfs.ext2"
# Nonzero blocks: debugfs sparsifies all-zero input and would hide exhaustion.
dd if=/dev/zero bs=1M count=8 2>/dev/null | tr '\000' '\377' > "$work/old-api"
cp "$work/old-api" "$work/new-api"
printf 'new-fixture-api' | dd of="$work/new-api" conv=notrunc 2>/dev/null
printf 'client\n' > "$work/client"
printf 'kernel\n' > "$work/kernel"
printf 'dtb\n' > "$work/dtb"
for dir in /usr /usr/bin /usr/libexec; do
    debugfs -w -R "mkdir $dir" "$work/base/rootfs.ext2" >/dev/null 2>&1
done
debugfs -w -R "write $work/old-api /usr/bin/phantowd-api" "$work/base/rootfs.ext2" >/dev/null 2>&1
debugfs -R "dump /usr/bin/phantowd-api $work/check" "$work/base/rootfs.ext2" >/dev/null 2>&1
cmp "$work/old-api" "$work/check"
rm "$work/check"
free_blocks=$(debugfs -R stats "$work/base/rootfs.ext2" 2>/dev/null | awk '/^Free blocks:/ { print $3 }')
[ -n "$free_blocks" ] && [ "$free_blocks" -lt 8192 ]
(cd "$work/base" && sha256sum rootfs.ext2 > SHA256SUMS)
cat > "$work/bin/qemu-system-arm" <<'STUB'
#!/bin/sh
set -eu
image=
for argument in "$@"; do
    case "$argument" in file=*,if=none,id=rootdisk,*) image=${argument#file=}; image=${image%%,*} ;; esac
done
[ -n "$image" ]
debugfs -R "dump /usr/bin/phantowd-api $LIO_IMAGE_TEST_WORK/check" "$image" >/dev/null 2>&1
cmp "$LIO_IMAGE_TEST_WORK/new-api" "$LIO_IMAGE_TEST_WORK/check"
rm "$LIO_IMAGE_TEST_WORK/check"
debugfs -R "dump /usr/libexec/phantowd-lio-fixture-init $LIO_IMAGE_TEST_WORK/init" "$image" >/dev/null 2>&1
grep -F '/usr/bin/phantowd-api -qemu-lio-credential-test' "$LIO_IMAGE_TEST_WORK/init" >/dev/null
grep -F '/usr/bin/phantowd-api -qemu-lio-target-test' "$LIO_IMAGE_TEST_WORK/init" >/dev/null
printf '%s\n' 'IMAGE_INJECTION_VERIFIED_NO_GUEST_BOOT'
STUB
cat > "$work/bin/python3" <<'STUB'
#!/bin/sh
set -eu
[ "$1" = -B ]
shift
[ "$#" = 2 ]
case "$1" in */support/container/qemu_lio_result.py) ;; *) exit 1 ;; esac
grep -Fx 'IMAGE_INJECTION_VERIFIED_NO_GUEST_BOOT' "$2" >/dev/null
STUB
chmod 0755 "$work/bin/qemu-system-arm" "$work/bin/python3"
status=0
PATH="$work/bin:$PATH" TMPDIR="$scratch" LIO_IMAGE_TEST_WORK="$work" \
    PHANTOWD_LIO_REQUIRE_MUTUAL=0 PHANTOWD_LIO_IDLE_GUARD=0 \
    sh "$source_dir/support/qemu-lio-fixture.sh" "$work/base" "$work/kernel" "$work/dtb" \
    "$work/client" "$source_dir" "$work/serial.log" "$work/new-api" > "$work/runner.log" 2>&1 || status=$?
if [ "$status" != 0 ]; then tail -20 "$work/runner.log" >&2; exit "$status"; fi
(cd "$work/base" && sha256sum -c SHA256SUMS)
printf '%s\n' 'LIO image replacement regression passed; actual injection verified, guest and validator stubbed.'
