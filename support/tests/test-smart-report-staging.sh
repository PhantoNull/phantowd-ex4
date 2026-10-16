#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Real debugfs allocation failure must refuse at staging, never at guest boot.
set -eu
[ "$#" -eq 2 ] || exit 1
debugfs=$1 source_dir=$2
tmpdir=${TMPDIR:-/tmp}
case "$tmpdir" in /*) ;; *) exit 1 ;; esac
case "$tmpdir" in *[!a-zA-Z0-9_./-]*) exit 1 ;; esac
tmpdir=$(CDPATH='' cd -P "$tmpdir" && pwd -P) || exit 1
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || exit 1
scratch=$(mktemp -d "$tmpdir/phantowd-smart-stage-test.XXXXXX")
cleanup() {
    rm -f "$scratch/base/rootfs.ext2" "$scratch/base/zImage" \
        "$scratch/base/versatile-pb.dtb" "$scratch/base/SHA256SUMS" \
        "$scratch/bin/go" "$scratch/bin/qemu-system-arm" \
        "$scratch/guest-started" "$scratch/runner.log" \
        "$scratch/direct.ext2" "$scratch/input" "$scratch/check"
    rmdir "$scratch/base" "$scratch/bin" "$scratch"
}
trap cleanup EXIT
mkdir "$scratch/base" "$scratch/bin"
truncate -s 4M "$scratch/base/rootfs.ext2"
"$(dirname "$debugfs")/mke2fs" -q -F -t ext2 "$scratch/base/rootfs.ext2"
"$debugfs" -w -R 'mkdir /usr' "$scratch/base/rootfs.ext2" >/dev/null 2>&1
"$debugfs" -w -R 'mkdir /usr/sbin' "$scratch/base/rootfs.ext2" >/dev/null 2>&1
cp "$scratch/base/rootfs.ext2" "$scratch/direct.ext2"
truncate -s 64K "$scratch/input"
for name in phantowd-smart-report-test phantowd-smart-collector-test phantowd-smart-report-init; do
    sh "$source_dir/support/tests/stage-smart-report-file.sh" "$debugfs" \
        "$scratch/direct.ext2" "$scratch/input" "/usr/sbin/$name" "$scratch/check"
done
printf 'changed' >"$scratch/input"
if sh "$source_dir/support/tests/stage-smart-report-file.sh" "$debugfs" \
    "$scratch/direct.ext2" "$scratch/input" /usr/sbin/phantowd-smart-report-init "$scratch/check"; then
    echo 'SMART staging accepted stale existing bytes' >&2
    exit 1
fi
if sh "$source_dir/support/tests/stage-smart-report-file.sh" "$debugfs" \
    "$scratch/direct.ext2" "$scratch/input" /usr/sbin/foreign "$scratch/check"; then
    echo 'SMART staging accepted an undeclared destination' >&2
    exit 1
fi
printf 'host-fixture-only' >"$scratch/base/zImage"
printf 'host-fixture-only' >"$scratch/base/versatile-pb.dtb"
(cd "$scratch/base" && sha256sum rootfs.ext2 zImage versatile-pb.dtb >SHA256SUMS)
base_hash=$(sha256sum "$scratch/base/rootfs.ext2" | awk '{print $1}')
cat >"$scratch/bin/go" <<'FIXTURE'
#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ]; then shift; output=$1; break; fi
    shift
done
case "${output##*/}" in
    report.test) dd if=/dev/zero bs=1048576 count=129 2>/dev/null | tr '\000' x >"$output" ;;
    collector.test) printf 'synthetic non-executable payload' >"$output" ;;
    *) exit 1 ;;
esac
FIXTURE
cat >"$scratch/bin/qemu-system-arm" <<'FIXTURE'
#!/bin/sh
printf 'guest-must-not-start' >"$PHANTOWD_SMART_STAGE_GUEST_MARKER"
exit 0
FIXTURE
chmod 700 "$scratch/bin/go" "$scratch/bin/qemu-system-arm"
status=0
PATH="$scratch/bin:$PATH" TMPDIR="$tmpdir" \
    PHANTOWD_SMART_STAGE_GUEST_MARKER="$scratch/guest-started" \
    sh "$source_dir/support/tests/test-qemu-smart-report.sh" \
    "$scratch/base" "$scratch/bin/go" "$debugfs" "$source_dir" \
    >"$scratch/runner.log" 2>&1 || status=$?
[ "$status" -ne 0 ] || { echo 'Incomplete SMART image accepted' >&2; exit 1; }
if [ -e "$scratch/guest-started" ]; then
    echo 'Incomplete SMART staging reached QEMU' >&2
    exit 1
fi
grep -Fx 'PHANTOWD_SMART_REPORT_STAGING_FAILED exact_bytes_or_metadata=false' "$scratch/runner.log" >/dev/null
[ "$(sha256sum "$scratch/base/rootfs.ext2" | awk '{print $1}')" = "$base_hash" ]
echo 'PHANTOWD_SMART_REPORT_STAGING_TEST_READY exact_copy=true stale_bytes_refused=true undeclared_refused=true exhausted_image_refused=true before_guest=true base_unchanged=true scope=host-tmpfs-only'
