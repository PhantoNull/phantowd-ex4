#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Execute parser and fake-backend coordinator tests in one disposable ARMv5 boot.
set -eu
base=${1:?BASE GO DEBUGFS SOURCE}
go_binary=${2:?pinned Go required}
debugfs=${3:?pinned debugfs required}
source_dir=${4:?source required}
failure_log=${5:-}
tmpdir=${TMPDIR:-/tmp}
export TMPDIR="$tmpdir"
case "$base:$go_binary:$debugfs:$source_dir:$tmpdir:$failure_log" in
    *[!a-zA-Z0-9_./:-]*) exit 1 ;;
esac
case "$tmpdir" in /*) ;; *) exit 1 ;; esac
resolved_tmpdir=$(realpath -e "$tmpdir") || exit 1
[ "$resolved_tmpdir" = "$tmpdir" ] || exit 1
awk -v target="$tmpdir" '$3 == "tmpfs" && (target == $2 || index(target, $2 "/") == 1) { found = 1 } END { exit !found }' /proc/mounts || exit 1
for file in rootfs.ext2 zImage versatile-pb.dtb SHA256SUMS; do
    [ -f "$base/$file" ] && [ ! -L "$base/$file" ] || exit 1
done
scratch=$(mktemp -d "$tmpdir/phantowd-smart-report.XXXXXX")
child_pid=
cleanup() {
    if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    # All targets belong to this exact newly-created tmpfs directory.
    rm -f "$scratch/rootfs.ext2" "$scratch/report.test" "$scratch/collector.test" "$scratch/guest.log"
    rm -rf "$scratch/go-cache" "$scratch/go-path"
    rmdir "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
(cd "$base" && sha256sum -c SHA256SUMS)
base_hash=$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')
export GOPROXY=off GOTOOLCHAIN=local GOFLAGS='-mod=vendor -buildvcs=false -p=2' GOMAXPROCS=2
export GOCACHE="$scratch/go-cache" GOPATH="$scratch/go-path"
(cd "$source_dir/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    "$go_binary" test -c -trimpath -o "$scratch/report.test" ./internal/smartreport)
(cd "$source_dir/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    "$go_binary" test -c -trimpath -o "$scratch/collector.test" ./internal/smartcollect)
rm -rf "$scratch/go-cache" "$scratch/go-path"
cp "$base/rootfs.ext2" "$scratch/rootfs.ext2"
for pair in "$scratch/report.test phantowd-smart-report-test" \
    "$scratch/collector.test phantowd-smart-collector-test" \
    "$source_dir/support/tests/smart-report-init.sh phantowd-smart-report-init"; do
    input=${pair%% *}
    output=${pair#* }
    "$debugfs" -w -R "write $input /usr/sbin/$output" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output mode 0100755" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output uid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
    "$debugfs" -w -R "set_inode_field /usr/sbin/$output gid 0" "$scratch/rootfs.ext2" >/dev/null 2>&1
done
timeout --signal=TERM --kill-after=5 90 qemu-system-arm \
    -M versatilepb -cpu arm926 -m 256M -nographic -no-reboot -nic none \
    -kernel "$base/zImage" -dtb "$base/versatile-pb.dtb" \
    -append 'console=ttyAMA0 root=/dev/sda rootwait ro panic=-1 init=/usr/sbin/phantowd-smart-report-init' \
    -drive "file=$scratch/rootfs.ext2,format=raw,if=scsi,snapshot=on" \
    >"$scratch/guest.log" 2>&1 &
child_pid=$!
status=0
wait "$child_pid" || status=$?
child_pid=
# The guest serial console emits CRLF; allow only that optional trailing CR.
cr=$(printf '\r')
if [ "$status" -ne 0 ] || \
    ! grep -E "^PHANTOWD_SMART_REPORT_TESTS_READY scope=synthetic-parser-only${cr}?$" "$scratch/guest.log" >/dev/null || \
    ! grep -E "^PHANTOWD_SMART_COLLECTOR_TESTS_READY scope=trusted-backend-fake-only${cr}?$" "$scratch/guest.log" >/dev/null; then
    printf 'PHANTOWD_SMART_REPORT_RUNNER_FAILED exit=%s\n' "$status" >&2
    if [ -n "$failure_log" ]; then
        mkdir -p "$(dirname "$failure_log")"
        cp "$scratch/guest.log" "$failure_log"
    fi
    tail -n 100 "$scratch/guest.log" >&2
    exit 1
fi
grep -E "^PASS${cr}?$" "$scratch/guest.log" >/dev/null
grep -E '^--- PASS: (TestATAExitBitsAndAssessment|TestUnobservedAndUnsupportedStates|TestRejectInvalidAndAmbiguousReports|TestRedactionAndInputNotRetained|FuzzParse) ' "$scratch/guest.log"
grep -F PHANTOWD_SMART_REPORT_TESTS_READY "$scratch/guest.log"
grep -E '^--- PASS: (TestFixedSourceAndSampleSemantics|TestEveryBindingChangeBeforeOrAfterCaptureRefuses|TestUnsettledCaptureRetainsReferenceUntilExplicitVerification|TestCancellationNeverPublishesAndStillVerifiesOwnership|FuzzPublicationRequiresAdmittedSourceAndOrdinaryExit) ' "$scratch/guest.log"
grep -F PHANTOWD_SMART_COLLECTOR_TESTS_READY "$scratch/guest.log"
[ "$(sha256sum "$base/rootfs.ext2" | awk '{print $1}')" = "$base_hash" ]
echo 'PHANTOWD_SMART_REPORT_BASE_UNCHANGED'
