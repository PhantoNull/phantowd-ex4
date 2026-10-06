#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
helper="$repo_root/board/qemu/armv5/rootfs-overlay/usr/lib/phantowd/qemu-selftest-once.sh"
fake="$repo_root/support/tests/fixtures/qemu-selftest-fake.sh"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/phantowd-qemu-selftest-test.XXXXXX")
trap 'rm -f "$temporary/stdout" "$temporary/stderr" "$temporary/calls"; rmdir "$temporary"' EXIT HUP INT TERM

fail() {
    echo "$1" >&2
    exit 1
}

[ -f "$helper" ] || fail 'missing one-shot QEMU API self-test helper'
export QEMU_SELFTEST_CALLS="$temporary/calls"
if sh "$helper" "$fake" "$temporary/stderr" >"$temporary/stdout"; then
    fail 'one-shot helper accepted a failing QEMU self-test'
fi
[ "$(wc -l <"$temporary/calls")" -eq 1 ] || fail 'QEMU self-test helper did not run exactly once'
grep -F 'PHANTOWD_QEMU_API_SELFTEST_FAILURE detail=PHANTOWD_API_ERROR invalid storage response status?503 path??dev?sda' \
    "$temporary/stdout" >/dev/null || fail 'QEMU self-test helper did not preserve the first bounded failure'
if grep -F '/dev/sda' "$temporary/stdout" >/dev/null; then
    fail 'QEMU self-test helper leaked an unredacted device path'
fi
[ ! -e "$temporary/stderr" ] || fail 'QEMU self-test helper left its error file behind'

: >"$temporary/calls"
QEMU_SELFTEST_RESULT=success sh "$helper" "$fake" "$temporary/stderr" >"$temporary/stdout" ||
    fail 'one-shot helper rejected a passing QEMU self-test'
[ "$(wc -l <"$temporary/calls")" -eq 1 ] || fail 'passing QEMU self-test ran more than once'
grep -F 'PHANTOWD_QEMU_FAKE_SELFTEST_READY' "$temporary/stdout" >/dev/null ||
    fail 'one-shot helper suppressed the successful self-test output'
[ ! -e "$temporary/stderr" ] || fail 'successful QEMU self-test left its error file behind'

printf 'QEMU API self-test first-failure contract passed\n'
