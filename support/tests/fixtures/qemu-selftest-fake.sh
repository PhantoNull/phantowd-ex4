#!/bin/sh
set -eu

[ "$#" -eq 1 ] && [ "$1" = '--self-test' ] || exit 2
printf 'called\n' >>"$QEMU_SELFTEST_CALLS"
if [ "${QEMU_SELFTEST_RESULT:-failure}" = success ]; then
    printf 'PHANTOWD_QEMU_FAKE_SELFTEST_READY\n'
    exit 0
fi
printf 'PHANTOWD_API_ERROR invalid storage response status=503 path=/dev/sda\n' >&2
exit 1
