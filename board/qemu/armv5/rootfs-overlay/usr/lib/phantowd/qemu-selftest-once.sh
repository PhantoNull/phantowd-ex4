#!/bin/sh
set -eu

selftest=${1:?self-test executable required}
error_log=${2:?self-test error log required}

if "$selftest" --self-test 2>"$error_log"; then
    rm -f "$error_log"
    exit 0
else
    selftest_status=$?
fi
echo "PHANTOWD_QEMU_ERROR diagnostics-api-unavailable exit=$selftest_status"
error_summary="$(awk '
    index($0, "PHANTOWD_API_ERROR ") == 1 {
        gsub(/[^A-Za-z0-9 _-]/, "?")
        print substr($0, 1, 160)
        exit
    }
' "$error_log" 2>/dev/null || true)"
if [ -n "$error_summary" ]; then
    echo "PHANTOWD_QEMU_API_SELFTEST_FAILURE detail=$error_summary"
else
    echo 'PHANTOWD_QEMU_API_SELFTEST_FAILURE detail=no-error-marker'
fi
rm -f "$error_log"
exit 1
