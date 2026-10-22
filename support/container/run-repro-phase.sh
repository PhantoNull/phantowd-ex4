#!/bin/sh
# Independent clean-build diagnostics only; budgets are ceilings, not retries.
set -eu
[ "$#" -eq 3 ] || { echo 'Expected phase, image and isolated volume' >&2; exit 2; }
phase=$1
case "$phase" in
    toolchain) seconds=2400 ;;
    kernel) seconds=1200 ;;
    userspace) seconds=3600 ;;
    rootfs) seconds=900 ;;
    boot) seconds=2700 ;;
    *) echo "Unknown independent-build phase: $phase" >&2; exit 2 ;;
esac
started=$(date +%s)
printf 'PHANTOWD_REPRO_PHASE_START phase=%s budget_seconds=%s\n' "$phase" "$seconds"
if docker run --rm \
    --tmpfs /phantowd-qemu-fixture-tmp:rw,exec,nosuid,nodev,size=512m \
    --mount type=bind,source="$PWD",target=/external \
    --mount type=volume,source="$3",target=/workspace \
    --env "PHANTOWD_REPRO_PHASE=$phase" \
    "$2" timeout --signal=TERM --kill-after=10 "$seconds" \
    /external/support/container/build-qemu.sh; then
    printf 'PHANTOWD_REPRO_PHASE_DONE phase=%s elapsed_seconds=%s\n' \
        "$phase" "$(($(date +%s) - started))"
else
    status=$?
    printf '::error::PHANTOWD_REPRO_PHASE_FAILED phase=%s status=%s elapsed_seconds=%s budget_seconds=%s\n' \
        "$phase" "$status" "$(($(date +%s) - started))" "$seconds" >&2
    exit "$status"
fi
