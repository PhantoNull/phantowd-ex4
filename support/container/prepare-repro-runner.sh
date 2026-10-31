#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Only the disposable hosted clean-build job may remove unused host SDKs.
set -eu
if [ "$#" -ne 0 ]; then
    echo '::error::PHANTOWD_REPRO_DISK_REFUSED reason=unexpected-arguments' >&2
    exit 2
fi
if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
    echo '::error::PHANTOWD_REPRO_DISK_REFUSED reason=not-github-hosted' >&2
    exit 2
fi
if [ "${RUNNER_OS:-}" != Linux ] || [ "${RUNNER_ARCH:-}" != X64 ] || \
    [ "${ImageOS:-}" != ubuntu24 ] || [ "${RUNNER_TOOL_CACHE:-}" != /opt/hostedtoolcache ]; then
    echo '::error::PHANTOWD_REPRO_DISK_REFUSED reason=unsupported-host' >&2
    exit 2
fi
if ! status=$(git -C "${GITHUB_WORKSPACE:?}" status --porcelain --untracked-files=all); then
    echo '::error::PHANTOWD_REPRO_DISK_REFUSED reason=worktree-unavailable' >&2
    exit 2
fi
if [ -n "$status" ]; then
    echo '::error::PHANTOWD_REPRO_DISK_REFUSED reason=dirty-worktree' >&2
    exit 2
fi
if ! docker_root=$(docker info --format '{{.DockerRootDir}}'); then
    echo '::error::PHANTOWD_REPRO_DISK_FAILED reason=docker-root-unavailable' >&2
    exit 1
fi
case "$docker_root" in
    /*) ;;
    *) echo '::error::PHANTOWD_REPRO_DISK_FAILED reason=docker-root-unavailable' >&2; exit 1 ;;
esac
required_kib=41943040 # Existing local full-build admission policy: 40 GiB.
available_kib() {
    if ! report=$(df -Pk "${GITHUB_WORKSPACE:?}" "$docker_root"); then
        echo '::error::PHANTOWD_REPRO_DISK_FAILED reason=disk-probe-failed' >&2
        return 1
    fi
    printf '%s\n' "$report" >&2
    if ! available=$(printf '%s\n' "$report" | awk '
        NR > 1 {
            if ($4 !~ /^[0-9]+$/ || length($4) > 12) { bad=1; exit }
            n++; if (n == 1 || $4 < least) least=$4
        }
        END { if (bad || n != 2) exit 1; printf "%.0f\n", least }'); then
        echo '::error::PHANTOWD_REPRO_DISK_FAILED reason=invalid-disk-metric' >&2
        return 1
    fi
    printf '%s\n' "$available"
}
available=$(available_kib)
if [ "$available" -ge "$required_kib" ]; then
    printf 'PHANTOWD_REPRO_DISK_READY available_kib=%s required_kib=%s cleanup=none\n' \
        "$available" "$required_kib"
    exit 0
fi
printf 'PHANTOWD_REPRO_DISK_PREPARE available_kib=%s required_kib=%s\n' \
    "$available" "$required_kib"
if ! sudo -n rm -rf -- /usr/share/dotnet /usr/local/lib/android /opt/hostedtoolcache; then
    echo '::error::PHANTOWD_REPRO_DISK_FAILED reason=cleanup-failed' >&2
    exit 1
fi
available=$(available_kib)
if [ "$available" -lt "$required_kib" ]; then
    echo '::error::PHANTOWD_REPRO_DISK_FAILED reason=insufficient-space' >&2
    exit 1
fi
printf 'PHANTOWD_REPRO_DISK_READY available_kib=%s required_kib=%s cleanup=performed\n' \
    "$available" "$required_kib"
