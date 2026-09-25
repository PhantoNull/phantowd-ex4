#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
qemu_workflow="$repo_root/.github/workflows/qemu-armv5.yml"
stage_b_workflow="$repo_root/.github/workflows/ex4-stage-b.yml"
stage_b2_workflow="$repo_root/.github/workflows/ex4-stage-b2.yml"

require_ignored_path() {
    workflow=$1
    path=$2
    if ! grep -F "      - '$path'" "$workflow" >/dev/null; then
        printf 'workflow %s must ignore unrelated path %s\n' "$workflow" "$path" >&2
        exit 1
    fi
}

require_manual_dispatch() {
    workflow=$1
    if ! grep -F '  workflow_dispatch:' "$workflow" >/dev/null; then
        printf 'workflow %s must retain manual dispatch\n' "$workflow" >&2
        exit 1
    fi
}

host_tool_paths='
tools/phantowd-lab/**
support/test-lab-tools.ps1
support/container/test-lab-tools.sh
'
api_and_qemu_paths='
src/phantowd-api/**
package/phantowd-api/**
board/qemu/armv5/**
configs/phantowd_qemu_armv5_defconfig
support/container/test-api.sh
support/qemu-smoke.sh
support/test-api.ps1
support/test-dashboard-ui.mjs
support/dashboard-preview.mjs
'

for workflow in "$qemu_workflow" "$stage_b_workflow" "$stage_b2_workflow"; do
    while IFS= read -r path; do
        [ -n "$path" ] && require_ignored_path "$workflow" "$path"
    done <<EOF
$host_tool_paths
EOF
    require_manual_dispatch "$workflow"
done

for workflow in "$stage_b_workflow" "$stage_b2_workflow"; do
    while IFS= read -r path; do
        [ -n "$path" ] && require_ignored_path "$workflow" "$path"
    done <<EOF
$api_and_qemu_paths
EOF
done

if grep -F "      - 'src/phantowd-api/**'" "$qemu_workflow" >/dev/null; then
    printf 'QEMU workflow must still run for API changes\n' >&2
    exit 1
fi

printf 'Firmware workflow path-contract tests passed\n'
