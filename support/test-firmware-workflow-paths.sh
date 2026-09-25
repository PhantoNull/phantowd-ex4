#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
qemu_workflow="$repo_root/.github/workflows/qemu-armv5.yml"
stage_b_workflow="$repo_root/.github/workflows/ex4-stage-b.yml"
stage_b2_workflow="$repo_root/.github/workflows/ex4-stage-b2.yml"
host_workflow="$repo_root/.github/workflows/host-tools.yml"

require_event_path() {
    workflow=$1
    event=$2
    path=$3
    if ! awk -v event="$event" -v path="$path" '
        $0 == "  " event ":" { in_event = 1; next }
        /^  [a-z_]+:/ { in_event = 0 }
        in_event && $0 == "      - \047" path "\047" { found = 1 }
        END { exit !found }
    ' "$workflow"; then
        printf 'workflow %s must list path %s under %s\n' "$workflow" "$path" "$event" >&2
        exit 1
    fi
}

require_ignored_path() {
    workflow=$1
    path=$2
    require_event_path "$workflow" push "$path"
    require_event_path "$workflow" pull_request "$path"
}

require_triggered_path() {
    workflow=$1
    path=$2
    require_event_path "$workflow" push "$path"
    require_event_path "$workflow" pull_request "$path"
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
support/test-firmware-workflow-paths.sh
.github/workflows/host-tools.yml
'
documentation_paths='
**/*.md
doc/**
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
    while IFS= read -r path; do
        [ -n "$path" ] && require_ignored_path "$workflow" "$path"
    done <<EOF
$documentation_paths
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

while IFS= read -r path; do
    [ -n "$path" ] && require_triggered_path "$host_workflow" "$path"
done <<EOF
$host_tool_paths
EOF
require_manual_dispatch "$host_workflow"

if grep -F "      - 'src/phantowd-api/**'" "$qemu_workflow" >/dev/null; then
    printf 'QEMU workflow must still run for API changes\n' >&2
    exit 1
fi

printf 'Firmware workflow path-contract tests passed\n'
