#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
qemu_workflow="$repo_root/.github/workflows/qemu-armv5.yml"
stage_b_workflow="$repo_root/.github/workflows/ex4-stage-b.yml"
stage_b2_workflow="$repo_root/.github/workflows/ex4-stage-b2.yml"
stage_b3_workflow="$repo_root/.github/workflows/ex4-stage-b3.yml"
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

require_not_ignored_pattern() {
    workflow=$1
    event=$2
    pattern=$3
    if awk -v event="$event" -v pattern="$pattern" '
        $0 == "  " event ":" { in_event = 1; next }
        /^  [a-z_]+:/ { in_event = 0; in_ignore = 0 }
        in_event && $0 == "    paths-ignore:" { in_ignore = 1; next }
        in_event && in_ignore && /^    [a-z_]+:/ { in_ignore = 0 }
        in_event && in_ignore && $0 == "      - \047" pattern "\047" { found = 1 }
        END { exit !found }
    ' "$workflow"; then
        printf 'workflow %s must not ignore build input pattern %s under %s\n' \
            "$workflow" "$pattern" "$event" >&2
        exit 1
    fi
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

require_develop_push() {
    workflow=$1
    if ! grep -F '    branches: [main, develop]' "$workflow" >/dev/null; then
        printf 'workflow %s must validate both main and develop pushes\n' "$workflow" >&2
        exit 1
    fi
}

require_manual_only() {
    workflow=$1
    if grep -Eq '^  (push|pull_request):' "$workflow"; then
        printf 'workflow %s must not run automatically; keep it manual-only\n' \
            "$workflow" >&2
        exit 1
    fi
    require_manual_dispatch "$workflow"
}

host_tool_paths='
tools/phantowd-lab/**
support/test-lab-tools.ps1
support/container/test-lab-tools.sh
support/test-firmware-workflow-paths.sh
support/tests/test-ex4-stage-b-kernel-config-audit.sh
.github/workflows/qemu-armv5.yml
.github/workflows/ex4-stage-b.yml
.github/workflows/ex4-stage-b2.yml
.github/workflows/ex4-stage-b3.yml
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
qemu_unrelated_ex4_stage_paths='
board/wd/ex4/stage-b/**
board/wd/ex4/stage-b2/**
board/wd/ex4/stage-b3/**
support/container/build-ex4-stage-b2.sh
support/container/build-ex4-stage-b3.sh
support/container/audit-ex4-stage-b-kernel-config.sh
support/tests/test-ex4-stage-b-kernel-config-audit.sh
'

for workflow in "$qemu_workflow" "$stage_b3_workflow"; do
    require_develop_push "$workflow"
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

require_manual_only "$stage_b_workflow"
require_manual_only "$stage_b2_workflow"

for workflow in "$stage_b3_workflow"; do
    for event in push pull_request; do
        require_not_ignored_pattern \
            "$workflow" "$event" support/container/audit-ex4-stage-b-kernel-config.sh
    done
done

while IFS= read -r path; do
    [ -n "$path" ] && require_ignored_path "$qemu_workflow" "$path"
done <<EOF
$qemu_unrelated_ex4_stage_paths
EOF

require_develop_push "$host_workflow"

for workflow in "$stage_b3_workflow"; do
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
require_triggered_path \
    "$host_workflow" support/container/audit-ex4-stage-b-kernel-config.sh
require_manual_dispatch "$host_workflow"

stage_b3_build_inputs='
board/wd/ex4/stage-b3/**
board/wd/ex4/**
board/wd/**
board/**
configs/phantowd_ex4_stage_b3_defconfig
configs/**
support/container/build-ex4-stage-b3.sh
support/container/**
support/**
versions.env
**
'
for event in push pull_request; do
    while IFS= read -r pattern; do
        [ -n "$pattern" ] && require_not_ignored_pattern \
            "$stage_b3_workflow" "$event" "$pattern"
    done <<EOF
$stage_b3_build_inputs
EOF
done

if grep -F "      - 'src/phantowd-api/**'" "$qemu_workflow" >/dev/null; then
    printf 'QEMU workflow must still run for API changes\n' >&2
    exit 1
fi

printf 'Firmware workflow path-contract tests passed\n'
