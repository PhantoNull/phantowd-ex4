#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
qemu_workflow="$repo_root/.github/workflows/qemu-armv5.yml"
stage_a_workflow="$repo_root/.github/workflows/ex4-stage-a.yml"
stage_b_workflow="$repo_root/.github/workflows/ex4-stage-b.yml"
stage_b2_workflow="$repo_root/.github/workflows/ex4-stage-b2.yml"
stage_b3_workflow="$repo_root/.github/workflows/ex4-stage-b3.yml"
host_workflow="$repo_root/.github/workflows/host-tools.yml"
reproducibility_workflow="$repo_root/.github/workflows/reproducibility.yml"

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

require_pr_ready_for_review() {
    workflow=$1
    if ! awk '
        $0 == "  pull_request:" { in_event = 1; next }
        /^  [a-z_]+:/ { in_event = 0 }
        in_event && $0 == "    types: [opened, synchronize, reopened, ready_for_review]" {
            found = 1
        }
        END { exit !found }
    ' "$workflow"; then
        printf 'workflow %s must run when a draft PR becomes ready for review\n' \
            "$workflow" >&2
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

require_checkout_credentials_not_persisted() {
    workflow=$1
    if ! awk '
        function finish_step() {
            if (in_checkout) {
                checkouts++
                if (!disabled) bad = 1
            }
            in_checkout = 0
            disabled = 0
        }
        /^      - / { finish_step() }
        /^        uses: actions\/checkout@/ { in_checkout = 1 }
        in_checkout && /^          persist-credentials: false$/ { disabled = 1 }
        END {
            finish_step()
            if (checkouts == 0 || bad) exit 1
        }
    ' "$workflow"; then
        printf 'workflow %s must disable persisted checkout credentials\n' \
            "$workflow" >&2
        exit 1
    fi
}

require_bounded_qemu_ccache() {
    workflow=$1
    if ! grep -Fx 'BR2_CCACHE=y' \
        "$repo_root/configs/phantowd_qemu_armv5_defconfig" >/dev/null; then
        printf 'QEMU defconfig must enable Buildroot compiler caching\n' >&2
        exit 1
    fi
    if ! grep -Fx 'BR2_CCACHE_INITIAL_SETUP="--max-size=1G"' \
        "$repo_root/configs/phantowd_qemu_armv5_defconfig" >/dev/null; then
        printf 'QEMU compiler cache must have a bounded size\n' >&2
        exit 1
    fi
    if ! grep -F 'uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0' \
        "$workflow" >/dev/null ||
        ! grep -F 'uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0' \
        "$workflow" >/dev/null; then
        printf 'QEMU compiler-cache actions must be pinned to the reviewed revision\n' >&2
        exit 1
    fi
    if ! grep -F 'github.event_name == '\''push'\'' && github.ref == '\''refs/heads/develop'\''' \
        "$workflow" >/dev/null; then
        printf 'QEMU compiler-cache writes must be restricted to trusted develop pushes\n' >&2
        exit 1
    fi
    if ! grep -F -- "--mount type=bind,source=\"\$RUNNER_TEMP/phantowd-buildroot-ccache\",target=/ccache" \
        "$workflow" >/dev/null ||
        ! grep -F 'PHANTOWD_CCACHE_DIR=/ccache' "$workflow" >/dev/null; then
        printf 'QEMU build must mount the compiler cache into Buildroot\n' >&2
        exit 1
    fi
}

require_fixed_fuzz_campaigns() {
    script=$1
    expected_count=$2
    if grep -Eq -- '-fuzztime=[0-9]+(ns|us|ms|s|m|h)' "$script"; then
        printf 'fuzz campaigns in %s must use fixed execution counts, not wall time\n' \
            "$script" >&2
        exit 1
    fi
    actual_count=$(grep -Ec -- '-fuzztime=[1-9][0-9]*x' "$script" || true)
    if [ "$actual_count" -ne "$expected_count" ]; then
        printf 'expected %s fixed fuzz campaigns in %s; found %s\n' \
            "$expected_count" "$script" "$actual_count" >&2
        exit 1
    fi
}

# Execute the actual small workflow selector, not a second parser pretending
# to cover it. Fixtures never download a toolchain or source versions.env.
require_locked_host_go_sdk() {
    python3 - "$1" "$2" <<'PY'
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

workflow = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
pins = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
bash_executable = shutil.which("bash")
if bash_executable is None:
    raise SystemExit("host Go selector requires an installed Bash")
bash_executable = str(pathlib.Path(bash_executable).resolve(strict=True))
header = (
    r"^      - name: Select pinned host Go SDK\n"
    r"        id: host_go\n"
    r"        shell: bash\n"
    r"        run: \|\n"
    r"(?P<script>(?:          .*\n)+)"
)
selectors = list(re.finditer(header, workflow, re.MULTILINE))
if len(selectors) != 1:
    raise SystemExit("host CI must select exactly one Go SDK from versions.env")
selector = selectors[0]
script = "\n".join(line[10:] for line in selector["script"].splitlines()) + "\n"
locked_input = "          go-version: ${{ steps.host_go.outputs.version }}"
runtime_check = '          test "$(go env GOVERSION)" = "go${{ steps.host_go.outputs.version }}"'
if workflow.count(locked_input) != 1 or workflow.count(runtime_check) != 1:
    raise SystemExit("host CI must select and verify the exact locked Go SDK")
if re.search(r"^\s+go-version-file:", workflow, re.MULTILINE):
    raise SystemExit("module language minimum must not select the host compiler")
setup = workflow.find("        uses: actions/setup-go@")
if setup < selector.end() or workflow.count("        uses: actions/setup-go@") != 1:
    raise SystemExit("locked Go selection must precede the only setup-go step")
actual = re.findall(r"^GO_VERSION=([0-9]+\.[0-9]+\.[0-9]+)$", pins, re.MULTILINE)
if len(actual) != 1:
    raise SystemExit("versions.env requires one canonical Go pin")
cases = [
    ("current-lock", pins, actual[0]),
    ("synthetic-other-pin", "GO_VERSION=7.8.9\n", "7.8.9"),
    ("not-shell-code", "OTHER=$(touch pin-was-executed)\nGO_VERSION=1.2.3\n", "1.2.3"),
    ("missing", "OTHER=1\n", None),
    ("empty", "GO_VERSION=\n", None),
    ("duplicate", "GO_VERSION=1.2.3\nGO_VERSION=1.2.3\n", None),
    ("duplicate-empty-after", "GO_VERSION=1.2.3\nGO_VERSION=\n", None),
    ("duplicate-empty-before", "GO_VERSION=\nGO_VERSION=1.2.3\n", None),
    ("conflicting", "GO_VERSION=1.2.3\nGO_VERSION=4.5.6\n", None),
    ("no-patch", "GO_VERSION=1.2\n", None),
    ("quoted", 'GO_VERSION="1.2.3"\n', None),
    ("suffix", "GO_VERSION=1.2.3-extra\n", None),
    ("trailing-space", "GO_VERSION=1.2.3 \n", None),
    ("CRLF", "GO_VERSION=1.2.3\r\n", None),
    ("not-an-assignment", "GO_VERSION\n", None),
    ("payload", "GO_VERSION=1.2.3;touch pin-was-executed\n", None),
]
for name, contents, expected in cases:
    with tempfile.TemporaryDirectory(prefix="phantowd-host-go-pin-") as directory:
        root = pathlib.Path(directory)
        # Text mode rewrites this deliberately LF-versus-CRLF corpus on Windows.
        (root / "versions.env").write_bytes(contents.encode("utf-8"))
        if (root / "versions.env").read_bytes() != contents.encode("utf-8"):
            raise SystemExit(f"host Go selector fixture bytes changed: {name}")
        output = root / "github-output"
        environment = {"PATH": os.environ["PATH"], "LC_ALL": "C", "GITHUB_OUTPUT": str(output)}
        result = subprocess.run(
            [bash_executable, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
            cwd=root, env=environment, capture_output=True, timeout=5, check=False,
        )
        observed = output.read_bytes() if output.exists() else b""
        if (root / "pin-was-executed").exists():
            raise SystemExit(f"host Go selector executed pin data: {name}")
        if expected is not None:
            if result.returncode != 0 or observed != f"version={expected}\n".encode("ascii"):
                raise SystemExit(f"host Go selector refused a canonical fixture: {name}")
        elif result.returncode == 0 or observed:
            raise SystemExit(f"host Go selector accepted an unsafe fixture: {name}")
print(f"Locked host Go workflow selector passed {len(cases)} execution fixtures")
PY
}

host_tool_paths='
tools/phantowd-lab/**
support/test-lab-tools.ps1
support/test-dashboard-browser.mjs
support/tests/test-dashboard-preview.mjs
support/tests/test-iscsi-panel.mjs
support/tests/test-network-panel.mjs
src/phantowd-api/browser_fixture_test.go
src/phantowd-api/browser_policy_fixture_test.go
support/browser-resource-contract.mjs
support/browser-service-policy-flow.mjs
support/container/test-lab-tools.sh
support/build-qemu.ps1
support/clean-qemu-build-volumes.ps1
support/test-firmware-workflow-paths.sh
support/tests/test-ex4-stage-b-kernel-config-audit.sh
.github/workflows/qemu-armv5.yml
.github/workflows/ex4-stage-a.yml
.github/workflows/ex4-stage-b.yml
.github/workflows/ex4-stage-b2.yml
.github/workflows/ex4-stage-b3.yml
.github/workflows/host-tools.yml
'

# The optional local Linux API wrapper changes no firmware input. Validate its
# external command contract in cheap host CI without unrelated image builds.
for path in 'support/test-api-linux.ps1' 'support/tests/test-api-linux-wrapper.ps1'; do
    require_triggered_path "$host_workflow" "$path"
    require_ignored_path "$qemu_workflow" "$path"
    require_ignored_path "$stage_b3_workflow" "$path"
done

# Internal launcher tests must not rebuild EX4 research profiles, but must
# retain the one QEMU lane and cheap native host refusals.
for path in 'src/phantowd-service-launcher/**' \
    'support/test-service-launcher.ps1' \
    'support/tests/test-service-launcher.py' \
    'support/tests/test-qemu-service-launcher.sh' \
    'support/tests/service-launcher-fixture.c' \
    'support/tests/service-launcher-init.sh'; do
    require_triggered_path "$host_workflow" "$path"
    require_ignored_path "$stage_b3_workflow" "$path"
    require_not_ignored_pattern "$qemu_workflow" push "$path"
    require_not_ignored_pattern "$qemu_workflow" pull_request "$path"
done
# Runtime experiments and their QEMU kernel-input helper are not EX4 build
# inputs. Keep native refusals and ARMv5 integration without a redundant B3.
for path in 'support/test-runtime-loader.ps1' \
    'support/test-atomic-dispatch.ps1' \
    'support/tests/atomic-*' \
    'support/tests/atomic_dispatch_fixture.py' \
    'support/tests/test-atomic-dispatch-fixture.py' \
    'support/tests/test-qemu-atomic-dispatch.sh' \
    'support/test-runtime-owner.ps1' \
    'support/tests/runtime-owner-init.sh' \
    'support/tests/test-qemu-runtime-owner.sh' \
    'support/test-samba-root.ps1' \
    'support/tests/runtime_loader_fixture.py' \
    'support/tests/test-runtime-loader-fixture.py' \
    'support/tests/test-qemu-runtime-loader.sh' \
    'support/tests/samba-root-*' \
    'support/tests/samba-charset-fixture.c' \
    'support/tests/samba_root_fixture.py' \
    'support/tests/test-samba-root-fixture.py' \
    'support/tests/test-qemu-samba-root.sh' \
    'support/container/qemu_kernel_inputs.py' \
    'support/tests/test-qemu-kernel-inputs.py'; do
    require_triggered_path "$host_workflow" "$path"
    require_ignored_path "$stage_b3_workflow" "$path"
    require_not_ignored_pattern "$qemu_workflow" push "$path"
    require_not_ignored_pattern "$qemu_workflow" pull_request "$path"
done
documentation_paths='
**/*.md
doc/**
.github/assets/**
'
# Native synthetic SMART replay tests do not consume EX4 board build inputs.
# Keep their host/QEMU validation while avoiding unrelated B3 compilation.
for path in 'support/tests/test-smart-replay.sh' \
    'support/tests/test-smart-replay-boundaries.py' \
    'support/test-smart-report.ps1' \
    'support/tests/test-qemu-smart-report.sh' \
    'support/tests/smart-report-init.sh' \
    'support/tests/test-smart-replay-contract.py'; do
    require_ignored_path "$stage_b3_workflow" "$path"
    require_triggered_path "$host_workflow" "$path"
    require_not_ignored_pattern "$qemu_workflow" push "$path"
    require_not_ignored_pattern "$qemu_workflow" pull_request "$path"
done

# Generic-producer replay is a disposable QEMU userspace fixture, not an EX4
# kernel input. Keep actual guest execution selected and fast host checks too.
for path in 'support/test-smart-replay-arm.ps1' \
    'support/tests/smart-capture-receipts.py' \
    'support/tests/test-qemu-smart-replay.sh' \
    'support/tests/smart-replay-arm-init.sh' \
    'support/tests/smart-replay-corpus.py' \
    'support/tests/smart-temperature-corpus.py'; do
    require_ignored_path "$stage_b3_workflow" "$path"
    require_triggered_path "$host_workflow" "$path"
    for event in push pull_request; do
        require_not_ignored_pattern "$qemu_workflow" "$event" "$path"
    done
done
require_ignored_path "$stage_b3_workflow" 'support/tests/test-smart-report-wrapper.ps1'
require_ignored_path "$qemu_workflow" 'support/tests/test-smart-report-wrapper.ps1'
require_triggered_path "$host_workflow" 'support/tests/test-smart-report-wrapper.ps1'
# This PowerShell regression mocks Docker; it is not a firmware input. Keep
# both event filters explicit while retaining the actual host execution.
require_ignored_path "$stage_b3_workflow" 'support/tests/test-samba-root-wrapper.ps1'
require_ignored_path "$qemu_workflow" 'support/tests/test-samba-root-wrapper.ps1'
require_triggered_path "$host_workflow" 'support/tests/test-samba-root-wrapper.ps1'
api_and_qemu_paths='
src/phantowd-api/**
package/phantowd-api/**
board/qemu/armv5/**
configs/phantowd_qemu_armv5_defconfig
support/container/test-api.sh
support/container/build-qemu.sh
support/container/build_jobs.py
support/tests/test-build-jobs.py
support/container/save-qemu-failure-log.sh
support/tests/test-qemu-build-feedback.py
support/tests/test-qemu-md-v10-init-mode.sh
support/docker/entrypoint.sh
support/qemu-smoke.sh
support/qemu-state-reboot.sh
support/qemu-md-v10-fixture.sh
support/test-qemu-md-v10.ps1
support/test-volume-probe-build.py
support/tests/test-volume-probe-license.py
src/phantowd-volume-probe/**
package/phantowd-volume-probe/**
support/container/test-volume-probe.sh
support/container/build-volume-probe-fixture.sh
support/container/patch-volume-probe-fixture.sh
support/container/test-qemu-api-overlay.sh
support/container/apply-buildroot-samba-json-patch.sh
support/tests/test-buildroot-samba-json-patch.sh
support/tests/test-perl-configure-date.py
support/buildroot-patches/**
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

for workflow in "$qemu_workflow" "$stage_b3_workflow" "$host_workflow"; do
    require_pr_ready_for_review "$workflow"
done

require_manual_only "$stage_a_workflow"
require_manual_only "$stage_b_workflow"
require_manual_only "$stage_b2_workflow"

for event in push pull_request; do
	require_not_ignored_pattern \
		"$stage_b3_workflow" "$event" support/container/audit-ex4-stage-b-kernel-config.sh
	require_not_ignored_pattern \
		"$qemu_workflow" "$event" support/buildroot-patches/**
	require_not_ignored_pattern \
		"$qemu_workflow" "$event" support/container/apply-buildroot-samba-json-patch.sh
	require_not_ignored_pattern \
		"$qemu_workflow" "$event" support/tests/test-buildroot-samba-json-patch.sh
	require_not_ignored_pattern \
		"$qemu_workflow" "$event" support/tests/test-volume-probe-license.py
done

while IFS= read -r path; do
    [ -n "$path" ] && require_ignored_path "$qemu_workflow" "$path"
done <<EOF
$qemu_unrelated_ex4_stage_paths
EOF

require_develop_push "$host_workflow"
require_triggered_path "$host_workflow" versions.env
require_triggered_path "$host_workflow" 'src/phantowd-api/**'
for path in \
    'support/container/build-qemu-lio-kernel.sh' \
    'support/container/build-qemu-iscsi-client.sh' \
    'support/container/qemu_lio_inputs.py' \
    'support/container/qemu_lio_result.py' \
    'support/fixtures/iscsi-loopback-client.c' \
    'support/fixtures/qemu-lio-init.sh' \
    'support/fixtures/patches/linux-lio-strict-mutual.patch' \
    'support/fixtures/patches/linux-lio-idle-disable.patch' \
    'support/fixtures/lio-lun-set.h' \
    'support/tests/lio-lun-set-fixture.c' \
    'support/tests/test-lio-lun-set.sh' \
    'support/qemu-lio-fixture.sh' \
    'support/test-qemu-lio.ps1' \
    'support/tests/test-qemu-lio-inputs.py' \
    'support/tests/test-qemu-lio-result.py' \
    'support/tests/test-qemu-lio-snapshot-temp.sh' \
    'support/tests/test-qemu-lio-wrapper.ps1'; do
    require_triggered_path "$host_workflow" "$path"
    require_ignored_path "$qemu_workflow" "$path"
    require_ignored_path "$stage_b3_workflow" "$path"
done
for path in 'support/build-qemu.ps1' \
    'support/run-cached-qemu.mjs' \
    'support/tests/test-cached-qemu-runner.mjs' \
    'support/tests/fixtures/cached-docker.mjs' \
    'support/tests/test-cached-qemu-wrapper.ps1' \
    'support/tests/test-cached-qemu-preflight.py'; do
    require_triggered_path "$host_workflow" "$path"
    require_ignored_path "$qemu_workflow" "$path"
    require_ignored_path "$stage_b3_workflow" "$path"
done
require_bounded_qemu_ccache "$qemu_workflow"
require_triggered_path "$host_workflow" support/tests/test-smart-replay-identify.py
require_ignored_path "$qemu_workflow" support/tests/test-smart-replay-identify.py
require_ignored_path "$stage_b3_workflow" support/tests/test-smart-replay-identify.py
for event in push pull_request; do
    require_not_ignored_pattern "$qemu_workflow" "$event" support/tests/smart-replay-corpus.py
done
require_fixed_fuzz_campaigns "$repo_root/support/container/test-api.sh" 24
require_fixed_fuzz_campaigns "$repo_root/support/container/test-lab-tools.sh" 5
require_fixed_fuzz_campaigns "$host_workflow" 4

for workflow in "$qemu_workflow" "$stage_a_workflow" "$stage_b_workflow" "$stage_b2_workflow" \
    "$stage_b3_workflow" "$host_workflow" "$reproducibility_workflow"; do
    require_checkout_credentials_not_persisted "$workflow"
done

while IFS= read -r path; do
    [ -n "$path" ] && require_ignored_path "$stage_b3_workflow" "$path"
done <<EOF
$api_and_qemu_paths
EOF

while IFS= read -r path; do
    [ -n "$path" ] && require_triggered_path "$host_workflow" "$path"
done <<EOF
$host_tool_paths
EOF
require_triggered_path \
    "$host_workflow" support/container/audit-ex4-stage-b-kernel-config.sh
require_manual_dispatch "$host_workflow"
require_triggered_path "$host_workflow" support/tests/test-qemu-build-feedback.py
require_triggered_path "$host_workflow" support/container/build_jobs.py
require_triggered_path "$host_workflow" support/tests/test-build-jobs.py
require_triggered_path "$host_workflow" support/container/save-qemu-failure-log.sh

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

overlay_script="$repo_root/support/container/test-qemu-api-overlay.sh"
if ! grep -F 'grep -aF' "$overlay_script" >/dev/null ||
    ! grep -F 'schema_version":2' "$overlay_script" >/dev/null ||
    ! grep -F 'does not advertise schema_version 2' "$overlay_script" >/dev/null; then
    printf 'QEMU overlay must reject reused volume-probe helpers with an obsolete schema\n' >&2
    exit 1
fi
if ! grep -F 'package/phantowd-api/mdev.conf' "$overlay_script" >/dev/null ||
    ! grep -F 'Mirror the current package-owned mdev rule' "$overlay_script" >/dev/null; then
    printf 'QEMU overlay must apply the current package-owned broker device rule\n' >&2
    exit 1
fi

require_locked_host_go_sdk "$host_workflow" "$repo_root/versions.env"
for command in '          node --check support/test-dashboard-browser.mjs' \
    '          node support/tests/test-dashboard-preview.mjs' \
    '          node support/test-dashboard-ui.mjs' \
    "        run: go test -count=1 -run '^Test(BrowserFixtureDiagnosticsStaySynthetic|DashboardBrowserAPIFixture)\$' ."; do
    if ! grep -Fx "$command" "$host_workflow" >/dev/null; then
        printf 'host workflow must execute dashboard check: %s\n' "$command" >&2
        exit 1
    fi
done
sh "$repo_root/support/tests/test-storage-broker-buildroot.sh"

printf 'Firmware workflow path-contract tests passed\n'
