#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Exercise the hosted-runner admission CLI with external commands replaced."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "support/container/prepare-repro-runner.sh"


class ReproRunner(unittest.TestCase):
    def invoke(self, hosted=False, dirty=False, arguments=(), **overrides):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            trace = directory / "trace"
            workspace = directory / "checkout"
            workspace.mkdir()
            real_git = shutil.which("git")
            subprocess.run([real_git, "init", "-q", str(workspace)],
                           check=True, capture_output=True)
            if dirty:
                (workspace / "uncommitted").write_text("fixture\n")
            bodies = {
                "git": 'exec "$REAL_GIT" "$@"\n',
                "df": 'value=$DISK_BEFORE_KIB\n'
                      'docker_value=${DOCKER_BEFORE_KIB:-$value}\n'
                      'if grep -q "^sudo " "$TRACE"; then '
                      'value=${DISK_AFTER_KIB:-$DISK_BEFORE_KIB}; '
                      'docker_value=${DOCKER_AFTER_KIB:-'
                      '${DOCKER_BEFORE_KIB:-$value}}; fi\n'
                      'printf "Filesystem 1024-blocks Used Available Capacity '
                      'Mounted\\nfixture 90000000 1000000 %s 2%% /fixture\\n" '
                      '"$value"\n'
                      'if [ "$#" -ge 3 ]; then printf "fixture 90000000 '
                      '1000000 %s 2%% /docker\\n" "$docker_value"; fi\n'
                      'code=${DF_EXIT:-0}\n'
                      'if grep -q "^sudo " "$TRACE"; then '
                      'code=${DF_AFTER_EXIT:-$code}; fi\nexit "$code"\n',
                "docker": 'printf "%s\\n" "${DOCKER_ROOT:-/var/lib/docker}"\n'
                          'exit "${DOCKER_EXIT:-0}"\n',
                "sudo": 'exit "${SUDO_EXIT:-0}"\n',
            }
            for name, body in bodies.items():
                program = directory / name
                program.write_text(
                    f'#!/bin/sh\nprintf "%s\\n" "{name} $*" >> "$TRACE"\n'
                    + body, encoding="utf-8")
                program.chmod(0o700)
            env = {**os.environ, "PATH": f"{directory}:{os.environ['PATH']}",
                   "TRACE": str(trace), "REAL_GIT": real_git,
                   "GITHUB_ACTIONS": "true" if hosted else "false",
                   "RUNNER_ENVIRONMENT": "github-hosted" if hosted
                   else "self-hosted", "RUNNER_OS": "Linux",
                   "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24",
                   "RUNNER_TOOL_CACHE": "/opt/hostedtoolcache",
                   "DISK_BEFORE_KIB": "41943040",
                   "GITHUB_WORKSPACE": str(workspace), **overrides}
            result = subprocess.run(
                ["sh", str(SCRIPT), *arguments], cwd=directory, env=env,
                capture_output=True, text=True, timeout=5)
            return result, trace.read_text() if trace.exists() else ""

    def test_non_hosted_runner_refuses_before_commands(self):
        result, trace = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertIn("reason=not-github-hosted", result.stderr)
        self.assertEqual(trace, "")

    def test_sufficient_workspace_space_needs_no_cleanup(self):
        result, trace = self.invoke(hosted=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PHANTOWD_REPRO_DISK_READY", result.stdout)
        self.assertIn("available_kib=41943040", result.stdout)
        self.assertIn("cleanup=none", result.stdout)
        self.assertNotIn("sudo ", trace)

    def test_unknown_host_profile_refuses_before_commands(self):
        for override in ({"GITHUB_ACTIONS": "false"},
                         {"RUNNER_ENVIRONMENT": "self-hosted"},
                         {"RUNNER_OS": "Windows"},
                         {"RUNNER_ARCH": "ARM64"},
                         {"ImageOS": "ubuntu26"},
                         {"RUNNER_TOOL_CACHE": "/tmp/other-cache"}):
            with self.subTest(override=override):
                result, trace = self.invoke(hosted=True, **override)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("PHANTOWD_REPRO_DISK_REFUSED", result.stderr)
                self.assertEqual(trace, "")

    def test_dirty_checkout_refuses_before_disk_or_cleanup(self):
        result, trace = self.invoke(hosted=True, dirty=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("reason=dirty-worktree", result.stderr)
        self.assertNotIn("df ", trace)
        self.assertNotIn("sudo ", trace)

    def test_arguments_cannot_override_the_fixed_cleanup_scope(self):
        result, trace = self.invoke(hosted=True, arguments=("/tmp",))
        self.assertEqual(result.returncode, 2)
        self.assertIn("reason=unexpected-arguments", result.stderr)
        self.assertEqual(trace, "")

    def test_invalid_capacity_refuses_before_cleanup(self):
        for value in ("not-a-number", "-1", "9" * 30):
            with self.subTest(value=value):
                result, trace = self.invoke(hosted=True,
                                            DISK_BEFORE_KIB=value)
                self.assertEqual(result.returncode, 1)
                self.assertIn("reason=invalid-disk-metric", result.stderr)
                self.assertNotIn("sudo ", trace)

    def test_failed_probe_does_not_admit_plausible_output(self):
        result, trace = self.invoke(hosted=True, DF_EXIT="7")
        self.assertEqual(result.returncode, 1)
        self.assertIn("reason=disk-probe-failed", result.stderr)
        self.assertNotIn("PHANTOWD_REPRO_DISK_READY", result.stdout)
        self.assertNotIn("sudo ", trace)

    def test_shortfall_removes_only_unused_sdks_then_rechecks(self):
        result, trace = self.invoke(hosted=True, DISK_BEFORE_KIB="1048576",
                                    DISK_AFTER_KIB="41943040")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("available_kib=1048576", result.stdout)
        self.assertIn("available_kib=41943040", result.stdout)
        self.assertIn("cleanup=performed", result.stdout)
        self.assertEqual([row for row in trace.splitlines()
                          if row.startswith("sudo ")], [
            "sudo -n rm -rf -- /usr/share/dotnet /usr/local/lib/android "
            "/opt/hostedtoolcache"])
        self.assertEqual(len([row for row in trace.splitlines()
                              if row.startswith("df ")]), 2)

    def test_checkout_space_does_not_mask_a_full_docker_filesystem(self):
        result, trace = self.invoke(hosted=True, DOCKER_BEFORE_KIB="0",
                                    DOCKER_ROOT="/mnt/isolated-docker")
        self.assertEqual(result.returncode, 1)
        self.assertIn("reason=insufficient-space", result.stderr)
        self.assertIn("/mnt/isolated-docker", trace)
        self.assertNotIn("PHANTOWD_REPRO_DISK_READY", result.stdout)

    def test_cleanup_failure_stops_without_a_second_probe(self):
        result, trace = self.invoke(hosted=True, DISK_BEFORE_KIB="0",
                                    DISK_AFTER_KIB="41943040", SUDO_EXIT="7")
        self.assertEqual(result.returncode, 1)
        self.assertIn("reason=cleanup-failed", result.stderr)
        self.assertNotIn("PHANTOWD_REPRO_DISK_READY", result.stdout)
        self.assertEqual(trace.count("sudo "), 1)
        self.assertEqual(trace.count("df "), 1)

    def test_remaining_shortfall_refuses_without_retry(self):
        result, trace = self.invoke(hosted=True, DISK_BEFORE_KIB="0",
                                    DISK_AFTER_KIB="41943039")
        self.assertEqual(result.returncode, 1)
        self.assertIn("reason=insufficient-space", result.stderr)
        self.assertNotIn("PHANTOWD_REPRO_DISK_READY", result.stdout)
        self.assertEqual(trace.count("sudo "), 1)
        self.assertEqual(trace.count("df "), 2)

    def test_unknown_docker_root_refuses_before_probe_or_cleanup(self):
        for override in ({"DOCKER_EXIT": "7"}, {"DOCKER_ROOT": "relative"}):
            with self.subTest(override=override):
                result, trace = self.invoke(hosted=True, **override)
                self.assertEqual(result.returncode, 1)
                self.assertIn("reason=docker-root-unavailable", result.stderr)
                self.assertNotIn("df ", trace)
                self.assertNotIn("sudo ", trace)

    def test_unavailable_checkout_refuses_before_resource_commands(self):
        result, trace = self.invoke(hosted=True,
                                    GITHUB_WORKSPACE="/missing-checkout")
        self.assertEqual(result.returncode, 2)
        self.assertIn("reason=worktree-unavailable", result.stderr)
        self.assertNotIn("docker ", trace)
        self.assertNotIn("df ", trace)
        self.assertNotIn("sudo ", trace)

    def test_second_probe_failure_cannot_report_ready(self):
        result, trace = self.invoke(hosted=True, DISK_BEFORE_KIB="0",
                                    DISK_AFTER_KIB="41943040",
                                    DF_AFTER_EXIT="7")
        self.assertEqual(result.returncode, 1)
        self.assertIn("reason=disk-probe-failed", result.stderr)
        self.assertNotIn("PHANTOWD_REPRO_DISK_READY", result.stdout)
        self.assertEqual(trace.count("sudo "), 1)

    def test_clean_workflow_admits_disk_before_building_any_image(self):
        workflow = (ROOT / ".github/workflows/reproducibility.yml").read_text()
        command = "sh support/container/prepare-repro-runner.sh"
        self.assertIn(command, workflow)
        self.assertLess(workflow.index(command),
                        workflow.index("docker build --file"))
        self.assertLess(workflow.index(command),
                        workflow.index('docker volume create "$BUILD_VOLUME"'))
        self.assertIn("python3 -B support/tests/test-repro-runner.py",
                      workflow)


if __name__ == "__main__":
    unittest.main()
