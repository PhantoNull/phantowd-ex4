# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Execute the actual shell preflight on disposable Linux fixtures."""

import hashlib
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class CachedPreflightTests(unittest.TestCase):
    def setUp(self):
        wrapper = (ROOT / "support/build-qemu.ps1").read_text()
        self.script = wrapper.split("    $cachedScript = @'\n", 1)[1]
        self.script = self.script.split("\n'@", 1)[0]
        self.scratch = tempfile.TemporaryDirectory(
            prefix="phantowd-preflight-")
        self.addCleanup(self.scratch.cleanup)
        self.directory = pathlib.Path(self.scratch.name)
        for fixed in ("/workspace", "/ccache", "/external"):
            self.script = self.script.replace(
                fixed, str(self.directory) + fixed)
        self.external = self.directory / "external"
        self.workspace = self.directory / "workspace"
        self.cache = self.directory / "ccache"
        self.artifacts = self.external / "artifacts"
        self.config = self.external / "configs/phantowd_qemu_armv5_defconfig"
        self.config.parent.mkdir(parents=True)
        self.config.write_text("synthetic pinned config\n")
        (self.external / "versions.env").write_text(
            'BUILDROOT_VERSION="2025.02.18"\n')
        fingerprint = hashlib.sha256(self.config.read_bytes()).hexdigest()[:16]
        self.output = self.workspace / f"output/2025.02.18-{fingerprint}"
        self.toolchain = self.output / "host/bin/go"
        self.toolchain.parent.mkdir(parents=True)
        self.toolchain.write_text("#!/bin/sh\nexit 0\n")
        self.toolchain.chmod(0o755)
        (self.output / "target").mkdir()
        self.cache.mkdir()
        self.artifacts.mkdir()
        for location in (self.workspace, self.cache, self.artifacts):
            (location / ".phantowd-owner-builder-v1").touch()
        self.started = self.directory / "started"
        build = self.external / "support/container/build-qemu.sh"
        build.parent.mkdir(parents=True)
        build.write_text(
            f"#!/bin/sh\nprintf started > '{self.started}'\n")

    def run_preflight(self, accepted=False):
        result = subprocess.run(["sh", "-c", self.script], text=True,
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0 if accepted else 2,
                         result.stderr)
        self.assertEqual(self.started.exists(), accepted)
        return result

    def test_initialized_current_output_executes_once(self):
        self.run_preflight(accepted=True)
        self.assertEqual(self.started.read_text(), "started")

    def test_each_missing_marker_refuses_before_builder(self):
        for location in (self.workspace, self.cache, self.artifacts):
            with self.subTest(location=location.name):
                marker = location / ".phantowd-owner-builder-v1"
                marker.unlink()
                self.assertIn("not initialized", self.run_preflight().stderr)
                marker.touch()

    def test_directory_is_not_an_initialization_marker(self):
        marker = self.cache / ".phantowd-owner-builder-v1"
        marker.unlink()
        marker.mkdir()
        self.run_preflight()

    def test_missing_or_nonexecutable_toolchain_refuses(self):
        self.toolchain.chmod(0o644)
        self.run_preflight()
        self.toolchain.unlink()
        self.run_preflight()

    def test_missing_target_refuses(self):
        (self.output / "target").rmdir()
        self.run_preflight()

    def test_changed_configuration_does_not_adopt_old_output(self):
        self.config.write_text("different synthetic config\n")
        self.assertIn("current configuration is missing",
                      self.run_preflight().stderr)

    def test_nonwritable_artifacts_refuses_without_ownership_repair(self):
        self.artifacts.chmod(0o555)
        self.addCleanup(self.artifacts.chmod, 0o755)
        self.assertIn("no ownership repair", self.run_preflight().stderr)
        self.assertEqual(self.artifacts.stat().st_mode & 0o777, 0o555)


if __name__ == "__main__":
    unittest.main()
