#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Fast real runner preconditions; no compiler, fixture or QEMU is started."""

from pathlib import Path
import hashlib
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "support/tests/test-qemu-smart-replay.sh"
REPORT_RUNNER = ROOT / "support/tests/test-qemu-smart-report.sh"


class ReplayContractTests(unittest.TestCase):
    def run_missing_compiler(self, compiler):
        return subprocess.run(
            ["sh", str(RUNNER), "/missing/base", compiler, "/missing/go",
             "/missing/debugfs", "/missing/source", "/missing/archive"],
            capture_output=True, text=True, timeout=3, check=False,
        )

    def test_actual_gplusplus_name_reaches_missing_toolchain_refusal(self):
        result = self.run_missing_compiler(
            "/missing/arm-buildroot-linux-gnueabi-g++"
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("MISSING_CXX full-rebuild-required=true", result.stderr)

    def test_unsafe_paths_are_refused_before_toolchain_check(self):
        for path in ("/missing/g++;echo", "/missing/g++ space",
                     "/missing/$(command)", "/missing/g++\n"):
            with self.subTest(path=path):
                result = self.run_missing_compiler(path)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout + result.stderr, "")


class CollectionRunnerContractTests(unittest.TestCase):
    """Real runner admission/markers/cleanup, with deliberately fake tools.

    This does not execute ARM code or validate filesystem injection. The actual
    guest lane separately establishes those facts.
    """

    def test_noncanonical_scratch_is_refused_before_any_tool(self):
        for tmpdir in ("/tmp/../tmp", "/tmp/", "/tmp/./"):
            env = dict(os.environ, TMPDIR=tmpdir)
            result = subprocess.run(
                ["sh", str(REPORT_RUNNER), "/missing/base", "/missing/go",
                 "/missing/debugfs", "/missing/source"], env=env,
                capture_output=True, text=True, timeout=3, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout + result.stderr, "")

    def test_one_boot_requires_both_markers_and_removes_all_scratch(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            base, tools, scratch = (root / name for name in
                                    ("base", "tools", "scratch"))
            for directory in (base, tools, scratch):
                directory.mkdir()
            for name in ("rootfs.ext2", "zImage", "versatile-pb.dtb"):
                (base / name).write_bytes(b"contract-only-not-an-image")
            digest = hashlib.sha256((base / "rootfs.ext2").read_bytes())
            (base / "SHA256SUMS").write_text(
                digest.hexdigest() + "  rootfs.ext2\n", encoding="ascii")
            scripts = {
                "go": "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n"
                      "if [ \"$1\" = -o ]; then shift; : > \"$1\"; fi\n"
                      "shift\ndone\n",
                "debugfs": "#!/bin/sh\nexit 0\n",
                "qemu-system-arm": "#!/bin/sh\n"
                      "echo boot >> \"$BOOT_COUNT\"\n"
                      "printf '%s\\n' \"$GUEST_OUTPUT\"\n",
            }
            for name, contents in scripts.items():
                path = tools / name
                path.write_text(contents, encoding="ascii")
                path.chmod(0o755)
            parser = ("PHANTOWD_SMART_REPORT_TESTS_READY "
                      "scope=synthetic-parser-only")
            collector = ("PHANTOWD_SMART_COLLECTOR_TESTS_READY "
                         "scope=trusted-backend-fake-only")
            passes = ("PASS\n--- PASS: TestATAExitBitsAndAssessment (0.00s)\n"
                      "--- PASS: TestFixedSourceAndSampleSemantics (0.00s)\n")
            count = root / "boots"
            for markers, success in ((parser, False), (collector, False),
                                     (parser + "\n" + collector, True)):
                with self.subTest(markers=markers):
                    count.unlink(missing_ok=True)
                    env = dict(os.environ, TMPDIR=str(scratch),
                               PATH=str(tools) + ":" + os.environ["PATH"],
                               BOOT_COUNT=str(count),
                               GUEST_OUTPUT=passes + markers)
                    result = subprocess.run(
                        ["sh", str(REPORT_RUNNER), str(base),
                         str(tools / "go"),
                         str(tools / "debugfs"), str(ROOT)], env=env,
                        capture_output=True, text=True, timeout=5, check=False,
                    )
                    self.assertEqual(result.returncode == 0, success,
                                     result.stdout + result.stderr)
                    self.assertEqual(count.read_text(), "boot\n")
                    self.assertEqual(list(scratch.iterdir()), [])
                    self.assertEqual(
                        hashlib.sha256(
                            (base / "rootfs.ext2").read_bytes()).hexdigest(),
                        digest.hexdigest())


if __name__ == "__main__":
    unittest.main()
