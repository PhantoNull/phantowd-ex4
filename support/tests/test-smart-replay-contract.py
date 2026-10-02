#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Fast real runner preconditions; no compiler, fixture or QEMU is started."""

from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "support/tests/test-qemu-smart-replay.sh"


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


if __name__ == "__main__":
    unittest.main()
