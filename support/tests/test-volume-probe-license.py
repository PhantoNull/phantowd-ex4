#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Exercise pinned Buildroot license verification without an image build."""

import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
HASH_FILE = ROOT / "package/phantowd-volume-probe/phantowd-volume-probe.hash"


class LicenseVerificationTests(unittest.TestCase):
    def test_repository_license_is_verified_and_tampering_is_refused(self):
        checker = pathlib.Path(sys.argv[1])
        self.assertTrue(checker.is_file(),
                        "Pinned Buildroot checker required")
        with tempfile.TemporaryDirectory(
                prefix="phantowd-license-") as scratch:
            license_file = pathlib.Path(scratch) / "LICENSE"
            original = (ROOT / "LICENSE").read_bytes()
            license_file.write_bytes(original)
            result = subprocess.run(
                ["bash", str(checker), str(license_file), "LICENSE",
                 str(HASH_FILE)], capture_output=True, text=True,
                timeout=5, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("LICENSE: OK (sha256:", result.stdout)
            self.assertEqual(result.stderr, "")
            license_file.write_bytes(original + b"\nchanged-fixture-only\n")
            result = subprocess.run(
                ["bash", str(checker), str(license_file), "LICENSE",
                 str(HASH_FILE)], capture_output=True, text=True,
                timeout=5, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("LICENSE has wrong sha256 hash", result.stderr)
            self.assertNotIn("LICENSE: OK", result.stdout)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: test-volume-probe-license.py BUILDROOT_CHECK_HASH"
        )
    unittest.main(argv=[sys.argv[0]])
