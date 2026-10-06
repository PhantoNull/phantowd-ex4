#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Host rejection tests only; successful namespace setup is checked in QEMU."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class LauncherRefusal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(
            prefix="phantowd-launcher-")
        cls.binary = Path(cls.directory.name) / "launcher"
        source = (Path(__file__).resolve().parents[2] /
                  "src/phantowd-service-launcher/launcher.c")
        subprocess.run(
            [os.environ.get("CC", "cc"), "-std=c11", "-O2", "-Wall", "-Wextra",
             "-Werror", "-o", str(cls.binary), str(source)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def refused(self, arguments):
        result = subprocess.run([str(self.binary)] + arguments,
                                stdin=subprocess.DEVNULL, capture_output=True,
                                start_new_session=True, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"service launcher refused\n")

    def test_missing_descriptors(self):
        self.refused(["v1", "1000", "1000", "1000", "--", "/probe"])

    def test_disposable_handoff_root_has_trusted_tmpfs_ancestor(self):
        root = Path(__file__).resolve().parents[2]
        init = (root / "support/tests/service-launcher-init.sh").read_text()
        # The real handoff requires every ancestor non-writable by group/other.
        # Bare tmpfs defaults to 1777, causing a correct pre-child refusal.
        self.assertIn("mount -t tmpfs -o mode=0755 tmpfs /run", init)

    def test_invalid_credentials_and_groups(self):
        for uid in ("0", "999", "60001", "01000", "+1000", "1e3", "1000x"):
            with self.subTest(uid=uid):
                self.refused(["v1", uid, "1000", "1000", "--", "/probe"])
        for groups in ("", "0", "1000,1000", "1001,1000", "1000,", ",1000"):
            with self.subTest(groups=groups):
                self.refused(["v1", "1000", "1000", groups, "--", "/probe"])

    def test_argument_bounds_and_version(self):
        self.refused([])
        self.refused(["v2", "1000", "1000", "-", "--", "/probe"])
        self.refused(["v1", "1000", "1000", "-", "--", ""])
        self.refused(["v1", "1000", "1000", "-", "--", "a" * 4097])
        self.refused(["v1", "1000", "1000", "-", "--"] + ["arg"] * 65)


if __name__ == "__main__":
    if sys.platform != "linux":
        raise SystemExit("Native test requires Linux and the existing "
                         "read-only build container.")
    unittest.main()
