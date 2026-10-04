#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Consumer-contract tests, not a target/initiator test."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "support/container/qemu_lio_result.py"
SPEC = importlib.util.spec_from_file_location("lio_result", SCRIPT)
result = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(result)


class LIOResult(unittest.TestCase):
    def valid(self):
        return ("ordinary boot log\n" + "\n".join(result.MARKERS) + "\n").encode()

    def test_complete(self):
        result.validate(self.valid())
        result.validate(self.valid().replace(b"\n", b"\r\n"))

    def test_every_marker_missing_duplicate_or_substring_refused(self):
        for marker in result.MARKERS:
            for replacement in ("", marker + "\n" + marker, "prefix " + marker):
                with self.subTest(marker=marker, replacement=replacement):
                    with self.assertRaises(ValueError):
                        result.validate(self.valid().replace(marker.encode(),
                                                            replacement.encode()))

    def test_errors_secrets_and_wrong_scope_refused(self):
        for token in result.DENIED:
            with self.subTest(token=token), self.assertRaises(ValueError):
                result.validate(self.valid() + token.encode())
        with self.assertRaises(ValueError):
            result.validate(self.valid().replace(b"disposable-qemu-only", b"product"))

    def test_size_and_encoding(self):
        for data in (self.valid() + b"\xff", b"x" * (result.MAX_BYTES + 1)):
            with self.assertRaises(ValueError):
                result.validate(data)

    def test_additional_unknown_or_contradictory_results_refused(self):
        for marker in (
            "PHANTOWD_LIO_CLIENT_READY case=unexpected",
            "PHANTOWD_LIO_MUTUAL_READY enforcement=true scope=product",
            "PHANTOWD_LIO_PEERS_READY concurrent=1",
            "PHANTOWD_LIO_READY scope=product",
            "prefix PHANTOWD_LIO_READY scope=product",
        ):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                result.validate(self.valid() + marker.encode() + b"\n")

    def test_cli_regular_missing_directory_and_redacted_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            log = directory / "log"
            log.write_bytes(self.valid())
            good = subprocess.run([sys.executable, "-B", str(SCRIPT), str(log)],
                                  capture_output=True, check=False)
            self.assertEqual(good.returncode, 0)
            for path in (directory, directory / "private-missing-log"):
                bad = subprocess.run([sys.executable, "-B", str(SCRIPT), str(path)],
                                     capture_output=True, check=False)
                self.assertEqual(bad.returncode, 1)
                self.assertEqual(bad.stderr.replace(b"\r\n", b"\n"),
                                 b"LIO guest qualification refused\n")
            log.write_bytes(self.valid() + b"synthetic-chap-only-2026")
            bad = subprocess.run([sys.executable, "-B", str(SCRIPT), str(log)],
                                 capture_output=True, check=False)
            self.assertEqual(bad.returncode, 1)
            self.assertNotIn(b"synthetic-chap", bad.stderr)


if __name__ == "__main__":
    unittest.main()
