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
    def valid(self, strict=False):
        markers = result.STRICT_MARKERS if strict else result.MARKERS
        return ("ordinary boot log\n" + "\n".join(markers) + "\n").encode()

    def test_complete(self):
        result.validate(self.valid())
        result.validate(self.valid().replace(b"\n", b"\r\n"))

    def test_strict_mode_refuses_default_cross_mode_and_mixed_evidence(self):
        strict = self.valid(strict=True)
        result.validate(strict, required_mutual=True)
        result.validate(strict.replace(b"\n", b"\r\n"), required_mutual=True)
        with self.assertRaises(ValueError):
            result.validate(self.valid(), required_mutual=True)
        with self.assertRaises(ValueError):
            result.validate(strict)
        for marker in result.STRICT_MARKERS:
            for replacement in ("", marker + "\n" + marker, "prefix " + marker):
                with self.subTest(marker=marker, replacement=replacement), self.assertRaises(ValueError):
                    result.validate(strict.replace(marker.encode(), replacement.encode()), required_mutual=True)
        for old in set(result.MARKERS) - set(result.STRICT_MARKERS):
            with self.assertRaises(ValueError):
                result.validate(strict + old.encode() + b"\n", required_mutual=True)
        for token in result.DENIED:
            with self.assertRaises(ValueError):
                result.validate(strict + token.encode(), required_mutual=True)

    def test_every_marker_missing_duplicate_or_substring_refused(self):
        for marker in result.MARKERS:
            for replacement in ("", marker + "\n" + marker, "prefix " + marker):
                with self.subTest(marker=marker, replacement=replacement):
                    with self.assertRaises(ValueError):
                        result.validate(self.valid().replace(marker.encode(),
                                                            replacement.encode()))

    def test_multiple_lun_evidence_cannot_be_omitted_or_weakened(self):
        marker = "PHANTOWD_LIO_LUNS_READY count=2 block_sizes=512,4096 primary_luns=0,1 peer_luns=0,3 " \
                 "opposite_access=true ungranted_refused=true data_isolated=true teardown=true scope=disposable-qemu-only"
        self.assertIn(marker, result.MARKERS)
        self.assertIn(marker, result.STRICT_MARKERS)
        for strict in (False, True):
            good = self.valid(strict=strict)
            for old, new in (("count=2", "count=1"), ("4096", "512"),
                             ("peer_luns=0,3", "peer_luns=0,1"),
                             ("ungranted_refused=true", "ungranted_refused=false"),
                             ("data_isolated=true", "data_isolated=false"),
                             ("teardown=true", "teardown=false")):
                with self.subTest(strict=strict, old=old), self.assertRaises(ValueError):
                    result.validate(good.replace(marker.encode(), marker.replace(old, new).encode()),
                                    required_mutual=strict)

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
