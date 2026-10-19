#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("nfs_code_result", Path(__file__).resolve().parents[1] / "nfs-code-result.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class CodeReceiptTests(unittest.TestCase):
    def setUp(self):
        self.report = json.dumps({"format": "phantowd-nfs-runtime-candidate", "schema_version": 1,
                                  "static_dependencies_resolved": True, "runtime_qualified": False,
                                  "execution_authorized": False, "total_bytes": 400,
                                  "objects": [{"size": 100, "bindings": ["one"]} for _ in range(4)]}).encode()
        self.lines = [b"PHANTOWD_NFS_CODE_COUNTS files=4 aliases=0 bytes=400", checker.READY, checker.DONE]

    def test_lf_and_serial_crlf_have_same_exact_meaning(self):
        for ending in (b"\n", b"\r\n"):
            checker.verify(ending.join(self.lines) + ending, self.report)

    def test_missing_duplicate_reordered_or_failed_receipts_refuse(self):
        variants = [self.lines[:i] + self.lines[i+1:] for i in range(3)]
        variants += [self.lines[:i] + [self.lines[i]] + self.lines[i:] for i in range(3)]
        variants += [list(reversed(self.lines)), self.lines + [b"PHANTOWD_NFS_CODE_FAILED"],
                     self.lines + [b"PHANTOWD_NFS_CODE_FAILURE phase=normal-lifetime"],
                     [self.lines[0], checker.READY.replace(b"execution=loader-list-only", b"execution=daemon"), checker.DONE],
                     [self.lines[0], checker.READY.replace(b"original_pins", b"original_\rpins"), checker.DONE],
                     [self.lines[0] + b"\r", checker.READY + b"\r\r", checker.DONE],
                     [self.lines[0].replace(b"bytes=400", b"bytes=399"), checker.READY, checker.DONE]]
        for lines in variants:
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                checker.verify(b"\n".join(lines), self.report)

    def test_incomplete_expected_scope_and_excess_logs_refuse(self):
        for key, value in (("runtime_qualified", True), ("execution_authorized", True),
                           ("static_dependencies_resolved", False), ("total_bytes", 399)):
            report = json.loads(self.report)
            report[key] = value
            with self.assertRaises(ValueError):
                checker.verify(b"\n".join(self.lines), json.dumps(report).encode())
        with self.assertRaises(ValueError):
            checker.verify(b"x" * (checker.MAX_LOG + 1), self.report)

    def test_wrong_json_shapes_refuse_with_fixed_validation_error(self):
        for value in (None, [], 1, {"format": "phantowd-nfs-runtime-candidate", "schema_version": 1,
                                   "static_dependencies_resolved": True, "runtime_qualified": False,
                                   "execution_authorized": False, "objects": [None] * 4}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                checker.verify(b"\n".join(self.lines), json.dumps(value).encode())


if __name__ == "__main__":
    unittest.main()
