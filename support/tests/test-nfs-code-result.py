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
        self.lines = [checker.TABLE, checker.INPUTS, b"PHANTOWD_NFS_CODE_COUNTS files=4 aliases=0 bytes=400", checker.READY, checker.DONE]

    def test_lf_and_serial_crlf_have_same_exact_meaning(self):
        for ending in (b"\n", b"\r\n"):
            checker.verify(ending.join(self.lines) + ending, self.report)

    def test_old_input_only_receipt_cannot_claim_real_table_execution(self):
        without_table = [line for line in self.lines if not line.startswith(b"PHANTOWD_NFS_TABLE_")]
        with self.assertRaises(ValueError):
            checker.verify(b"\n".join(without_table), self.report)

    def test_missing_duplicate_reordered_or_failed_receipts_refuse(self):
        variants = [self.lines[:i] + self.lines[i+1:] for i in range(len(self.lines))]
        variants += [self.lines[:i] + [self.lines[i]] + self.lines[i:] for i in range(len(self.lines))]
        variants += [list(reversed(self.lines)), self.lines + [b"PHANTOWD_NFS_CODE_FAILED"],
                     self.lines + [b"PHANTOWD_NFS_CODE_FAILURE phase=normal-lifetime"],
                     self.lines + [b"PHANTOWD_NFS_TABLE_FAILURE phase=capture"]]
        for old, new in ((b"execution=loader-list-and-exportfs-s", b"execution=daemon"),
                         (b"original_pins", b"original_\rpins"),
                         (b"bytes=400", b"bytes=399"), (b"service=false", b"service=true"),
                         (b"state_dirs=2", b"state_dirs=3"), (b"services=false", b"services=true"),
                         (b"kernel_control=false", b"kernel_control=true")):
            variants.append([line.replace(old, new) for line in self.lines])
        variants.append([line + b"\r\r" for line in self.lines])
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
