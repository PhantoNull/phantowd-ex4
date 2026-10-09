#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
import copy
from pathlib import Path
import tempfile
import unittest
from pending_client_inputs_fixture import DOCUMENTS, manifest, read_bounded


class PendingInputsTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "format": "phantowd-elf-runtime-candidate", "schema_version": 1,
            "entry": "usr/lib/libsmbclient.so.0",
            "static_dependencies_resolved": True,
            "runtime_qualified": False, "execution_authorized": False,
            "total_bytes": 2,
            "objects": [
                {"path": "lib/ld-linux.so.3", "sha256": "11" * 32,
                 "size": 1, "bindings": ["lib/ld-linux.so.3"]},
                {"path": "usr/lib/libsmbclient.so.0.8.0", "sha256": "22" * 32,
                 "size": 1, "bindings": ["usr/lib/libsmbclient.so.0"]},
            ],
        }
        self.documents = {name: "non-secret-test-document"
                          for name in DOCUMENTS}

    def test_fixed_roles_modes_and_aliases(self):
        value = manifest(self.report, self.documents, b"client", b"helper")
        self.assertEqual(len(value["RootFiles"]), 9)
        self.assertEqual(value["RootAliases"], [{
            "Path": "usr/lib/libsmbclient.so.0",
            "Target": "usr/lib/libsmbclient.so.0.8.0"}])
        self.assertEqual(value["BootstrapFiles"][0]["Mode"], 0o555)
        self.assertEqual(sum(item["Mode"] == 0o444
                             for item in value["RootFiles"]), 6)

    def test_candidate_scope_and_byte_budget_refuse(self):
        for field, value in (("execution_authorized", True),
                             ("runtime_qualified", True),
                             ("schema_version", True), ("total_bytes", True),
                             ("total_bytes", 3), ("entry", "usr/sbin/smbd")):
            report = copy.deepcopy(self.report)
            report[field] = value
            with self.assertRaises(ValueError):
                manifest(report, self.documents, b"client", b"helper")

    def test_missing_reserved_traversal_duplicate_bindings_refuse(self):
        for path in ("../outside", "/outside", "lib//outside",
                     "fixture/client", "etc/passwd"):
            report = copy.deepcopy(self.report)
            report["objects"][0]["path"] = path
            with self.assertRaises(ValueError):
                manifest(report, self.documents, b"client", b"helper")
        report = copy.deepcopy(self.report)
        report["objects"][1]["bindings"] = ["lib/ld-linux.so.3"]
        with self.assertRaises(ValueError):
            manifest(report, self.documents, b"client", b"helper")

    def test_documents_and_programs_bounded(self):
        for documents in ({}, {**self.documents, "other": "extra"},
                          {**self.documents, "etc/passwd": ""}):
            with self.assertRaises(ValueError):
                manifest(self.report, documents, b"client", b"helper")
        for client, helper in ((b"", b"helper"), (b"client", b""),
                               (b"x" * (1024 * 1024 + 1), b"helper")):
            with self.assertRaises(ValueError):
                manifest(self.report, self.documents, client, helper)

    def test_real_build_input_read_is_bounded_and_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"fixed")
            self.assertEqual(read_bounded(path, 5), b"fixed")
            fd_count = len(list(Path("/proc/self/fd").iterdir()))
            for _ in range(8):
                with self.assertRaises(ValueError):
                    read_bounded(path, 4)
                with self.assertRaises(ValueError):
                    read_bounded(directory, 5)
            self.assertEqual(len(list(Path("/proc/self/fd").iterdir())),
                             fd_count)
            alias = Path(directory) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                read_bounded(alias, 5)


if __name__ == "__main__":
    unittest.main()
