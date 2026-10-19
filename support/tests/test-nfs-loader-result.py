#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
import copy
import unittest

import nfs_loader_result as checker


ENTRIES = ("usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs")
READY = ("PHANTOWD_NFS_LOADER_READY nonroot=true capabilities_zero=true "
         "root_restricted=true private_namespace=true original_code=true "
         "stop_reaped=true fd_balance=true entrypoints=false scope=qemu-only")


def fixture():
    shared = [{"path": name, "sha256": digest * 64, "size": 100, "bindings": [name]}
              for name, digest in (("lib/libc.so.6", "b"), ("lib/ld-linux.so.3", "c"))]
    reports = {}
    objects = copy.deepcopy(shared)
    log = []
    for index, entry in enumerate(ENTRIES):
        item = {"path": entry, "sha256": str(index + 1) * 64, "size": 100, "bindings": [entry]}
        objects.append(item)
        reports[entry] = {"format": "phantowd-elf-runtime-candidate", "schema_version": 1,
                          "entry": entry, "root_digest_sha256": "a" * 64,
                          "static_dependencies_resolved": True, "runtime_qualified": False,
                          "execution_authorized": False, "total_bytes": 300,
                          "objects": [item] + copy.deepcopy(shared)}
        log += ["PHANTOWD_NFS_LOADER_BEGIN entry=" + entry,
                "  libc.so.6 => /lib/libc.so.6 (0x12340000)",
                "  /lib/ld-linux.so.3 (0x45670000)",
                "PHANTOWD_NFS_LOADER_END entry=" + entry]
    union = {"format": "phantowd-nfs-runtime-candidate", "schema_version": 1,
             "root_digest_sha256": "a" * 64, "expected_entries": list(ENTRIES),
             "static_dependencies_resolved": True, "runtime_qualified": False,
             "execution_authorized": False, "total_bytes": 500, "objects": objects}
    return "\n".join(log + [READY]), union, reports


class NFSLoaderResultTests(unittest.TestCase):
    def test_all_three_actual_resolutions_match_one_code_graph(self):
        log, union, reports = fixture()
        self.assertEqual(checker.verify(log, union, reports), 3)
        self.assertEqual(checker.verify(log.replace("\n", "\r\n"), union, reports), 3)

    def test_partial_extra_duplicate_or_entrypoint_receipts_refuse(self):
        log, union, reports = fixture()
        for changed in (log.replace("  libc.so.6 => /lib/libc.so.6 (0x12340000)\n", "", 1),
                        log.replace("/lib/libc.so.6 (", "/outside/libc.so.6 (", 1),
                        log.replace("  /lib/ld-linux.so.3 (0x45670000)", "  /lib/ld-linux.so.3 (0x45670000)\n  /lib/ld-linux.so.3 (0x45670000)", 1),
                        log + "\n" + READY, log.replace("entrypoints=false", "entrypoints=true"),
                        log.replace("PHANTOWD_NFS_LOADER_END", "PHANTOWD_NFS_LOADER_UNKNOWN", 1),
                        log.replace("PHANTOWD_NFS_LOADER_BEGIN", "PHANTOWD_NFS_LOADER_BE\rGIN", 1),
                        log.replace("\n", "\r\r\n")):
            with self.subTest(log=changed), self.assertRaises(ValueError):
                checker.verify(changed, union, reports)

    def test_changed_or_incomplete_independent_metadata_refuses(self):
        log, union, reports = fixture()
        for value in (None, [], {}, {ENTRIES[0]: reports[ENTRIES[0]]}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                checker.verify(log, union, value)
        for field, value in (("root_digest_sha256", "d" * 64), ("execution_authorized", True)):
            changed = copy.deepcopy(reports)
            changed[ENTRIES[1]][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                checker.verify(log, union, changed)
        changed = copy.deepcopy(reports)
        changed[ENTRIES[1]]["objects"][1]["sha256"] = "d" * 64
        with self.assertRaises(ValueError):
            checker.verify(log, union, changed)
        changed_union = copy.deepcopy(union)
        changed_union["objects"].pop()
        with self.assertRaises(ValueError):
            checker.verify(log, changed_union, reports)


if __name__ == "__main__":
    unittest.main()
