#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Host parser controls; not execution of a guest or proof of persistence."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("history-reboot-result.py")
SPEC = importlib.util.spec_from_file_location("history_reboot_result", SCRIPT)
result = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(result)
NONCE = "11111111222233334444555555555555"
ROOT = "/run/phantowd-revisionstore-media/phantowd-transaction-fixed"


def proof(phase):
    entries = []
    for i, name in enumerate((".", "policy", "operations", "policy/nas-services.json",
                              "operations/" + "1" * 32 + ".json", "operations/" + "2" * 32 + ".json")):
        directory = i < 3
        entries.append({"name": name, "data": None if directory else base64.b64encode(b"{}").decode(),
                        "inode": i + 10, "mode": 0o40700 if directory else 0o100600, "uid": 0, "gid": 0,
                        "links": (4 if i == 0 else 2) if directory else 1, "size": 4096 if directory else 2,
                        "atime_sec": 1, "atime_nsec": 0, "mtime_sec": 1, "mtime_nsec": 0,
                        "ctime_sec": 1, "ctime_nsec": 0})
    entries.sort(key=lambda entry: entry["name"])
    return {"version": 1, "phase": phase, "nonce": NONCE,
            "boot_id": ("11111111" if phase == "produce" else "aaaaaaaa") + "-2222-3333-4444-555555555555",
            "pid": 123, "root": ROOT, "entries": entries}


def log(phase):
    value = proof(phase)
    return ("ordinary kernel log\nPHANTOWD_HISTORY_REBOOT_PREPARED phase=" + phase + " scope=qemu-only\n"
            "=== RUN   TestRuntimeHistoryAcrossCleanReboot\nPHANTOWD_HISTORY_REBOOT_RECORD " + json.dumps(value) +
            "\n--- PASS: TestRuntimeHistoryAcrossCleanReboot (0.1s)\nPASS\n"
            "PHANTOWD_HISTORY_REBOOT_DONE phase=" + phase + " pid=123 normal_unmount=true scope=qemu-only\n").encode()


class RebootResult(unittest.TestCase):
    def test_every_required_log_line_is_unique_and_ordered(self):
        for phase in ("produce", "observe"):
            wire = log(phase)
            lines = wire.splitlines(keepends=True)
            for index in range(1, len(lines)):
                for bad in (b"".join(lines[:index] + lines[index + 1:]),
                            b"".join(lines[:index] + [lines[index], lines[index]] + lines[index + 1:])):
                    with self.subTest(phase=phase, index=index), self.assertRaises(ValueError):
                        result.validate_log(bad, phase, NONCE)
            reordered = lines[:]
            reordered[2], reordered[3] = reordered[3], reordered[2]
            with self.assertRaises(ValueError):
                result.validate_log(b"".join(reordered), phase, NONCE)
            for suffix in (b"--- PASS: Foreign (1s)\n", b"testing: warning: no tests to run\n", b"FAIL\n",
                           b"Kernel panic\n", b"runtime error:\n", b"WARNING: DATA RACE\n", b"\xff"):
                with self.assertRaises(ValueError):
                    result.validate_log(wire + suffix, phase, NONCE)

    def test_exact_file_bytes_and_stable_metadata_cannot_drift(self):
        first, second = proof("produce"), proof("observe")
        for index, entry in enumerate(second["entries"]):
            for field in entry:
                bad = copy.deepcopy(second)
                if field == "data":
                    bad["entries"][index][field] = "W10=" if entry[field] is not None else ""
                elif field == "name":
                    bad["entries"][index][field] += "x"
                else:
                    bad["entries"][index][field] += 1
                with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                    result.compare(first, bad, NONCE)

    def test_strict_bounded_json_and_complete_metadata(self):
        value = proof("produce")
        wire = json.dumps(value).encode()
        self.assertEqual(result.decode_proof(wire + b" " * (result.MAX_PROOF - len(wire)), "produce", NONCE), value)
        for bad in (wire + b" " * (result.MAX_PROOF + 1 - len(wire)), wire + wire, b"", b"\xff",
                    wire.replace(b'"pid": 123', b'"pid": 123,"pid": 123'),
                    wire.replace(b'"inode": 10', b'"inode": 10,"inode": 10')):
            with self.assertRaises(ValueError):
                result.decode_proof(bad, "produce", NONCE)
        for field in value:
            bad = copy.deepcopy(value)
            del bad[field]
            with self.assertRaises(ValueError):
                result.validate_proof(bad, "produce", NONCE)
        for changed in ({"version": True}, {"version": 2}, {"pid": True}, {"pid": 0}, {"extra": 1},
                        {"entries": value["entries"][:-1]}, {"entries": value["entries"][::-1]}):
            bad = copy.deepcopy(value)
            bad.update(changed)
            with self.assertRaises(ValueError):
                result.validate_proof(bad, "produce", NONCE)
        for field in value["entries"][0]:
            bad = copy.deepcopy(value)
            del bad["entries"][0][field]
            with self.assertRaises(ValueError):
                result.validate_proof(bad, "produce", NONCE)
        good_log = log("produce")
        result.validate_log(good_log + b" " * (result.MAX_LOG - len(good_log)), "produce", NONCE)
        with self.assertRaises(ValueError):
            result.validate_log(good_log + b" " * (result.MAX_LOG + 1 - len(good_log)), "produce", NONCE)

    def test_cli_requires_both_complete_receipts(self):
        with tempfile.TemporaryDirectory(prefix="phantowd-reboot-result-") as directory:
            root = Path(directory)
            first, second, raw = root / "first.json", root / "second.json", root / "guest.log"
            first.write_text(json.dumps(proof("produce")), encoding="utf-8")
            second.write_text(json.dumps(proof("observe")), encoding="utf-8")
            raw.write_bytes(log("produce"))
            for args in (("log", "produce", NONCE, str(raw)), ("bindings", NONCE, str(first)),
                         ("compare", NONCE, str(first), str(second))):
                completed = subprocess.run([sys.executable, "-B", str(SCRIPT), *args], capture_output=True, timeout=5)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, b"")
            second.write_text(json.dumps(proof("produce")), encoding="utf-8")
            for args in (("compare", NONCE, str(first), str(second)), ("foreign",),
                         ("log", "produce", NONCE, str(root / "missing"))):
                completed = subprocess.run([sys.executable, "-B", str(SCRIPT), *args], capture_output=True, timeout=5)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, b"")
                self.assertEqual(completed.stderr.replace(b"\r\n", b"\n"), b"Synthetic history reboot proof refused.\n")

    def test_complete_boot_log_requires_ordered_bound_evidence(self):
        for phase in ("produce", "observe"):
            wire = log(phase)
            self.assertEqual(result.validate_log(wire, phase, NONCE), proof(phase))
            self.assertEqual(result.validate_log(wire.replace(b"\n", b"\r\n"), phase, NONCE), proof(phase))
            for bad in (b"", wire.replace(b"pid=123", b"pid=124"), wire.replace(b"\nPASS\n", b"\n"),
                        wire.replace(b"--- PASS:", b"--- SKIP:"), wire + b"PHANTOWD_FOREIGN_READY\n",
                        wire.replace(b"normal_unmount=true", b"normal_unmount=false")):
                with self.subTest(phase=phase, wire=bad[:80]), self.assertRaises(ValueError):
                    result.validate_log(bad, phase, NONCE)

    def test_same_snapshot_requires_two_distinct_bound_boots(self):
        first, second = proof("produce"), proof("observe")
        result.compare(first, second, NONCE)
        for field, value in (("boot_id", first["boot_id"]), ("root", ROOT + "x"), ("nonce", "f" * 32)):
            bad = copy.deepcopy(second)
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                result.compare(first, bad, NONCE)


if __name__ == "__main__":
    unittest.main()
