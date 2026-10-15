#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Pure invented ATA input checks; does not run a producer, device or QEMU."""

from pathlib import Path
from contextlib import redirect_stdout
import io
import json
import runpy
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

FIXTURE_PATH = Path(__file__).with_name("smart-replay-corpus.py")
FIXTURE = runpy.run_path(str(FIXTURE_PATH))
ROOT = Path(__file__).resolve().parents[2]


class IdentifyInputTests(unittest.TestCase):
    def test_identity_words_and_support_bits_are_independent(self):
        for available in (False, True):
            for enabled in (False, True):
                with self.subTest(available=available, enabled=enabled):
                    data = FIXTURE["identify"](available, enabled)
                    self.assertEqual(len(data), 512)
                    words = struct.unpack("<256H", data)
                    self.assertEqual(words[82], int(available))
                    self.assertEqual(words[85], int(enabled))
                    self.assertEqual(words[87], 0x4100)
                    self.assertEqual(words[108:112],
                                     (0x5abc, 0xdef1, 0x2345, 0x6789))
                    # Independent literal oracle for upstream's ATA words.
                    self.assertEqual((words[108] & 0xfff) * 4096
                                     + words[109] // 16, 11259375)
                    self.assertEqual((words[109] & 15) * 4294967296
                                     + words[110] * 65536 + words[111],
                                     4886718345)
                    serial = data[20:40]
                    decoded = b"".join(serial[i:i+2][::-1]
                                       for i in range(0, 20, 2))
                    self.assertEqual(decoded, b"SYNTHETIC-ONLY      ")

    def test_original_seven_case_health_and_exit_contract_remains(self):
        cases = FIXTURE["fixture_cases"]()
        self.assertEqual([(case[0], case[2]) for case in cases],
                         [("pass", 0), ("fail", 8), ("partial-fail", 12),
                          ("partial-pass", 4), ("unsupported", 4),
                          ("disabled", 0), ("empty", 2)])
        for name, data, *_ in cases:
            with self.subTest(name=name):
                self.assertLess(len(data), 65536)
                if name == "empty":
                    self.assertEqual(data, b"")
                else:
                    self.assertEqual(data.count(b"DATA START synthetic"),
                                     1 if name in (
                                         "unsupported", "disabled",
                                         "partial-fail", "partial-pass")
                                     else 3)


class WorkflowRoutingTests(unittest.TestCase):
    @staticmethod
    def event_entries(workflow, event):
        lines = (ROOT / ".github/workflows" / workflow).read_text(
            encoding="utf-8").splitlines()
        start = lines.index(f"  {event}:")
        result = []
        for line in lines[start + 1:]:
            if line.startswith("  ") and not line.startswith("   "):
                break
            result.append(line)
        return result

    def test_pure_input_test_is_host_only_for_both_events(self):
        entry = "      - 'support/tests/test-smart-replay-identify.py'"
        for event in ("push", "pull_request"):
            for workflow in ("host-tools.yml", "qemu-armv5.yml",
                             "ex4-stage-b3.yml"):
                with self.subTest(event=event, workflow=workflow):
                    entries = self.event_entries(workflow, event)
                    self.assertEqual(entries.count(entry), 1)
                    self.assertIn("    paths:" if workflow == "host-tools.yml"
                                  else "    paths-ignore:", entries)
        workflow = (ROOT / ".github/workflows/host-tools.yml").read_text(
            encoding="utf-8")
        self.assertIn(
            "run: python3 -B support/tests/test-smart-replay-identify.py",
            workflow)

    def test_actual_producer_fixture_still_requires_qemu(self):
        for event in ("push", "pull_request"):
            entries = self.event_entries("qemu-armv5.yml", event)
            self.assertNotIn(
                "      - 'support/tests/smart-replay-corpus.py'", entries)
            self.assertNotIn("      - 'src/phantowd-api/**'", entries)


class ProjectionGuardTests(unittest.TestCase):
    """Runner acceptance controls with fake replies, NOT producer execution."""

    @staticmethod
    def report(case):
        name, _, exit_status, available, enabled, passed = case
        result = {
            "json_format_version": [1, 0],
            "smartctl": {"version": [7, 5], "pre_release": False,
                         "exit_status": exit_status},
        }
        if name != "empty":
            result.update({
                "device": {"protocol": "ATA"},
                "serial_number": "SYNTHETIC-ONLY",
                "wwn": {"naa": 5, "oui": 11259375, "id": 4886718345},
                "smart_support": {"available": available, "enabled": enabled},
            })
        if passed is not None:
            result["smart_status"] = {"passed": passed}
        return result

    def test_seven_cases_reach_projection_guard_with_fake_replies(self):
        cases = FIXTURE["fixture_cases"]()
        replies = [subprocess.CompletedProcess(
            [], case[2], json.dumps(self.report(case)).encode("ascii"), b"")
            for case in cases]
        with tempfile.TemporaryDirectory(
                prefix="phantowd-smart-input-") as temp:
            with mock.patch.object(FIXTURE["subprocess"], "run",
                                   side_effect=replies) as execute:
                # Never emit actual-producer-looking markers from fake replies.
                with redirect_stdout(io.StringIO()):
                    FIXTURE["run"](Path("NOT-A-PRODUCER"), Path(temp), [7, 5])
            self.assertEqual(execute.call_count, 7)
            self.assertEqual(sorted(p.name for p in Path(temp).iterdir()),
                             sorted(case[0] + ".json" for case in cases))
            for call, case in zip(execute.call_args_list, cases):
                self.assertEqual(call.args[0],
                                 ["NOT-A-PRODUCER", "-j", "-i", "-H", "-"])
                self.assertEqual(call.kwargs["input"], case[1])
                self.assertEqual(call.kwargs["timeout"], 15)

    def test_identity_loss_or_change_refuses_before_report_write(self):
        for field, value in (
                ("serial_number", "DIFFERENT-SYNTHETIC"),
                ("serial_number", None), ("serial_number", ""),
                ("wwn", {"naa": 5, "oui": 11259375, "id": 4886718344}),
                ("wwn", {"naa": 5, "id": 4886718345}),
                ("wwn", None)):
            with self.subTest(field=field, value=value):
                report = self.report(FIXTURE["fixture_cases"]()[0])
                report[field] = value
                reply = subprocess.CompletedProcess(
                    [], 0, json.dumps(report).encode("ascii"), b"")
                with tempfile.TemporaryDirectory(
                        prefix="phantowd-smart-input-") as temp:
                    with mock.patch.object(FIXTURE["subprocess"], "run",
                                           return_value=reply) as execute:
                        with self.assertRaisesRegex(
                                RuntimeError, "producer identity projection"):
                            FIXTURE["run"](Path("NOT-A-PRODUCER"), Path(temp),
                                           [7, 5])
                    self.assertEqual(execute.call_count, 1)
                    self.assertEqual(list(Path(temp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
