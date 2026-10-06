#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Actual generic-only producer characterization, never a collection policy."""

import json
from pathlib import Path
import runpy
import subprocess
import sys
import unittest

FIXTURE_PATH = Path(__file__).with_name("smart-replay-corpus.py")
FIXTURE = runpy.run_path(str(FIXTURE_PATH))
command = FIXTURE["command"]
identify = FIXTURE["identify"]
smart_sector = FIXTURE["smart_sector"]
trace = FIXTURE["trace"]


BINARY = None
VERSION = None


def checksum_trace(strict=False, damaged=True):
    sector = bytearray(smart_sector())
    if damaged:
        sector[-1] ^= 1
    if bool(sum(sector) & 255) != damaged:
        raise ValueError("incorrect synthetic checksum fixture")
    text = command("IDENTIFY DEVICE", data=identify())
    text += command("SMART READ ATTRIBUTE VALUES", data=sector)
    # Strict checksum failure exits before subsequent reads/status requests.
    if not (strict and damaged):
        text += command("SMART READ ATTRIBUTE THRESHOLDS", data=smart_sector())
        text += command("SMART STATUS CHECK")
    return text.encode("ascii")


def power_trace(error=None, continued=False):
    if error not in (None, 5, 38):
        raise ValueError("only synthetic EIO/ENOSYS power inputs are admitted")
    text = command("CHECK POWER MODE", -1 if error is not None else 0)
    if error is not None:
        if text.count("errno=5 ") != 1:
            raise ValueError("unexpected synthetic error transcript")
        text = text.replace("errno=5 ", f"errno={error} ", 1)
    return text.encode("ascii") + (trace() if continued else b"")


class ProducerBoundaryTests(unittest.TestCase):
    def producer(self, data, options, expected_exit, passed):
        self.assertLess(len(data), 65536)
        result = subprocess.run(
            [str(BINARY), *options, "-i", "-H", "-"], input=data,
            capture_output=True, timeout=15, check=False,
        )
        self.assertEqual(result.returncode, expected_exit)
        self.assertEqual(result.stderr, b"")
        self.assertGreater(len(result.stdout), 0)
        self.assertLessEqual(len(result.stdout), 65536)
        self.assertNotIn(b"REPLAY-IOCTL", result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report["json_format_version"], [1, 0])
        self.assertEqual(report["smartctl"]["version"], VERSION)
        self.assertIs(report["smartctl"]["pre_release"], False)
        self.assertEqual(report["smartctl"]["exit_status"], expected_exit)
        if passed is None:
            self.assertNotIn("smart_status", report)
        else:
            self.assertIs(report["smart_status"]["passed"], passed)
        return report, result.stdout

    def test_default_checksum_warning_is_not_json_integrity_evidence(self):
        report, raw = self.producer(checksum_trace(), ["--json"], 0, True)
        self.assertNotIn(b"checksum", raw.lower())
        self.assertFalse(report["smartctl"].get("messages"))
        self.assertNotIn("power_mode", report)

    def test_checksum_text_requires_explicit_plaintext_json_option(self):
        report, _ = self.producer(checksum_trace(), ["--json=o"], 0, True)
        output = report["smartctl"]["output"]
        self.assertIsInstance(output, list)
        self.assertTrue(output)
        self.assertTrue(all(isinstance(line, str) for line in output))
        self.assertTrue(any("checksum" in line.lower() for line in output))
        self.assertFalse(report["smartctl"].get("messages"))

    def test_strict_checksum_failure_has_no_health_assessment(self):
        report, raw = self.producer(checksum_trace(strict=True),
                                    ["--json", "-b", "exit"], 4, None)
        self.assertNotIn(b"checksum", raw.lower())
        self.assertFalse(report["smartctl"].get("messages"))

    def test_valid_checksum_control_passes_strict_policy(self):
        self.producer(checksum_trace(strict=True, damaged=False),
                      ["--json", "-b", "exit"], 0, True)

    def test_power_io_error_can_be_labelled_sleep_but_is_not_proof(self):
        report, _ = self.producer(power_trace(error=5),
                                  ["--json", "-n", "standby,3,5"], 3, None)
        self.assertNotIn("smart_support", report)
        if VERSION == [7, 4]:
            self.assertNotIn("power_mode", report)
        else:
            self.assertEqual(report["power_mode"]["ata_value"], -1)
            self.assertEqual(report["power_mode"]["name"], "SLEEP")

    def test_unsupported_power_check_explicit_policy_stops_before_health(self):
        report, _ = self.producer(power_trace(error=38),
                                  ["--json", "-n", "standby,3,5"], 5, None)
        self.assertNotIn("smart_support", report)
        self.assertNotIn("power_mode", report)

    def test_default_unsupported_power_check_can_continue_to_health(self):
        report, _ = self.producer(power_trace(error=38, continued=True),
                                  ["--json", "-n", "standby"], 0, True)
        self.assertNotIn("power_mode", report)

    def test_successful_generic_power_is_hardcoded_not_standby_coverage(self):
        report, _ = self.producer(power_trace(continued=True),
                                  ["--json", "-n", "standby,3,5"], 0, True)
        if VERSION == [7, 4]:
            self.assertNotIn("power_mode", report)
        else:
            self.assertEqual(report["power_mode"]["ata_value"], 255)
            self.assertEqual(report["power_mode"]["name"], "ACTIVE or IDLE")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[2] not in ("7.4", "7.5"):
        raise SystemExit(
            "usage: test-smart-replay-boundaries.py GENERIC_SMARTCTL 7.4|7.5"
        )
    BINARY = Path(sys.argv[1])
    VERSION = [int(part) for part in sys.argv[2].split(".")]
    result = unittest.main(argv=[sys.argv[0]], verbosity=2, exit=False).result
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("PHANTOWD_SMART_BOUNDARY_READY scope=native-generic-synthetic-only "
          f"version={sys.argv[2]} cases={result.testsRun}")
