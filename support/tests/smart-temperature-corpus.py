#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Separate attribute-temperature profile; never a device or raw capture."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location(
    "health_fixture", Path(__file__).with_name("smart-replay-corpus.py"))
HEALTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HEALTH)


def fixture_cases():
    for name, raw, expected in (("reported", 37, 37),
                                ("zero-omitted", 0, None),
                                ("upper", 127, 127),
                                ("invalid-omitted", 255, None)):
        sector = bytearray(HEALTH.smart_sector())
        # Invented ATA attribute 194: ID, flags, normalized/worst, six raw
        # bytes, reserved. No vendor drive profile or threshold is imported.
        sector[2:14] = bytes((194, 2, 0, 100, 100, raw, 0, 0, 0, 0, 0, 0))
        sector[-1] = 0
        sector[-1] = (-sum(sector)) & 255
        trace = HEALTH.command("IDENTIFY DEVICE", data=HEALTH.identify())
        trace += HEALTH.command("SMART READ ATTRIBUTE VALUES", data=sector)
        trace += HEALTH.command("SMART READ ATTRIBUTE THRESHOLDS",
                                data=HEALTH.smart_sector())
        trace += HEALTH.command("SMART STATUS CHECK")
        yield name, trace.encode("ascii"), expected


def run(binary, output, version):
    for name, trace, expected in fixture_cases():
        result = subprocess.run(
            [str(binary), "-j", "-i", "-H", "-A", "-"], input=trace,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
            check=False)
        if (result.returncode != 0 or result.stderr
                or not 0 < len(result.stdout) <= 65536
                or b"REPLAY-IOCTL" in result.stdout):
            raise RuntimeError("temperature producer boundary failed: " + name)
        report = json.loads(result.stdout)
        tool = report["smartctl"]
        temperature = report.get("temperature", {})
        if (report["json_format_version"] != [1, 0]
                or tool["version"] != version
                or tool["pre_release"] is not False
                or tool["exit_status"] != 0
                or report["device"]["protocol"] != "ATA"
                or report["smart_status"]["passed"] is not True
                or temperature.get("current") != expected
                or (expected is None and "current" in temperature)):
            raise RuntimeError(
                "temperature producer projection failed: " + name)
        (output / (name + ".json")).write_bytes(result.stdout)
        print("PHANTOWD_SMART_TEMPERATURE_PRODUCER case=" + name + " exit=0")


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[3] not in ("7.4", "7.5"):
        raise SystemExit("usage: smart-temperature-corpus.py GENERIC_SMARTCTL "
                         "EMPTY_TEMP_DIR 7.4|7.5")
    output = Path(sys.argv[2])
    if not output.is_dir() or any(output.iterdir()):
        raise SystemExit("output must be an empty temporary directory")
    if sys.argv[1] == "--traces":
        for name, trace, _ in fixture_cases():
            (output / (name + ".trace")).write_bytes(trace)
        print("PHANTOWD_SMART_TEMPERATURE_TRACES_READY cases=4")
    else:
        run(Path(sys.argv[1]), output,
            [int(part) for part in sys.argv[3].split(".")])
