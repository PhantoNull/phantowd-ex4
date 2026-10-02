#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Synthetic ATA stdin replay only. Never accepts a device name or raw capture."""

import json
from pathlib import Path
import struct
import subprocess
import sys


def identify(available=True, enabled=True):
    data = bytearray(512)
    for word, value in ((0, 0x0040), (49, 0x0200), (60, 32768),
                        (82, int(available)), (83, 0x4000),
                        (85, int(enabled)), (87, 0x4000)):
        struct.pack_into("<H", data, word * 2, value)
    for word, width, text in ((10, 20, "SYNTHETIC-ONLY"),
                              (23, 8, "FIXTURE"),
                              (27, 40, "PhantoWD CPU-only replay fixture")):
        raw = text.encode("ascii").ljust(width, b" ")
        data[word * 2:word * 2 + width] = b"".join(
            raw[i:i + 2][::-1] for i in range(0, width, 2))
    return bytes(data)


def smart_sector():
    data = bytearray(512)
    struct.pack_into("<H", data, 0, 1)
    data[-1] = (-sum(data)) & 255
    return bytes(data)


def command(name, result=0, data=None):
    text = f"REPORT-IOCTL: Device=SYNTHETIC Command={name}\n"
    text += f"REPORT-IOCTL: Device=SYNTHETIC Command={name} returned {result}"
    if result < 0:
        text += " errno=5 synthetic error"
    text += "\n"
    if data is not None:
        assert len(data) == 512
        text += f"===== [{name}] DATA START synthetic =====\n"
        for offset in range(0, 512, 16):
            text += f"{offset:3d}-{offset + 15:3d}: "
            text += " ".join(f"{b:02x}" for b in data[offset:offset + 16]) + "\n"
        text += f"===== [{name}] DATA END synthetic =====\n"
    return text


def trace(available=True, enabled=True, failed=False, read_error=False):
    text = command("IDENTIFY DEVICE", data=identify(available, enabled))
    if available and enabled:
        text += command("SMART READ ATTRIBUTE VALUES", -1 if read_error else 0,
                        None if read_error else smart_sector())
        if not read_error:
            text += command("SMART READ ATTRIBUTE THRESHOLDS", data=smart_sector())
        text += command("SMART STATUS CHECK", int(failed))
    return text.encode("ascii")


def run(binary, output):
    # Expected producer results, independent of the Go projection expectations.
    cases = (
        ("pass", trace(), 0, True, True, True),
        ("fail", trace(failed=True), 8, True, True, False),
        ("partial-fail", trace(failed=True, read_error=True), 12, True, True, False),
        ("partial-pass", trace(read_error=True), 4, True, True, True),
        ("unsupported", trace(available=False, enabled=False), 4, False, False, None),
        # Upstream returns the accumulated status (zero here) when SMART is disabled.
        ("disabled", trace(enabled=False), 0, True, False, None),
        ("empty", b"", 2, None, None, None),
    )
    for name, data, exit_status, available, enabled, passed in cases:
        assert len(data) < 65536
        # '-' selects upstream's parsed ATA pseudo-device. -d is deliberately absent.
        result = subprocess.run([str(binary), "-j", "-i", "-H", "-"],
                                input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=15, check=False)
        if result.returncode != exit_status or result.stderr or len(result.stdout) > 65536:
            raise RuntimeError(f"producer boundary failed for {name}: exit={result.returncode}")
        report = json.loads(result.stdout)
        tool = report["smartctl"]
        if (report["json_format_version"] != [1, 0] or tool["version"] != [7, 4]
                or tool["pre_release"] is not False or tool["exit_status"] != exit_status
                or report.get("device", {}).get("protocol") != (None if name == "empty" else "ATA")):
            raise RuntimeError(f"producer profile failed for {name}")
        if b"REPLAY-IOCTL" in result.stdout:
            raise RuntimeError(f"replay coverage/order failed for {name}")
        support = report.get("smart_support", {})
        if name == "empty" and ("device" in report or "smart_support" in report
                                or "smart_status" in report):
            raise RuntimeError("empty input unexpectedly reports device evidence")
        if available is not None and support.get("available") is not available:
            raise RuntimeError(f"support projection failed for {name}")
        if available and support.get("enabled") is not enabled:
            raise RuntimeError(f"enable projection failed for {name}")
        health = report.get("smart_status", {})
        if health.get("passed") is not passed:
            raise RuntimeError(f"health projection failed for {name}")
        # Output contains only invented identities and is private temporary test input.
        (output / f"{name}.json").write_bytes(result.stdout)
        print(f"PHANTOWD_SMART_REPLAY_PRODUCER case={name} exit={result.returncode}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: smart-replay-corpus.py GENERIC_SMARTCTL EMPTY_TEMP_DIR")
    output = Path(sys.argv[2])
    if not output.is_dir() or any(output.iterdir()):
        raise SystemExit("output must be an empty temporary directory")
    run(Path(sys.argv[1]), output)
