#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Closed compared-capture receipts, not a producer/provenance oracle."""
from pathlib import Path
import re
import sys


PARENT = "TestFixedProducerCaptureCompared"
CASES = ("pass", "fail", "partial-fail", "partial-pass", "unsupported",
         "disabled", "empty", "foreign-serial", "foreign-wwn", "source-change")
MARKER = ("PHANTOWD_SMART_ARM_COMPARISON_READY "
          "scope=report-consistency-only source=fake cases=10")


def verify(text):
    lines = text.splitlines()
    if lines.count(MARKER) != 1:
        raise ValueError("comparison marker missing or repeated")
    observed = []
    for line in lines:
        match = re.fullmatch(r"\s*--- PASS: (\S+) \([0-9]+\.[0-9]+s\)", line)
        if match and (match[1] == PARENT or match[1].startswith(PARENT + "/")):
            observed.append(match[1])
        if re.search(r"--- (FAIL|SKIP): " + PARENT + r"(?:/| )", line):
            raise ValueError("comparison test failed or skipped")
    expected = {PARENT, *(PARENT + "/" + case for case in CASES)}
    if len(observed) != len(expected) or set(observed) != expected:
        raise ValueError("comparison receipt catalogue differs")


if __name__ == "__main__":
    try:
        verify(Path(sys.argv[1]).read_text(encoding="utf-8", errors="strict"))
    except (IndexError, OSError, UnicodeError, ValueError):
        sys.exit("SMART compared capture receipts refused")
