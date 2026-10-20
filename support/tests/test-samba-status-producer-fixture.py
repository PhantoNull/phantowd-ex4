#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Transcript controls; real producer behavior requires ARM execution."""
import base64
import json
from pathlib import Path
import unittest

import samba_status_producer_fixture as fixture


def encoded(data):
    return base64.b64encode(data).decode("ascii")


PROGRAMS = {"smbstatus": "a" * 64, "tdbtool": "b" * 64,
            "tdbdump": "c" * 64, "smbconf": "e" * 64}
MALFORMED = b'{\nkey(4) = "\\00\\00\\00\\01"\ndata(1) = "\\01"\n}\n'
EMPTY = json.dumps({"version": "4.22.11", "sessions": {}}).encode()


def transcript(fault_exit=1, fault_output=b""):
    def row(case, status, output, dump):
        return (f"PHANTOWD_STATUS_PRODUCER_CASE case={case} exit={status} "
                f"before_sha256={'d' * 64} after_sha256={'d' * 64} "
                f"holder_live=true holder_exit=0 stderr_bytes=0 "
                f"stdout_b64={encoded(output)} "
                f"dump_b64={encoded(dump)}")
    return "\n".join([
        "PHANTOWD_STATUS_PRODUCER_GUARD_READY readonly_root=true "
        "tmpfs_state=true no_daemon=true scope=qemu-only",
        "PHANTOWD_STATUS_PRODUCER_INPUTS " + " ".join(
            f"{name}={value}" for name, value in PROGRAMS.items()),
        row("empty", 0, EMPTY, b""),
        row("malformed", fault_exit, fault_output, MALFORMED),
        "PHANTOWD_STATUS_PRODUCER_DONE cases=2 scope=qemu-only",
    ])


class ProducerTranscriptTests(unittest.TestCase):
    def test_driver_declares_its_validated_ram_scratch_to_qemu(self):
        root = Path(__file__).resolve().parents[2]
        driver = root / "support/tests/test-qemu-samba-status-producer.sh"
        self.assertTrue('export TMPDIR="$scratch"' in driver.read_text(),
                        "QEMU snapshot temporary files lack RAM scratch")

    def test_false_empty_from_malformed_source_is_not_qualified(self):
        with self.assertRaisesRegex(ValueError, "false empty"):
            fixture.verify(transcript(0, EMPTY), PROGRAMS)

    def test_healthy_empty_and_explicit_failure_with_no_output(self):
        fixture.verify(transcript(), PROGRAMS)

    def test_no_partial_stdout_or_timeout_is_accepted_as_refusal(self):
        for code, output in ((1, EMPTY), (124, b""), (137, b""), (0, b"")):
            with self.subTest(code=code, output=bool(output)):
                with self.assertRaises(ValueError):
                    fixture.verify(transcript(code, output), PROGRAMS)

    def test_source_and_holder_evidence_must_be_complete(self):
        good = transcript()
        for bad in (
                good.replace("after_sha256=" + "d" * 64,
                             "after_sha256=" + "e" * 64),
                good.replace("holder_exit=0", "holder_exit=137"),
                good.replace(encoded(MALFORMED), ""),
                good.replace("no_daemon=true", "no_daemon=false"),
                good.replace("cases=2", "cases=1")):
            with self.assertRaises(ValueError):
                fixture.verify(bad, PROGRAMS)

    def test_json_errors_are_not_repaired(self):
        for payload in (b'{"sessions":{},"sessions":{}}', b"\xff",
                        b'{"version":"4.22.11","sessions":null}',
                        b'{"version":"4.22.11","sessions":{},"x":NaN}',
                        b'{"version":"4.22.10","sessions":{}}'):
            with self.assertRaises(ValueError):
                candidate = transcript().replace(encoded(EMPTY),
                                                 encoded(payload))
                fixture.verify(candidate, PROGRAMS)

    def test_input_hashes_case_order_and_trailing_markers_are_exact(self):
        good = transcript()
        lines = good.splitlines()
        for bad in (good.replace("a" * 64, "f" * 64),
                    "\n".join([*lines[:2], lines[3], lines[2], lines[4]]),
                    good + "\n" + lines[4], good + "\n"
                    + "PHANTOWD_STATUS_PRODUCER_UNEXPECTED"):
            with self.assertRaises(ValueError):
                fixture.verify(bad, PROGRAMS)


if __name__ == "__main__":
    unittest.main()
