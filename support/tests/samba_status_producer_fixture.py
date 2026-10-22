#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Strict transcript oracle for an isolated stock-producer experiment.

This validates synthetic evidence, not product service/source authority.
"""
import argparse
import base64
import json
from pathlib import Path
import re
import stat

MAX_LOG = 1 << 20
MAX_OUTPUT = 8192
PREFIX = "PHANTOWD_STATUS_PRODUCER_"
GUARD = (PREFIX + "GUARD_READY readonly_root=true tmpfs_state=true "
         "no_daemon=true scope=qemu-only")
DONE = PREFIX + "DONE cases=2 scope=qemu-only"
HASH = r"[0-9a-f]{64}"
CASE = re.compile(
    PREFIX + r"CASE case=(empty|malformed) exit=([0-9]{1,3}) "
    r"before_sha256=(" + HASH + r") after_sha256=(" + HASH + r") "
    r"holder_live=true holder_exit=0 stderr_bytes=([0-9]{1,5}) "
    r"stdout_b64=([A-Za-z0-9+/=]{0,10924}) "
    r"dump_b64=([A-Za-z0-9+/=]{0,1368})")
MALFORMED_DUMP = (
    b'{\nkey(4) = "\\00\\00\\00\\01"\ndata(1) = "\\01"\n}\n')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def decoded(text, limit):
    try:
        result = base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid encoded evidence") from exc
    if len(result) > limit or base64.b64encode(result).decode("ascii") != text:
        raise ValueError("noncanonical or excessive encoded evidence")
    return result


def reject_constant(_):
    raise ValueError("nonfinite JSON value")


def empty_sessions(output):
    try:
        value = json.loads(output.decode("utf-8"),
                           object_pairs_hook=unique_object,
                           parse_constant=reject_constant)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid producer JSON") from exc
    return (isinstance(value, dict) and value.get("version") == "4.22.11"
            and type(value.get("sessions")) is dict
            and not value["sessions"])


def verify(log, programs):
    if (not isinstance(log, str) or len(log.encode("utf-8")) > MAX_LOG
            or set(programs) != {"smbstatus", "tdbtool", "tdbdump", "smbconf"}
            or any(not isinstance(value, str) or not re.fullmatch(HASH, value)
                   for value in programs.values())):
        raise ValueError("invalid producer experiment inputs")
    rows = [line for line in log.splitlines() if line.startswith(PREFIX)]
    expected_inputs = PREFIX + "INPUTS " + " ".join(
        f"{name}={programs[name]}" for name in
        ("smbstatus", "tdbtool", "tdbdump", "smbconf"))
    if (len(rows) != 5 or rows[0] != GUARD or rows[1] != expected_inputs
            or rows[-1] != DONE):
        raise ValueError("incomplete, mixed or repeated producer experiment")
    cases = []
    for index, name in enumerate(("empty", "malformed"), 2):
        match = CASE.fullmatch(rows[index])
        if match is None:
            raise ValueError("unsupported producer case")
        case, code, before, after, stderr_bytes, output, dump = match.groups()
        code, stderr_bytes = int(code), int(stderr_bytes)
        if (case != name or code > 255 or stderr_bytes > MAX_OUTPUT
                or before != after):
            raise ValueError("source drift or incomplete producer case")
        output = decoded(output, MAX_OUTPUT)
        dump = decoded(dump, 1024)
        if dump != (b"" if name == "empty" else MALFORMED_DUMP):
            raise ValueError("synthetic source record not established")
        cases.append((code, stderr_bytes, output))
    if cases[0][0] != 0 or cases[0][1] != 0 or not empty_sessions(cases[0][2]):
        raise ValueError("healthy empty producer baseline failed")
    if cases[1][0] == 0 and empty_sessions(cases[1][2]):
        raise ValueError("false empty session inventory from malformed source")
    if cases[1][0] != 1 or cases[1][2]:
        raise ValueError("producer fault must exit1 without partial stdout")


def read_log(path):
    entry = Path(path)
    if not stat.S_ISREG(entry.lstat().st_mode):
        raise ValueError("regular guest log required")
    with entry.open("rb") as source:
        data = source.read(MAX_LOG + 1)
    if len(data) > MAX_LOG:
        raise ValueError("excessive guest log")
    return data.decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("verify")
    check.add_argument("log")
    for name in ("smbstatus", "tdbtool", "tdbdump", "smbconf"):
        check.add_argument(name)
    record = sub.add_parser("record")
    record.add_argument("log")
    record.add_argument("guest_exit", type=int)
    args = parser.parse_args()
    log = read_log(args.log)
    if args.command == "record":
        if not 0 <= args.guest_exit <= 255:
            raise ValueError("invalid guest exit")
        print(json.dumps({"format": "phantowd-status-producer-diagnostic",
                          "schema_version": 2, "qualifying": False,
                          "guest_exit": args.guest_exit, "log": log},
                         ensure_ascii=True, separators=(",", ":")))
    else:
        verify(log, {name: getattr(args, name) for name in
                     ("smbstatus", "tdbtool", "tdbdump", "smbconf")})
        print("Samba producer fixture verified; synthetic guest only")


if __name__ == "__main__":
    main()
