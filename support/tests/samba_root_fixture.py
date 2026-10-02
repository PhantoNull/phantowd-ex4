#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Merge three fixed public-runtime candidates for a QEMU-only Samba test."""
import argparse
import json
from pathlib import Path

from runtime_loader_fixture import MAX_LOG, MAX_REPORT, read_bounded, validate


ENTRIES = ("usr/sbin/smbd", "usr/bin/smbpasswd", "usr/bin/testparm")
MARKERS = (
    "PHANTOWD_SAMBA_ROOT_BOUNDARY_READY caps=00000000000000db "
    "nnp=true original_denied=true kernel_ro=true",
    "PHANTOWD_SAMBA_ROOT_POLICY_READY writer_uid=1801 reader_uid=1802 "
    "outsider_denied=true kernel_ro=true original_denied=true "
    "unix_ownership=true unix_denial=true utf8_roundtrip=true scope=qemu-only",
    "PHANTOWD_SAMBA_ROOT_STOPPED", "PHANTOWD_SAMBA_ROOT_DONE",
)


def check_guest(log):
    if not isinstance(log, str) or len(log.encode("utf-8")) > MAX_LOG:
        raise ValueError("oversized guest evidence")
    markers = [line for line in log.splitlines()
               if line.startswith("PHANTOWD_SAMBA_ROOT_")]
    if markers != list(MARKERS):
        raise ValueError("incomplete, failed or repeated guest evidence")


def merge(reports):
    if not isinstance(reports, list) or len(reports) != len(ENTRIES):
        raise ValueError("complete fixed runtime set required")
    objects, aliases = {}, {}
    for entry, report in zip(ENTRIES, reports):
        selected, bindings, _ = validate(report, fixed_entry=entry)
        for name in bindings:
            if (name not in ENTRIES
                    and not name.startswith(("lib/", "usr/lib/"))):
                raise ValueError("runtime overlaps generated fixture state")
        for item in selected:
            evidence = (item["sha256"], item["size"])
            previous = objects.setdefault(item["path"], evidence)
            if previous != evidence:
                raise ValueError("conflicting runtime bytes")
        for alias, canonical in bindings.items():
            previous = aliases.setdefault(alias, canonical)
            if previous != canonical:
                raise ValueError("conflicting runtime alias")
    if (len(objects) > 256 or len(aliases) > 1024
            or sum(size for _, size in objects.values()) > 64 * 1024 * 1024):
        raise ValueError("merged runtime budget exceeded")
    rows = []
    for alias, canonical in sorted(aliases.items()):
        digest, _ = objects[canonical]
        rows.append(f"{digest} /{canonical} /{alias}\n")
    return "".join(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("smbd")
    prepare.add_argument("smbpasswd")
    prepare.add_argument("testparm")
    prepare.add_argument("manifest")
    verify = sub.add_parser("verify")
    verify.add_argument("log")
    args = parser.parse_args()
    if args.command == "prepare":
        reports = [json.loads(read_bounded(name, MAX_REPORT)) for name in (
            args.smbd, args.smbpasswd, args.testparm)]
        Path(args.manifest).write_text(merge(reports))
    else:
        check_guest(read_bounded(args.log, MAX_LOG))
        print("\n".join(MARKERS))


if __name__ == "__main__":
    main()
