#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Fixture-only NFS loader differential; never service admission."""
import importlib.util
import json
from pathlib import Path
import re
import sys

import runtime_loader_fixture as runtime_fixture

spec = importlib.util.spec_from_file_location("nfs_code_result", Path(__file__).resolve().parents[1] / "nfs-code-result.py")
bounded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounded)

ENTRIES = ("usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs")
READY = ("PHANTOWD_NFS_LOADER_READY nonroot=true capabilities_zero=true "
         "root_restricted=true private_namespace=true original_code=true "
         "stop_reaped=true fd_balance=true entrypoints=false scope=qemu-only")


def roster(objects):
    result = {}
    for item in objects:
        path = item["path"]
        if path in result:
            raise ValueError("repeated object")
        result[path] = (item["sha256"], item["size"], frozenset(item["bindings"] + [path]))
    return result


def verify(log, union, reports):
    if (not isinstance(log, str) or len(log.encode()) > bounded.MAX_LOG
            or not isinstance(union, dict) or not isinstance(reports, dict)
            or set(reports) != set(ENTRIES)
            or union.get("format") != "phantowd-nfs-runtime-candidate"
            or type(union.get("schema_version")) is not int or union["schema_version"] != 1
            or union.get("expected_entries") != list(ENTRIES)
            or union.get("static_dependencies_resolved") is not True
            or union.get("runtime_qualified") is not False
            or union.get("execution_authorized") is not False
            or not isinstance(union.get("root_digest_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", union["root_digest_sha256"]) is None):
        raise ValueError("fixture scope")
    combined, candidates = {}, {}
    for entry in ENTRIES:
        report = reports[entry]
        objects, aliases, expected = runtime_fixture.validate(report, fixed_entry=entry)
        if report.get("root_digest_sha256") != union["root_digest_sha256"]:
            raise ValueError("different inventory")
        for path, (digest, size, bindings) in roster(objects).items():
            prior = combined.get(path)
            if prior and prior[:2] != (digest, size):
                raise ValueError("changed code")
            combined[path] = (digest, size, bindings | (prior[2] if prior else frozenset()))
        candidates[entry] = aliases, expected
    # Validate the union with the same bounded object rules, independently of
    # the per-entry reports; none of this metadata grants execution authority.
    pseudo = dict(union, format="phantowd-elf-runtime-candidate", entry=ENTRIES[0])
    runtime_fixture.validate(pseudo, fixed_entry=ENTRIES[0])
    if roster(union["objects"]) != combined:
        raise ValueError("union differs")
    lines = [line[:-1] if line.endswith("\r") else line for line in log.split("\n")]
    relevant = [i for i, line in enumerate(lines) if line.startswith("PHANTOWD_NFS_LOADER_")]
    markers = []
    for entry in ENTRIES:
        markers += ["PHANTOWD_NFS_LOADER_BEGIN entry=" + entry, "PHANTOWD_NFS_LOADER_END entry=" + entry]
    markers.append(READY)
    if [lines[i] for i in relevant] != markers:
        raise ValueError("missing duplicate unordered or unknown marker")
    for index, entry in enumerate(ENTRIES):
        aliases, expected = candidates[entry]
        loaded, vdso = set(), False
        for line in lines[relevant[2 * index] + 1:relevant[2 * index + 1]]:
            if len(line) > 8192:
                raise ValueError("loader line budget")
            if re.fullmatch(r"\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)", line):
                if vdso:
                    raise ValueError("duplicate virtual object")
                vdso = True
                continue
            match = re.fullmatch(r"\s*(?:[a-zA-Z0-9_.+-]+ => )?(/[a-zA-Z0-9_./+-]+) \(0x[0-9a-f]+\)", line)
            if match is None or match[1][1:] not in aliases:
                raise ValueError("unknown loader resolution")
            path = aliases[match[1][1:]]
            if path in loaded:
                raise ValueError("duplicate loader resolution")
            loaded.add(path)
        if loaded != expected:
            raise ValueError("loader and expected graph differ")
    return len(ENTRIES)


def main():
    try:
        if len(sys.argv) != 6:
            raise ValueError("arguments")
        log = bounded.read_regular(sys.argv[1], bounded.MAX_LOG).decode("utf-8")
        reports = [json.loads(bounded.read_regular(path, bounded.MAX_REPORT)) for path in sys.argv[2:]]
        verify(log, reports[0], dict(zip(ENTRIES, reports[1:])))
    except (ValueError, OSError, TypeError, KeyError, RecursionError):
        print("NFS loader receipt refused", file=sys.stderr)
        return 1
    print("PHANTOWD_NFS_LOADER_MATCH entries=3 original_code=true entrypoints=false scope=qemu-only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
