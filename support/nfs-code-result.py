#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Strict disposable NFS-code receipt; never product execution authority."""
import json
import os
import re
import stat
import sys

MAX_LOG = 4 << 20
MAX_REPORT = 128 << 10
READY = (b"PHANTOWD_NFS_CODE_READY original_pins=true namespace_bound=true "
         b"caller_copy_closed=true normal_fd_balance=true constructor_rollback=true "
         b"non_elf_refused=true same_bytes_overmount_refused=true restored_refused=true "
         b"review_retained=true execution=loader-list-only scope=code-retention-and-loader-list")
DONE = b"PHANTOWD_NFS_CODE_DONE"
COUNTS = re.compile(rb"PHANTOWD_NFS_CODE_COUNTS files=([0-9]{1,3}) aliases=([0-9]{1,4}) bytes=([0-9]{1,8})")


def verify(log, report):
    if len(log) > MAX_LOG or len(report) > MAX_REPORT:
        raise ValueError("log budget")
    expected = json.loads(report)
    if (not isinstance(expected, dict)
            or expected.get("format") != "phantowd-nfs-runtime-candidate"
            or type(expected.get("schema_version")) is not int
            or expected["schema_version"] != 1
            or expected.get("static_dependencies_resolved") is not True
            or expected.get("runtime_qualified") is not False
            or expected.get("execution_authorized") is not False):
        raise ValueError("expected scope")
    objects = expected.get("objects")
    if not isinstance(objects, list) or not 4 <= len(objects) <= 256:
        raise ValueError("object roster")
    if any(not isinstance(item, dict) or not isinstance(item.get("bindings"), list)
           or not item["bindings"] or not all(isinstance(name, str) for name in item["bindings"])
           for item in objects):
        raise ValueError("object bindings")
    sizes = [item.get("size") for item in objects]
    if any(type(size) is not int or size <= 0 for size in sizes):
        raise ValueError("size")
    total = sum(sizes)
    aliases = sum(len(item["bindings"]) - 1 for item in objects)
    if (not 0 < total <= 8 << 20 or type(expected.get("total_bytes")) is not int
            or total != expected["total_bytes"] or not 0 <= aliases <= 1024 - len(objects)):
        raise ValueError("fixture budget")
    seen = []
    for raw in log.split(b"\n"):
        # The serial transport adds ONE terminal CR. Embedded/repeated CR is
        # not stripped and therefore cannot manufacture an accepted marker.
        line = raw[:-1] if raw.endswith(b"\r") else raw
        if not line.startswith(b"PHANTOWD_NFS_CODE_"):
            continue
        match = COUNTS.fullmatch(line)
        if match:
            if tuple(map(int, match.groups())) != (len(objects), aliases, total):
                raise ValueError("counts mismatch")
            seen.append("counts")
        elif line == READY:
            seen.append("ready")
        elif line == DONE:
            seen.append("done")
        else:
            raise ValueError("unknown or failed code receipt")
    if seen != ["counts", "ready", "done"]:
        raise ValueError("incomplete duplicate or reordered receipt")


def read_regular(path, limit):
    before = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
        raise ValueError("regular bounded input required")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as file:
        after = os.fstat(file.fileno())
        if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError("input changed")
        data = file.read(limit + 1)
    if len(data) != before.st_size:
        raise ValueError("input size changed")
    return data


def main():
    try:
        if len(sys.argv) != 3:
            raise ValueError("arguments")
        verify(read_regular(sys.argv[1], MAX_LOG), read_regular(sys.argv[2], MAX_REPORT))
    except (ValueError, OSError, TypeError, KeyError, RecursionError):
        print("NFS code receipt refused", file=sys.stderr)
        return 1
    print("PHANTOWD_NFS_CODE_RECEIPT_READY transport=LF-or-CRLF exact=true scope=code-retention-and-loader-list")
    return 0


if __name__ == "__main__":
    sys.exit(main())
