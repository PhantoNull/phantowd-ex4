# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Bounded test-only IFUNC dispatch evidence, not CPU or EX4 qualification."""
import pathlib
import re
import sys

OPERATIONS = ("load", "store", "exchange", "compare_exchange", "fetch_add",
              "fetch_sub", "fetch_and", "fetch_or", "fetch_xor")
NAMES = {f"__atomic_{op}_{width}" for width in (1, 2, 4, 8)
         for op in OPERATIONS}
MAX_BYTES = 512 * 1024


def compare(symbols, log, library_size):
    if not 0 < library_size <= 4 * 1024 * 1024:
        raise ValueError("library size outside fixture bounds")
    if len(symbols) > MAX_BYTES or len(log) > MAX_BYTES:
        raise ValueError("fixture evidence exceeds bounds")
    resolvers = {}
    for line in symbols.decode("ascii").splitlines():
        match = re.fullmatch(
            r"\s*\d+:\s+([0-9a-f]+)\s+\d+\s+IFUNC\s+GLOBAL\s+DEFAULT"
            r"\s+\d+\s+(__atomic_\w+)@@LIBATOMIC_1\.0", line)
        if match and match[2] in NAMES:
            if match[2] in resolvers:
                raise ValueError("duplicate dynamic symbol")
            resolvers[match[2]] = int(match[1], 16)
    if set(resolvers) != NAMES:
        raise ValueError("incomplete IFUNC roster")
    lines = [line for line in log.decode("ascii").splitlines()
             if line.startswith("PHANTOWD_ATOMIC_")]
    if len(lines) != 44:
        raise ValueError("incomplete or additional guest evidence")
    environment = re.fullmatch(
        r"PHANTOWD_ATOMIC_ENV uid=1000 caps=0 nnp=1 helper_version=(\d+)",
        lines[0])
    if not environment or int(environment[1]) < 5:
        raise ValueError("missing privilege/kernel-helper evidence")
    seen = set()
    cursor = 1
    for width in (1, 2, 4, 8):
        for operation in OPERATIONS:
            match = re.fullmatch(
                r"PHANTOWD_ATOMIC_SYMBOL name=(__atomic_\w+) "
                r"offset=([0-9a-f]+)",
                lines[cursor])
            expected = f"__atomic_{operation}_{width}"
            if not match or match[1] != expected or expected in seen:
                raise ValueError("unordered or duplicate resolution")
            offset = int(match[2], 16)
            if (not 0 < offset < library_size or
                    (offset & ~1) == (resolvers[expected] & ~1)):
                raise ValueError("unresolved or out-of-bounds implementation")
            seen.add(expected)
            cursor += 1
        if lines[cursor] != (f"PHANTOWD_ATOMIC_WIDTH bytes={width} "
                             "scenarios=50 increments=4000 guards=unchanged"):
            raise ValueError("missing width semantics evidence")
        cursor += 1
    if lines[cursor:] != [
            "PHANTOWD_ATOMIC_READY scope=arm926-qemu-only widths=4 symbols=36",
            "PHANTOWD_ATOMIC_NEGATIVE missing-symbol=refused",
            "PHANTOWD_ATOMIC_DONE"]:
        raise ValueError("missing completion or refusal evidence")


def bounded_read(path):
    with pathlib.Path(path).open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("fixture file exceeds bounds")
    return data


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("SYMBOLS LOG LIBRARY_SIZE required")
        compare(bounded_read(sys.argv[1]), bounded_read(sys.argv[2]),
                int(sys.argv[3]))
        print("PHANTOWD_ATOMIC_COMPARE_PASS symbols=36 scope=arm926-qemu-only")
    except (ValueError, OSError, UnicodeError):
        print("PHANTOWD_ATOMIC_COMPARE_FAILED", file=sys.stderr)
        sys.exit(1)
