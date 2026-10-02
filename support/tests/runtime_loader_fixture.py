#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Test-only fixed smbd loader differential; never a product manifest owner."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re


MAX_REPORT = 1024 * 1024
MAX_LOG = 512 * 1024
FIXED_ENTRY = "usr/sbin/smbd"


def safe_path(value):
    return (isinstance(value, str) and len(value) <= 4096
            and re.fullmatch(r"[a-zA-Z0-9_./+-]+", value)
            and not value.startswith("/")
            and all(p not in ("", ".", "..") for p in value.split("/"))
            and str(PurePosixPath(value)) == value)


def validate(report, *, fixed_entry=FIXED_ENTRY):
    if fixed_entry not in (
            FIXED_ENTRY, "usr/bin/smbpasswd", "usr/bin/testparm",
            "usr/lib/samba/vfs/streams_xattr.so", "usr/lib/gconv/IBM850.so"):
        raise ValueError("unsupported fixed fixture entry")
    if not isinstance(report, dict):
        raise ValueError("invalid candidate")
    if (report.get("format") != "phantowd-elf-runtime-candidate"
            or type(report.get("schema_version")) is not int
            or report["schema_version"] != 1
            or report.get("entry") != fixed_entry
            or report.get("static_dependencies_resolved") is not True
            or report.get("runtime_qualified") is not False
            or report.get("execution_authorized") is not False):
        raise ValueError("candidate scope refused")
    objects = report.get("objects")
    if not isinstance(objects, list) or not 2 <= len(objects) <= 256:
        raise ValueError("invalid object roster")
    paths, aliases, total, bindings = set(), {}, 0, 0
    for item in objects:
        if not isinstance(item, dict):
            raise ValueError("invalid object")
        name = item.get("path")
        digest, size = item.get("sha256"), item.get("size")
        if (not safe_path(name) or name in paths
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or type(size) is not int or size <= 0):
            raise ValueError("invalid object evidence")
        paths.add(name)
        total += size
        names = item.get("bindings")
        if not isinstance(names, list) or not names:
            raise ValueError("missing bindings")
        for alias in names:
            if not safe_path(alias) or alias in aliases:
                raise ValueError("conflicting binding")
            aliases[alias] = name
            bindings += 1
    if (total > 64 * 1024 * 1024 or bindings > 1024
            or type(report.get("total_bytes")) is not int
            or report["total_bytes"] != total
            or fixed_entry not in paths
            or aliases.get(fixed_entry) != fixed_entry
            or (fixed_entry not in ("usr/lib/samba/vfs/streams_xattr.so",
                                    "usr/lib/gconv/IBM850.so")
                and aliases.get("lib/ld-linux.so.3") != "lib/ld-linux.so.3")):
        raise ValueError("candidate budget or fixed entry refused")
    for name in paths:
        if name in aliases and aliases[name] != name:
            raise ValueError("canonical path conflicts with alias")
        aliases[name] = name
    return objects, aliases, paths - {fixed_entry}


def prepare(report):
    objects, _, _ = validate(report)
    rows = []
    for item in sorted(objects, key=lambda item: item["path"]):
        for binding in sorted(set(item["bindings"] + [item["path"]])):
            rows.append(f"{item['sha256']} /{item['path']} /{binding}\n")
    script = """#!/bin/sh
# Generated test-only PID1; fixed trusted Buildroot loader, never WD input.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
run_fixture() {
    mount -t proc proc /proc || return 1
    mount -t tmpfs -o mode=0755 tmpfs /run || return 1
    [ ! -e /etc/ld.so.preload ] || return 1
    while read -r expected canonical binding; do
        [ "$(readlink -f "$binding")" = "$canonical" ] || return 1
        actual=$(sha256sum "$binding") || return 1
        [ "${actual%% *}" = "$expected" ] || return 1
    done </usr/lib/phantowd/qemu-runtime-loader.manifest
    echo PHANTOWD_RUNTIME_BYTES_READY
    /bin/busybox env -i /lib/ld-linux.so.3 \\
        --inhibit-cache --list /usr/sbin/smbd \\
        >/run/loader-list 2>&1 || { cat /run/loader-list; return 1; }
    echo PHANTOWD_RUNTIME_LOADER_BEGIN
    cat /run/loader-list || return 1
    echo PHANTOWD_RUNTIME_LOADER_END
}
if run_fixture; then
    echo PHANTOWD_RUNTIME_LOADER_DONE
else
    echo PHANTOWD_RUNTIME_LOADER_FAILED
fi
sync
reboot -f
"""
    return script, "".join(rows)


def compare(report, log):
    _, aliases, expected = validate(report)
    if not isinstance(log, str) or len(log.encode()) > MAX_LOG:
        raise ValueError("invalid guest log")
    markers = ("PHANTOWD_RUNTIME_BYTES_READY", "PHANTOWD_RUNTIME_LOADER_BEGIN",
               "PHANTOWD_RUNTIME_LOADER_END", "PHANTOWD_RUNTIME_LOADER_DONE")
    lines = log.splitlines()
    if any(line.startswith("PHANTOWD_RUNTIME_LOADER_FAILED")
           for line in lines):
        raise ValueError("guest refused candidate")
    positions = []
    for marker in markers:
        found = [i for i, line in enumerate(lines) if line == marker]
        if len(found) != 1:
            raise ValueError("incomplete or repeated guest marker")
        positions.append(found[0])
    if positions != sorted(positions):
        raise ValueError("unordered guest markers")
    loaded = set()
    for line in lines[positions[1] + 1:positions[2]]:
        if len(line) > 8192:
            raise ValueError("oversized loader line")
        # Only the kernel-provided virtual DSO has no filesystem binding.
        if re.fullmatch(r"\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)", line):
            continue
        match = re.fullmatch(
            r"\s*(?:[a-zA-Z0-9_.+-]+ => )?(/[a-zA-Z0-9_./+-]+) "
            r"\(0x[0-9a-f]+\)", line)
        if match is None:
            raise ValueError("unrecognized loader resolution")
        path = match[1][1:]
        if not safe_path(path) or path not in aliases:
            raise ValueError("unexpected loader object")
        loaded.add(aliases[path])
    if loaded != expected:
        raise ValueError("loader and candidate rosters differ")
    return len(loaded)


def read_bounded(file, limit):
    with Path(file).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("oversized fixture input")
    return data.decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("candidate")
    prepare_parser.add_argument("output")
    compare_parser = sub.add_parser("compare")
    compare_parser.add_argument("candidate")
    compare_parser.add_argument("log")
    args = parser.parse_args()
    report = json.loads(read_bounded(args.candidate, MAX_REPORT))
    if args.command == "prepare":
        script, manifest = prepare(report)
        output = Path(args.output)
        (output / "init.sh").write_text(script)
        (output / "manifest").write_text(manifest)
    else:
        count = compare(report, read_bounded(args.log, MAX_LOG))
        print("PHANTOWD_RUNTIME_LOADER_MATCH "
              f"dependencies={count} hashes_and_aliases=true "
              "daemon_started=false product_authority=false scope=qemu-only")


if __name__ == "__main__":
    main()
