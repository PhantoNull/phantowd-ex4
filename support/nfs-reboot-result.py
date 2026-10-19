#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Compare complete receipts from the dedicated two-kernel NFS fixture."""
import os
import re
import stat
import sys
import uuid

MAX_LOG = 4 << 20
PREFIX = "PHANTOWD_NFS_REBOOT"
ROW = re.compile(
    r"PHANTOWD_NFS_REBOOT_PHASE_READY phase=(?P<phase>seed|verify) "
    r"boot_id=(?P<boot_id>[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}) "
    r"policy_sha256=(?P<policy_sha256>[0-9a-f]{64}) inode=(?P<inode>[1-9][0-9]{0,19}) "
    r"data_sha256=(?P<data_sha256>[0-9a-f]{64}) "
    r"rw=true ro_denied=true client_denied=true uid=101000 gid=101000 "
    r"kernel_profile=v3-tcp-only kernel_stopped=true fsid_rebind_refused=true "
    r"teardown=true scope=clean-qemu-reboot-only")


def validate_log(data, phase):
    if phase not in ("seed", "verify") or not 0 < len(data) <= MAX_LOG:
        raise ValueError("invalid phase/log size")
    lines = data.decode("utf-8", errors="strict").splitlines()
    rows = [(i, ROW.fullmatch(line)) for i, line in enumerate(lines) if PREFIX in line]
    if len(rows) != 1 or rows[0][1] is None:
        raise ValueError("missing/duplicate/invalid NFS receipt")
    index, match = rows[0]
    proof = match.groupdict()
    if proof["phase"] != phase or int(proof["inode"]) >= 1 << 64 or uuid.UUID(proof["boot_id"]).int == 0:
        raise ValueError("unbound NFS receipt")
    ready = "PHANTOWD_STATE_BOOT_READY phase=" + phase + " scope=disposable-qemu-only"
    ready_positions = [i for i, line in enumerate(lines) if "PHANTOWD_STATE_BOOT_READY" in line]
    restarts = [i for i, line in enumerate(lines) if line.endswith("reboot: Restarting system")]
    if (len(ready_positions) != 1 or lines[ready_positions[0]] != ready or len(restarts) != 1 or
            not index < ready_positions[0] < restarts[0] or
            any(error in line for line in lines for error in ("PHANTOWD_STATE_ERROR", "PHANTOWD_API_ERROR", "Kernel panic"))):
        raise ValueError("incomplete or failed boot")
    return proof


def compare(first, second):
    if (first["phase"] != "seed" or second["phase"] != "verify" or first["boot_id"] == second["boot_id"] or
            any(first[key] != second[key] for key in ("policy_sha256", "inode", "data_sha256"))):
        raise ValueError("reboot identity/policy/data mismatch")


def read_log(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("regular log required")
        return stream.read(MAX_LOG + 1)


def main(args):
    if len(args) != 2:
        raise ValueError("two boot logs required")
    compare(validate_log(read_log(args[0]), "seed"), validate_log(read_log(args[1]), "verify"))
    print("PHANTOWD_NFS_REBOOT_READY boots=2 distinct_kernels=true policy_retained=true data_retained=true "
          "rw=true ro_denied=true client_denied=true uid=101000 gid=101000 "
          "kernel_profile=v3-tcp-only kernel_stopped=true fsid_rebind_refused=true teardown=true scope=clean-qemu-reboot-only")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, KeyError, TypeError):
        print("Synthetic NFS reboot proof refused.", file=sys.stderr)
        sys.exit(1)
