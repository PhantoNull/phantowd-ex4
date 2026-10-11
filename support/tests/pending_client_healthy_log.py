#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Separate healthy-client prerequisite; never the default ten-guest union."""
import sys

import samba_root_fixture as samba
from runtime_loader_fixture import MAX_LOG, read_bounded


READY = (
    "PHANTOWD_SAMBA_OWNER_PENDING_CLIENT_READY complete_inputs=true "
    "actual_client=true actual_loader=true single_open=true close_only=true "
    "client_exit0=true client_group_absent=true daemon_stopped=true "
    "caller_duplicates_closed=true local_object_unchanged=true "
    "no_fd_leak=true "
    "server_open_observed=true server_open_continuity=true "
    "local_object_matched=true "
    "connection_original=true connection_continuity=true "
    "retained_namespaces=true "
    "smb_object_bound=false pending_io=false activation=false scope=qemu-only")
ENROLLMENT = next(row for row in samba.MARKERS if row.startswith(
    "PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY"))
EXPECTED = (*samba.MARKERS[:3], samba.CENSUS_MARKER, ENROLLMENT, READY,
            "PHANTOWD_SAMBA_ROOT_PENDING_DONE")


def verify(log):
    if not isinstance(log, str) or len(log.encode()) > MAX_LOG:
        raise ValueError("bounded guest evidence required")
    prefixes = ("PHANTOWD_SAMBA_ROOT_", "PHANTOWD_SAMBA_OWNER_",
                "PHANTOWD_PENDING_", "PHANTOWD_SMB_WRITE_CLIENT_",
                "PHANTOWD_RUNTIME_BUNDLE_", "PHANTOWD_DIAG_PENDING_")
    rows = tuple(line for line in log.splitlines()
                 if line.startswith(prefixes))
    if rows != EXPECTED:
        raise ValueError("ordered healthy-client prerequisite required")
    return samba.scan_cost(log)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("one disposable guest log required")
    verify(read_bounded(sys.argv[1], MAX_LOG))
    print("PHANTOWD_PENDING_HEALTHY_LOG_VERIFIED scope=qemu-only "
          "smb_object_bound=false pending_io=false product=false")
