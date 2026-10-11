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
PEER_EXIT_READY = (
    "PHANTOWD_SAMBA_OWNER_PENDING_PEER_EXIT_READY original_connection=true "
    "actual_peer_stop=true connection_refused=true client_group_absent=true "
    "daemon_group_absent=true review_sticky=true inputs_retained=true "
    "namespaces_retained=true close_refused=true restart_refused=true "
    "local_object_unchanged=true subprocess_disposal=true "
    "parent_fd_equal=true "
    "smb_object_bound=false pending_io=false activation=false scope=qemu-only")
PEER_EXIT_EXPECTED = (*samba.MARKERS[:3], samba.CENSUS_MARKER, ENROLLMENT,
                      PEER_EXIT_READY,
                      "PHANTOWD_SAMBA_ROOT_PENDING_PEER_EXIT_DONE")
HANDLE_READY = READY.replace(
    "PENDING_CLIENT_READY", "PENDING_HANDLE_READY").replace(
    "smb_object_bound=false", "client_handle_observed=true "
    "client_handle_continuity=true client_session_tree_matched=true "
    "smb_object_bound=false")
HANDLE_EXPECTED = (*samba.MARKERS[:3], samba.CENSUS_MARKER, ENROLLMENT,
                   HANDLE_READY, "PHANTOWD_SAMBA_ROOT_PENDING_HANDLE_DONE")


def verify(log, mode="healthy"):
    if mode not in ("healthy", "peer-exit", "handle"):
        raise ValueError("fixed pending-client mode required")
    if not isinstance(log, str) or len(log.encode()) > MAX_LOG:
        raise ValueError("bounded guest evidence required")
    prefixes = ("PHANTOWD_SAMBA_ROOT_", "PHANTOWD_SAMBA_OWNER_",
                "PHANTOWD_PENDING_", "PHANTOWD_SMB_WRITE_CLIENT_",
                "PHANTOWD_RUNTIME_BUNDLE_", "PHANTOWD_DIAG_PENDING_",
                "PHANTOWD_SMB_CLIENT_HANDLE_")
    rows = tuple(line for line in log.splitlines()
                 if line.startswith(prefixes))
    expected = {"healthy": EXPECTED, "peer-exit": PEER_EXIT_EXPECTED,
                "handle": HANDLE_EXPECTED}[mode]
    if rows != expected:
        raise ValueError("ordered healthy-client prerequisite required")
    return samba.scan_cost(log)


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        raise SystemExit("one disposable guest log and fixed mode required")
    mode = sys.argv[2] if len(sys.argv) == 3 else "healthy"
    verify(read_bounded(sys.argv[1], MAX_LOG), mode)
    marker = {"healthy": "HEALTHY", "peer-exit": "PEER_EXIT",
              "handle": "HANDLE"}[mode]
    print(f"PHANTOWD_PENDING_{marker}_LOG_VERIFIED scope=qemu-only "
          "smb_object_bound=false pending_io=false product=false")
