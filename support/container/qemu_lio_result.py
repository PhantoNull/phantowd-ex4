#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Bounded synthetic LIO guest result validation, not device authority."""
import argparse
from pathlib import Path
import sys


MARKERS = (
    "PHANTOWD_LIO_CREDENTIALS_READY root_only_claim=true typed_fixed_attributes=true same_configfs_acl_refused=true exact_readback=true "
    "chap=true mutual_exchange=true wrong_secret_refused=true missing_secret_refused=true stale_outbound_cleared=true "
    "restored_drift_review=true no_retry=true teardown_before_release=true data_luns=0 scope=disposable-qemu-only",
    *(f"PHANTOWD_LIO_CLIENT_READY case={mode}"
      for mode in ("rw", "revoked", "disabled", "reenabled", "wrong", "none", "foreign", "ro", "check",
                   "mutual", "mutual-target-wrong", "mutual-user-wrong", "mutual-inbound-wrong",
                   "mutual-oneway", "rotated-old", "rotated", "peer-cross", "primary-hold", "peer-ro-hold",
                   "multi-primary", "multi-peer", "multi-primary-check")),
    "PHANTOWD_LIO_MUTUAL_READY exchange=true wrong_target_refused=true wrong_user_refused=true "
    "wrong_inbound_refused=true oneway_still_accepted=true enforcement=false",
    "PHANTOWD_LIO_ROTATION_READY no_active_session=true old_refused=true new_verified=true data_preserved=true durable=false",
    "PHANTOWD_LIO_PEERS_READY concurrent=2 separate_credentials=true cross_credentials_refused=true "
    "primary_readwrite=true peer_readonly=true logout_independent=true data_preserved=true",
    "PHANTOWD_LIO_LUNS_READY count=2 block_sizes=512,4096 primary_luns=0,1 peer_luns=0,3 "
    "opposite_access=true ungranted_refused=true data_isolated=true teardown=true scope=disposable-qemu-only",
    "PHANTOWD_LIO_SESSION_READY observed=true revoked=true admission_disabled=true reenabled_data=true",
    "PHANTOWD_LIO_DESCRIPTOR_READY closed_refused=true missing_refused=true recreated=false",
    "PHANTOWD_LIO_READY chap=true access=ro-rw retained_fd=true replacement_unchanged=true "
    "unlinked_rebind=true size=33554432 block_size=512 write_cache=false teardown=true "
    "scope=disposable-qemu-only",
)
MAX_BYTES = 1024 * 1024
STRICT_MARKERS = tuple(
    marker.replace("case=mutual-oneway", "case=mutual-oneway-refused")
    if marker == "PHANTOWD_LIO_CLIENT_READY case=mutual-oneway" else
    marker.replace("oneway_still_accepted=true enforcement=false", "oneway_refused=true enforcement=login-when-configured")
    for marker in MARKERS
)
DENIED = ("PHANTOWD_LIO_ERROR", "PHANTOWD_LIO_CLIENT_ERROR", "Kernel panic",
          "synthetic-chap-only-2026", "synthetic-outbound-only-2026",
          "synthetic-rotated-only-2026", "synthetic-peer-only-2026", "deliberately-wrong")
IDLE_MARKERS = (
    "PHANTOWD_LIO_TARGET_SESSION_READY active_stop_refused=true same_client_readwrite=true complete_resources_retained=true "
    "owner_review=true no_retry=true logout_not_recovery=true independent_fixture_disposal=true scope=disposable-qemu-only",
    "PHANTOWD_LIO_TARGET_ACCESS_READY peers=2 separate_credentials=true primary_readwrite=true peer_readonly=true "
    "ungranted_refused=true cross_credentials_refused=true foreign_refused=true original_data_preserved=true scope=disposable-qemu-only",
    "PHANTOWD_LIO_TARGET_READY complete_roster=true luns=0,7 block_sizes=512,4096 actual_mount_owner=true "
    "proc_fd_binding=true chap=true exact_data=true write_only_open_modes=true active_attribute_checks=true later_member_drift=true "
    "uncertain_retains_all=true no_retry=true idle_teardown_before_release=true scope=disposable-qemu-only",
    "PHANTOWD_LIO_CLIENT_READY case=idle-disabled",
    "PHANTOWD_LIO_CLIENT_READY case=idle-reenabled",
    "PHANTOWD_LIO_IDLE_READY active_refused=true session_io_survived=true idle_disabled=true "
    "new_logins_refused=true rtpi_released=true reenabled_data=true invalid_refused=true scope=disposable-qemu-only",
)


def validate(data, required_mutual=False, idle_guard=False):
    if len(data) > MAX_BYTES:
        raise ValueError("LIO guest qualification refused")
    text = data.decode("utf-8", errors="strict")
    lines = text.splitlines()
    expected = STRICT_MARKERS if required_mutual else MARKERS
    if idle_guard:
        expected += IDLE_MARKERS
    if any(token in text for token in DENIED):
        raise ValueError("LIO guest qualification refused")
    if any("PHANTOWD_LIO_" in line and line not in expected for line in lines):
        raise ValueError("LIO guest qualification refused")
    if any(lines.count(marker) != 1 for marker in expected):
        raise ValueError("LIO guest qualification refused")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log")
    parser.add_argument("--required-mutual", action="store_true")
    parser.add_argument("--idle-guard", action="store_true")
    args = parser.parse_args()
    try:
        path = Path(args.log)
        if path.is_symlink() or not path.is_file():
            raise ValueError()
        with path.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        validate(data, args.required_mutual, args.idle_guard)
    except (OSError, ValueError):
        print("LIO guest qualification refused", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
