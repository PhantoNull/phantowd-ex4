#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Bounded synthetic LIO guest result validation, not device authority."""
import argparse
from pathlib import Path
import sys


MARKERS = (
    *(f"PHANTOWD_LIO_CLIENT_READY case={mode}"
      for mode in ("rw", "revoked", "disabled", "reenabled", "wrong", "none", "foreign", "ro", "check",
                   "mutual", "mutual-target-wrong", "mutual-user-wrong", "mutual-inbound-wrong",
                   "mutual-oneway", "rotated-old", "rotated", "peer-cross", "primary-hold", "peer-ro-hold")),
    "PHANTOWD_LIO_MUTUAL_READY exchange=true wrong_target_refused=true wrong_user_refused=true "
    "wrong_inbound_refused=true oneway_still_accepted=true enforcement=false",
    "PHANTOWD_LIO_ROTATION_READY no_active_session=true old_refused=true new_verified=true data_preserved=true durable=false",
    "PHANTOWD_LIO_PEERS_READY concurrent=2 separate_credentials=true cross_credentials_refused=true "
    "primary_readwrite=true peer_readonly=true logout_independent=true data_preserved=true",
    "PHANTOWD_LIO_SESSION_READY observed=true revoked=true admission_disabled=true reenabled_data=true",
    "PHANTOWD_LIO_DESCRIPTOR_READY closed_refused=true missing_refused=true recreated=false",
    "PHANTOWD_LIO_READY chap=true access=ro-rw retained_fd=true replacement_unchanged=true "
    "unlinked_rebind=true size=33554432 block_size=512 write_cache=false teardown=true "
    "scope=disposable-qemu-only",
)
MAX_BYTES = 1024 * 1024
DENIED = ("PHANTOWD_LIO_ERROR", "PHANTOWD_LIO_CLIENT_ERROR", "Kernel panic",
          "synthetic-chap-only-2026", "synthetic-outbound-only-2026",
          "synthetic-rotated-only-2026", "synthetic-peer-only-2026", "deliberately-wrong")


def validate(data):
    if len(data) > MAX_BYTES:
        raise ValueError("LIO guest qualification refused")
    text = data.decode("utf-8", errors="strict")
    lines = text.splitlines()
    if any(token in text for token in DENIED):
        raise ValueError("LIO guest qualification refused")
    if any("PHANTOWD_LIO_" in line and line not in MARKERS for line in lines):
        raise ValueError("LIO guest qualification refused")
    if any(lines.count(marker) != 1 for marker in MARKERS):
        raise ValueError("LIO guest qualification refused")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log")
    args = parser.parse_args()
    try:
        path = Path(args.log)
        if path.is_symlink() or not path.is_file():
            raise ValueError()
        with path.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        validate(data)
    except (OSError, ValueError):
        print("LIO guest qualification refused", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
