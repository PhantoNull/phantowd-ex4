#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Audit a disposable LIO kernel profile; never authorizes target activation."""
import argparse
from pathlib import Path


ENABLED = (
    "ARM", "CPU_ARM926T", "AEABI", "PROC_FS", "SYSFS", "TMPFS",
    "INET", "SCSI", "SCSI_SYM53C8XX_2", "EXT4_FS", "CONFIGFS_FS",
    "TARGET_CORE", "TCM_FILEIO", "ISCSI_TARGET", "CRYPTO_MD5",
)
DISABLED = ("TCM_IBLOCK", "TCM_PSCSI", "TCM_USER2", "LOOPBACK_TARGET",
            "ISCSI_TCP", "ISCSI_BOOT_SYSFS")


def audit(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular LIO research config required")
    with path.open("rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("LIO research config budget exceeded")
    lines = data.decode("ascii").splitlines()
    for symbol in (*ENABLED, *DISABLED):
        key = "CONFIG_" + symbol
        expected = key + "=y" if symbol in ENABLED else f"# {key} is not set"
        observed = [line for line in lines if line.startswith(key + "=")
                    or line == f"# {key} is not set"]
        # Kconfig omits disabled symbols whose dependencies are unavailable
        # (e.g. TCM_USER2 without UIO). Absence is not an enabled backend.
        permitted = ([expected],) if symbol in ENABLED else ([], [expected])
        if observed not in permitted:
            raise ValueError(f"LIO research profile requires {expected}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config")
    args = parser.parse_args()
    audit(args.config)


if __name__ == "__main__":
    main()
