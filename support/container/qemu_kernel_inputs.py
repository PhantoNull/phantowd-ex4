#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Fixed QEMU kernel inputs and configuration checks; no build authority."""
import argparse
import hashlib
from pathlib import Path


EXTERNAL_FILES = (
    "configs/phantowd_qemu_armv5_defconfig",
    "board/qemu/armv5/linux-nfs.fragment",
    "board/qemu/armv5/linux-md.fragment",
    "board/qemu/armv5/linux-qemu-rng.fragment",
)
BUILDROOT_FILE = "board/qemu/arm-versatile/linux.fragment"
FRAGMENTS = [BUILDROOT_FILE] + [
    "$(BR2_EXTERNAL_PHANTOWD_EX4_PATH)/" + name for name in EXTERNAL_FILES[1:]]
FRAGMENT_DECLARATION = (
    'BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES="' + " ".join(FRAGMENTS) + '"')
REQUIRED = (
    "CONFIG_EXT4_FS=y", "CONFIG_EXT4_FS_POSIX_ACL=y",
    "CONFIG_TMPFS_POSIX_ACL=y", "CONFIG_MD=y", "CONFIG_MD_RAID1=y",
    "# CONFIG_MD_AUTODETECT is not set",
)


def read_regular(file):
    file = Path(file)
    if file.is_symlink() or not file.is_file():
        raise ValueError("regular kernel input required")
    with file.open("rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("kernel input budget exceeded")
    return data


def fingerprint(external, buildroot):
    config = read_regular(Path(external) / EXTERNAL_FILES[0]).decode("ascii")
    declarations = [line for line in config.splitlines() if line.startswith(
        "BR2_LINUX_KERNEL_CONFIG_FRAGMENT_FILES=")]
    if declarations != [FRAGMENT_DECLARATION]:
        raise ValueError("fixed QEMU kernel fragment roster required")
    digest = hashlib.sha256(b"phantowd-fixed-qemu-kernel-inputs-v1\0")
    for root, name in [*(
            (Path(external), name) for name in EXTERNAL_FILES),
            (Path(buildroot), BUILDROOT_FILE)]:
        data = read_regular(root / name)
        # Stable logical names: different cache/checkout paths are irrelevant.
        digest.update(name.encode() + b"\0")
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


def audit(config):
    lines = read_regular(config).decode("ascii").splitlines()
    for expected in REQUIRED:
        key = expected.split("=", 1)[0].removeprefix("# ").split(" ", 1)[0]
        observed = [line for line in lines if line.startswith(key + "=")
                    or line == f"# {key} is not set"]
        if observed != [expected]:
            raise ValueError(f"QEMU storage kernel requires {expected}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    inputs = sub.add_parser("fingerprint")
    inputs.add_argument("external")
    inputs.add_argument("buildroot")
    check = sub.add_parser("audit")
    check.add_argument("config")
    args = parser.parse_args()
    if args.command == "fingerprint":
        print(fingerprint(args.external, args.buildroot))
    else:
        audit(args.config)


if __name__ == "__main__":
    main()
