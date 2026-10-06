#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

"""Create or initialize one tiny disposable GPT disk for ARMv5 QEMU fixtures."""

import os
import stat
import struct
import sys
import uuid
import zlib


SECTOR_SIZE = 512
SECTOR_COUNT = 32 * 1024 * 1024 // SECTOR_SIZE
ENTRY_COUNT = 128
ENTRY_SIZE = 128
ENTRY_ARRAY_BYTES = ENTRY_COUNT * ENTRY_SIZE
ENTRY_ARRAY_SECTORS = ENTRY_ARRAY_BYTES // SECTOR_SIZE
PARTITION_FIRST_LBA = 2048
PARTITION_LAST_LBA = SECTOR_COUNT - 1 - ENTRY_ARRAY_SECTORS - 1
DEFAULT_DISK_GUID = "fedcba98-7654-3210-fedc-ba9876543210"
DEFAULT_PARTITION_GUID = "8fd20a43-e550-4632-9a8e-5241c40c0861"
DEFAULT_PARTITION_TYPE_GUID = "0fc63daf-8483-4772-8e79-3d69d8477de4"


def write_at(image, offset, data):
    image.seek(offset)
    image.write(data)


def make_entry_array(partition_guid, partition_type_guid):
    entries = bytearray(ENTRY_ARRAY_BYTES)
    type_guid = uuid.UUID(partition_type_guid)
    unique_guid = uuid.UUID(partition_guid)
    entry = struct.pack(
        "<16s16sQQQ72s",
        type_guid.bytes_le,
        unique_guid.bytes_le,
        PARTITION_FIRST_LBA,
        PARTITION_LAST_LBA,
        0,
        bytes(72),
    )
    entries[:ENTRY_SIZE] = entry
    return entries


def make_header(current_lba, backup_lba, entries_lba, entries_crc, disk_guid):
    header = bytearray(SECTOR_SIZE)
    disk_guid = uuid.UUID(disk_guid)
    struct.pack_into(
        "<8sIIIIQQQQ16sQIII",
        header,
        0,
        b"EFI PART",
        0x00010000,
        92,
        0,
        0,
        current_lba,
        backup_lba,
        34,
        SECTOR_COUNT - 1 - ENTRY_ARRAY_SECTORS - 1,
        disk_guid.bytes_le,
        entries_lba,
        ENTRY_COUNT,
        ENTRY_SIZE,
        entries_crc,
    )
    header_crc = zlib.crc32(header[:92]) & 0xFFFFFFFF
    struct.pack_into("<I", header, 16, header_crc)
    return header


def zeroed_file(image):
    image.seek(0)
    remaining = SECTOR_COUNT * SECTOR_SIZE
    while remaining:
        block = image.read(min(1024 * 1024, remaining))
        if not block or any(block):
            return False
        remaining -= len(block)
    return True


def create(path, disk_guid, partition_guid, partition_type_guid):
    if SECTOR_COUNT <= PARTITION_LAST_LBA or PARTITION_LAST_LBA < PARTITION_FIRST_LBA:
        raise ValueError("invalid fixture geometry")
    backup_header_lba = SECTOR_COUNT - 1
    backup_entries_lba = backup_header_lba - ENTRY_ARRAY_SECTORS
    entries = make_entry_array(partition_guid, partition_type_guid)
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF
    protective_mbr = bytearray(SECTOR_SIZE)
    protective_mbr[446 + 4] = 0xEE
    struct.pack_into("<II", protective_mbr, 446 + 8, 1, min(SECTOR_COUNT - 1, 0xFFFFFFFF))
    protective_mbr[510:512] = b"\x55\xaa"

    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size != SECTOR_COUNT * SECTOR_SIZE:
            raise ValueError("existing fixture must be a regular 32 MiB file")
        descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        created = False

    with os.fdopen(descriptor, "r+b", buffering=0) as image:
        if created:
            image.truncate(SECTOR_COUNT * SECTOR_SIZE)
        elif not zeroed_file(image):
            raise ValueError("existing fixture must be entirely zero-filled before GPT initialization")
        write_at(image, 0, protective_mbr)
        write_at(image, 2 * SECTOR_SIZE, entries)
        write_at(image, backup_entries_lba * SECTOR_SIZE, entries)
        write_at(image, SECTOR_SIZE, make_header(1, backup_header_lba, 2, entries_crc, disk_guid))
        write_at(
            image,
            backup_header_lba * SECTOR_SIZE,
            make_header(backup_header_lba, 1, backup_entries_lba, entries_crc, disk_guid),
        )


if __name__ == "__main__":
    if len(sys.argv) == 2:
        create(sys.argv[1], DEFAULT_DISK_GUID, DEFAULT_PARTITION_GUID, DEFAULT_PARTITION_TYPE_GUID)
    elif len(sys.argv) == 5:
        create(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        raise SystemExit(
            "usage: make-qemu-gpt-fixture.py IMAGE [DISK-GUID PARTITION-GUID PARTITION-TYPE-GUID]"
        )
