#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

"""Create one tiny disposable GPT disk for the ARMv5 QEMU smoke fixture."""

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


def write_at(image, offset, data):
    image.seek(offset)
    image.write(data)


def make_entry_array():
    entries = bytearray(ENTRY_ARRAY_BYTES)
    type_guid = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
    unique_guid = uuid.UUID("8fd20a43-e550-4632-9a8e-5241c40c0861")
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


def make_header(current_lba, backup_lba, entries_lba, entries_crc):
    header = bytearray(SECTOR_SIZE)
    disk_guid = uuid.UUID("fedcba98-7654-3210-fedc-ba9876543210")
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


def create(path):
    if SECTOR_COUNT <= PARTITION_LAST_LBA or PARTITION_LAST_LBA < PARTITION_FIRST_LBA:
        raise ValueError("invalid fixture geometry")
    backup_header_lba = SECTOR_COUNT - 1
    backup_entries_lba = backup_header_lba - ENTRY_ARRAY_SECTORS
    entries = make_entry_array()
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF
    protective_mbr = bytearray(SECTOR_SIZE)
    protective_mbr[446 + 4] = 0xEE
    struct.pack_into("<II", protective_mbr, 446 + 8, 1, min(SECTOR_COUNT - 1, 0xFFFFFFFF))
    protective_mbr[510:512] = b"\x55\xaa"

    with open(path, "xb", buffering=0) as image:
        image.truncate(SECTOR_COUNT * SECTOR_SIZE)
        write_at(image, 0, protective_mbr)
        write_at(image, 2 * SECTOR_SIZE, entries)
        write_at(image, backup_entries_lba * SECTOR_SIZE, entries)
        write_at(image, SECTOR_SIZE, make_header(1, backup_header_lba, 2, entries_crc))
        write_at(
            image,
            backup_header_lba * SECTOR_SIZE,
            make_header(backup_header_lba, 1, backup_entries_lba, entries_crc),
        )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: make-qemu-gpt-fixture.py IMAGE")
    create(sys.argv[1])
