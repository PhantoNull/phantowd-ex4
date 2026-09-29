#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Regular-file-only integration tests; no loop devices or mounts."""
import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
import zlib

binary = pathlib.Path(sys.argv[1]).resolve(strict=True)


def probe(source, expected, *args):
    result = subprocess.run([str(binary), *args], stdin=source,
                            capture_output=True, timeout=8, check=False)
    if expected is None:
        assert result.returncode == 1 and not result.stdout, result
        assert result.stderr == b"volume metadata probe failed\n", result
        return None
    assert result.returncode == 0 and not result.stderr, (getattr(source, "name", source), result)
    assert len(result.stdout) < 64 * 1024
    observed = json.loads(result.stdout)
    assert observed["schema_version"] == 2
    assert observed["status"] == expected, observed
    assert observed["source_kind"] == "regular-image"
    assert observed["partition_table"] in ("", "gpt", "dos"), observed
    assert isinstance(observed["partition_table_id"], str), observed
    assert isinstance(observed["partitions"], list), observed
    if not observed["partition_table"]:
        assert observed["partition_table_id"] == "" and observed["partitions"] == [], observed
    for field in ("mount_performed", "compatibility_qualified", "activation_allowed"):
        assert observed[field] is False
    return observed


def synthetic_xfs_header():
    """Probe-only v4 geometry, not a mountable XFS image.

    Layout and consistency checks follow pinned util-linux 2.40.4
    libblkid/src/superblocks/xfs.c. No upstream code or disk dump is copied.
    The first 512 bytes do not overlap the ext superblock at offset 1024.
    """
    header = bytearray(512)
    header[:4] = b"XFSB"
    struct.pack_into(">I", header, 4, 4096)  # block size
    struct.pack_into(">Q", header, 8, 4096)  # data blocks: 16 MiB
    header[32:48] = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    struct.pack_into(">III", header, 80, 1, 4096, 1)  # realtime size, AG size/count
    struct.pack_into(">HHHH", header, 100, 4, 512, 256, 16)
    header[120:125] = bytes((12, 9, 8, 4, 12))  # log2 geometry
    return header


def synthetic_gpt(path, *, backup_partition_guid=None,
                  partition_start=34, partition_end=None,
                  sector_count=128):
    """Build a mirrored, CRC-valid GPT image; it is never mounted."""
    sector_size = 512
    disk_guid = uuid.UUID("fedcba98-7654-3210-fedc-ba9876543210")
    part_guid = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
    type_guid = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
    backup_part_guid = backup_partition_guid or part_guid
    partition_end = partition_end if partition_end is not None else partition_start + 15
    entries_lbas = 32
    primary_entries_lba = 2
    backup_header_lba = sector_count - 1
    backup_entries_lba = backup_header_lba - entries_lbas
    first_usable_lba = primary_entries_lba + entries_lbas
    last_usable_lba = backup_entries_lba - 1

    entry = struct.pack("<16s16sQQQ72s", type_guid.bytes_le, part_guid.bytes_le,
                        partition_start, partition_end, 0, bytes(72))
    entries = entry + bytes((128 - 1) * 128)
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF
    backup_entry = struct.pack("<16s16sQQQ72s", type_guid.bytes_le,
                               backup_part_guid.bytes_le, partition_start,
                               partition_end, 0, bytes(72))
    backup_entries = backup_entry + bytes((128 - 1) * 128)
    backup_entries_crc = zlib.crc32(backup_entries) & 0xFFFFFFFF
    # Protective MBR covering every LBA after LBA 0.
    mbr = bytearray(sector_size)
    struct.pack_into("<B3sB3sII", mbr, 446, 0, bytes(3), 0xEE, bytes(3),
                     1, sector_count - 1)
    mbr[510:512] = b"\x55\xaa"

    def header(current_lba, alternate_lba, entries_lba):
        data = bytearray(sector_size)
        struct.pack_into("<8sIIIIQQQQ16sQIII", data, 0, b"EFI PART", 0x00010000,
                         92, 0, 0, current_lba, alternate_lba,
                         first_usable_lba, last_usable_lba, disk_guid.bytes_le,
                         entries_lba, 128, 128, entries_crc)
        crc = zlib.crc32(data[:92]) & 0xFFFFFFFF
        struct.pack_into("<I", data, 16, crc)
        return data

    backup_header = header(backup_header_lba, 1, backup_entries_lba)
    struct.pack_into("<I", backup_header, 88, backup_entries_crc)
    struct.pack_into("<I", backup_header, 16, 0)
    struct.pack_into("<I", backup_header, 16, zlib.crc32(backup_header[:92]) & 0xFFFFFFFF)
    with path.open("wb") as output:
        # truncate keeps the >2 GiB fixture sparse on filesystems that support
        # holes. Only metadata sectors are physically written.
        output.truncate(sector_count * sector_size)
        output.seek(0)
        output.write(mbr)
        output.seek(primary_entries_lba * sector_size)
        output.write(entries)
        output.seek(backup_entries_lba * sector_size)
        output.write(backup_entries)
        output.seek(sector_size)
        output.write(header(1, backup_header_lba, primary_entries_lba))
        output.seek(backup_header_lba * sector_size)
        output.write(backup_header)


def write_gpt_entry(image, array_lba, slot, partition_guid, start, end):
    offset = array_lba * 512 + slot * 128
    type_guid = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
    struct.pack_into("<16s16sQQQ72s", image, offset, type_guid.bytes_le,
                     partition_guid.bytes_le, start, end, 0, bytes(72))


def seal_gpt_copy(image, header_lba, entries_lba):
    header_offset = header_lba * 512
    header = image[header_offset:header_offset + 512]
    entry_count = struct.unpack_from("<I", header, 80)[0]
    entry_size = struct.unpack_from("<I", header, 84)[0]
    entries_offset = entries_lba * 512
    entries_length = entry_count * entry_size
    entries_crc = zlib.crc32(image[entries_offset:entries_offset + entries_length]) & 0xFFFFFFFF
    struct.pack_into("<I", header, 88, entries_crc)
    struct.pack_into("<I", header, 16, 0)
    struct.pack_into("<I", header, 16, zlib.crc32(header[:92]) & 0xFFFFFFFF)
    image[header_offset:header_offset + 512] = header


def mbr_entry(partition_type, start, size, boot=0):
    return struct.pack("<B3sB3sII", boot, bytes(3), partition_type,
                       bytes(3), start, size)


def synthetic_dos_ebr_image(path):
    """Build one MBR primary data entry and a two-entry logical chain."""
    sector_size = 512
    image = bytearray(8192 * sector_size)
    struct.pack_into("<I", image, 440, 0x12345678)
    image[446:462] = mbr_entry(0x83, 2048, 512)
    image[462:478] = mbr_entry(0x0f, 4096, 2048)
    image[510:512] = b"\x55\xaa"

    first_ebr = 4096 * sector_size
    image[first_ebr + 446:first_ebr + 462] = mbr_entry(0x83, 1, 256)
    image[first_ebr + 462:first_ebr + 478] = mbr_entry(0x0f, 1024, 1024)
    image[first_ebr + 510:first_ebr + 512] = b"\x55\xaa"

    second_ebr = 5120 * sector_size
    image[second_ebr + 446:second_ebr + 462] = mbr_entry(0x83, 1, 256)
    image[second_ebr + 510:second_ebr + 512] = b"\x55\xaa"
    path.write_bytes(image)


with tempfile.TemporaryDirectory(prefix="phantowd-probe-") as workspace:
    root = pathlib.Path(workspace)
    empty = root / "empty.img"
    with empty.open("wb") as output:
        output.truncate(16 * 1024 * 1024)
    with empty.open("rb") as source:
        assert probe(source, "unidentified")["filesystem_uuid"] == ""
    # A valid GPT must expose its whole-disk and partition identities, not just
    # classify the protective MBR/GPT as another signature.
    gpt = root / "valid-gpt.img"
    synthetic_gpt(gpt)
    original = hashlib.sha256(gpt.read_bytes()).digest()
    with gpt.open("rb") as source:
        observed = probe(source, "other-signature")
    assert observed["partition_table"] == "gpt", observed
    assert observed["partition_table_id"] == "fedcba98-7654-3210-fedc-ba9876543210", observed
    assert observed["partitions"] == [{
        "number": 1,
        "start_512b_sectors": 34,
        "size_512b_sectors": 16,
        "uuid": "00112233-4455-6677-8899-aabbccddeeff",
        "type_id": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
        "extended": False,
    }], observed
    assert hashlib.sha256(gpt.read_bytes()).digest() == original
    malformed_gpt_empty_slot = root / "malformed-gpt-empty-mbr-slot.img"
    synthetic_gpt(malformed_gpt_empty_slot)
    image = bytearray(malformed_gpt_empty_slot.read_bytes())
    image[463] = 0x08  # CHS residue in a type-zero protective-MBR slot
    malformed_gpt_empty_slot.write_bytes(image)
    with malformed_gpt_empty_slot.open("rb") as source:
        probe(source, None)
    # Exercise large-file offsets needed to read the mirrored GPT header at
    # the end of a disk larger than the signed 32-bit file-offset boundary.
    large_gpt = root / "large-sparse-gpt.img"
    synthetic_gpt(large_gpt, sector_count=8_388_608)  # exactly 4 GiB
    with large_gpt.open("rb") as source:
        observed = probe(source, "other-signature")
    assert observed["partition_table"] == "gpt", observed
    assert observed["partition_table_id"] == "fedcba98-7654-3210-fedc-ba9876543210", observed
    assert observed["partitions"][0]["size_512b_sectors"] == 16, observed
    mismatched_gpt = root / "mismatched-gpt-copies.img"
    synthetic_gpt(mismatched_gpt,
                  backup_partition_guid=uuid.UUID("11112233-4455-6677-8899-aabbccddeeff"))
    original = hashlib.sha256(mismatched_gpt.read_bytes()).digest()
    with mismatched_gpt.open("rb") as source:
        probe(source, None)
    assert hashlib.sha256(mismatched_gpt.read_bytes()).digest() == original
    out_of_range_gpt = root / "out-of-range-gpt-entry.img"
    synthetic_gpt(out_of_range_gpt, partition_start=95, partition_end=110)
    original = hashlib.sha256(out_of_range_gpt.read_bytes()).digest()
    with out_of_range_gpt.open("rb") as source:
        probe(source, None)
    assert hashlib.sha256(out_of_range_gpt.read_bytes()).digest() == original
    bad_backup_crc = root / "bad-backup-header-crc.img"
    synthetic_gpt(bad_backup_crc)
    image = bytearray(bad_backup_crc.read_bytes())
    image[-512 + 16] ^= 1
    bad_backup_crc.write_bytes(image)
    original = hashlib.sha256(bad_backup_crc.read_bytes()).digest()
    with bad_backup_crc.open("rb") as source:
        probe(source, None)
    assert hashlib.sha256(bad_backup_crc.read_bytes()).digest() == original

    for label, second_guid, second_start, second_end in (
        ("duplicate-gpt-guid", uuid.UUID("00112233-4455-6677-8899-aabbccddeeff"), 60, 70),
        ("overlapping-gpt-entry", uuid.UUID("11112233-4455-6677-8899-aabbccddeeff"), 40, 55),
    ):
        image_path = root / (label + ".img")
        synthetic_gpt(image_path)
        image = bytearray(image_path.read_bytes())
        for entries_lba in (2, 95):
            write_gpt_entry(image, entries_lba, 1, second_guid, second_start, second_end)
        seal_gpt_copy(image, 1, 2)
        seal_gpt_copy(image, 127, 95)
        image_path.write_bytes(image)
        original = hashlib.sha256(image_path.read_bytes()).digest()
        with image_path.open("rb") as source:
            probe(source, None)
        assert hashlib.sha256(image_path.read_bytes()).digest() == original

    mbr = root / "valid-dos-ebr.img"
    synthetic_dos_ebr_image(mbr)
    original = hashlib.sha256(mbr.read_bytes()).digest()
    with mbr.open("rb") as source:
        observed = probe(source, "other-signature")
    assert observed["partition_table"] == "dos", observed
    assert observed["partition_table_id"] == "12345678", observed
    assert observed["partitions"] == [
        {"number": 1, "start_512b_sectors": 2048, "size_512b_sectors": 512,
         "uuid": "12345678-01", "type_id": "0x83", "extended": False},
        {"number": 2, "start_512b_sectors": 4096, "size_512b_sectors": 2048,
         "uuid": "12345678-02", "type_id": "0x0f", "extended": True},
        {"number": 5, "start_512b_sectors": 4097, "size_512b_sectors": 256,
         "uuid": "12345678-05", "type_id": "0x83", "extended": False},
        {"number": 6, "start_512b_sectors": 5121, "size_512b_sectors": 256,
         "uuid": "12345678-06", "type_id": "0x83", "extended": False},
    ], observed
    assert hashlib.sha256(mbr.read_bytes()).digest() == original
    malformed_dos_empty_slot = root / "malformed-dos-empty-mbr-slot.img"
    synthetic_dos_ebr_image(malformed_dos_empty_slot)
    image = bytearray(malformed_dos_empty_slot.read_bytes())
    image[479] = 0x08  # CHS residue in an unused primary entry
    malformed_dos_empty_slot.write_bytes(image)
    with malformed_dos_empty_slot.open("rb") as source:
        probe(source, None)
    looping_ebr = root / "looping-dos-ebr.img"
    synthetic_dos_ebr_image(looping_ebr)
    image = bytearray(looping_ebr.read_bytes())
    second_ebr = 5120 * 512
    image[second_ebr + 462:second_ebr + 478] = mbr_entry(0x0f, 1024, 1024)
    looping_ebr.write_bytes(image)
    original = hashlib.sha256(looping_ebr.read_bytes()).digest()
    with looping_ebr.open("rb") as source:
        probe(source, None)
    assert hashlib.sha256(looping_ebr.read_bytes()).digest() == original
    with empty.open("r+b") as source:
        probe(source, None)
    with empty.open("rb") as source:
        probe(source, None, "unexpected")
    # Pipes are not seekable storage and must be refused before probing.
    invalid = subprocess.run([str(binary)], input=b"not storage", capture_output=True,
                             timeout=8, check=False)
    assert invalid.returncode == 1 and not invalid.stdout
    # O_PATH may look read-only through O_ACCMODE but cannot provide data.
    for path, flags in ((empty, os.O_PATH), (root, os.O_RDONLY | os.O_DIRECTORY)):
        descriptor = os.open(path, flags | os.O_CLOEXEC)
        try:
            probe(descriptor, None)
        finally:
            os.close(descriptor)
    expected_uuid = "00112233-4455-6677-8899-aabbccddeeff"
    for filesystem in ("ext2", "ext3", "ext4"):
        image = root / (filesystem + ".img")
        shutil.copyfile(empty, image)
        subprocess.run(["/sbin/mkfs." + filesystem, "-q", "-F", "-U", expected_uuid,
                        str(image)], check=True, timeout=15)
        original = hashlib.sha256(image.read_bytes()).digest()
        with image.open("rb") as source:
            observed = probe(source, "ext-metadata")
        assert observed["filesystem"] == filesystem, observed
        assert observed["filesystem_uuid"] == expected_uuid, observed
        assert hashlib.sha256(image.read_bytes()).digest() == original
    # A real low-level safeprobe collision, not a mocked return. In pinned
    # 2.40.4, probe.c converts every negative chain result (including -2) to
    # BLKID_PROBE_ERROR (-1). Require exact failure without JSON, not a guessed
    # ambiguity classification or permission to fall back to an ext match.
    # Each signature alone is recognized and malformed XFS is not.
    for label, base, header, expected in (
        ("xfs-only", empty, synthetic_xfs_header(), "other-signature"),
        ("xfs-ext2", root / "ext2.img", synthetic_xfs_header(), None),
        ("invalid-xfs", empty, b"XFSB" + bytes(508), "unidentified"),
    ):
        image = root / (label + ".img")
        shutil.copyfile(base, image)
        with image.open("r+b") as output:
            output.write(header)
        original = hashlib.sha256(image.read_bytes()).digest()
        with image.open("rb") as source:
            observed = probe(source, expected)
        if observed is not None:
            assert observed["filesystem_uuid"] == "" and observed["filesystem"] == ""
        assert hashlib.sha256(image.read_bytes()).digest() == original
    # Swap is a recognized other signature, not an empty/reusable disk.
    swap = root / "swap.img"
    shutil.copyfile(empty, swap)
    subprocess.run(["/sbin/mkswap", "-q", str(swap)], check=True, timeout=10)
    with swap.open("rb") as source:
        observed = probe(source, "other-signature")
    assert observed["filesystem_uuid"] == "" and observed["filesystem"] == ""
    # Recognized ext metadata without a usable UUID is never selected.
    zero_uuid = root / "zero-uuid.img"
    shutil.copyfile(empty, zero_uuid)
    subprocess.run(["/sbin/mkfs.ext2", "-q", "-F", "-U", "clear", str(zero_uuid)],
                   check=True, timeout=15)
    with zero_uuid.open("rb") as source:
        observed = probe(source, "unusable-signature")
    assert observed["filesystem_uuid"] == "" and observed["filesystem"] == ""
print("Volume probe regular-image integration passed; no mounts or block devices used")
