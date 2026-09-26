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

binary = pathlib.Path(sys.argv[1]).resolve(strict=True)


def probe(source, expected, *args):
    result = subprocess.run([str(binary), *args], stdin=source,
                            capture_output=True, timeout=8, check=False)
    if expected is None:
        assert result.returncode == 1 and not result.stdout, result
        assert result.stderr == b"volume metadata probe failed\n", result
        return None
    assert result.returncode == 0 and not result.stderr, (getattr(source, "name", source), result)
    assert len(result.stdout) < 512
    observed = json.loads(result.stdout)
    assert observed["schema_version"] == 1
    assert observed["status"] == expected, observed
    assert observed["source_kind"] == "regular-image"
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


with tempfile.TemporaryDirectory(prefix="phantowd-probe-") as workspace:
    root = pathlib.Path(workspace)
    empty = root / "empty.img"
    with empty.open("wb") as output:
        output.truncate(16 * 1024 * 1024)
    with empty.open("rb") as source:
        assert probe(source, "unidentified")["filesystem_uuid"] == ""
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
