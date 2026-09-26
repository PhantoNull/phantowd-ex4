#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Regular-file-only integration tests; no loop devices or mounts."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

binary = pathlib.Path(sys.argv[1]).resolve(strict=True)


def probe(source, expected, *args):
    result = subprocess.run([str(binary), *args], stdin=source,
                            capture_output=True, timeout=8, check=False)
    if expected is None:
        assert result.returncode != 0 and not result.stdout, result
        return None
    assert result.returncode == 0 and not result.stderr, result
    assert len(result.stdout) < 512
    observed = json.loads(result.stdout)
    assert observed["schema_version"] == 1
    assert observed["status"] == expected, observed
    assert observed["source_kind"] == "regular-image"
    for field in ("mount_performed", "compatibility_qualified", "activation_allowed"):
        assert observed[field] is False
    return observed


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
    assert invalid.returncode != 0 and not invalid.stdout
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
