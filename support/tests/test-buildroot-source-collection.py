#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Bounded generated-file source collection; no real build or device writes."""

import hashlib
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
COLLECTOR = ROOT / "support/container/collect-buildroot-source.sh"
VERSION = "2025.02.18"
NAME = f"buildroot-{VERSION}.tar.xz"
DATA = b"synthetic archive bytes; collector never extracts them\n"
DIGEST = hashlib.sha256(DATA).hexdigest()


class CollectionTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="phantowd-source-test-")
        self.addCleanup(scratch.cleanup)
        self.root = pathlib.Path(scratch.name)
        self.archive = self.root / NAME
        self.archive.write_bytes(DATA)
        self.legal = self.root / "legal-info"
        self.legal.mkdir()
        for name in ("README", "buildroot.config", "manifest.csv",
                     "host-manifest.csv"):
            (self.legal / name).write_bytes(b"unchanged fixture metadata\n")
        self.destination_dir = self.legal / "phantowd-build-inputs"
        self.destination = self.destination_dir / NAME

    def collect(self, archive=None, version=VERSION, digest=DIGEST, env=None):
        return subprocess.run(
            ["sh", str(COLLECTOR), str(archive or self.archive),
             str(self.legal), version, digest],
            capture_output=True, text=True, timeout=5, check=False, env=env,
        )

    def test_collects_exact_bytes_and_reuses_without_overwrite(self):
        result = self.collect()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("compliance_qualified=false", result.stdout)
        self.assertEqual(self.destination.read_bytes(), DATA)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o644)
        original = self.destination.stat()
        result = self.collect()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.destination.stat().st_ino, original.st_ino)
        self.assertEqual(self.archive.read_bytes(), DATA)
        self.assertEqual(list(self.destination_dir.iterdir()),
                         [self.destination])
        self.assertEqual((self.legal / "README").read_bytes(),
                         b"unchanged fixture metadata\n")

    def test_refuses_hash_mismatch_before_output_creation(self):
        self.archive.write_bytes(b"tampered")
        result = self.collect()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.destination_dir.exists())

    def test_failed_copy_or_publication_cleans_only_owned_temporary(self):
        for command in ("cp", "ln"):
            with self.subTest(command=command):
                fake_bin = self.root / f"fake-{command}"
                fake_bin.mkdir()
                fake = fake_bin / command
                fake.write_text("#!/bin/sh\nexit 1\n")
                fake.chmod(0o755)
                result = self.collect(env={
                    **os.environ,
                    "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
                })
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.destination.exists())
                self.assertEqual(list(self.destination_dir.iterdir()), [])
                self.assertEqual(self.archive.read_bytes(), DATA)
                self.assertEqual((self.legal / "README").read_bytes(),
                                 b"unchanged fixture metadata\n")

    def test_build_driver_checks_early_and_collects_after_legal_info(self):
        script = (ROOT / "support/container/build-qemu.sh").read_text()
        regression = script.index(
            'python3 -B "$external_dir/support/tests/'
            'test-buildroot-source-collection.py"')
        compile_step = script.index('    -j"$(getconf _NPROCESSORS_ONLN)"')
        legal_step = script.index('    legal-info\n')
        collection = script.index(
            '\nsh "$external_dir/support/container/'
            'collect-buildroot-source.sh"')
        native_tests = script.index(
            'sh "$external_dir/support/container/test-volume-probe.sh"')
        self.assertLess(regression, compile_step)
        self.assertLess(compile_step, legal_step)
        self.assertLess(legal_step, collection)
        self.assertLess(collection, native_tests)
        self.assertIn(
            '"$workspace_dir/$buildroot_archive" "$output_dir/legal-info" '
            '\\\n    "$BUILDROOT_VERSION" "$BUILDROOT_ARCHIVE_SHA256"', script)

    def test_corrupted_successful_copy_is_not_published(self):
        fake_bin = self.root / "corrupt-copy"
        fake_bin.mkdir()
        fake = fake_bin / "cp"
        fake.write_text('#!/bin/sh\nprintf "%s\\n" corrupted > "$3"\n')
        fake.chmod(0o755)
        result = self.collect(env={
            **os.environ,
            "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Copied Buildroot source differs", result.stderr)
        self.assertEqual(list(self.destination_dir.iterdir()), [])
        self.assertEqual(self.archive.read_bytes(), DATA)

    def test_directory_created_at_publication_cannot_redirect_link(self):
        fake_bin = self.root / "race-directory"
        fake_bin.mkdir()
        fake = fake_bin / "ln"
        fake.write_text(
            '#!/bin/sh\nmkdir -- "$4"\n'
            'PATH=/usr/bin:/bin exec ln "$@"\n')
        fake.chmod(0o755)
        result = self.collect(env={
            **os.environ,
            "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.destination.is_dir())
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertEqual(list(self.destination_dir.iterdir()),
                         [self.destination])
        self.assertEqual(self.archive.read_bytes(), DATA)

    def test_refuses_existing_different_source_without_replacement(self):
        self.destination_dir.mkdir()
        self.destination.write_bytes(b"existing unrelated bytes")
        result = self.collect()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.destination.read_bytes(),
                         b"existing unrelated bytes")

    def test_refuses_symlinked_input_output_and_metadata(self):
        with self.subTest("input"):
            alias = self.root / "alias" / NAME
            alias.parent.mkdir()
            alias.symlink_to(self.archive)
            self.assertNotEqual(self.collect(archive=alias).returncode, 0)
            self.assertFalse(self.destination_dir.exists())
        with self.subTest("output directory"):
            self.destination_dir.symlink_to(
                self.root, target_is_directory=True)
            self.assertNotEqual(self.collect().returncode, 0)
            self.destination_dir.unlink()
        with self.subTest("output file"):
            self.destination_dir.mkdir()
            self.destination.symlink_to(self.archive)
            self.assertNotEqual(self.collect().returncode, 0)
            self.destination.unlink()
        with self.subTest("metadata"):
            metadata = self.legal / "manifest.csv"
            metadata.unlink()
            metadata.symlink_to(self.archive)
            self.assertNotEqual(self.collect().returncode, 0)
        self.assertEqual(self.archive.read_bytes(), DATA)

    def test_refuses_invalid_version_hash_name_and_missing_metadata(self):
        for version in ("../2025.02.18", "2025.02.18\n", "2025", ""):
            with self.subTest(version=version):
                self.assertNotEqual(
                    self.collect(version=version).returncode, 0)
        for digest in ("f" * 63, "G" * 64, "f" * 64 + "\n", ""):
            with self.subTest(digest=digest):
                self.assertNotEqual(self.collect(digest=digest).returncode, 0)
        wrong_name = self.root / "wrong.tar.xz"
        wrong_name.write_bytes(DATA)
        self.assertNotEqual(self.collect(archive=wrong_name).returncode, 0)
        (self.legal / "host-manifest.csv").unlink()
        self.assertNotEqual(self.collect().returncode, 0)
        self.assertFalse(self.destination_dir.exists())


if __name__ == "__main__":
    unittest.main()
