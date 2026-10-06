#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Exercise pinned Perl Configure with Buildroot's diagnostic date wrapper."""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PATCH = (ROOT / "board/qemu/armv5/patches/perl/5.40.5" /
         "0001-Configure-date-stderr.patch")
ARCHIVE_SHA256 = (
    "1fe6f825b487d26c35aa51a35f52fe494d4cfc77b8051f8b1ee3391bf0289bc6")
EPOCH = "1789067700"
ARGS = None


class ConfigureDateTests(unittest.TestCase):
    def test_configuration_time_is_data_not_executable_diagnostic(self):
        archive = Path(ARGS.archive)
        date_wrapper = Path(ARGS.date_wrapper)
        self.assertFalse(archive.is_symlink())
        self.assertTrue(archive.is_file())
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),
                         ARCHIVE_SHA256)
        self.assertFalse(date_wrapper.is_symlink())
        self.assertTrue(date_wrapper.is_file())
        with tempfile.TemporaryDirectory(prefix="phantowd-perl-date-") as temp:
            scratch = Path(temp)
            # Use the source wrapper too: a clean build need not already have
            # installed host-fakedate. Keep the executable named date so its
            # recursion guard can locate the real date further down PATH.
            wrapper_bin = scratch / "bin"
            wrapper_bin.mkdir()
            copied_date = wrapper_bin / "date"
            shutil.copyfile(date_wrapper, copied_date)
            copied_date.chmod(0o700)
            subprocess.run(["tar", "-xf", str(archive), "-C", str(scratch)],
                           check=True, timeout=15)
            package = scratch / "perl-5.40.5"
            if not ARGS.unpatched:
                with PATCH.open("rb") as patch:
                    subprocess.run(
                        ["patch", "--strip=1", "--fuzz=0", "--batch",
                         "--forward"],
                        cwd=package, stdin=patch, check=True, timeout=15,
                    )
            environment = {
                "PATH": f"{wrapper_bin}:/usr/bin:/bin",
                "LC_ALL": "C", "LANGUAGE": "C", "SOURCE_DATE_EPOCH": EPOCH,
            }
            control = subprocess.run(
                [str(copied_date)], env=environment, check=True,
                capture_output=True, text=True, timeout=10,
            )
            self.assertIn("SOURCE_DATE_EPOCH", control.stderr)
            self.assertEqual(len(control.stdout.splitlines()), 1)
            with (scratch / "configure.stdout").open("w") as output, \
                    (scratch / "configure.stderr").open("w") as diagnostic:
                subprocess.run(
                    ["/bin/sh", "./Configure", "-des",
                     f"-Dprefix={scratch / 'install'}", "-Dcc=/usr/bin/gcc",
                     "-Dman1dir=none", "-Dman3dir=none"],
                    cwd=package, env=environment, stdout=output,
                    stderr=diagnostic, check=True, timeout=120,
                )
            config = (package / "config.sh").read_text()
            self.assertTrue(
                f"# Configuration time: {control.stdout.strip()}\n" in config,
                "Configure embedded date diagnostics in its shell comment",
            )
            self.assertFalse("SOURCE_DATE_EPOCH" in config,
                             "date warning escaped into generated config.sh")
            loaded = subprocess.run(
                ["/bin/sh", "-c", ". ./config.sh"], cwd=package,
                env=environment, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(loaded.returncode, 0, loaded.stderr)
            self.assertEqual(loaded.stderr, "")
            # Preserve the useful wrapper warning in build diagnostics instead
            # of globally silencing it or storing it inside generated shell.
            self.assertIn("SOURCE_DATE_EPOCH",
                          (scratch / "configure.stderr").read_text())
            self.assertTrue(f"cf_time='{control.stdout.strip()}'" in config,
                            "configuration timestamp changed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument("date_wrapper")
    parser.add_argument("--unpatched", action="store_true",
                        help="negative control: show the upstream failure")
    ARGS = parser.parse_args()
    if os.name != "posix":
        parser.error("Configure regression requires a disposable Linux host")
    unittest.main(argv=[__file__], verbosity=2)
