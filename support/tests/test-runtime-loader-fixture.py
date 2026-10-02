#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Bounded parser/generator tests; no ELF is executed by these host tests."""
import copy
import unittest

import runtime_loader_fixture as fixture


def candidate():
    return {
        "format": "phantowd-elf-runtime-candidate", "schema_version": 1,
        "entry": "usr/sbin/smbd", "static_dependencies_resolved": True,
        "runtime_qualified": False, "execution_authorized": False,
        "total_bytes": 300, "objects": [
            {"path": "usr/sbin/smbd", "sha256": "a" * 64, "size": 100,
             "bindings": ["usr/sbin/smbd"]},
            {"path": "lib/libc-actual.so", "sha256": "b" * 64, "size": 100,
             "bindings": ["lib/libc.so.6"]},
            {"path": "lib/ld-linux.so.3", "sha256": "c" * 64, "size": 100,
             "bindings": ["lib/ld-linux.so.3"]},
        ],
    }


def guest_log():
    return "\n".join([
        "ordinary boot diagnostics",
        "PHANTOWD_RUNTIME_BYTES_READY",
        "PHANTOWD_RUNTIME_LOADER_BEGIN",
        "  libc.so.6 => /lib/libc.so.6 (0x12345000)",
        "  /lib/ld-linux.so.3 (0xabcdef00)",
        "PHANTOWD_RUNTIME_LOADER_END",
        "PHANTOWD_RUNTIME_LOADER_DONE",
    ])


class RuntimeLoaderFixture(unittest.TestCase):
    def test_aliases_and_direct_interpreter_match(self):
        self.assertEqual(fixture.compare(candidate(), guest_log()), 2)

    def test_no_partial_or_extra_resolution_accepted(self):
        for log in (
            guest_log().replace(
                "  libc.so.6 => /lib/libc.so.6 (0x12345000)", ""),
            guest_log().replace("/lib/libc.so.6", "/outside/libc.so.6"),
            guest_log().replace("libc.so.6 => /lib/libc.so.6",
                                "libc.so.6 => not found"),
            guest_log().replace("PHANTOWD_RUNTIME_BYTES_READY", ""),
            guest_log().replace("PHANTOWD_RUNTIME_LOADER_DONE", ""),
            guest_log() + "\nPHANTOWD_RUNTIME_LOADER_FAILED",
            guest_log().replace("PHANTOWD_RUNTIME_LOADER_BEGIN", "\n".join([
                "PHANTOWD_RUNTIME_LOADER_BEGIN",
                "PHANTOWD_RUNTIME_LOADER_BEGIN"])),
            guest_log().replace("  /lib/ld-linux.so.3",
                                "unexpected /lib/ld-linux.so.3"),
        ):
            with self.subTest(log=log):
                with self.assertRaises(ValueError):
                    fixture.compare(candidate(), log)

    def test_bounded_candidate_never_authorizes_product(self):
        for field, value in (("runtime_qualified", True),
                             ("execution_authorized", True),
                             ("static_dependencies_resolved", False),
                             ("entry", "bin/untrusted"),
                             ("schema_version", True), ("total_bytes", 301)):
            report = candidate()
            report[field] = value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    fixture.prepare(report)

    def test_fixture_generation_rejects_shell_and_path_injection(self):
        for value in ("../etc/passwd", "/lib/libc.so.6", "lib/x;reboot",
                      "lib/a'", "lib/x\n", "lib/x y", "lib/./x", "lib/$x"):
            report = candidate()
            report["objects"][1]["bindings"] = [value]
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    fixture.prepare(report)

    def test_conflicting_aliases_objects_and_hashes_refused(self):
        edits = [
            lambda r: r["objects"].append(copy.deepcopy(r["objects"][1])),
            lambda r: r["objects"][1].update(sha256="x" * 64),
            lambda r: r["objects"][1].update(size=True),
            lambda r: r["objects"][1].update(bindings=["lib/ld-linux.so.3"]),
            lambda r: r["objects"][1].update(bindings=[]),
        ]
        for edit in edits:
            report = candidate()
            edit(report)
            with self.assertRaises(ValueError):
                fixture.prepare(report)

    def test_generated_init_lists_only_fixed_trusted_smbd(self):
        script, manifest = fixture.prepare(candidate())
        self.assertIn("--inhibit-cache --list /usr/sbin/smbd", script)
        self.assertIn("readlink -f", script)
        self.assertIn("sha256sum", script)
        self.assertNotIn("smbd -", script)
        self.assertIn("b" * 64 + " /lib/libc-actual.so /lib/libc.so.6",
                      manifest)

    def test_fixture_parser_and_snapshot_budget_are_enforced(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]
        wrapper = (root / "support/test-runtime-loader.ps1").read_text()
        driver_path = root / "support/tests/test-qemu-runtime-loader.sh"
        driver = driver_path.read_text()
        self.assertIn("--pull never --network none --read-only", wrapper)
        self.assertIn("/tmp:rw,exec,nosuid,nodev,size=512m", wrapper)
        self.assertIn("/var/tmp:rw,noexec,nosuid,nodev,size=128m", wrapper)
        self.assertNotIn("docker volume create", wrapper)
        self.assertIn("rootwait ro", driver)
        self.assertIn("if=scsi,snapshot=on", driver)
        self.assertIn("timeout --signal=TERM --kill-after=5 90", driver)
        release = driver.index(
            'rm -rf "$scratch/go-cache" "$scratch/go-path"',
            driver.index('"$go_binary" build'))
        self.assertLess(release, driver.index('cp "$base/rootfs.ext2"'))


if __name__ == "__main__":
    unittest.main()
