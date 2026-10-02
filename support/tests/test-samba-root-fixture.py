#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Negative manifests and source-contract checks for a QEMU-only experiment."""
import copy
from pathlib import Path
import unittest

import samba_root_fixture as fixture


def reports():
    return [{
        "format": "phantowd-elf-runtime-candidate", "schema_version": 1,
        "entry": entry, "static_dependencies_resolved": True,
        "runtime_qualified": False, "execution_authorized": False,
        "total_bytes": 200, "objects": [
            {"path": entry, "sha256": "a" * 64, "size": 100,
             "bindings": [entry]},
            {"path": "lib/ld-linux.so.3", "sha256": "b" * 64,
             "size": 100, "bindings": ["lib/ld-linux.so.3"]},
        ],
    } for entry in fixture.ENTRIES]


class SambaRootFixture(unittest.TestCase):
    def test_deduplicated_fixed_roster(self):
        manifest = fixture.merge(reports())
        self.assertEqual(len(manifest.splitlines()), 4)
        self.assertEqual(manifest.count("b" * 64), 1)

    def test_partial_reordered_or_authorized_inputs_refused(self):
        values = [reports()[:2], reports()[::-1]]
        for field, value in (("execution_authorized", True),
                             ("runtime_qualified", True),
                             ("static_dependencies_resolved", False),
                             ("entry", "usr/bin/untrusted")):
            changed = reports()
            changed[1][field] = value
            values.append(changed)
        for value in values:
            with self.assertRaises(ValueError):
                fixture.merge(value)

    def test_cross_candidate_byte_alias_conflict_refused(self):
        changed = reports()
        changed[1]["objects"][1]["sha256"] = "c" * 64
        with self.assertRaises(ValueError):
            fixture.merge(changed)
        changed = reports()
        changed[1]["objects"][0]["bindings"].append("usr/sbin/smbd")
        with self.assertRaises(ValueError):
            fixture.merge(changed)

    def test_shell_and_path_injection_refused(self):
        for alias in ("../state", "etc/passwd", "lib/x;reboot", "lib/$x"):
            # etc/passwd must not overlap generated non-ELF configuration.
            changed = reports()
            changed[0]["objects"][0]["bindings"].append(alias)
            with self.assertRaises(ValueError):
                fixture.merge(changed)

    def test_copy_does_not_mutate_candidates(self):
        values = reports()
        saved = copy.deepcopy(values)
        fixture.merge(values)
        self.assertEqual(values, saved)

    def test_merged_budget_and_guest_log_size_refused(self):
        values = reports()
        for report in values:
            report["objects"][0]["size"] = 24 * 1024 * 1024
            report["total_bytes"] = 24 * 1024 * 1024 + 100
        with self.assertRaises(ValueError):
            fixture.merge(values)
        with self.assertRaises(ValueError):
            fixture.check_guest("x" * (512 * 1024 + 1))

    def test_guest_crlf_and_strict_complete_markers(self):
        lines = [
            "PHANTOWD_SAMBA_ROOT_BOUNDARY_READY caps=00000000000000db "
            "nnp=true original_denied=true kernel_ro=true",
            "PHANTOWD_SAMBA_ROOT_POLICY_READY writer_uid=1801 "
            "reader_uid=1802 outsider_denied=true kernel_ro=true "
            "original_denied=true unix_ownership=true unix_denial=true "
            "utf8_roundtrip=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_STOPPED", "PHANTOWD_SAMBA_ROOT_DONE",
        ]
        fixture.check_guest("\r\n".join(lines))
        for invalid in (lines[:-1], lines + [lines[0]], lines[::-1],
                        lines + ["PHANTOWD_SAMBA_ROOT_FAILED"],
                        lines + ["PHANTOWD_SAMBA_ROOT_LAUNCH_REFUSED"]):
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(invalid))

    def test_fixed_experiment_scope_and_runtime_assertions(self):
        root = Path(__file__).resolve().parents[2]
        wrapper = (root / "support/test-samba-root.ps1").read_text()
        driver = (root / "support/tests/test-qemu-samba-root.sh").read_text()
        native = (root / "support/tests/samba-root-launcher-fixture.c"
                  ).read_text()
        init = (root / "support/tests/samba-root-init.sh").read_text()
        self.assertIn("--pull never --network none --read-only", wrapper)
        self.assertNotIn("docker volume create", wrapper)
        self.assertIn("timeout --signal=TERM --kill-after=5 180", driver)
        self.assertIn("-nic none", driver)
        self.assertIn("rootwait ro", driver)
        self.assertIn("if=scsi,snapshot=on", driver)
        self.assertIn("ARM Versatile PB", native)
        self.assertIn("unshare(CLONE_NEWNS)", native)
        self.assertIn("SYS_close_range", native)
        self.assertIn("PR_SET_NO_NEW_PRIVS", native)
        self.assertIn("errno != EROFS", native)
        self.assertIn("NT_STATUS_BAD_NETWORK_NAME", init)
        self.assertIn("created.st_uid != 1801", native)
        self.assertIn("PHANTOWD_SAMBA_ROOT_STOPPED", init)
        self.assertIn("now.tv_sec - start.tv_sec >= 10", native)
        self.assertIn('return 124;', native)
        self.assertIn('[ "$status" -eq 1 ]', init)
        self.assertNotIn("timeout -s", init)
        self.assertIn('/bin/busybox kill -TERM "-$daemon_pid"', init)
        self.assertIn('[ "$stop_status" -ne 143 ]', init)
        self.assertIn('[ "$stop_attempted" -eq 0 ]', init)


if __name__ == "__main__":
    unittest.main()
