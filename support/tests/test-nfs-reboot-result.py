#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Synthetic receipt controls, not execution of NFS or a kernel reboot."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "nfs-reboot-result.py"
SPEC = importlib.util.spec_from_file_location("nfs_reboot_result", SCRIPT)
result = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(result)


def log(phase):
    boot = ("11111111" if phase == "seed" else "aaaaaaaa") + "-2222-3333-4444-555555555555"
    return ("ordinary kernel log\nPHANTOWD_NFS_REBOOT_PHASE_READY phase=" + phase + " boot_id=" + boot +
            " policy_sha256=" + "a" * 64 + " inode=12 data_sha256=" + "b" * 64 +
            " rw=true ro_denied=true client_denied=true uid=101000 gid=101000"
            " kernel_profile=v3-tcp-only kernel_stopped=true fsid_rebind_refused=true listener_identity=true teardown=true"
            " scope=clean-qemu-reboot-only\nPHANTOWD_STATE_BOOT_READY phase=" + phase +
            " scope=disposable-qemu-only\n[   1.000] reboot: Restarting system\n").encode()


class NFSRebootResult(unittest.TestCase):
    def test_exact_listener_identity_is_required(self):
        legacy = log("seed").replace(b" listener_identity=true", b"")
        with self.assertRaises(ValueError):
            result.validate_log(legacy, "seed")

    def test_kernel_profile_and_stopped_readback_are_required(self):
        wire = log("seed")
        result.validate_log(wire, "seed")
        for removed in (b" kernel_profile=v3-tcp-only", b" kernel_stopped=true",
                        b" fsid_rebind_refused=true",
                        b" listener_identity=true",
                        b" kernel_profile=v3-tcp-only kernel_stopped=true"):
            # Legacy access-only receipts cannot establish the new readbacks.
            with self.subTest(removed=removed), self.assertRaises(ValueError):
                result.validate_log(wire.replace(removed, b""), "seed")

    def test_two_complete_boots_match_policy_and_original_data(self):
        first = result.validate_log(log("seed"), "seed")
        second = result.validate_log(log("verify").replace(b"\n", b"\r\n"), "verify")
        result.compare(first, second)
        self.assertEqual(first["inode"], "12")

    def test_incomplete_duplicate_changed_or_failed_boot_is_refused(self):
        for phase in ("seed", "verify"):
            wire = log(phase)
            lines = wire.splitlines(keepends=True)
            for index in range(1, len(lines)):
                for changed in (b"".join(lines[:index] + lines[index + 1:]),
                                b"".join(lines[:index] + [lines[index], lines[index]] + lines[index + 1:])):
                    with self.subTest(phase=phase, index=index), self.assertRaises(ValueError):
                        result.validate_log(changed, phase)
            for before, after in ((b"phase=" + phase.encode(), b"phase=unknown"),
                                  (b"rw=true", b"rw=false"), (b"ro_denied=true", b"ro_denied=false"),
                                  (b"client_denied=true", b"client_denied=false"),
                                  (b"teardown=true", b"teardown=false"), (b"uid=101000", b"uid=0"),
                                  (b"kernel_profile=v3-tcp-only", b"kernel_profile=unknown"),
                                  (b"kernel_stopped=true", b"kernel_stopped=false"),
                                  (b"fsid_rebind_refused=true", b"fsid_rebind_refused=false"),
                                  (b"listener_identity=true", b"listener_identity=false"),
                                  (b"inode=12", b"inode=18446744073709551616"),
                                  (b"inode=12", b"inode=012"),
                                  (b"data_sha256=" + b"b" * 64, b"data_sha256=" + b"b" * 63)):
                with self.subTest(before=before), self.assertRaises(ValueError):
                    result.validate_log(wire.replace(before, after), phase)
            for suffix in (b"PHANTOWD_STATE_ERROR\n", b"PHANTOWD_API_ERROR\n", b"Kernel panic\n",
                           b"PHANTOWD_NFS_REBOOT_FOREIGN\n", b"\xff"):
                with self.assertRaises(ValueError):
                    result.validate_log(wire + suffix, phase)
            reordered = lines[:]
            reordered[1], reordered[2] = reordered[2], reordered[1]
            with self.assertRaises(ValueError):
                result.validate_log(b"".join(reordered), phase)

    def test_distinct_kernels_and_identical_policy_data_inode_required(self):
        first, second = result.validate_log(log("seed"), "seed"), result.validate_log(log("verify"), "verify")
        for key in ("policy_sha256", "data_sha256", "inode"):
            changed = dict(second, **{key: "c" * 64 if key != "inode" else "13"})
            with self.subTest(key=key), self.assertRaises(ValueError):
                result.compare(first, changed)
        with self.assertRaises(ValueError):
            result.compare(first, dict(second, boot_id=first["boot_id"]))
        with self.assertRaises(ValueError):
            result.compare(second, first)

    def test_log_size_is_bounded(self):
        wire = log("seed")
        result.validate_log(wire + b" " * (result.MAX_LOG - len(wire)), "seed")
        for changed in (b"", wire + b" " * (result.MAX_LOG + 1 - len(wire))):
            with self.assertRaises(ValueError):
                result.validate_log(changed, "seed")

    def test_cli_accepts_only_two_complete_matching_logs(self):
        with tempfile.TemporaryDirectory(prefix="phantowd-nfs-reboot-receipts-") as directory:
            root = Path(directory)
            seed, verify = root / "seed.log", root / "verify.log"
            seed.write_bytes(log("seed"))
            verify.write_bytes(log("verify"))
            completed = subprocess.run([sys.executable, "-B", str(SCRIPT), str(seed), str(verify)],
                                       capture_output=True, timeout=5)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn(b"boots=2 distinct_kernels=true", completed.stdout)
            for args in ((str(verify), str(seed)), (str(seed),), (str(seed), str(root)),
                         (str(seed), str(root / "missing"))):
                completed = subprocess.run([sys.executable, "-B", str(SCRIPT), *args], capture_output=True, timeout=5)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, b"")
                self.assertEqual(completed.stderr.replace(b"\r\n", b"\n"), b"Synthetic NFS reboot proof refused.\n")


if __name__ == "__main__":
    unittest.main()
