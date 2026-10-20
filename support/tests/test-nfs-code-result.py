#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

spec = importlib.util.spec_from_file_location("nfs_code_result", Path(__file__).resolve().parents[1] / "nfs-code-result.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class CodeReceiptTests(unittest.TestCase):
    def setUp(self):
        self.report = json.dumps({"format": "phantowd-nfs-runtime-candidate", "schema_version": 1,
                                  "static_dependencies_resolved": True, "runtime_qualified": False,
                                  "execution_authorized": False, "total_bytes": 400,
                                  "objects": [{"size": 100, "bindings": ["one"]} for _ in range(4)]}).encode()
        self.lines = [checker.TABLE, checker.KERNEL, checker.MOUNTD, checker.RPCBIND, checker.INPUTS, b"PHANTOWD_NFS_CODE_COUNTS files=4 aliases=0 bytes=400", checker.READY, checker.DONE]

    def test_lf_and_serial_crlf_have_same_exact_meaning(self):
        for ending in (b"\n", b"\r\n"):
            checker.verify(ending.join(self.lines) + ending, self.report)

    def test_source_join_receipt_requires_its_own_complete_proof(self):
        source = [b"PHANTOWD_NFS_SOURCE_COUNTS files=4 aliases=0 bytes=400",
                  b"PHANTOWD_NFS_SOURCE_IO_READY original_sources=true private_0700=true rw=true ro_read=true ro_erofs=true denied_client=true anon_uid_gid=1000 fsynced=true clients_unmounted=true exports_withdrawn=true product=false scope=qemu-only",
                  b"PHANTOWD_NFS_SOURCE_KERNEL_READY original_control=true original_namespaces=true original_daemons_live=true threads=2 stop_verified=true fd_balance=true exports_withdrawn=true owner_backend=false product=false scope=qemu-only",
                  b"PHANTOWD_NFS_SOURCE_MOUNTD_READY original_channels=3 original_sources=3 filehandle_view=true private_view=true uid_gid=0 caps=dac-read-search listener_pid_bound=true stop_reaped=true fd_balance=true product=false scope=qemu-only",
                  b"PHANTOWD_NFS_SOURCE_RPCBIND_READY original_inputs=true uid_gid=1 capabilities_zero=true listener_pid_bound=true stop_reaped=true fd_balance=true product=false scope=qemu-only",
                  b"PHANTOWD_NFS_SOURCE_READY original_roster=true roots=3 input_pair=true complete_candidate=true parent_closure_excluded=true copied_refused=true duplicate_refused=true canceled_unchanged=true mismatch_rollback=true normal_fd_balance=true source_replacement_review=true restored_refused=true original_refs_retained=true daemons=false kernel_backend=false product=false scope=disposable-qemu-only",
                  b"PHANTOWD_NFS_SOURCE_DONE"]
        for ending in (b"\n", b"\r\n"):
            checker.verify_source(ending.join(source) + ending, self.report)
        variants = [source[:i] + source[i+1:] for i in range(len(source))]
        variants += [source[:i] + [source[i]] + source[i:] for i in range(len(source))]
        variants += [[source[0], source[-2].replace(b"roots=3", b"roots=2"), source[-1]],
                     [line + b"\r\r" for line in source]]
        for old, new in ((b"original_sources=true", b"original_sources=false"),
                         (b"private_0700=true", b"private_0700=false"),
                         (b"ro_erofs=true", b"ro_erofs=false"),
                         (b"denied_client=true", b"denied_client=false"),
                         (b"anon_uid_gid=1000", b"anon_uid_gid=0"),
                         (b"clients_unmounted=true", b"clients_unmounted=false"),
                         (b"exports_withdrawn=true", b"exports_withdrawn=false"),
                         (b"caps=dac-read-search", b"caps=all"),
                         (b"product=false", b"product=true")):
            variants.append([line.replace(old, new) for line in source])
        variants += [[source[0], source[2]], source + [source[1]], list(reversed(source)), self.lines,
                      source + [b"PHANTOWD_NFS_SOURCE_FAILED"], source + [checker.KERNEL],
                      [line.replace(b"daemons=false", b"daemons=true") for line in source],
                      [line.replace(b"bytes=400", b"bytes=399") for line in source]]
        for lines in variants:
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                checker.verify_source(b"\n".join(lines), self.report)

    def test_old_input_only_receipt_cannot_claim_real_table_execution(self):
        without_table = [line for line in self.lines if not line.startswith(b"PHANTOWD_NFS_TABLE_")]
        with self.assertRaises(ValueError):
            checker.verify(b"\n".join(without_table), self.report)

    def test_old_table_only_receipt_cannot_claim_rpcbind_lifetime(self):
        without_daemon = [line for line in self.lines if not line.startswith(b"PHANTOWD_NFS_RPCBIND_")]
        with self.assertRaises(ValueError):
            checker.verify(b"\n".join(without_daemon), self.report)

    def test_old_rpcbind_only_receipt_cannot_claim_mountd_channels(self):
        without_mountd = [line for line in self.lines if not line.startswith(b"PHANTOWD_NFS_MOUNTD_")]
        with self.assertRaises(ValueError):
            checker.verify(b"\n".join(without_mountd), self.report)

    def test_old_mountd_only_receipt_cannot_claim_retained_kernel(self):
        without_kernel = [line for line in self.lines if not line.startswith(b"PHANTOWD_NFS_KERNEL_")]
        with self.assertRaises(ValueError):
            checker.verify(b"\n".join(without_kernel), self.report)

    def test_old_inputs_receipt_cannot_claim_original_input_reservation(self):
        old = [line.replace(b" input_lease=true full_evidence_match=true parent_close_excluded=true lease_review_retained=true", b"")
               for line in self.lines]
        with self.assertRaises(ValueError):
            checker.verify(b"\n".join(old), self.report)

    def test_code_receipt_cannot_hide_a_failed_source_campaign(self):
        with self.assertRaises(ValueError):
            checker.verify(b"\n".join(self.lines + [b"PHANTOWD_NFS_SOURCE_FAILED"]), self.report)

    def test_missing_duplicate_reordered_or_failed_receipts_refuse(self):
        variants = [self.lines[:i] + self.lines[i+1:] for i in range(len(self.lines))]
        variants += [self.lines[:i] + [self.lines[i]] + self.lines[i:] for i in range(len(self.lines))]
        variants += [list(reversed(self.lines)), self.lines + [b"PHANTOWD_NFS_CODE_FAILED"],
                     self.lines + [b"PHANTOWD_NFS_CODE_FAILURE phase=normal-lifetime"],
                     self.lines + [b"PHANTOWD_NFS_TABLE_FAILURE phase=capture"]]
        for old, new in ((b"execution=loader-table-rpcbind-mountd", b"execution=unrestricted"),
                         (b"original_pins", b"original_\rpins"),
                         (b"bytes=400", b"bytes=399"), (b"service=false", b"service=true"),
                         (b"state_dirs=2", b"state_dirs=3"), (b"services=false", b"services=true"),
                         (b"kernel_control=false", b"kernel_control=true"),
                         (b"uid_gid=1", b"uid_gid=0"), (b"nfsd=true", b"nfsd=false"),
                         (b"listener_pid_bound=true", b"listener_pid_bound=false"),
                         (b"original_channels=3", b"original_channels=0"),
                         (b"child_channels_rw=true", b"child_channels_rw=false"),
                         (b"exports=false", b"exports=true"),
                         (b"threads=2", b"threads=0"),
                         (b"original_control=true", b"original_control=false"),
                         (b"owner_backend=false", b"owner_backend=true"),
                         (b"input_lease=true", b"input_lease=false"),
                         (b"full_evidence_match=true", b"full_evidence_match=false"),
                         (b"parent_close_excluded=true", b"parent_close_excluded=false"),
                         (b"lease_review_retained=true", b"lease_review_retained=false")):
            variants.append([line.replace(old, new) for line in self.lines])
        variants.append([line + b"\r\r" for line in self.lines])
        for lines in variants:
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                checker.verify(b"\n".join(lines), self.report)

    def test_incomplete_expected_scope_and_excess_logs_refuse(self):
        for key, value in (("runtime_qualified", True), ("execution_authorized", True),
                           ("static_dependencies_resolved", False), ("total_bytes", 399)):
            report = json.loads(self.report)
            report[key] = value
            with self.assertRaises(ValueError):
                checker.verify(b"\n".join(self.lines), json.dumps(report).encode())
        with self.assertRaises(ValueError):
            checker.verify(b"x" * (checker.MAX_LOG + 1), self.report)

    def test_wrong_json_shapes_refuse_with_fixed_validation_error(self):
        for value in (None, [], 1, {"format": "phantowd-nfs-runtime-candidate", "schema_version": 1,
                                   "static_dependencies_resolved": True, "runtime_qualified": False,
                                   "execution_authorized": False, "objects": [None] * 4}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                checker.verify(b"\n".join(self.lines), json.dumps(value).encode())


@unittest.skipUnless(sys.platform.startswith("linux"), "actual POSIX shell required")
class ShellModeTests(unittest.TestCase):
    def test_actual_init_selects_source_only_after_proc_is_available(self):
        init = (Path(__file__).parent / "nfs-code-init.sh").read_text()
        init = init.replace("/usr/sbin/phantowd-nfs-code-fixture", "fixture_probe")
        stubs = '''proc_ready=0
mount() { if [ "$2" = proc ]; then proc_ready=1; fi; }
grep() { test "$proc_ready" = 1; }
mkdir() { :; }
ip() { :; }
reboot() { :; }
fixture_probe() { test "$#" = 1 && test "$1" = --source-binding; }
'''
        completed = subprocess.run(["sh", "-c", stubs + init], capture_output=True, timeout=2)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(b"PHANTOWD_NFS_SOURCE_DONE", completed.stdout)
        self.assertNotIn(b"FAILED", completed.stdout)

    def test_actual_image_staging_function_preserves_fixture_selection(self):
        driver = (Path(__file__).parent / "test-qemu-nfs-code.sh").read_text()
        selected = re.search(r"^(\w+)=\$\{7:-code\}$", driver, re.M).group(1)
        function = re.search(r"^install_image_file\(\) \{\n.*?^\}", driver, re.M | re.S).group(0)
        # The REAL function and selector assignment, with only its external image
        # tools stubbed. No image/file is created/deleted and no QEMU is started.
        script = (f"{selected}=source\ndebugfs=:\nscratch=/unused\n"
                  "cmp() { :; }\nrm() { :; }\n" + function +
                  f'\ninstall_image_file unused unused 0100555\ntest "${selected}" = source\n')
        completed = subprocess.run(["sh", "-eu", "-c", script], capture_output=True, timeout=2)
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
