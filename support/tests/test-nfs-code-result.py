#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("nfs_code_result", Path(__file__).resolve().parents[1] / "nfs-code-result.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class CodeReceiptTests(unittest.TestCase):
    def test_partial_start_requires_original_rpc_stop_without_claiming_other_stops(self):
        lines=[b"PHANTOWD_NFS_SOURCE_COUNTS files=4 aliases=0 bytes=400",checker.SOURCE_POLICY,
               b"PHANTOWD_NFS_SOURCE_OWNER_PARTIAL_START_ARMED original_rpcbind_ready=true mountd_constructor_refused=true mountd_started=false kernel_started=false exports_activated=false product=false scope=qemu-only",
               b"PHANTOWD_NFS_SERVER_FAILURE phase=mountd-construct",
               b"PHANTOWD_NFS_SOURCE_OWNER_PARTIAL_START_READY rpcbind_stopped=true mountd_never_started=true kernel_never_started=true exports_never_activated=true original_stopped_observation=true review_retained=true source_refs_retained=true no_retry=true no_restart=true release=false product=false scope=qemu-only",
               b"PHANTOWD_NFS_SOURCE_OWNER_PARTIAL_START_DONE"]
        for ending in (b"\n",b"\r\n"):
            checker.verify_source_owner_partial_start(ending.join(lines)+ending,self.report)
        variants=[lines[:i]+lines[i+1:] for i in range(len(lines))]
        variants += [lines[:i]+[lines[i]]+lines[i:] for i in range(len(lines))]
        variants += [list(reversed(lines)),lines+[b"PHANTOWD_NFS_SOURCE_OWNER_PARTIAL_START_FAILED"]]
        for old,new in ((b"rpcbind_stopped=true",b"rpcbind_stopped=false"),(b"release=false",b"release=true"),
                        (b"mountd_never_started=true",b"mountd_stopped=true"),(b"no_retry=true",b"no_retry=false"),
                        (b"original_stopped_observation=true",b"original_stopped_observation=false"),
                        (b"phase=mountd-construct",b"phase=original-mountd")):
            variants.append([line.replace(old,new) for line in lines])
        for variant in variants:
            with self.subTest(variant=variant),self.assertRaises(ValueError):
                checker.verify_source_owner_partial_start(b"\n".join(variant),self.report)

    def test_explicit_stop_peer_loss_cannot_borrow_supervision_receipts(self):
        lines=[b"PHANTOWD_NFS_SOURCE_COUNTS files=4 aliases=0 bytes=400",checker.SOURCE_POLICY,
               b"PHANTOWD_NFS_SOURCE_OWNER_STOP_LOSS_ARMED real_io=true original_mountd_exit=true historical_owner_running=true no_check_before_stop=true no_supervision=true product=false scope=qemu-only",
               b"PHANTOWD_NFS_SERVER_FAILURE phase=original-mountd",
               b"PHANTOWD_NFS_SOURCE_OWNER_STOP_LOSS_READY explicit_stop_detection=true supervised_detection=false original_mountd_exit=true kernel_stopped=true daemons_stopped=true exports_withdrawn=true review_retained=true source_refs_retained=true no_retry=true no_restart=true release=false quiescence=false product=false scope=qemu-only",
               b"PHANTOWD_NFS_SOURCE_OWNER_STOP_LOSS_DONE"]
        for ending in (b"\n",b"\r\n"):
            checker.verify_source_owner_stop_loss(ending.join(lines)+ending,self.report)
        variants=[lines[:i]+lines[i+1:] for i in range(len(lines))]
        variants += [lines[:i]+[lines[i]]+lines[i:] for i in range(len(lines))]
        variants += [list(reversed(lines)),lines+[b"PHANTOWD_NFS_SOURCE_OWNER_STOP_LOSS_FAILED"],
                     [line+b"\r\r" for line in lines]]
        for old,new in ((b"kernel_stopped=true",b"kernel_stopped=false"),(b"release=false",b"release=true"),
                        (b"no_retry=true",b"no_retry=false"),(b"no_supervision=true",b"no_supervision=false"),
                        (b"no_check_before_stop=true",b"no_check_before_stop=false"),
                        (b"SOURCE_OWNER_STOP_LOSS",b"SOURCE_OWNER_DAEMON_LOSS"),
                        (b"supervised_detection=false",b"supervised_detection=true")):
            variants.append([line.replace(old,new) for line in lines])
        for variant in variants:
            with self.subTest(variant=variant),self.assertRaises(ValueError):
                checker.verify_source_owner_stop_loss(b"\n".join(variant),self.report)

    def test_independent_owner_daemon_loss_requires_stopped_proof_not_just_review(self):
        lines = [b"PHANTOWD_NFS_SOURCE_COUNTS files=4 aliases=0 bytes=400", checker.SOURCE_POLICY,
                 b"PHANTOWD_NFS_SOURCE_OWNER_DAEMON_LOSS_ARMED real_io=true original_mountd_exit=true fault_before_supervision=true historical_owner_running=true detection=false product=false scope=qemu-only",
                 b"PHANTOWD_NFS_SERVER_FAILURE phase=original-mountd",
                 b"PHANTOWD_NFS_SOURCE_OWNER_DAEMON_LOSS_READY scheduled_detection=true manual_detection=false original_mountd_exit=true kernel_stopped=true daemons_stopped=true exports_withdrawn=true review_retained=true source_refs_retained=true no_retry=true no_restart=true release=false quiescence=false product=false scope=qemu-only",
                 b"PHANTOWD_NFS_SOURCE_OWNER_DAEMON_LOSS_DONE"]
        for ending in (b"\n", b"\r\n"):
            checker.verify_source_owner_daemon_loss(ending.join(lines)+ending,self.report)
        variants = [lines[:i]+lines[i+1:] for i in range(len(lines))]
        variants += [lines[:i]+[lines[i]]+lines[i:] for i in range(len(lines))]
        variants += [list(reversed(lines)),lines+[b"PHANTOWD_NFS_SOURCE_OWNER_DAEMON_LOSS_FAILED"],
                     lines+[b"PHANTOWD_NFS_SERVER_FAILURE phase=original-daemons"],
                     [line+b"\r\r" for line in lines]]
        for old,new in ((b"kernel_stopped=true",b"kernel_stopped=false"),(b"daemons_stopped=true",b"daemons_stopped=false"),
                        (b"release=false",b"release=true"),(b"no_retry=true",b"no_retry=false"),
                        (b"manual_detection=false",b"manual_detection=true"),(b"source_refs_retained=true",b"source_refs_retained=false")):
            variants.append([line.replace(old,new) for line in lines])
        for variant in variants:
            with self.subTest(variant=variant),self.assertRaises(ValueError):
                checker.verify_source_owner_daemon_loss(b"\n".join(variant),self.report)

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
                  checker.SOURCE_POLICY,
                  b"PHANTOWD_NFS_SOURCE_IO_READY original_sources=true private_0700=true rw=true ro_read=true ro_erofs=true denied_client=true anon_uid_gid=1000 fsynced=true clients_unmounted=true exports_withdrawn=true product=false scope=qemu-only",
                  b"PHANTOWD_NFS_SOURCE_KERNEL_READY original_control=true original_namespaces=true original_daemons_live=true threads=2 stop_verified=true fd_balance=true exports_withdrawn=true owner_backend=false product=false scope=qemu-only",
                  b"PHANTOWD_NFS_SOURCE_MOUNTD_READY original_channels=3 original_sources=3 filehandle_view=true private_view=true uid_gid=0 caps=dac-read-search listener_pid_bound=true stop_reaped=true fd_balance=true product=false scope=qemu-only",
                  b"PHANTOWD_NFS_SOURCE_RPCBIND_READY original_inputs=true uid_gid=1 capabilities_zero=true listener_pid_bound=true stop_reaped=true fd_balance=true product=false scope=qemu-only",
                  checker.SOURCE_SERVER,
                  b"PHANTOWD_NFS_SOURCE_OWNER_READY fixed_backend=true original_claims=true real_start_check_stop=true idle_cancel=true exclusive=true close_after_stop=true no_restart=true periodic_real_check=false product=false scope=qemu-only",
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
                         (b"original_policy_lease=true", b"original_policy_lease=false"),
                         (b"original_identity_lease=true", b"original_identity_lease=false"),
                         (b"unix_census=true", b"unix_census=false"),
                         (b"released_claims_refused=true", b"released_claims_refused=false"),
                         (b"mismatch_refused=true", b"mismatch_refused=false"),
                         (b"no_claim_release=true", b"no_claim_release=false"),
                         (b"split_calls=true", b"split_calls=false"),
                         (b"owner_ready_checks=2", b"owner_ready_checks=1"),
                         (b"exports_verified=true", b"exports_verified=false"),
                         (b"stopped=true", b"stopped=false"),
                         (b"fixed_backend=true", b"fixed_backend=false"),
                         (b"original_claims=true", b"original_claims=false"),
                         (b"real_start_check_stop=true", b"real_start_check_stop=false"),
                         (b"idle_cancel=true", b"idle_cancel=false"),
                         (b"exclusive=true", b"exclusive=false"),
                         (b"close_after_stop=true", b"close_after_stop=false"),
                         (b"no_restart=true", b"no_restart=false"),
                         (b"periodic_real_check=false", b"periodic_real_check=true"),
                         (b"product=false", b"product=true")):
            variants.append([line.replace(old, new) for line in source])
        variants += [[source[0], source[2]], source + [source[1]], list(reversed(source)), self.lines,
                      source + [b"PHANTOWD_NFS_SOURCE_FAILED"], source + [checker.KERNEL],
                      [line.replace(b"daemons=false", b"daemons=true") for line in source],
                      [line.replace(b"bytes=400", b"bytes=399") for line in source]]
        for lines in variants:
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                checker.verify_source(b"\n".join(lines), self.report)

    def test_periodic_owner_policy_loss_requires_stopped_retained_review(self):
        fault = (b"PHANTOWD_NFS_SOURCE_OWNER_POLICY_LOSS_READY periodic_detection=true manual_detection=false exclusive=true "
                 b"same_bytes_replacement=true atomic_exchange=true policy_review=true kernel_stopped=true daemons_stopped=true exports_withdrawn=true "
                 b"original_claims_retained=true source_refs_retained=true review_retained=true restored_refused=true "
                 b"no_retry=true no_restart=true release=false quiescence=false product=false scope=qemu-only")
        lines = [b"PHANTOWD_NFS_SOURCE_COUNTS files=4 aliases=0 bytes=400", checker.SOURCE_POLICY,
                 checker.SOURCE_IO, checker.SOURCE_KERNEL, checker.SOURCE_MOUNTD, checker.SOURCE_RPCBIND,
                 fault, b"PHANTOWD_NFS_SOURCE_OWNER_POLICY_LOSS_DONE"]
        for ending in (b"\n", b"\r\n"):
            checker.verify_source_owner_policy_loss(ending.join(lines)+ending, self.report)
        variants = [lines[:i]+lines[i+1:] for i in range(len(lines))]
        variants += [lines[:i]+[lines[i]]+lines[i:] for i in range(len(lines))]
        variants += [list(reversed(lines)), lines+[checker.SOURCE_OWNER], lines+[checker.SOURCE_SERVER],
                     lines+[checker.SOURCE_LOSS], [line+b"\r\r" for line in lines]]
        for field in fault.split()[1:]:
            if field.endswith(b"=true") or field.endswith(b"=false"):
                changed = field[:-4]+b"false" if field.endswith(b"true") else field[:-5]+b"true"
                variants.append([line.replace(field,changed) for line in lines])
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                checker.verify_source_owner_policy_loss(b"\n".join(value),self.report)
        for verifier in (checker.verify,checker.verify_source,checker.verify_source_loss,checker.verify_source_daemon_loss):
            with self.assertRaises(ValueError):
                verifier(b"\n".join(lines), self.report)

    def test_live_source_loss_proof_cannot_claim_normal_settlement(self):
        loss = b"PHANTOWD_NFS_SOURCE_LOSS_READY original_sources=true same_payload_replacement=true live_client=true held_file=true binding_mismatch=true restored_refused=true unmount_ebusy=true kernel_and_daemons_live=true original_refs_retained=true forced_unmount=false restart=false settlement=false product=false scope=qemu-only"
        withdraw = b"PHANTOWD_NFS_SOURCE_WITHDRAW_READY admitted_cancel=true independent_cleanup=true exports_withdrawn=true kernel_stopped=true daemons_stopped=true listeners_absent=true client_mounts_retained=true cached_file_identity=true review_retained=true stop_once=true forced_unmount=false restart=false quiescence=false product=false scope=qemu-only"
        lines = [b"PHANTOWD_NFS_SOURCE_COUNTS files=4 aliases=0 bytes=400", checker.SOURCE_POLICY, loss, withdraw, b"PHANTOWD_NFS_SOURCE_LOSS_DONE"]
        for ending in (b"\n", b"\r\n"):
            checker.verify_source_loss(ending.join(lines) + ending, self.report)
        variants = [lines[:i] + lines[i+1:] for i in range(len(lines))]
        variants += [lines[:i] + [lines[i]] + lines[i:] for i in range(len(lines))]
        variants += [list(reversed(lines)), self.lines, lines+[checker.SOURCE_IO], lines+[b"PHANTOWD_NFS_KERNEL_FAILURE phase=ready"], [line+b"\r\r" for line in lines]]
        for old,new in ((b"binding_mismatch=true",b"binding_mismatch=false"), (b"unmount_ebusy=true",b"unmount_ebusy=false"),
                        (b"original_refs_retained=true",b"original_refs_retained=false"), (b"settlement=false",b"settlement=true"),
                        (b"forced_unmount=false",b"forced_unmount=true"), (b"restart=false",b"restart=true"), (b"bytes=400",b"bytes=399"),
                        (b"admitted_cancel=true",b"admitted_cancel=false"), (b"independent_cleanup=true",b"independent_cleanup=false"),
                        (b"kernel_stopped=true",b"kernel_stopped=false"), (b"daemons_stopped=true",b"daemons_stopped=false"),
                        (b"quiescence=false",b"quiescence=true")):
            variants.append([line.replace(old,new) for line in lines])
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                checker.verify_source_loss(b"\n".join(value),self.report)
        for verifier in (checker.verify,checker.verify_source):
            with self.assertRaises(ValueError):verifier(b"\n".join(lines),self.report)

    def test_combined_mountd_exit_requires_its_own_proof_and_completion(self):
        peer = b"PHANTOWD_NFS_SOURCE_DAEMON_LOSS_READY source_review=true original_mountd_exit=true mountd_review=true kernel_and_rpcbind_live=true original_refs_retained=true client_file_cached=true stop_attempted=false restart=false product=false scope=qemu-only"
        lines = [b"PHANTOWD_NFS_SOURCE_COUNTS files=4 aliases=0 bytes=400", checker.SOURCE_POLICY, checker.SOURCE_LOSS, peer,
                 checker.SOURCE_WITHDRAW, b"PHANTOWD_NFS_SOURCE_DAEMON_LOSS_DONE"]
        for ending in (b"\n", b"\r\n"):
            checker.verify_source_daemon_loss(ending.join(lines)+ending,self.report)
        variants = [lines[:i]+lines[i+1:] for i in range(len(lines))]
        variants += [lines[:i]+[lines[i]]+lines[i:] for i in range(len(lines))]
        variants += [list(reversed(lines)), lines+[checker.SOURCE_IO],
                     lines[:-1]+[b"PHANTOWD_NFS_SOURCE_LOSS_DONE"], lines+[b"PHANTOWD_NFS_SOURCE_DAEMON_LOSS_FAILED"]]
        for old,new in ((b"original_mountd_exit=true",b"original_mountd_exit=false"),
                        (b"mountd_review=true",b"mountd_review=false"),
                        (b"kernel_and_rpcbind_live=true",b"kernel_and_rpcbind_live=false"),
                        (b"stop_attempted=false",b"stop_attempted=true"), (b"product=false",b"product=true")):
            variants.append([line.replace(old,new) for line in lines])
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                checker.verify_source_daemon_loss(b"\n".join(value),self.report)
        for verifier in (checker.verify,checker.verify_source,checker.verify_source_loss):
            with self.assertRaises(ValueError):verifier(b"\n".join(lines),self.report)

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
    def test_server_cleanup_selector_rejects_mixed_or_duplicate_profiles(self):
        source = Path(__file__).parent / "nfs-table-bootstrap.c"
        prefix = "phantowd_nfs_code_fixture=1 phantowd_nfs_source_fixture=1 "
        flag = "phantowd_nfs_source_owner_daemon_loss_fixture=1"
        stop = "phantowd_nfs_source_owner_stop_loss_fixture=1"
        invalid = ["", prefix, flag, prefix+flag+" "+flag, prefix+flag.replace("=1","=0")]
        invalid += [prefix+flag+" "+stop.replace("=1","=0"),prefix+flag+" "+stop+" "+stop]
        invalid += [prefix+flag+" "+other for other in
                    ("phantowd_nfs_code_fixture=1", "phantowd_nfs_source_fixture=1",
                     "phantowd_nfs_code_fixture=0", "phantowd_nfs_source_fixture=0",
                     "phantowd_nfs_source_loss_fixture=1", "phantowd_nfs_source_daemon_loss_fixture=1",
                     "phantowd_nfs_source_owner_policy_loss_fixture=1")]
        body = ('#define main phantowd_original_bootstrap_main\n'
                f'#include "{source.resolve().as_posix()}"\n#undef main\n'
                'int main(void) {\n'
                f'char good[] = {json.dumps("console=ttyAMA0 "+prefix+flag+" ro")};\n'
                'if (server_cleanup_command(good,strlen(good))) return 1;\n')
        body += (f'char stopgood[] = {json.dumps(prefix+flag+" "+stop)};\n'
                 'if (server_cleanup_command(stopgood,strlen(stopgood))) return 4;\n')
        for index, value in enumerate(invalid):
            body += (f'char bad{index}[] = {json.dumps(value)};\n'
                     f'if (!server_cleanup_command(bad{index},strlen(bad{index}))) return 2;\n')
        body += 'char big[4098]; memset(big,120,sizeof(big)); if (!server_cleanup_command(big,4097)) return 3; return 0; }\n'
        with tempfile.TemporaryDirectory() as tmp:
            fixture, output = Path(tmp)/"selector.c", Path(tmp)/"selector"
            fixture.write_text(body)
            built = subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(fixture), "-o", str(output)],
                                   capture_output=True, timeout=20)
            self.assertEqual(built.returncode, 0, built.stderr)
            actual = subprocess.run([str(output)], capture_output=True, timeout=2)
            self.assertEqual(actual.returncode, 0, actual.stderr)

    def dispatch_init(self):
        init = (Path(__file__).parent / "nfs-code-init.sh").read_text()
        init, count = re.subn(r"^prepare_source_identity\(\) \{\n.*?^\}",
                              "prepare_source_identity() { :; }", init, flags=re.M | re.S)
        self.assertEqual(count, 1)
        return init.replace("/usr/sbin/phantowd-nfs-code-fixture", "fixture_probe")

    def test_source_identity_uses_one_ram_directory_without_changing_original(self):
        init = (Path(__file__).parent / "nfs-code-init.sh").read_text()
        function = re.search(r"^prepare_source_identity\(\) \{\n.*?^\}", init, re.M | re.S).group(0)
        for collision in (None, "uid", "gid", "name"):
            with self.subTest(collision=collision), tempfile.TemporaryDirectory() as tmp:
                original, scratch = Path(tmp)/"etc", Path(tmp)/"ram-etc"
                original.mkdir()
                passwd = b"root:x:0:0:root:/:/bin/sh\n"
                group = b"root:x:0:\n"
                if collision == "uid": passwd += b"other:!:1000:2::/:/bin/false\n"
                if collision == "gid": group += b"other:!:1000:\n"
                if collision == "name": passwd += b"nfsfixture:!:2:2::/:/bin/false\n"
                (original/"passwd").write_bytes(passwd)
                (original/"group").write_bytes(group)
                (original/"nsswitch.conf").write_text("passwd: files\ngroup: files\n")
                # Execute only the actual preparation function. Every path is
                # remapped beneath this fixture; mounts are observations only.
                script = function.replace("/run/nfs-fixture-etc", str(scratch)).replace("/etc", str(original))
                script = "mount() { printf 'MOUNT %s\\n' \"$*\"; }\n"+script+"\nprepare_source_identity\n"
                completed = subprocess.run(["sh", "-c", script], capture_output=True, timeout=2)
                self.assertEqual((original/"passwd").read_bytes(), passwd)
                self.assertEqual((original/"group").read_bytes(), group)
                if collision:
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertFalse(scratch.exists())
                    self.assertEqual(completed.stdout, b"")
                else:
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual((scratch/"passwd").read_bytes(), passwd+b"nfsfixture:!:1000:1000::/:/sbin/nologin\n")
                    self.assertEqual((scratch/"group").read_bytes(), group+b"nfsfixture:!:1000:\n")
                    self.assertEqual((scratch/"nsswitch.conf").read_bytes(), (original/"nsswitch.conf").read_bytes())
                    self.assertEqual(completed.stdout.decode().splitlines(),
                                     [f"MOUNT -o bind {scratch} {original}", f"MOUNT -o remount,bind,ro {original}"])

    def test_actual_init_selects_source_only_after_proc_is_available(self):
        init = self.dispatch_init()
        stubs = '''proc_ready=0
mount() { if [ "$2" = proc ]; then proc_ready=1; fi; }
grep() { test "$proc_ready" = 1 || return; case "$2" in *source_loss_fixture*|*source_daemon_loss_fixture*|*source_owner_policy_loss_fixture*|*source_owner_daemon_loss_fixture*|*source_owner_stop_loss_fixture*|*source_owner_rpc_start_failure_fixture*) return 1;; esac; }
mkdir() { :; }
ip() { :; }
reboot() { :; }
fixture_probe() { test "$#" = 1 && test "$1" = --source-binding; }
'''
        completed = subprocess.run(["sh", "-c", stubs + init], capture_output=True, timeout=2)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(b"PHANTOWD_NFS_SOURCE_DONE", completed.stdout)
        self.assertNotIn(b"FAILED", completed.stdout)

    def test_actual_init_selects_loss_with_explicit_loss_selector(self):
        init = self.dispatch_init()
        stubs = '''proc_ready=0
mount() { if [ "$2" = proc ]; then proc_ready=1; fi; }
grep() { test "$proc_ready" = 1 || return; case "$2" in *source_daemon_loss_fixture*|*source_owner_policy_loss_fixture*|*source_owner_daemon_loss_fixture*|*source_owner_stop_loss_fixture*|*source_owner_rpc_start_failure_fixture*) return 1;; esac; }
mkdir() { :; }
ip() { :; }
reboot() { :; }
fixture_probe() { test "$#" = 1 && test "$1" = --source-loss; }
'''
        completed = subprocess.run(["sh", "-c", stubs+init],capture_output=True,timeout=2)
        self.assertEqual(completed.returncode,0,completed.stderr)
        self.assertIn(b"PHANTOWD_NFS_SOURCE_LOSS_DONE",completed.stdout)
        self.assertNotIn(b"FAILED",completed.stdout)

    def test_actual_init_selects_combined_source_daemon_loss_explicitly(self):
        init = self.dispatch_init()
        stubs = '''proc_ready=0
mount() { if [ "$2" = proc ]; then proc_ready=1; fi; }
grep() { test "$proc_ready" = 1 || return; case "$2" in *source_owner_policy_loss_fixture*|*source_owner_daemon_loss_fixture*|*source_owner_stop_loss_fixture*|*source_owner_rpc_start_failure_fixture*) return 1;; esac; }
mkdir() { :; }
ip() { :; }
reboot() { :; }
fixture_probe() { test "$#" = 1 && test "$1" = --source-daemon-loss; }
'''
        completed = subprocess.run(["sh", "-c", stubs+init],capture_output=True,timeout=2)
        self.assertEqual(completed.returncode,0,completed.stderr)
        self.assertIn(b"PHANTOWD_NFS_SOURCE_DAEMON_LOSS_DONE",completed.stdout)
        self.assertNotIn(b"FAILED",completed.stdout)

    def test_actual_init_selects_owner_policy_loss_explicitly(self):
        init = self.dispatch_init()
        stubs = '''proc_ready=0
mount() { if [ "$2" = proc ]; then proc_ready=1; fi; }
grep() { test "$proc_ready" = 1 || return; case "$2" in *source_loss_fixture*|*source_daemon_loss_fixture*|*source_owner_daemon_loss_fixture*|*source_owner_stop_loss_fixture*|*source_owner_rpc_start_failure_fixture*) return 1;; esac; }
mkdir() { :; }
ip() { :; }
reboot() { :; }
fixture_probe() { test "$#" = 1 && test "$1" = --source-owner-policy-loss; }
'''
        completed = subprocess.run(["sh", "-c", stubs+init],capture_output=True,timeout=2)
        self.assertEqual(completed.returncode,0,completed.stderr)
        self.assertIn(b"PHANTOWD_NFS_SOURCE_OWNER_POLICY_LOSS_DONE",completed.stdout)
        self.assertNotIn(b"FAILED",completed.stdout)

    def test_actual_init_selects_independent_owner_daemon_loss_explicitly(self):
        init = self.dispatch_init()
        stubs = '''proc_ready=0
mount() { if [ "$2" = proc ]; then proc_ready=1; fi; }
grep() { test "$proc_ready" = 1 || return; case "$2" in *source_loss_fixture*|*source_daemon_loss_fixture*|*source_owner_policy_loss_fixture*|*source_owner_stop_loss_fixture*|*source_owner_rpc_start_failure_fixture*) return 1;; esac; }
mkdir() { :; }
ip() { :; }
reboot() { :; }
fixture_probe() { test "$#" = 1 && test "$1" = --source-owner-daemon-loss; }
'''
        completed = subprocess.run(["sh", "-c", stubs+init], capture_output=True, timeout=2)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(b"PHANTOWD_NFS_SOURCE_OWNER_DAEMON_LOSS_DONE", completed.stdout)
        self.assertNotIn(b"FAILED", completed.stdout)

    def test_actual_init_selects_explicit_stop_loss_without_supervision(self):
        init=self.dispatch_init()
        stubs='''proc_ready=0
mount() { if [ "$2" = proc ]; then proc_ready=1; fi; }
grep() { test "$proc_ready" = 1 || return; case "$2" in *source_loss_fixture*|*source_daemon_loss_fixture*|*source_owner_policy_loss_fixture*|*source_owner_rpc_start_failure_fixture*) return 1;; esac; }
mkdir() { :; }
ip() { :; }
reboot() { :; }
fixture_probe() { test "$#" = 1 && test "$1" = --source-owner-daemon-stop-loss; }
'''
        completed=subprocess.run(["sh","-c",stubs+init],capture_output=True,timeout=2)
        self.assertEqual(completed.returncode,0,completed.stderr)
        self.assertIn(b"PHANTOWD_NFS_SOURCE_OWNER_STOP_LOSS_DONE",completed.stdout)
        self.assertNotIn(b"FAILED",completed.stdout)

    def test_actual_init_selects_partial_start_profile(self):
        init=self.dispatch_init()
        stubs='''proc_ready=0
mount() { if [ "$2" = proc ]; then proc_ready=1; fi; }
grep() { test "$proc_ready" = 1 || return; case "$2" in *source_loss_fixture*|*source_daemon_loss_fixture*|*source_owner_policy_loss_fixture*|*source_owner_daemon_loss_fixture*|*source_owner_stop_loss_fixture*) return 1;; esac; }
mkdir() { :; }
ip() { :; }
reboot() { :; }
fixture_probe() { test "$#" = 1 && test "$1" = --source-owner-partial-start; }
'''
        completed=subprocess.run(["sh","-c",stubs+init],capture_output=True,timeout=2)
        self.assertEqual(completed.returncode,0,completed.stderr)
        self.assertIn(b"PHANTOWD_NFS_SOURCE_OWNER_PARTIAL_START_DONE",completed.stdout)
        self.assertNotIn(b"FAILED",completed.stdout)

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
