#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Negative manifests and source-contract checks for a QEMU-only experiment."""
import copy
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import samba_root_fixture as fixture

CATALOG = """# Modules and aliases for: IBM850
alias CP850// IBM850//
alias 850// IBM850//
alias CSPC850MULTILINGUAL// IBM850//
alias OSF10020352// IBM850//
module IBM850// INTERNAL IBM850 1
module INTERNAL IBM850// IBM850 1
"""

SCAN_COST = ("PHANTOWD_RUNTIME_SCAN_COST files=104 bytes=12000000 "
             "elapsed_ns=123456789 scope=qemu-emulation-only")


def merge(values):
    return fixture.merge(values, CATALOG)


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
    @unittest.skipUnless(os.name == "posix", "Linux owned group contract")
    def test_owned_group_requires_leader_and_anonymous_writable_pipes(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as scratch:
            executable = Path(scratch, "owned-context-host")
            compiled = subprocess.run(
                ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 str(root / "support/tests/"
                     "samba-root-owned-context-fixture.c"),
                 "-o", str(executable)], timeout=30, check=False,
                capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run(
                [str(executable)], timeout=5, check=False,
                capture_output=True, text=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertEqual(result.stdout,
                             "PHANTOWD_SAMBA_OWNED_CONTEXT_NATIVE_READY "
                             "accepted=1 denied=6 scope=host-process-only\n")
            for operation in ("put /run/upload owned-created",
                              "get owned-created /run/download",
                              "put /run/upload owned-readonly-denied"):
                checked = subprocess.run(
                    [str(executable), operation], timeout=5, check=False,
                    capture_output=True, text=True)
                self.assertEqual(checked.returncode, 0, operation)
            for operation in ("put /run/upload unapproved", "ls; reboot",
                              "get ../escape /tmp/escape", "", "LS"):
                checked = subprocess.run(
                    [str(executable), operation], timeout=5, check=False,
                    capture_output=True, text=True)
                self.assertEqual(checked.returncode, 1, operation)

    @unittest.skipUnless(os.name == "posix", "Linux process context contract")
    def test_actual_context_check_denies_each_leak_and_restores(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as scratch:
            executable = Path(scratch, "context-host")
            compile_result = subprocess.run(
                ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 str(root / "support/tests/samba-root-context-fixture.c"),
                 "-o", str(executable)], timeout=30, check=False,
                capture_output=True, text=True)
            self.assertEqual(compile_result.returncode, 0,
                             compile_result.stderr)
            result = subprocess.run(
                [str(executable)], timeout=5, check=False,
                capture_output=True, text=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertEqual(result.stdout,
                             "PHANTOWD_SAMBA_CONTEXT_NATIVE_READY "
                             "denied=8 restored=true "
                             "scope=host-process-only\n")

    @unittest.skipUnless(os.name == "posix", "POSIX shell contract")
    def test_fixed_mkdir_error_evidence_and_absence(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "support/tests/samba-root-init.sh").read_text()
        start = source.index("denied_mkdir() {")
        end = source.index("run_fixture() {", start)
        helper = source[start:end]
        prefix = "/run/phantowd-samba-source/approved/inherited/"
        self.assertEqual(helper.count(prefix), 1)
        with tempfile.TemporaryDirectory() as scratch:
            helper = helper.replace(prefix, scratch + "/")
            script = (helper + '\nclient_status=$3; evidence=$4\n'
                      'client() { return "$client_status"; }\n'
                      'grep() { printf "%s\\n" "$evidence"; }\n'
                      'denied_mkdir "$1" "$2"\n')
            expected = ("NT_STATUS_ACCESS_DENIED making remote directory "
                        "\\inherited\\reader-denied")

            def run(status, evidence, user="qpreader", folder="reader-denied"):
                return subprocess.run(
                    ["/bin/sh", "-c", script, "fixture", user, folder,
                     str(status), evidence], timeout=5, check=False,
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
                ).returncode

            for status in (0, 1):
                self.assertEqual(run(status, expected), 0)
            for status in (2, 124, 143):
                self.assertNotEqual(run(status, expected), 0)
            for evidence in ("", "NT_STATUS_LOGON_FAILURE", "success",
                             expected + "\n" + expected,
                             expected.replace("reader-denied", "other"),
                             expected + "\nNT_STATUS_UNSUCCESSFUL"):
                self.assertNotEqual(run(0, evidence), 0)
            self.assertNotEqual(run(0, expected, user="qpwriter"), 0)
            self.assertNotEqual(run(0, expected, folder="other"), 0)
            Path(scratch, "reader-denied").mkdir()
            self.assertNotEqual(run(0, expected), 0)

    def test_deduplicated_fixed_roster(self):
        manifest = merge(reports())
        self.assertEqual(len(manifest.splitlines()), 7)
        self.assertEqual(manifest.count("b" * 64), 1)
        self.assertIn(hashlib.sha256(CATALOG.encode()).hexdigest(), manifest)
        self.assertNotEqual(
            manifest, fixture.merge(reports(), CATALOG + "# x\n"))

    def test_partial_reordered_or_authorized_inputs_refused(self):
        values = [reports()[:2], reports()[:3], reports()[:4], reports()[::-1]]
        for field, value in (("execution_authorized", True),
                             ("runtime_qualified", True),
                             ("static_dependencies_resolved", False),
                             ("entry", "usr/bin/untrusted")):
            changed = reports()
            changed[1][field] = value
            values.append(changed)
        for value in values:
            with self.assertRaises(ValueError):
                merge(value)

    def test_only_fixed_stream_module_entry_admitted(self):
        changed = reports()
        # A DSO has no PT_INTERP; require it only for the fixed programs.
        changed[3]["objects"][1]["path"] = "usr/lib/libc.so.6"
        changed[3]["objects"][1]["bindings"] = ["usr/lib/libc.so.6"]
        self.assertIn("/usr/lib/samba/vfs/streams_xattr.so",
                      merge(changed))
        for entry in ("usr/lib/samba/vfs/acl_xattr.so",
                      "usr/lib/untrusted.so"):
            value = copy.deepcopy(changed)
            value[3]["entry"] = entry
            with self.assertRaises(ValueError):
                merge(value)
        changed[0]["objects"][1]["path"] = "usr/lib/libc.so.6"
        changed[0]["objects"][1]["bindings"] = ["usr/lib/libc.so.6"]
        with self.assertRaises(ValueError):
            merge(changed)

    def test_only_fixed_gconv_module_and_catalog_admitted(self):
        changed = reports()
        changed[4]["objects"][1]["path"] = "usr/lib/libc.so.6"
        changed[4]["objects"][1]["bindings"] = ["usr/lib/libc.so.6"]
        self.assertIn("/usr/lib/gconv/IBM850.so", merge(changed))
        for entry in ("usr/lib/gconv/IBM437.so", "usr/lib/gconv/../IBM850.so"):
            value = copy.deepcopy(changed)
            value[4]["entry"] = entry
            with self.assertRaises(ValueError):
                merge(value)
        catalogs = ["", "x" * 4097, CATALOG + "\x00", CATALOG + "\u00e9",
                    CATALOG + "alias CP850// IBM850//\n",
                    CATALOG.replace("IBM850 1", "../../untrusted 1"),
                    CATALOG.replace("CP850//", "untrusted//"),
                    CATALOG.replace("module INTERNAL IBM850// IBM850 1", ""),
                    CATALOG + "module UTF-8// INTERNAL UTF8 1\n"]
        for catalog in catalogs:
            with self.assertRaises(ValueError):
                fixture.merge(reports(), catalog)
        changed = reports()
        changed[4]["objects"][0]["bindings"].append(fixture.CATALOG_PATH)
        with self.assertRaises(ValueError):
            merge(changed)

    def test_cross_candidate_byte_alias_conflict_refused(self):
        changed = reports()
        changed[1]["objects"][1]["sha256"] = "c" * 64
        with self.assertRaises(ValueError):
            merge(changed)
        changed = reports()
        changed[1]["objects"][0]["bindings"].append("usr/sbin/smbd")
        with self.assertRaises(ValueError):
            merge(changed)

    def test_shell_and_path_injection_refused(self):
        for alias in ("../state", "etc/passwd", "lib/x;reboot", "lib/$x"):
            # etc/passwd must not overlap generated non-ELF configuration.
            changed = reports()
            changed[0]["objects"][0]["bindings"].append(alias)
            with self.assertRaises(ValueError):
                merge(changed)

    def test_copy_does_not_mutate_candidates(self):
        values = reports()
        saved = copy.deepcopy(values)
        merge(values)
        self.assertEqual(values, saved)

    def test_merged_budget_and_guest_log_size_refused(self):
        values = reports()
        for report in values:
            report["objects"][0]["size"] = 24 * 1024 * 1024
            report["total_bytes"] = 24 * 1024 * 1024 + 100
        with self.assertRaises(ValueError):
            merge(values)
        with self.assertRaises(ValueError):
            fixture.check_guest("x" * (512 * 1024 + 1))

    def test_guest_crlf_and_strict_complete_markers(self):
        lines = [
            "PHANTOWD_SAMBA_ROOT_ENTROPY_READY provider=virtio-rng "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true "
            "hashes_during_copy=true "
            "no_overwrite=true refusals=5 scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_CODE_ACL_READY baseline=true root=true "
            "directories=true files=true refusals=5 scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_BUNDLE_READY readonly=true "
            "complete_census=true hashes=true aliases=true refusals=5 "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_RETAINED_CODE_READY complete_code_pins=true "
            "caller_close=true dynamic_elf=true generic_dynamic_refused=true "
            "generic_root_refused=true canceled_refused=true "
            "released=true no_fd_leak=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_CODE_VIEWS_READY code_only=true "
            "config_separate=true "
            "same_inodes=true readonly_views=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_CODE_VIEWS_REFUSAL_READY "
            "same_bytes_copy=true "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_CHARSET_READY charset=CP850 bytes=true "
            "roundtrip=true isolated_root=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_CONTEXT_READY original_fds_closed=true "
            "signal_mask_empty=true dispositions_default=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_BOUNDARY_READY caps=00000000000000db "
            "nnp=true original_denied=true kernel_ro=true",
            "PHANTOWD_SAMBA_ROOT_STREAMS_READY module=streams_xattr "
            "xattr_bytes=true reader_write_denied=true kernel_ro=true "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_POSIX_ACL_READY fs=ext4 bytes=true "
            "named_reader=true outsider_denied=true mask_revocation=true "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_INHERITANCE_READY fs=ext4 directory_acl=true "
            "file_acl=true setgid=true reader_write_denied=true "
            "outsider_denied=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_POLICY_READY writer_uid=1801 "
            "reader_uid=1802 outsider_denied=true kernel_ro=true "
            "original_denied=true unix_ownership=true unix_denial=true "
            "utf8_roundtrip=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_STOPPED",
            "PHANTOWD_SAMBA_OWNER_GROUP_READY nonleader_refused=true "
            "pinned_helper=true caller_close=true canceled_refused=true "
            "same_group=true caps=db distinct_accounts=true "
            "writer_bytes=true unix_ownership=true kernel_ro=true "
            "duplicate_refused=true "
            "live_close_refused=true "
            "stopped_reaped=true scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_CODE_LIFETIME_READY caller_close=true "
            "live_code_pins=true normal_stop=true drift_stopped=true "
            "forced_stop_review=true "
            "review_retained=true restoration_refused=true released=true "
            "no_fd_leak=true scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_CONFIG_LIFETIME_READY exact_contents=true "
            "caller_close=true live_pins=true same_child_objects=true "
            "readonly_noexec=true normal_stop=true drift_stopped=true "
            "review_retained=true restoration_refused=true released=true "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_OWNER_STATE_LIFETIME_READY caller_close=true "
            "live_directory_pins=true same_child_objects=true "
            "writable_noexec=true mutable_passdb=true normal_stop=true "
            "drift_stopped=true review_retained=true "
            "restoration_refused=true released=true scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_DONE",
        ]
        fixture.check_guest("\r\n".join(lines + [SCAN_COST]))
        self.assertEqual(fixture.scan_cost("\r\n".join(lines + [SCAN_COST])),
                         (104, 12000000, 123456789))
        invalid_logs = [lines[:i] + lines[i + 1:] for i in range(len(lines))]
        invalid_logs += [lines + [lines[0]], lines[::-1],
                         lines + ["PHANTOWD_SAMBA_ROOT_FAILED"],
                         lines + ["PHANTOWD_SAMBA_ROOT_LAUNCH_REFUSED"]]
        for invalid in invalid_logs:
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(invalid + [SCAN_COST]))

    def test_guest_refuses_missing_or_predictable_entropy_evidence(self):
        expected = ("PHANTOWD_SAMBA_ROOT_ENTROPY_READY provider=virtio-rng "
                    "scope=qemu-only")
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for replacement in ("", expected.replace("virtio-rng", "none"),
                            expected.replace("virtio-rng", "fixed-seed"),
                            expected.replace("qemu-only", "product"),
                            expected + "\n" + expected):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_code_lifetime_requires_verified_stop_drift_and_retention(self):
        fields = ("caller_close", "live_code_pins", "normal_stop",
                  "drift_stopped", "review_retained", "restoration_refused",
                  "released", "no_fd_leak")
        for field in fields:
            changed = [row.replace(field + "=true", field + "=false")
                       if "CODE_LIFETIME_READY" in row else row
                       for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

    def test_configuration_lifetime_requires_protected_child_and_stop(self):
        for field in ("exact_contents", "caller_close", "live_pins",
                      "same_child_objects", "readonly_noexec", "normal_stop",
                      "drift_stopped", "review_retained",
                      "restoration_refused", "released"):
            changed = [row.replace(field + "=true", field + "=false")
                       if "CONFIG_LIFETIME_READY" in row else row
                       for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

    def test_code_lifetime_refuses_missing_or_false_forced_stop_review(self):
        for value in ("", " forced_stop_review=false"):
            changed = [row.replace(" forced_stop_review=true", value)
                       if "CODE_LIFETIME_READY" in row else row
                       for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

    def test_state_requires_mutable_same_objects_and_verified_stop(self):
        expected = ("PHANTOWD_SAMBA_OWNER_STATE_LIFETIME_READY "
                    "caller_close=true live_directory_pins=true "
                    "same_child_objects=true writable_noexec=true "
                    "mutable_passdb=true normal_stop=true drift_stopped=true "
                    "review_retained=true restoration_refused=true "
                    "released=true scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        good = "\n".join([*fixture.MARKERS, SCAN_COST])
        fixture.check_guest(good)
        for field in ("caller_close", "live_directory_pins",
                      "same_child_objects", "writable_noexec",
                      "mutable_passdb",
                      "normal_stop", "drift_stopped", "review_retained",
                      "restoration_refused", "released"):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, expected.replace(
                    field + "=true", field + "=false")))
        for replacement in ("", expected + "\n" + expected,
                            expected.replace("qemu-only", "product")):
            with self.assertRaises(ValueError):
                fixture.check_guest(good.replace(expected, replacement))

    def test_inherited_context_requires_exact_positive_evidence(self):
        evidence = ("PHANTOWD_SAMBA_ROOT_CONTEXT_READY "
                    "original_fds_closed=true signal_mask_empty=true "
                    "dispositions_default=true scope=qemu-only")
        lines = list(fixture.MARKERS)
        self.assertEqual(lines.count(evidence), 1)
        fixture.check_guest("\n".join(lines + [SCAN_COST]))
        for field in ("original_fds_closed", "signal_mask_empty",
                      "dispositions_default"):
            changed = [row.replace(field + "=true", field + "=false")
                       for row in lines]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

        for replacement in ("", evidence + "\n" + evidence,
                            evidence.replace("qemu-only", "physical-ex4")):
            changed = [replacement if row == evidence else row
                       for row in lines]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

    def test_owned_group_requires_executed_write_and_canceled_admission(self):
        expected = ("PHANTOWD_SAMBA_OWNER_GROUP_READY nonleader_refused=true "
                    "pinned_helper=true caller_close=true "
                    "canceled_refused=true "
                    "same_group=true caps=db distinct_accounts=true "
                    "writer_bytes=true unix_ownership=true kernel_ro=true "
                    "duplicate_refused=true live_close_refused=true "
                    "stopped_reaped=true scope=qemu-only")
        self.assertIn(expected, fixture.MARKERS)
        for field in ("canceled_refused", "writer_bytes", "unix_ownership",
                      "kernel_ro", "same_group", "stopped_reaped"):
            changed = [row.replace(field + "=true", field + "=false")
                       if row == expected else row for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))
        for extra in (expected, "PHANTOWD_SAMBA_OWNER_FAILED writer access"):
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(
                    list(fixture.MARKERS) + [SCAN_COST, extra]))

    def test_retained_code_requires_complete_roster_and_verified_release(self):
        evidence = ("PHANTOWD_SAMBA_ROOT_RETAINED_CODE_READY "
                    "complete_code_pins=true caller_close=true "
                    "dynamic_elf=true generic_dynamic_refused=true "
                    "generic_root_refused=true canceled_refused=true "
                    "released=true "
                    "no_fd_leak=true scope=qemu-only")
        self.assertIn(evidence, fixture.MARKERS)
        for field in ("complete_code_pins", "caller_close", "dynamic_elf",
                      "generic_dynamic_refused", "generic_root_refused",
                      "canceled_refused", "released", "no_fd_leak"):
            changed = [row.replace(field + "=true", field + "=false")
                       if row == evidence else row for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))
        for replacement in (evidence + "\n" + evidence,
                            evidence.replace("qemu-only", "physical-ex4"),
                            "PHANTOWD_SAMBA_ROOT_RETAINED_CODE_FAILED"):
            changed = [replacement if row == evidence else row
                       for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

    def test_code_views_require_identity_and_separation(self):
        fields = ("code_only", "config_separate", "same_inodes",
                  "readonly_views", "same_bytes_copy")
        for field in fields:
            changed = [row.replace(field + "=true", field + "=false")
                       for row in fixture.MARKERS]
            with self.assertRaises(ValueError):
                fixture.check_guest("\n".join(changed + [SCAN_COST]))

    def test_inspection_cost_is_single_bounded_emulation_evidence(self):
        good = "\n".join(fixture.MARKERS)
        with self.assertRaises(ValueError):
            fixture.check_guest(good)
        invalid = [SCAN_COST + "\n" + SCAN_COST]
        for old, new in (("files=104", "files=0"),
                         ("files=104", "files=257"),
                         ("bytes=12000000", "bytes=0"),
                         ("bytes=12000000", "bytes=67108865"),
                         ("elapsed_ns=123456789", "elapsed_ns=0"),
                         ("elapsed_ns=123456789", "elapsed_ns=-1"),
                         ("elapsed_ns=123456789", "elapsed_ns=01"),
                         ("elapsed_ns=123456789", "elapsed_ns=" + "9" * 1000),
                         ("qemu-emulation-only", "physical-ex4")):
            invalid.append(SCAN_COST.replace(old, new))
        for cost in invalid:
            with self.assertRaises(ValueError):
                fixture.check_guest(good + "\n" + cost)

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
        self.assertIn("--user 1000:1000 --cap-drop ALL", wrapper)
        self.assertIn("--memory 2g --pids-limit 256", wrapper)
        self.assertIn("server && poison_inherited_context()", native)
        self.assertIn("dup2(directory, 63)", native)
        self.assertIn("dup2(file, 64)", native)
        self.assertIn("sigaction(SIGINT, &ignored, NULL)", native)
        self.assertIn("sigismember(&observed, SIGTERM) != 1", native)
        self.assertIn("sigismember(&current_mask, number) != 0", native)
        self.assertIn("action.sa_handler != SIG_DFL", native)
        self.assertIn("fcntl(63, F_GETFD) != -1 || errno != EBADF", native)
        self.assertIn("fcntl(64, F_GETFD) != -1 || errno != EBADF", native)
        self.assertLess(
            native.index("if (server && verify_restored_context())"),
            native.index('execve("/usr/sbin/smbd"'))
        self.assertIn("^Cap(Inh|Amb):", init)
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
        self.assertIn("usr/lib/samba/vfs/streams_xattr.so", driver)
        self.assertIn("usr/lib/gconv/IBM850.so", driver)
        self.assertIn('./cmd/qemu-runtime-bundle', driver)
        self.assertIn('"bundle phantowd-runtime-bundle-probe"', driver)
        self.assertIn('inspect_runtime_bundle()', native)
        self.assertIn('PR_CAPBSET_DROP, cap, 0, 0, 0', native)
        bundle_call = init.index('phantowd-samba-root-launcher runtime-bundle')
        self.assertLess(init.index('phantowd-runtime-bundle-probe stage'),
                        bundle_call)
        acl_call = init.index('phantowd-runtime-bundle-probe inspect-acl')
        self.assertLess(init.index('phantowd-runtime-bundle-probe stage'),
                        acl_call)
        self.assertLess(acl_call, bundle_call)
        acl = (root / 'src/phantowd-api/cmd/qemu-runtime-bundle/acl.go'
               ).read_text()
        self.assertTrue(acl.startswith('//go:build qemu && linux'))
        self.assertIn('unix.Unshare(unix.CLONE_NEWNS)', acl)
        self.assertIn('unix.MS_REC|unix.MS_PRIVATE', acl)
        self.assertIn('runtime.LockOSThread()', acl)
        self.assertIn('unix.Getxattr', acl)
        self.assertIn('plan.Inspect(context.Background(), root)', acl)
        self.assertNotIn('UnlockOSThread', acl)
        self.assertNotIn('RemoveAll(', acl)
        self.assertNotIn('cp "$canonical"', init)
        stage = (root / "src/phantowd-api/internal/runtimebundle/"
                 "stage_qemu_linux.go").read_text()
        self.assertTrue(stage.startswith('//go:build qemu && linux'))
        self.assertIn('unix.O_EXCL', stage)
        self.assertIn('ErrStageIncomplete', stage)
        self.assertIn('unix.TMPFS_MAGIC', stage)
        self.assertNotIn('RemoveAll(', stage)
        self.assertLess(bundle_call, init.index('mkdir -p "$root/etc/samba"'))
        charset_copy = init.index('cp /usr/sbin/phantowd-samba-charset-probe')
        self.assertLess(bundle_call, charset_copy)
        self.assertIn("gconv-modules", driver)
        self.assertIn("dos charset = CP850", init)
        self.assertIn("phantowd-samba-root-launcher charset", init)
        probe = (root / "support/tests/samba-charset-fixture.c").read_text()
        self.assertIn('convert("UTF-8", aliases[i]', probe)
        self.assertIn('convert(aliases[i], "UTF-8"', probe)
        self.assertIn('EILSEQ, EILSEQ, EINVAL', probe)
        self.assertIn('"LC_ALL=C"', native)
        self.assertNotIn("GCONV_PATH=", native)
        config = (root / "configs/phantowd_qemu_armv5_defconfig").read_text()
        self.assertIn('BR2_TOOLCHAIN_GLIBC_GCONV_LIBS_COPY=y', config)
        self.assertIn('BR2_TOOLCHAIN_GLIBC_GCONV_LIBS_LIST="IBM850"', config)
        self.assertIn("vfs objects = streams_xattr", init)
        self.assertIn("user.DosStream.fixture:$DATA", native)
        self.assertIn("lgetxattr", native)
        self.assertNotIn("CAP_SYS_ADMIN)", native)
        self.assertIn('"system.posix_acl_access"', native)
        self.assertIn('"system.posix_acl_default"', native)
        self.assertIn('directory ? 02750 : 0640', native)
        self.assertIn('inheritance-verify', init)
        self.assertIn('map archive = no', init)
        self.assertIn('store dos attributes = yes', init)
        self.assertIn('put /run/upload-stream inherited/child/data', init)
        self.assertIn('denied_mkdir qpreader reader-denied', init)
        self.assertIn('mount -t ext4 -o acl,nosuid,nodev,noexec', init)
        self.assertIn('file=$scratch/acl.ext4,format=raw,if=scsi,snapshot=on',
                      driver)


if __name__ == "__main__":
    unittest.main()
