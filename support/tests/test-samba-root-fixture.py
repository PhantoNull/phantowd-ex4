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
            "PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true "
            "hashes_during_copy=true "
            "no_overwrite=true refusals=5 scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_CODE_ACL_READY baseline=true root=true "
            "directories=true files=true refusals=5 scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_BUNDLE_READY readonly=true "
            "complete_census=true hashes=true aliases=true refusals=5 "
            "scope=qemu-only",
            "PHANTOWD_SAMBA_ROOT_CHARSET_READY charset=CP850 bytes=true "
            "roundtrip=true isolated_root=true scope=qemu-only",
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
            "PHANTOWD_SAMBA_ROOT_STOPPED", "PHANTOWD_SAMBA_ROOT_DONE",
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
