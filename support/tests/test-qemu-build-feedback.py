#!/usr/bin/env python3
"""Regression contracts for early feedback and failed-guest diagnostics."""

import hashlib
import pathlib
import os
import re
import shlex
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
LOG_HELPER = ROOT / "support/container/save-qemu-failure-log.sh"


def workflow_step(name):
    workflow = (ROOT / ".github/workflows/qemu-armv5.yml").read_text()
    step = workflow.split(f"      - name: {name}\n")[1]
    return step.split("      - name:")[0]


def save_log(destination, source):
    return subprocess.run(
        ["sh", str(LOG_HELPER), str(destination), str(source)],
        text=True, capture_output=True, check=True,
    )


def make_target_position(script, target):
    """Find a target in a real multiline make command, not a literal roster."""
    for command in re.finditer(
            r"(?m)^make -C (?:[^\n]*\\\n)*[^\n]*(?:\n|$)", script):
        words = shlex.split(command.group().replace("\\\n", " "))
        if target in words:
            return command.start()
    raise AssertionError(f"No make invocation builds {target}")


class BuildFeedbackTests(unittest.TestCase):
    def test_runtime_owner_staging_qualifies_supplied_physical_tmpfs(self):
        tests = ROOT / "support/tests"
        staging = (tests / "test-samba-root-staging.sh").read_text()
        driver = (tests / "test-qemu-runtime-owner.sh").read_text()
        environment = tests / "test-samba-root-staging-environment.sh"
        controls = environment.read_text()
        self.assertIn('tmpdir=${TMPDIR:-/tmp}', staging)
        self.assertIn('cd -P "$tmpdir" && pwd -P', staging)
        qualification = staging.index('awk -v target=')
        self.assertLess(staging.index('cd -P'), qualification)
        self.assertLess(qualification, staging.index('mktemp'))
        self.assertIn('test-samba-root-staging-environment.sh', driver)
        self.assertIn('TMPDIR="$scratch/nested"', controls)
        self.assertIn('"$scratch/proc-link" "$scratch/../../proc"', controls)

    def test_go_recipe_and_installed_sdk_are_checked_before_heavy_tests(self):
        script = (ROOT / "support/container/build-qemu.sh").read_text()
        patch_fixture = script.index(
            '"$external_dir/support/tests/test-buildroot-go-maintenance.sh" '
            '"$buildroot_source"')
        patch_apply = script.index(
            'sh "$external_dir/support/container/'
            'apply-buildroot-go-maintenance.sh" \\\n')
        sdk_build = make_target_position(script, "host-go-bin")
        sdk_check = script.index(
            'sh "$external_dir/support/container/'
            'check-buildroot-go-sdk.sh" \\\n')
        host_test = script.index(
            'sh "$external_dir/support/container/test-api.sh"')
        target_build = script.index("\tphantowd-api-dirclean")
        self.assertLess(patch_fixture, patch_apply)
        self.assertLess(patch_apply, sdk_build)
        self.assertLess(sdk_build, sdk_check)
        self.assertLess(sdk_check, host_test)
        self.assertLess(host_test, target_build)

    def test_make_target_lookup_allows_multiple_targets_not_mentions(self):
        script = ('# host-go-bin\n'
                  'echo host-go-bin\n'
                  'make -C "$source" \\\n'
                  '    O="$output" host-libopenssl host-go-bin\n')
        expected = script.index('make -C')
        self.assertEqual(make_target_position(script, "host-go-bin"), expected)
        self.assertEqual(make_target_position(script, "host-libopenssl"),
                         expected)
        for missing in ("host-go", "libopenssl", "host-go-bin-dirclean"):
            with self.subTest(target=missing):
                with self.assertRaises(AssertionError):
                    make_target_position(script, missing)

    def test_openssl_selection_precedes_board_only_return_and_heavy_work(self):
        script = (ROOT / "support/container/build-qemu.sh").read_text()
        apply = script.index(
            'sh "$external_dir/support/container/'
            'apply-buildroot-openssl-maintenance.sh" \\\n')
        prepare_return = script.index(
            'if [ "${PHANTOWD_PREPARE_ONLY:-0}" = 1 ]; then')
        host_build = make_target_position(script, "host-libopenssl")
        check = ('sh "$external_dir/support/container/'
                 'check-buildroot-openssl-tool.sh" \\\n')
        checks = [
            match.start() for match in re.finditer(re.escape(check), script)
        ]
        full_build = script.index('\n    PARALLEL_JOBS="$build_jobs" '
                                  '-j"$build_jobs"\n')
        self.assertLess(apply, prepare_return)
        self.assertLess(prepare_return, host_build)
        self.assertEqual(len(checks), 2)
        self.assertLess(host_build, checks[0])
        self.assertLess(checks[0], script.index(
            'sh "$external_dir/support/container/test-api.sh"'))
        self.assertLess(full_build, checks[1])
        for name in ("a", "b", "b2"):
            with self.subTest(stage=name):
                board = (ROOT / f"support/container/"
                         f"build-ex4-stage-{name}.sh").read_text()
                self.assertLess(make_target_position(board, "host-libopenssl"),
                                board.index(check))
        board = (ROOT / "support/container/build-ex4-stage-b2.sh").read_text()
        self.assertLess(board.index(check),
                        make_target_position(board, "linux-configure"))

    def test_enrollment_lookup_requires_exact_unique_serial_evidence(self):
        marker = (
            "PHANTOWD_M24_NATIVE_ENROLLMENT_LOOKUP_READY accounts=2 "
            "before_enrollment=true private_groups=true files_only=true "
            "foreign_omitted=true journals_unchanged=true json_refused=true "
            "installed=false activation=false scope=disposable-qemu-only"
        )
        source = (ROOT / "support/qemu-smoke.sh").read_text()
        line = next(line.strip() for line in source.splitlines()
                    if line.strip().startswith("if ! ") and marker in line)
        command = line[len("if ! "):-len("; then")]
        with tempfile.TemporaryDirectory() as temporary:
            log = pathlib.Path(temporary) / "serial.log"
            cases = [("LF", marker + "\n", True),
                     ("CRLF", marker + "\r\n", True),
                     ("absent", "", False),
                     ("duplicate", (marker + "\n") * 2, False),
                     ("prefixed", "prefix " + marker + "\n", False)]
            cases += [(field, marker.replace(field, replacement) + "\n",
                       False) for field, replacement in (
                           ("accounts=2", "accounts=1"),
                           ("scope=disposable-qemu-only", "scope=product"),
                           ("installed=false", "installed=true"),
                           ("activation=false", "activation=true"),
                           ("private_groups=true", "private_groups=false"),
                           ("before_enrollment=true",
                            "before_enrollment=false"),
                           ("journals_unchanged=true",
                            "journals_unchanged=false"),
                           ("files_only=true", "files_only=false"),
                           ("foreign_omitted=true", "foreign_omitted=false"),
                           ("json_refused=true", "json_refused=false"))]
            for label, payload, accepted in cases:
                with self.subTest(label=label):
                    log.write_bytes(payload.encode("ascii"))
                    result = subprocess.run(
                        ["sh", "-c", command], capture_output=True,
                        env={**os.environ, "log_file": str(log)}, timeout=3,
                    )
                    self.assertEqual(result.returncode == 0, accepted)

    def test_owner_nss_marker_accepts_crlf_but_not_altered_evidence(self):
        marker = (
            "PHANTOWD_M41_OWNER_SAMBA_NSS_READY identity=owner_passdb "
            "storage=mounted_roster locks=ordered native_private_groups=true "
            "files_only=true census_refusals=2 desired_roundtrip=true "
            "journals_unchanged=true stale_refused=true installed=false "
            "activation=false scope=disposable-qemu-only"
        )
        source = (ROOT / "support/qemu-smoke.sh").read_text()
        # Execute the driver's real check against synthetic serial logs;
        # this proves command-boundary behavior, not a QEMU guest pass.
        line = next(line.strip() for line in source.splitlines()
                    if line.strip().startswith("if ! ") and marker in line)
        command = line[len("if ! "):-len("; then")]
        with tempfile.TemporaryDirectory() as temporary:
            log = pathlib.Path(temporary) / "serial.log"
            for label, payload, accepted in (
                    ("LF", marker + "\n", True),
                    ("serial CRLF", marker + "\r\n", True),
                    ("wrong scope", marker.replace(
                        "scope=disposable-qemu-only", "scope=product")
                     + "\r\n", False),
                    ("prefixed", "prefix " + marker + "\r\n", False),
                    ("partial", marker.replace("census_refusals=2 ", "")
                     + "\r\n", False),
                    ("embedded CR", marker.replace("identity=", "iden\rtity=")
                     + "\r\n", False)):
                with self.subTest(label=label):
                    log.write_bytes(payload.encode("ascii"))
                    result = subprocess.run(
                        ["sh", "-c", command], capture_output=True,
                        env={**os.environ, "log_file": str(log)}, timeout=3,
                    )
                    self.assertEqual(result.returncode == 0, accepted)

    def test_identity_consumer_marker_requires_exact_serial_evidence(self):
        marker = (
            "PHANTOWD_M44_IDENTITY_CONSUMER_READY owner_close=busy "
            "unchanged_verified=true credential_disable=true "
            "new_login_denied=true reenable_verified=true review_sticky=true "
            "stale_acquire_refused=true release_no_mutation=true "
            "service_owner=false scope=disposable-qemu-only"
        )
        source = (ROOT / "support/qemu-smoke.sh").read_text()
        line = next(line.strip() for line in source.splitlines()
                    if line.strip().startswith("if ! ") and marker in line)
        command = line[len("if ! "):-len("; then")]
        with tempfile.TemporaryDirectory() as temporary:
            log = pathlib.Path(temporary) / "serial.log"
            for label, payload, accepted in (
                    ("LF", marker + "\n", True),
                    ("serial CRLF", marker + "\r\n", True),
                    ("wrong scope", marker.replace(
                        "scope=disposable-qemu-only", "scope=product")
                     + "\r\n", False),
                    ("false service claim", marker.replace(
                        "service_owner=false", "service_owner=true")
                     + "\r\n", False),
                    ("partial", marker.replace("review_sticky=true ", "")
                     + "\r\n", False),
                    ("prefixed", "prefix " + marker + "\r\n", False)):
                with self.subTest(label=label):
                    log.write_bytes(payload.encode("ascii"))
                    result = subprocess.run(
                        ["sh", "-c", command], capture_output=True,
                        env={**os.environ, "log_file": str(log)}, timeout=3,
                    )
                    self.assertEqual(result.returncode == 0, accepted)

    def test_pinned_container_avoids_unnecessary_cmake_bootstrap(self):
        # The archived PR78 build spent ~11 minutes building host-cmake,
        # which cannot itself use ccache. Buildroot's ordinary host-tool
        # suitability check must remain responsible for selecting/fallback.
        dockerfile = (ROOT / "support/docker/Dockerfile").read_text()
        self.assertIn("        cmake \\\n", dockerfile)
        self.assertIn("COPY support/docker/debian-snapshot.sources",
                      dockerfile)
        self.assertNotIn("pip install", dockerfile)
        script = (ROOT / "support/container/build-qemu.sh").read_text()
        self.assertNotIn("BR2_CMAKE=", script)
        self.assertNotIn("BR2_CMAKE_HOST_DEPENDENCY=", script)
        probe = script.index('"$external_dir/support/tests/'
                             'test-buildroot-system-cmake.sh" \\\n')
        self.assertLess(probe, make_target_position(script, "host-go-bin"))
        fixture = (ROOT / "support/tests/test-buildroot-system-cmake.sh")
        fixture = fixture.read_text()
        self.assertIn("O=\"$scratch/output\"", fixture)
        self.assertIn("check-host-cmake.sh", fixture)
        self.assertIn("HOST_CCACHE_DEPENDENCIES", fixture)
        self.assertNotIn("BR2_CMAKE=", fixture.replace(
            "'BR2_CMAKE=/usr/bin/cmake'", ""))

    def test_system_cmake_fixture_refuses_missing_host_tool(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            source = directory / "source"
            external = directory / "external"
            source.mkdir()
            (source / ".phantowd-source-ready").touch()
            (external / "configs").mkdir(parents=True)
            (external / "configs/phantowd_qemu_armv5_defconfig").touch()
            result = subprocess.run(
                ["sh", str(ROOT / "support/tests/"
                           "test-buildroot-system-cmake.sh"),
                 str(source), str(external)],
                text=True, capture_output=True, timeout=3,
                env={**os.environ, "PATH": str(directory / "empty")},
                executable="/bin/sh",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must provide /usr/bin/cmake", result.stderr)
            self.assertNotIn("PHANTOWD_SYSTEM_CMAKE_READY", result.stdout)

    def test_local_full_lane_checks_exact_fuzz_roster_before_build(self):
        runner = (ROOT / "support/container/test-api.sh").read_text()
        checker = (ROOT / "support/"
                   "test-firmware-workflow-paths.sh").read_text()
        declarations = re.findall(
            r'^require_fixed_fuzz_campaigns '
            r'"\$repo_root/support/container/test-api.sh" ([1-9][0-9]*)$',
            checker, re.MULTILINE,
        )
        campaigns = [line for line in runner.splitlines()
                     if "-fuzztime=" in line]
        self.assertEqual(declarations, [str(len(campaigns))])
        for target, package in (
                ("FuzzDecode", "networkpolicy"),
                ("FuzzWireConsume", "networkinventory"),
                ("FuzzRoute", "networkinventory"),
                ("FuzzRule", "networkinventory"),
                ("FuzzNextHopObject", "networkinventory"),
                ("FuzzEvaluate", "thermalreport"),
                ("FuzzTachEstimate", "thermalreport")):
            expected = (
                '"$go_binary" test -run \'^$\' '
                f"-fuzz '^{target}$' -fuzztime=25000x -parallel=2 "
                f"./internal/{package}")
            self.assertEqual(campaigns.count(expected), 1)
        full = (ROOT / "support/container/build-qemu.sh").read_text()
        invocation = ('sh "$external_dir/support/'
                      'test-firmware-workflow-paths.sh"')
        self.assertIn(invocation, full)
        self.assertLess(full.index(invocation), full.index("shellcheck -s sh"))
        broker = (ROOT / "support/tests/"
                  "test-storage-broker-buildroot.sh").read_text()
        self.assertIn('git -c safe.directory="$repo_root" -C "$repo_root"',
                      broker)

    def test_network_inventory_requires_actual_kernel_assertion(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        selftest = (ROOT / "src/phantowd-api/selftest.go").read_text()
        fixture = (ROOT / "src/phantowd-api/"
                   "network_inventory_qemu_linux.go").read_text()
        for claim in ("PHANTOWD_NETWORK_INVENTORY_READY", "kernel=true",
                      "repeated=true", "routes=true", "fib_only=true",
                      "rules=true", "nexthops=true", "object_fixture=true",
                      "address_fixture=true", "counts_redacted=true",
                      "json_refused=true"):
            self.assertIn(claim, smoke)
            self.assertIn(claim, selftest)
        self.assertIn("exerciseQEMUNetworkInventory()", selftest)
        self.assertIn("networkinventory.Collect(context.Background())",
                      fixture)
        self.assertIn("networkinventory.Recheck(context.Background(),o)",
                      fixture.replace(" ", ""))
        self.assertIn("summary.Routes < 1", fixture)
        self.assertIn("summary.Rules < 1", fixture)
        self.assertIn("networkinventory.QEMUObjectFixture()", fixture)
        self.assertIn("networkinventory.QEMUAddressFixture()", fixture)
        collector = (ROOT / "src/phantowd-api/internal/networkinventory/"
                     "collect_linux.go").read_text()
        self.assertIn("r.query(ctx, unix.RTM_GETNEXTHOP, "
                      "unix.RTM_NEWNEXTHOP, unix.AF_UNSPEC)", collector)
        runner = (ROOT / "support/container/test-api.sh").read_text()
        for gate in ("TestQEMUNetworkPolicy", "TestQEMUNetworkInventory",
                     "FuzzWireConsume", "FuzzRoute", "FuzzRule",
                     "FuzzNextHopObject"):
            self.assertIn(gate, runner)

    def test_thermal_projection_requires_same_boot_guest_assertion(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        selftest = (ROOT / "src/phantowd-api/selftest.go").read_text()
        fixture = (ROOT / "src/phantowd-api/"
                   "thermalreport_selftest.go").read_text()
        marker = ("PHANTOWD_THERMAL_REPORT_READY identity=true age=true "
                  "quality=true zero_distinct=true no_fallback=true "
                  "tach_arithmetic=true control=false "
                  "scope=synthetic-memory-only")
        self.assertIn(marker, smoke)
        self.assertIn(marker, selftest)
        self.assertIn("exerciseQEMUThermalReport()", selftest)
        self.assertIn("thermalreport.Evaluate", fixture)
        for refusal in ("IdentityMismatch", "Stale", "InvalidTime",
                        "ReadFailed", "Unqualified", "OutOfRange",
                        "SourceSleeping", "Missing"):
            self.assertIn(refusal, fixture)
        # Only memory evaluation belongs in this fixture. Physical input and
        # fan/controller behavior require a separately qualified provider.
        for forbidden in ('"os"', '"os/exec"', '"net"', '"syscall"',
                          '"golang.org/x/sys/unix"'):
            self.assertNotIn(forbidden, fixture)

    def test_thermal_receipts_match_both_intentional_api_selftests(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        init = (ROOT / "board/qemu/armv5/rootfs-overlay/etc/init.d/"
                "S99phantowd-ready").read_text()
        self.assertEqual(init.count('/usr/lib/phantowd/qemu-selftest-once.sh '
                                    '/usr/bin/phantowd-api '
                                    '"$api_error_log"'), 2)
        marker = ("PHANTOWD_THERMAL_REPORT_READY identity=true age=true "
                  "quality=true zero_distinct=true no_fallback=true "
                  "tach_arithmetic=true control=false "
                  "scope=synthetic-memory-only")
        # Execute the actual guard, not a second implementation of its count.
        guard = next(block for block in re.findall(
            r"(?m)^        if ! test .*?^        fi$", smoke, re.DOTALL)
            if marker in block)
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / "guest.log"
            for count in (0, 1, 2, 3):
                log.write_bytes(((marker + "\r\n") * count).encode())
                result = subprocess.run(
                    ["sh", "-c", 'log_file="$1"\n' + guard,
                     "thermal-guard", str(log)], capture_output=True,
                    text=True, timeout=3)
                self.assertEqual(result.returncode, 0 if count == 2 else 1)
            log.write_text(marker + "\n" + marker + " extra\n")
            result = subprocess.run(
                ["sh", "-c", 'log_file="$1"\n' + guard,
                 "thermal-guard", str(log)], capture_output=True,
                text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)

    def test_policy_evidence_requires_both_synthetic_guest_receipts(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        marker = (
            "PHANTOWD_POLICY_EVIDENCE_READY schema=1 all_protocols=true "
            "exact_bytes=true private=true readonly=true admission=false "
            "scope=synthetic-memory-only"
        )
        guard = next(block for block in re.findall(
            r"(?m)^        if ! test .*?^        fi$", smoke, re.DOTALL)
            if marker in block)
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / "guest.log"
            for count in (0, 1, 2, 3):
                log.write_bytes(((marker + "\r\n") * count).encode())
                result = subprocess.run(
                    ["sh", "-c", 'log_file="$1"\n' + guard,
                     "policy-evidence-guard", str(log)],
                    capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 0 if count == 2 else 1)
            log.write_text(marker + "\n" + marker + " extra\n")
            result = subprocess.run(
                ["sh", "-c", 'log_file="$1"\n' + guard,
                 "policy-evidence-guard", str(log)],
                capture_output=True, text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)

    def test_policy_history_requires_both_exact_guest_receipts(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        marker = (
            "PHANTOWD_POLICY_HISTORY_READY records=2 anchored=true "
            "gap_refused=true duplicate_refused=true uncertain_tail=true "
            "private=true readonly=true admission=false "
            "scope=synthetic-memory-only"
        )
        guard = next(block for block in re.findall(
            r"(?m)^        if ! test .*?^        fi$", smoke, re.DOTALL)
            if marker in block)
        fixture = (ROOT / "src/phantowd-api/internal/policytransaction/"
                   "history_fixture_qemu.go").read_text()
        self.assertIn(marker, fixture)
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / "guest.log"
            for newline in ("\n", "\r\n"):
                for count in (0, 1, 2, 3):
                    log.write_bytes(((marker + newline) * count).encode())
                    result = subprocess.run(
                        ["sh", "-c", 'log_file="$1"\n' + guard,
                         "history-guard", str(log)], capture_output=True,
                        text=True, timeout=3)
                    self.assertEqual(result.returncode, 0 if count == 2 else 1)
            for bad in (marker + " extra",
                        marker.replace("anchored=true", "anchored=false")):
                log.write_text(marker + "\n" + bad + "\n")
                result = subprocess.run(
                    ["sh", "-c", 'log_file="$1"\n' + guard,
                     "history-guard", str(log)], capture_output=True,
                    text=True, timeout=3)
                self.assertEqual(result.returncode, 1)

    def test_policy_history_fs_requires_both_exact_guest_receipts(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        marker = (
            "PHANTOWD_POLICY_HISTORY_FS_READY records=2 original_locks=true "
            "name_bound=true checkpoint_owned=true pending_metadata_only=true "
            "sticky_review=true readonly=true admission=false "
            "scope=temporary-qemu-only"
        )
        guard = next(block for block in re.findall(
            r"(?m)^        if ! test .*?^        fi$", smoke, re.DOTALL)
            if marker in block)
        fixture = (ROOT / "src/phantowd-api/internal/policyevidencefs/"
                   "fixture_history_qemu_linux.go").read_text()
        self.assertIn(marker, fixture)
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / "guest.log"
            for newline in ("\n", "\r\n"):
                for count in (0, 1, 2, 3):
                    log.write_bytes(((marker + newline) * count).encode())
                    result = subprocess.run(
                        ["sh", "-c", 'log_file="$1"\n' + guard,
                         "history-fs-guard", str(log)], capture_output=True,
                        text=True, timeout=3)
                    self.assertEqual(result.returncode, 0 if count == 2 else 1)
            for bad in (marker + " extra",
                        marker.replace("name_bound=true", "name_bound=false")):
                log.write_text(marker + "\n" + bad + "\n")
                result = subprocess.run(
                    ["sh", "-c", 'log_file="$1"\n' + guard,
                     "history-fs-guard", str(log)], capture_output=True,
                    text=True, timeout=3)
                self.assertEqual(result.returncode, 1)

    def test_policy_history_writer_requires_both_exact_guest_receipts(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        marker = (
            "PHANTOWD_POLICY_HISTORY_WRITER_READY operations=2 "
            "original_locks=true history_preserved=true "
            "uncertainty_fenced=true no_retry=true product=false "
            "scope=temporary-qemu-only"
        )
        guard = next(block for block in re.findall(
            r"(?m)^        if ! test .*?^        fi$", smoke, re.DOTALL)
            if marker in block)
        fixture = (ROOT / "src/phantowd-api/internal/policytransaction/"
                   "history_writer_fixture_qemu_linux.go").read_text()
        self.assertIn(marker, fixture)
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / "guest.log"
            for newline in ("\n", "\r\n"):
                for count in (0, 1, 2, 3):
                    log.write_bytes(((marker + newline) * count).encode())
                    result = subprocess.run(
                        ["sh", "-c", 'log_file="$1"\n' + guard,
                         "history-writer-guard", str(log)],
                        capture_output=True,
                        text=True, timeout=3)
                    self.assertEqual(result.returncode, 0 if count == 2 else 1)
            for bad in (marker + " extra",
                        marker.replace("no_retry=true", "no_retry=false")):
                log.write_text(marker + "\n" + bad + "\n")
                result = subprocess.run(
                    ["sh", "-c", 'log_file="$1"\n' + guard,
                     "history-writer-guard", str(log)], capture_output=True,
                    text=True, timeout=3)
                self.assertEqual(result.returncode, 1)

    def test_policy_evidence_fs_requires_both_original_guest_receipts(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        marker = (
            "PHANTOWD_POLICY_EVIDENCE_FS_READY roles=3 original_locks=true "
            "unique_mount=true complete=true sticky_review=true readonly=true "
            "admission=false scope=temporary-qemu-only"
        )
        guard = next(block for block in re.findall(
            r"(?m)^        if ! test .*?^        fi$", smoke, re.DOTALL)
            if marker in block)
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / "guest.log"
            for count in (0, 1, 2, 3):
                log.write_bytes(((marker + "\r\n") * count).encode())
                result = subprocess.run(
                    ["sh", "-c", 'log_file="$1"\n' + guard,
                     "policy-evidence-fs-guard", str(log)],
                    capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 0 if count == 2 else 1)
            log.write_text(marker + "\n" + marker + " extra\n")
            result = subprocess.run(
                ["sh", "-c", 'log_file="$1"\n' + guard,
                 "policy-evidence-fs-guard", str(log)],
                capture_output=True, text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)

    def test_policy_evidence_close_requires_exact_receipts(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        marker = (
            "PHANTOWD_POLICY_EVIDENCE_CLOSE_READY profiles=2 boundaries=11 "
            "modes=2 cases=22 no_retry=true recycled_fd_safe=true "
            "remaining_retained=true admission=false scope=temporary-qemu-only"
        )
        guard = next(block for block in re.findall(
            r"(?m)^        if ! test .*?^        fi$", smoke, re.DOTALL)
            if marker in block)
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / "guest.log"
            for count in (0, 1, 2, 3):
                log.write_bytes(((marker + "\r\n") * count).encode())
                result = subprocess.run(
                    ["sh", "-c", 'log_file="$1"\n' + guard,
                     "policy-evidence-close-guard", str(log)],
                    capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 0 if count == 2 else 1)
            for altered in (
                marker + " extra", marker.replace("cases=22", "cases=21"),
                marker.replace("recycled_fd_safe=true",
                               "recycled_fd_safe=false")
            ):
                log.write_text(marker + "\n" + altered + "\n")
                result = subprocess.run(
                    ["sh", "-c", 'log_file="$1"\n' + guard,
                     "policy-evidence-close-guard", str(log)],
                    capture_output=True, text=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)

    def test_network_preview_requires_two_receipts_per_transport(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        for transport in ("http", "https"):
            marker = (
                "PHANTOWD_NETWORK_PREVIEW_HTTP_READY "
                f"transport={transport} authenticated=true csrf=true "
                "desired_only=true exact_revision=true apply=false "
                "scope=synthetic-submitted-only"
            )
            guard = next(block for block in re.findall(
                r"(?m)^        if ! test .*?^        fi$", smoke, re.DOTALL)
                if marker in block)
            with tempfile.TemporaryDirectory() as temp:
                log = pathlib.Path(temp) / "guest.log"
                for count in (0, 1, 2, 3):
                    log.write_bytes(((marker + "\r\n") * count).encode())
                    result = subprocess.run(
                        ["sh", "-c", 'log_file="$1"\n' + guard,
                         "network-preview-guard", str(log)],
                        capture_output=True, text=True, timeout=3)
                    self.assertEqual(result.returncode, 0 if count == 2 else 1)
                for altered in (marker + " extra",
                                marker.replace("apply=false", "apply=true")):
                    log.write_text(marker + "\n" + altered + "\n")
                    result = subprocess.run(
                        ["sh", "-c", 'log_file="$1"\n' + guard,
                         "network-preview-guard", str(log)],
                        capture_output=True, text=True, timeout=3)
                    self.assertNotEqual(result.returncode, 0)

    def test_iscsi_preview_requires_two_receipts_per_transport(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        for transport in ("http", "https"):
            marker = (
                "PHANTOWD_ISCSI_PREVIEW_HTTP_READY "
                f"transport={transport} authenticated=true csrf=true "
                "coherent=true exact_decimals=true redacted=true "
                "activation=false scope=synthetic-desired-only"
            )
            guard = next(block for block in re.findall(
                r"(?m)^        if ! test .*?^        fi$", smoke, re.DOTALL)
                if marker in block)
            with tempfile.TemporaryDirectory() as temp:
                log = pathlib.Path(temp) / "guest.log"
                for count in (0, 1, 2, 3):
                    log.write_bytes(((marker + "\r\n") * count).encode())
                    result = subprocess.run(
                        ["sh", "-c", 'log_file="$1"\n' + guard,
                         "iscsi-preview-guard", str(log)],
                        capture_output=True, text=True, timeout=3)
                    self.assertEqual(result.returncode,
                                     0 if count == 2 else 1)
                log.write_text(marker + "\n" + marker + " extra\n")
                result = subprocess.run(
                    ["sh", "-c", 'log_file="$1"\n' + guard,
                     "iscsi-preview-guard", str(log)],
                    capture_output=True, text=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)

    def test_front_panel_text_requires_both_synthetic_guest_receipts(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        selftest = (ROOT / "src/phantowd-api/selftest.go").read_text()
        fixture = (ROOT / "src/phantowd-api/"
                   "frontpaneltext_selftest.go").read_text()
        marker = ("PHANTOWD_FRONT_PANEL_TEXT_READY ascii=true byte_bound=true "
                  "no_truncation=true transmit=false "
                  "scope=synthetic-memory-only")
        self.assertIn(marker, selftest)
        self.assertIn("exerciseQEMUFrontPanelText()", selftest)
        for wrapper in ('support/test-api.ps1',
                        'support/container/test-api.sh'):
            self.assertIn('TestQEMUFrontPanelText',
                          (ROOT / wrapper).read_text())
        for forbidden in ('"os"', '"os/exec"', '"net"', '"syscall"',
                          '"golang.org/x/sys/unix"'):
            self.assertNotIn(forbidden, fixture)
        guard = next(block for block in re.findall(
            r"(?m)^        if ! test .*?^        fi$", smoke, re.DOTALL)
            if marker in block)
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / "guest.log"
            for count in (0, 1, 2, 3):
                log.write_bytes(((marker + "\r\n") * count).encode())
                result = subprocess.run(
                    ["sh", "-c", 'log_file="$1"\n' + guard,
                     "front-panel-guard", str(log)], capture_output=True,
                    text=True, timeout=3)
                self.assertEqual(result.returncode, 0 if count == 2 else 1)
            log.write_text(marker + "\n" + marker + " extra\n")
            result = subprocess.run(
                ["sh", "-c", 'log_file="$1"\n' + guard,
                 "front-panel-guard", str(log)], capture_output=True,
                text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)

    def test_dashboard_assets_share_exact_checks_for_http_and_tls(self):
        normal = (ROOT / "src/phantowd-api/selftest.go").read_text()
        tls = (ROOT / "src/phantowd-api/transport_qemu.go").read_text()
        helper = (ROOT / "src/phantowd-api/"
                  "dashboard_assets_selftest.go").read_text()
        self.assertIn('exerciseQEMUDashboardAssets(client, '
                      '"http://"+listenAddress)', normal)
        self.assertIn('exerciseQEMUDashboardAssets(client, '
                      'transport.AllowedOrigin)', tls)
        for body in (normal, tls):
            self.assertIn('PHANTOWD_DASHBOARD_ASSETS_READY transport=', body)
            self.assertIn('byte_exact=true scope=qemu-loopback-only', body)
        for contract in ('bytes.Equal(data, expected)',
                         'qemuDashboardAssetLimit+1',
                         'response.Body.Close()', 'closeErr != nil',
                         'len(values) != 1', 'Content-Security-Policy',
                         'X-Content-Type-Options'):
            self.assertIn(contract, helper)
        for wrapper in ('support/test-api.ps1',
                        'support/container/test-api.sh'):
            self.assertIn('TestQEMUDashboardAssets(HTTPAndTLS|Refusals)',
                          (ROOT / wrapper).read_text())

    def test_dashboard_receipts_require_both_transports_across_restart(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        guard = re.search(r'(?m)^        for transport in http https; do\n'
                          r'[\s\S]*?^        done$', smoke).group()
        self.assertIn('PHANTOWD_DASHBOARD_ASSETS_READY', guard)
        marker = ('PHANTOWD_DASHBOARD_ASSETS_READY transport={transport} '
                  'assets=9 byte_exact=true scope=qemu-loopback-only')
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / 'guest.log'
            for transport in ('http', 'https'):
                for count in (0, 1, 2, 3):
                    counts = {'http': 2, 'https': 2, transport: count}
                    lines = [marker.format(transport=kind)
                             for kind in ('http', 'https')
                             for _ in range(counts[kind])]
                    log.write_bytes(('\r\n'.join(lines)+'\r\n').encode())
                    result = subprocess.run(
                        ['sh', '-c', 'log_file="$1"\n'+guard,
                         'asset-guard', str(log)], capture_output=True,
                        text=True, timeout=3)
                    self.assertEqual(result.returncode, 0 if count == 2 else 1)
            lines = [marker.format(transport=kind)
                     for kind in ('http', 'https') for _ in range(2)]
            lines[-1] += ' lookalike'
            log.write_text('\n'.join(lines)+'\n')
            result = subprocess.run(
                ['sh', '-c', 'log_file="$1"\n'+guard,
                 'asset-guard', str(log)], capture_output=True,
                text=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)

            for transport in ('http', 'https'):
                for wrong_assets in (8, 10):
                    lines = [marker.format(transport=kind).replace(
                        'assets=9', f'assets={wrong_assets}'
                        if kind == transport else 'assets=9')
                        for kind in ('http', 'https') for _ in range(2)]
                    log.write_text('\n'.join(lines)+'\n')
                    result = subprocess.run(
                        ['sh', '-c', 'log_file="$1"\n'+guard,
                         'asset-guard', str(log)], capture_output=True,
                        text=True, timeout=3)
                    self.assertNotEqual(result.returncode, 0)

    def test_network_policy_requires_same_boot_guest_assertion(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        selftest = (ROOT / "src/phantowd-api/selftest.go").read_text()
        fixture = (ROOT / "src/phantowd-api/"
                   "networkpolicy_selftest.go").read_text()
        for claim in ("PHANTOWD_NETWORK_POLICY_READY", "dual_stack=true",
                      "conflict_refused=true", "strict_json=true",
                      "apply=false"):
            self.assertIn(claim, smoke)
            self.assertIn(claim, selftest)
        self.assertIn("exerciseQEMUNetworkPolicy()", selftest)
        self.assertIn('networkpolicy.Decode(strings.NewReader(input))',
                      fixture)
        self.assertIn('"192.0.2.10/16"', fixture)

    def test_smart_census_witness_set_requires_actual_guest_assertion(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        md = (ROOT / "src/phantowd-api/md_stack_qemu_linux.go").read_text()
        fixture = (ROOT / "src/phantowd-api/"
                   "smart_census_witness_set_qemu_linux.go").read_text()
        marker = "PHANTOWD_SMART_CENSUS_WITNESS_SET_READY"
        self.assertIn(marker, smoke)
        self.assertIn(marker, md)
        self.assertIn("exerciseQEMUSMARTCensusWitnessSet()", md)
        for claim in ("leaves=7", "rollback_no_leak=true",
                      "review_pins_retained=true",
                      "reader_failure_sticky=true", "explicit_release=true"):
            self.assertIn(claim, smoke)
            self.assertIn(claim, md)
        self.assertIn("fs.ReadLinkFS = (*qemuSMARTWitnessSetFS)(nil)", fixture)
        self.assertIn("Readdirnames(129)", fixture)

    def test_smart_fixed_census_opener_requires_actual_guest_assertion(self):
        marker = "PHANTOWD_SMART_CENSUS_OPEN_SET_READY"
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        md = (ROOT / "src/phantowd-api/md_stack_qemu_linux.go").read_text()
        fixture = (ROOT / "src/phantowd-api/"
                   "smart_census_witness_set_qemu_linux.go").read_text()
        self.assertIn(marker, smoke)
        self.assertIn(marker, md)
        self.assertIn("exerciseQEMUSMARTCensusOpenSet()", md)
        for claim in ("original_fds_closed=true", "review_sticky=true",
                      "post_open_reader_failure_refused=true",
                      "rollback_no_leak=true", "smart_command=false"):
            self.assertIn(claim, smoke)
            self.assertIn(claim, md)
        self.assertIn("openSMARTCensusWitnessSet(ctx, reader)", fixture)
        self.assertIn("volumeprobe.OpenObservedBlockSources(observed)",
                      fixture)
        self.assertIn("count != initial+7", fixture)
        guard = next(block for block in re.findall(
            r"(?m)^        if ! test .*?^        fi$", smoke, re.DOTALL)
            if marker in block)
        row = re.search(r"grep -Fxc '([^']+)'", guard).group(1)
        with tempfile.TemporaryDirectory() as temp:
            log = pathlib.Path(temp) / "guest.log"
            for count in (0, 1, 2):
                log.write_bytes(((row + "\r\n") * count).encode())
                result = subprocess.run(
                    ["sh", "-c", 'log_file="$1"\n' + guard,
                     "smart-open-guard", str(log)], capture_output=True,
                    text=True, timeout=3)
                self.assertEqual(result.returncode, 0 if count == 1 else 1)
            for bad in (row + " extra\n", row + "\n" + row + " extra\n",
                        row + "\n" + marker + "_forged\n"):
                log.write_text(bad)
                result = subprocess.run(
                    ["sh", "-c", 'log_file="$1"\n' + guard,
                     "smart-open-guard", str(log)], capture_output=True,
                    text=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)

    def test_smart_generation_witness_requires_actual_md_guest_assertion(self):
        marker = "PHANTOWD_SMART_FD_WITNESS_READY"
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        md = (ROOT / "src/phantowd-api/md_stack_qemu_linux.go").read_text()
        fixture = (ROOT / "src/phantowd-api/"
                   "smart_witness_qemu_linux.go").read_text()
        self.assertIn(marker, smoke)
        self.assertIn(marker, md)
        self.assertIn("metadata_ioctl=BLKGETDISKSEQ", smoke)
        self.assertIn("smart_command=false", smoke)
        self.assertIn("VerifyQEMUStickyReview", fixture)
        self.assertIn('[]string{"sde", "sdf"}', fixture)
        self.assertIn("sameSMARTDiskCensus(before, after)", fixture)

    def test_smart_census_requires_both_actual_guest_assertions(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        census = (ROOT / "src/phantowd-api/selftest.go").read_text()
        md = (ROOT / "src/phantowd-api/md_stack_qemu_linux.go").read_text()
        for marker, producer in (
            ("PHANTOWD_SMART_SYSFS_CENSUS_READY", census),
            ("PHANTOWD_SMART_MD_CENSUS_READY", md),
        ):
            self.assertIn(marker, smoke)
            self.assertIn(marker, producer)
        self.assertIn("active_md_members=2", smoke)
        self.assertIn("command_admitted=false", smoke)
        self.assertIn("device_opened=false", smoke)

    def test_runtime_code_owner_disposable_lane_is_bounded(self):
        init = (ROOT / "support/tests/runtime-owner-init.sh").read_text()
        self.assertLess(init.index('mount -t tmpfs'),
                        init.index('export TMPDIR=/run'))
        self.assertLess(init.index('export TMPDIR=/run'),
                        init.index('-test.run'))
        self.assertIn('-test.count=3 -test.cpu=1', init)
        script = (ROOT / "support/container/build-qemu.sh").read_text()
        self.assertIn('support/tests/test-qemu-runtime-owner.sh', script)
        self.assertIn('qemu-runtime-owner-failure.log', script)
        fixture = (ROOT / "support/tests/test-qemu-runtime-owner.sh")
        fixture = fixture.read_text()
        self.assertIn('format=raw,if=scsi,snapshot=on', fixture)
        self.assertIn('rootwait ro panic=-1', fixture)
        self.assertIn('timeout --signal=TERM --kill-after=5 120', fixture)
        self.assertEqual(fixture.count('qemu-system-arm \\\n'), 1)
        self.assertIn('PHANTOWD_CODE_OWNER_BASE_UNCHANGED', fixture)
        self.assertIn('PHANTOWD_CODE_OWNER_FORCED_REVIEW_READY', fixture)
        self.assertIn(
            "supervised='PHANTOWD_CODE_OWNER_SUPERVISION_READY "
            "canceled=true drift=true unexpected_exit=true forced_review=true "
            "group_reaped=true pins_retained=true concurrent_refused=true "
            "scope=qemu-only'", fixture
        )
        self.assertIn(
            '"$expected" "$supervised" "$scan" "$review" "$forced" '
            'PHANTOWD_CODE_OWNER_DONE', fixture
        )
        scan_source = (ROOT / "src/phantowd-api/cmd/"
                       "qemu-runtime-bundle/scan_drift.go").read_text()
        scan_marker = re.search(
            r'fmt.Println\("(PHANTOWD_CODE_OWNER_SCAN_READY[^\"]*)"\)',
            scan_source)
        self.assertIsNotNone(scan_marker)
        self.assertIn("scan='" + scan_marker.group(1) + "'", fixture)
        self.assertIn('//go:build qemu && linux', scan_source)
        release = fixture.index('rm -rf "$scratch/go-cache"',
                                fixture.index('"$go_binary" build'))
        self.assertLess(release, fixture.index('cp "$base/rootfs.ext2"'))

    def test_runtime_owner_late_readiness_uses_same_guest(self):
        tests = ROOT / "support/tests"
        driver = (tests / "test-qemu-runtime-owner.sh").read_text()
        init = (tests / "runtime-owner-init.sh").read_text()
        stage = (tests / "stage-samba-root-file.sh").read_text()
        self.assertIn('"$scratch/readiness" ./internal/processowner', driver)
        self.assertIn(
            '"$scratch/readiness phantowd-process-readiness-tests"', driver)
        self.assertIn(
            '/usr/sbin/phantowd-process-readiness-tests:0100755', stage)
        self.assertIn('^TestReadiness(CannotCommitAfterContextEnds|'
                      'ContextChecksOriginalAndDerivedMonotonicDeadlines)$',
                      init)
        self.assertIn('-test.count=3 -test.cpu=1 -test.timeout=15s', init)
        self.assertIn('prepare && readiness && metadata &&', init)
        self.assertIn('"$readiness" "$metadata" "$identity_context" '
                      '"$expected"', driver)
        self.assertIn('TestReadinessCannotCommitAfterContextEnds ', driver)
        self.assertIn('TestReadinessContextChecksOriginalAndDerived'
                      'MonotonicDeadlines ', driver)
        self.assertIn('[ "$readiness_cases" -ne 24 ]', driver)
        self.assertEqual(driver.count('qemu-system-arm \\\n'), 1)

    def test_runtime_owner_readiness_receipts_use_real_guard(self):
        tests = ROOT / 'support/tests'
        driver = (tests / 'test-qemu-runtime-owner.sh').read_text()
        guard = driver[driver.index("expected='"):driver.index(
            '\n[ "$(sha256sum')]
        markers = dict(re.findall(r"(?m)^(\w+)='([^'\n]+)'$", guard))
        lines = [markers[name] for name in
                 ('readiness', 'metadata', 'identity_context', 'expected',
                  'supervised', 'scan', 'review', 'forced')]
        lines += ['PHANTOWD_CODE_OWNER_DONE']
        lines += ['--- PASS: TestRetainedMetadataSynthetic (0.00s)'] * 12
        main = '--- PASS: TestReadinessCannotCommitAfterContextEnds (0.00s)'
        clock = ('--- PASS: TestReadinessContextChecksOriginalAndDerived'
                 'MonotonicDeadlines (0.00s)')
        lines += [main, clock] * 3
        cases = [f'    --- PASS: TestReadinessCannotCommitAfterContextEnds/'
                 f'expired={expired}/ready={ready}/failed={failed} (0.00s)'
                 for expired in ('false', 'true')
                 for ready in ('false', 'true')
                 for failed in ('false', 'true')]
        lines += cases * 3
        identity_main = ('--- PASS: TestFileServiceLeaseAdmittedContextFailure'
                         'KeepsCauseAndReview (0.00s)')
        identity_cases = [
            '    --- PASS: TestFileServiceLeaseAdmittedContextFailure'
            f'KeepsCauseAndReview/{stage}/{cause} (0.00s)'
            for stage in ('observation', 'derivation')
            for cause in ('canceled', 'deadline')]
        lines += [identity_main] * 3 + identity_cases * 3
        controls = [('LF', lines, 0, '\n', True),
                    ('CRLF', lines, 0, '\r\n', True),
                    ('missing-marker', lines[1:], 0, '\n', False),
                    ('duplicate-marker', [lines[0]] + lines, 0, '\n', False),
                    ('changed-marker', [lines[0].replace('cases=8', 'cases=7')]
                     + lines[1:], 0, '\n', False),
                    ('missing-case', [line for index, line in enumerate(lines)
                                      if index != lines.index(cases[0])],
                     0, '\n', False),
                    ('extra-case', lines + [cases[0]], 0, '\n', False),
                    ('missing-identity-main',
                     [line for line in lines if line != identity_main],
                     0, '\n', False),
                    ('missing-identity-marker',
                     [line for line in lines
                      if line != markers['identity_context']],
                     0, '\n', False),
                    ('missing-identity-case', lines[:-1], 0, '\n', False),
                    ('extra-identity-case', lines + [identity_cases[0]],
                     0, '\n', False),
                    ('missing-main', [line for line in lines if line != main],
                     0, '\n', False),
                    ('missing-clock',
                     [line for line in lines if line != clock],
                     0, '\n', False),
                    ('guest-failed', lines, 1, '\n', False),
                    ('test-failed', lines + ['--- FAIL: synthetic'],
                     0, '\n', False),
                    ('skipped', lines + ['    --- SKIP: synthetic'],
                     0, '\n', False)]
        with tempfile.TemporaryDirectory() as temporary:
            log = pathlib.Path(temporary) / 'guest.log'
            for label, rows, status, newline, accepted in controls:
                with self.subTest(label=label):
                    log.write_bytes((newline.join(rows) + newline).encode())
                    header = 'scratch="$1"; status="$2"; failure_log=\n'
                    result = subprocess.run(
                        ['sh', '-ec', header + guard,
                         'owner-readiness-guard', temporary,
                         str(status)], text=True, capture_output=True,
                        timeout=3)
                    self.assertEqual(result.returncode == 0, accepted,
                                     result.stderr)

    def test_runtime_owner_identity_context_uses_same_guest(self):
        tests = ROOT / 'support/tests'
        driver = (tests / 'test-qemu-runtime-owner.sh').read_text()
        init = (tests / 'runtime-owner-init.sh').read_text()
        stage = (tests / 'stage-samba-root-file.sh').read_text()
        self.assertIn('"$scratch/identity-context" ./identityowner', driver)
        self.assertIn('"$scratch/identity-context '
                      'phantowd-identity-context-tests"', driver)
        self.assertIn('/usr/sbin/phantowd-identity-context-tests:0100755',
                      stage)
        self.assertIn('^TestFileServiceLeaseAdmittedContextFailure'
                      'KeepsCauseAndReview$', init)
        self.assertIn('metadata && identity_context &&', init)
        self.assertIn('[ "$identity_cases" -ne 12 ]', driver)
        self.assertEqual(driver.count('qemu-system-arm \\\n'), 1)

    def test_perl_regression_precedes_build_and_scoped_refresh(self):
        script = (ROOT / "support/container/build-qemu.sh").read_text()
        regression = script.index(
            '"$external_dir/support/tests/test-perl-configure-date.py" \\\n'
        )
        full_build = script.index('\n    PARALLEL_JOBS="$build_jobs" '
                                  '-j"$build_jobs"\n')
        self.assertLess(regression, full_build)
        self.assertIn('PARALLEL_JOBS="$build_jobs" host-perl-dirclean', script)
        self.assertIn('"$perl_inputs_previous" != "$perl_patch_digest"',
                      script)
        self.assertIn('Perl patch changed during the build', script)
        audited_source = script.index(
            '"$output_dir/build/host-perl-5.40.5/Configure" >/dev/null'
        )
        stamp = script.index(
            'mv "$perl_inputs_stamp.part" "$perl_inputs_stamp"')
        self.assertLess(full_build, audited_source)
        self.assertLess(audited_source, stamp)

    def test_smoke_budget_is_explicit_finite_and_not_a_retry(self):
        script = (ROOT / "support/qemu-smoke.sh").read_text()
        self.assertIn(
            'smoke_timeout=${PHANTOWD_QEMU_SMOKE_TIMEOUT_SECONDS:-240}', script
        )
        self.assertIn('while [ "$attempt" -lt "$smoke_timeout" ]', script)
        self.assertIn('timeout_seconds=$smoke_timeout', script)
        self.assertEqual(script.count('"$qemu_binary" \\\n'), 1)

    def test_invalid_smoke_budget_fails_before_fixture_or_qemu(self):
        for value in ("0", "301", "-1", "+120", "001", "2.5", "x", " ",
                      "9" * 30):
            with self.subTest(value=value):
                result = subprocess.run(
                    ["sh", str(ROOT / "support/qemu-smoke.sh"),
                     "/nonexistent-budget-test"], capture_output=True,
                    text=True, timeout=3,
                    env={**os.environ,
                         "PHANTOWD_QEMU_SMOKE_TIMEOUT_SECONDS": value},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("QEMU smoke timeout must", result.stderr)
                self.assertNotIn("Missing QEMU artifact", result.stderr)

    def test_valid_smoke_budget_does_not_bypass_artifact_validation(self):
        for value in ("1", "120", "240", "300"):
            with self.subTest(value=value):
                result = subprocess.run(
                    ["sh", str(ROOT / "support/qemu-smoke.sh"),
                     "/nonexistent-budget-test"], capture_output=True,
                    text=True, timeout=3,
                    env={**os.environ,
                         "PHANTOWD_QEMU_SMOKE_TIMEOUT_SECONDS": value},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Missing QEMU artifact", result.stderr)
                self.assertNotIn("QEMU smoke timeout must", result.stderr)

    def test_local_and_ci_fixture_tmpfs_fit_native_owner_compilation(self):
        # A real cold owner-fixture compile exhausted the former 128 MiB.
        # The final native/Go probe passes with this bounded 512 MiB budget.
        mount = "/phantowd-qemu-fixture-tmp:rw,exec,nosuid,nodev,size=512m"
        for file in ("support/build-qemu.ps1",
                     ".github/workflows/qemu-armv5.yml"):
            with self.subTest(file=file):
                self.assertIn(mount, (ROOT / file).read_text())
        fixture = ROOT / "support/tests/test-qemu-service-launcher.sh"
        script = fixture.read_text()
        build = script.index('"$go_binary" build -tags=qemu')
        release = script.index('rm -rf "$scratch/go-cache" "$scratch/go-path"',
                               build)
        image_copy = script.index('cp "$base/rootfs.ext2"')
        self.assertLess(build, release)
        self.assertLess(release, image_copy)

    def test_direct_guest_entrypoints_have_executable_source_mode(self):
        # Docker Desktop bind mounts can mask a non-executable Git mode.
        # Check the index when available, not the Windows-host file mode.
        paths = [
            "board/qemu/armv5/rootfs-overlay/usr/lib/phantowd/"
            + filename for filename in (
                "qemu-md-v10-init.sh", "qemu-state-init.sh",
                "qemu-selftest-once.sh",
            )
        ]
        for path in paths:
            with self.subTest(path=path):
                if (ROOT / ".git").exists():
                    result = subprocess.run(
                        ["git", "-c", f"safe.directory={ROOT}",
                         "-C", str(ROOT), "ls-files", "--stage",
                         "--", path], check=True, text=True,
                        capture_output=True,
                    )
                    self.assertTrue(result.stdout.startswith("100755 "))
                else:
                    # Source archives have no index; check their Unix mode.
                    self.assertTrue((ROOT / path).is_file())
                    self.assertTrue(os.access(ROOT / path, os.X_OK))

    def test_pinned_host_tests_precede_full_build(self):
        script = (ROOT / "support/container/build-qemu.sh").read_text()
        toolchain = make_target_position(script, "host-go-bin")
        api = script.index('sh "$external_dir/support/container/test-api.sh"')
        lab = script.index(
            'sh "$external_dir/support/container/test-lab-tools.sh"'
        )
        full_build = script.index('\n    PARALLEL_JOBS="$build_jobs" '
                                  '-j"$build_jobs"\n')
        self.assertLess(toolchain, api)
        self.assertLess(api, full_build)
        self.assertLess(lab, full_build)
        self.assertEqual(script.count(
            'sh "$external_dir/support/container/test-api.sh"'
        ), 1)

    def test_compile_checkpoint_is_fresh_and_precedes_guest_tests(self):
        script = (ROOT / "support/container/build-qemu.sh").read_text()
        reset = script.index('rm -f "$compile_checkpoint"')
        full_build = script.index('\n    PARALLEL_JOBS="$build_jobs" '
                                  '-j"$build_jobs"\n')
        checkpoint = script.index(
            "printf 'complete\\n' > \"$compile_checkpoint\""
        )
        smoke = script.index('if ! "$external_dir/support/qemu-smoke.sh"')
        self.assertLess(reset, full_build)
        self.assertLess(full_build, checkpoint)
        self.assertLess(checkpoint, smoke)

    def test_source_only_preparation_preserves_compile_checkpoint(self):
        script = (ROOT / "support/container/build-qemu.sh").read_text()
        self.assertIn(
            'if [ "${PHANTOWD_PREPARE_ONLY:-0}" != 1 ]; then\n'
            '    rm -f "$compile_checkpoint"\nfi', script
        )

    def test_workflow_preserves_diagnostics_on_failure(self):
        step = workflow_step("Upload failed QEMU diagnostics")
        self.assertIn("if: failure()", step)
        self.assertIn("artifacts/qemu-armv5/*-failure.log", step)
        self.assertNotIn("rootfs", step)
        self.assertIn("retention-days: 7", step)

    def test_failed_guest_can_seed_only_trusted_completed_compile_cache(self):
        detector = workflow_step("Observe completed compiler checkpoint")
        self.assertIn("if: ${{ !cancelled() }}", detector)
        self.assertIn('= "complete"', detector)
        save = workflow_step("Save bounded Buildroot compiler cache")
        self.assertIn("!cancelled()", save)
        self.assertIn(
            "steps.compiler_checkpoint.outputs.ready == 'true'", save
        )
        self.assertIn(
            "github.event_name == 'push' && "
            "github.ref == 'refs/heads/develop'", save
        )
        self.assertNotIn("if: success()", save)

    def test_restore_prefers_exact_inputs_before_qemu_only_fallback(self):
        restore = workflow_step("Restore Buildroot compiler cache")
        self.assertIn(
            "restore-keys: |\n"
            "            ${{ steps.ccache_key.outputs.base }}-\n"
            "            qemu-ccache-linux-", restore
        )
        self.assertNotIn("ex4", restore)
        self.assertIn("${{ steps.ccache_namespace.outputs.week }}", restore)

    def test_log_copy_and_bounded_console_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            source = directory / "guest.log"
            destination = directory / "artifacts/guest-failure.log"
            source.write_text("".join(f"line-{i}\n" for i in range(200)))
            result = save_log(destination, source)
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertIn("line-199", result.stderr)
            self.assertNotIn("line-79\n", result.stderr)
            self.assertIn("line-80\n", result.stderr)
            self.assertEqual(result.stdout, "")

    def test_missing_log_is_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            destination = directory / "artifacts/guest-failure.log"
            result = save_log(destination, directory / "missing.log")
            self.assertIn("did not create its log", destination.read_text())
            self.assertIn("did not create its log", result.stderr)


@unittest.skipUnless(os.name == 'posix', 'POSIX process-group signal contract')
class SambaSignalRetentionTests(unittest.TestCase):
    """Actual driver cleanup with stub compiler, image and QEMU commands."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix='phantowd-samba-signal-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name)
        self.source = self.directory / 'source'
        tests = self.source / 'support/tests'
        tests.mkdir(parents=True)
        for relative in ('tools/phantowd-lab', 'src/phantowd-api'):
            (self.source / relative).mkdir(parents=True)
        for name in ('test-samba-root-staging.sh',
                     'stage-samba-root-file.sh'):
            (tests / name).write_text('#!/bin/sh\nexit 0\n')
        (tests / 'samba_root_fixture.py').write_text(
            'import pathlib,sys\n'
            'command=sys.argv[1]\n'
            'if command=="select-campaigns": print("service")\n'
            'elif command=="guest-timeout": print("180")\n'
            'elif command=="prepare":\n'
            ' pathlib.Path(sys.argv[-1]).write_text("synthetic manifest")\n'
            'elif command not in ("verify-campaign","timing-summary"):\n'
            ' sys.exit(2)\n')
        self.base = self.directory / 'base'
        self.base.mkdir()
        payload = b'synthetic immutable base\n'
        names = ('rootfs.ext2', 'zImage', 'versatile-pb.dtb')
        for name in names:
            (self.base / name).write_bytes(payload)
        (self.base / 'SHA256SUMS').write_text(''.join(
            hashlib.sha256(payload).hexdigest() + '  ' + name + '\n'
            for name in names))
        self.target = self.directory / 'target'
        self.target.mkdir()
        self.binary = self.directory / 'bin'
        self.binary.mkdir()
        tool = (
            '#!/usr/bin/env python3\nimport pathlib,sys\n'
            'if "-o" in sys.argv:\n'
            ' output=pathlib.Path(sys.argv[sys.argv.index("-o")+1])\n'
            ' output.write_text("#!/bin/sh\\nprintf \'{}\\\\n\'\\n"'
            ' if output.name=="lab" else "synthetic executable")\n'
            ' output.chmod(0o755)\n')
        for name in ('go', 'compiler', 'debugfs', 'resize2fs', 'mke2fs'):
            self.executable(name, tool)
        self.executable('qemu-system-arm',
                        '#!/usr/bin/env python3\n'
                        'import os,pathlib,signal,sys\n'
                        'root=pathlib.Path(os.environ['
                        '"PHANTOWD_SIGNAL_FIXTURE_DIR"])\n'
                        'def emit(data):\n'
                        ' sys.stdout.buffer.write(data)\n'
                        ' sys.stdout.buffer.flush()\n'
                        ' with (root/"expected").open("ab") as stream:\n'
                        '  stream.write(data)\n'
                        'def stop(signum,frame):\n'
                        ' signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                        ' emit(b"synthetic-final-on-stop\\n")\n'
                        ' sys.exit(143)\n'
                        'signal.signal(signal.SIGTERM,stop)\n'
                        'emit(b"synthetic-before-interruption\\n")\n'
                        'if os.environ.get("PHANTOWD_SIGNAL_FIXTURE_LARGE")'
                        '=="yes": emit(b"x"*(1048576+65536))\n'
                        'mode=os.environ["PHANTOWD_SIGNAL_FIXTURE_MODE"]\n'
                        'if mode!="wait": sys.exit(0 if mode=="pass" else 7)\n'
                        '(root/"ready").write_text(str(os.getpid()))\n'
                        'while True: signal.pause()\n')
        self.failure = self.directory / 'artifacts/failure.log'
        self.failure.parent.mkdir()
        self.failure.write_bytes(b'stale-before-this-run\n')
        self.failure_argument = str(self.failure)
        self.large = False

    def executable(self, name, body):
        path = self.binary / name
        path.write_text(body)
        path.chmod(0o755)

    def driver_spec(self, mode):
        command = [
            'sh', str(ROOT / 'support/tests/test-qemu-samba-root.sh'),
            str(self.base), str(self.target), str(self.binary / 'go'),
            str(self.binary / 'debugfs'), str(self.binary / 'compiler'),
            str(self.source), self.failure_argument, 'service']
        environment = {
            **os.environ, 'TMPDIR': str(self.directory),
            'PATH': str(self.binary) + os.pathsep + os.environ['PATH'],
            'PHANTOWD_SIGNAL_FIXTURE_DIR': str(self.directory),
            'PHANTOWD_SIGNAL_FIXTURE_MODE': mode,
            'PHANTOWD_OUTER_GROUP_TIMEOUT': '1',
            'PHANTOWD_SIGNAL_FIXTURE_LARGE': 'yes' if self.large else 'no'}
        return command, environment

    def controller_script(self, command):
        source = (ROOT / 'support/container/build-qemu.sh').read_text()
        prologue = source.split('external_dir=', 1)[0]
        # The actual controller's signal prologue, then its foreground-call
        # shape. Heavy build commands are not executed by this unit fixture.
        return prologue + '\n' + shlex.join(command) + (
            '; status=$?; exit "$status"')

    def test_controller_drain_requires_declared_outer_group_bound(self):
        command, _ = self.driver_spec('pass')
        prologue = self.controller_script(command)
        self.assertIn('if [ "${PHANTOWD_OUTER_GROUP_TIMEOUT:-0}" = 1 ];',
                      prologue)
        self.assertEqual(prologue.count("trap 'exit 1' INT TERM"), 1)
        wrapper = (ROOT / 'support/build-qemu.ps1').read_text()
        self.assertEqual(wrapper.count(
            'export PHANTOWD_OUTER_GROUP_TIMEOUT=1'), 1)
        self.assertLess(wrapper.index(
            'export PHANTOWD_OUTER_GROUP_TIMEOUT=1'), wrapper.index(
                'exec /bin/sh /external/support/container/build-qemu.sh'))

    def test_controller_without_bound_keeps_default_signals(self):
        controller = ROOT / 'support/container/build-qemu.sh'
        prologue = controller.read_text().split('external_dir=', 1)[0]
        environment = dict(os.environ)
        environment.pop('PHANTOWD_OUTER_GROUP_TIMEOUT', None)
        result = subprocess.run(['sh', '-ec', prologue + '\ntrap'],
                                env=environment, capture_output=True,
                                text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')

    def run_driver(self, mode, group_signal=False, controller=False,
                   signum=signal.SIGTERM):
        command, environment = self.driver_spec(mode)
        if controller:
            command = ['sh', '-c', self.controller_script(command)]
        process = subprocess.Popen(
            command, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        try:
            if mode == 'wait':
                deadline = time.monotonic() + 5
                while not (self.directory / 'ready').exists():
                    self.assertIsNone(process.poll(),
                                      'driver exited before fake guest')
                    self.assertLess(time.monotonic(), deadline,
                                    'fake guest readiness deadline')
                    time.sleep(0.01)
                if group_signal:
                    os.killpg(process.pid, signum)
                else:
                    process.send_signal(signum)
            stdout, stderr = process.communicate(timeout=5)
        finally:
            # Only this test's newly-created session, never the test runner.
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=3)
        self.assertEqual(list(self.directory.glob('phantowd-samba-root.*')),
                         [], 'real driver cleanup left its tmpfs fixture')
        if (self.directory / 'ready').exists():
            guest_pid = int((self.directory / 'ready').read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(guest_pid, 0)
        return process.returncode, stdout, stderr

    def check_interrupted(self, group_signal, controller=False):
        status, stdout, stderr = self.run_driver(
            'wait', group_signal, controller)
        self.assertNotEqual(status, 0)
        self.assertEqual(self.failure.read_bytes(),
                         (self.directory / 'expected').read_bytes())
        self.assertIn(b'synthetic-final-on-stop\n', self.failure.read_bytes())
        self.assertNotIn(b'PHANTOWD_SAMBA_FOCUSED_COMPLETE', stdout)
        self.assertNotIn(b'PHANTOWD_SAMBA_ROOT_BASE_UNCHANGED', stdout)
        self.assertIn(b'qualifying=false', stderr)

    def test_parent_term_preserves_settled_active_log(self):
        self.check_interrupted(False)

    def test_group_term_preserves_settled_active_log(self):
        self.check_interrupted(True)

    def test_controller_group_term_preserves_settled_active_log(self):
        self.check_interrupted(True, controller=True)

    def test_group_int_still_fails_and_preserves_active_log(self):
        status, stdout, stderr = self.run_driver(
            'wait', group_signal=True, signum=signal.SIGINT)
        self.assertNotEqual(status, 0)
        self.assertEqual(self.failure.read_bytes(),
                         (self.directory / 'expected').read_bytes())
        self.assertNotIn(b'PHANTOWD_SAMBA_FOCUSED_COMPLETE', stdout)
        self.assertIn(b'qualifying=false', stderr)

    def test_interrupted_artifact_and_console_are_byte_bounded(self):
        self.large = True
        status, stdout, stderr = self.run_driver('wait', group_signal=True)
        self.assertNotEqual(status, 0)
        expected = (self.directory / 'expected').read_bytes()
        self.assertGreater(len(expected), 1048576)
        self.assertEqual(self.failure.read_bytes(), expected[:1048576])
        self.assertLessEqual(len(stderr), 17408)
        self.assertIn(b'completeness=unknown qualifying=false', stderr)
        self.assertNotIn(b'PHANTOWD_SAMBA_FOCUSED_COMPLETE', stdout)

    def test_no_artifact_path_keeps_console_diagnostics_only(self):
        self.failure_argument = ''
        status, stdout, stderr = self.run_driver('wait')
        self.assertNotEqual(status, 0)
        self.assertEqual(self.failure.read_bytes(), b'stale-before-this-run\n')
        self.assertIn(b'synthetic-final-on-stop', stderr)
        self.assertNotIn(b'PHANTOWD_SAMBA_FOCUSED_COMPLETE', stdout)

    def test_artifact_write_refusal_does_not_mask_interruption(self):
        self.failure.unlink()
        self.failure.mkdir()
        status, stdout, stderr = self.run_driver('wait')
        self.assertNotEqual(status, 0)
        self.assertTrue(self.failure.is_dir())
        self.assertIn(b'PHANTOWD_SAMBA_INTERRUPTED_LOG_SAVE_FAILED', stderr)
        self.assertIn(b'synthetic-final-on-stop', stderr)
        self.assertNotIn(b'PHANTOWD_SAMBA_FOCUSED_COMPLETE', stdout)

    def test_normal_failure_keeps_existing_raw_capture(self):
        status, stdout, _ = self.run_driver('fail')
        self.assertNotEqual(status, 0)
        self.assertEqual(self.failure.read_bytes(),
                         (self.directory / 'expected').read_bytes())
        self.assertNotIn(b'PHANTOWD_SAMBA_FOCUSED_COMPLETE', stdout)

    def test_success_does_not_replace_stale_failure_artifact(self):
        status, stdout, stderr = self.run_driver('pass')
        self.assertEqual(status, 0, stderr)
        self.assertEqual(self.failure.read_bytes(), b'stale-before-this-run\n')
        self.assertIn(b'PHANTOWD_SAMBA_FOCUSED_COMPLETE', stdout)
        self.assertNotIn(b'qualifying=false', stderr)


if __name__ == "__main__":
    unittest.main()
