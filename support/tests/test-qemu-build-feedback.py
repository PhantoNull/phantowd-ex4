#!/usr/bin/env python3
"""Regression contracts for early feedback and failed-guest diagnostics."""

import pathlib
import os
import subprocess
import tempfile
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


class BuildFeedbackTests(unittest.TestCase):
    def test_smart_census_witness_set_requires_actual_guest_assertion(self):
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        md = (ROOT / "src/phantowd-api/md_stack_qemu_linux.go").read_text()
        fixture = (ROOT / "src/phantowd-api/smart_census_witness_set_qemu_linux.go").read_text()
        marker = "PHANTOWD_SMART_CENSUS_WITNESS_SET_READY"
        self.assertIn(marker, smoke)
        self.assertIn(marker, md)
        self.assertIn("exerciseQEMUSMARTCensusWitnessSet()", md)
        for claim in ("leaves=7", "rollback_no_leak=true", "review_pins_retained=true",
                      "reader_failure_sticky=true", "explicit_release=true"):
            self.assertIn(claim, smoke)
            self.assertIn(claim, md)
        self.assertIn("fs.ReadLinkFS = (*qemuSMARTWitnessSetFS)(nil)", fixture)
        self.assertIn("Readdirnames(129)", fixture)

    def test_smart_generation_witness_requires_actual_md_guest_assertion(self):
        marker = "PHANTOWD_SMART_FD_WITNESS_READY"
        smoke = (ROOT / "support/qemu-smoke.sh").read_text()
        md = (ROOT / "src/phantowd-api/md_stack_qemu_linux.go").read_text()
        fixture = (ROOT / "src/phantowd-api/smart_witness_qemu_linux.go").read_text()
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
            '"$expected" "$supervised" "$review" "$forced" '
            'PHANTOWD_CODE_OWNER_DONE', fixture
        )
        release = fixture.index('rm -rf "$scratch/go-cache"',
                                fixture.index('"$go_binary" build'))
        self.assertLess(release, fixture.index('cp "$base/rootfs.ext2"'))

    def test_perl_regression_precedes_build_and_scoped_refresh(self):
        script = (ROOT / "support/container/build-qemu.sh").read_text()
        regression = script.index(
            '"$external_dir/support/tests/test-perl-configure-date.py" \\\n'
        )
        full_build = script.index('    -j"$(getconf _NPROCESSORS_ONLN)"')
        self.assertLess(regression, full_build)
        self.assertIn('O="$output_dir" host-perl-dirclean', script)
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
        toolchain = script.index("    host-go-bin\n")
        api = script.index('sh "$external_dir/support/container/test-api.sh"')
        lab = script.index(
            'sh "$external_dir/support/container/test-lab-tools.sh"'
        )
        full_build = script.index('    -j"$(getconf _NPROCESSORS_ONLN)"')
        self.assertLess(toolchain, api)
        self.assertLess(api, full_build)
        self.assertLess(lab, full_build)
        self.assertEqual(script.count(
            'sh "$external_dir/support/container/test-api.sh"'
        ), 1)

    def test_compile_checkpoint_is_fresh_and_precedes_guest_tests(self):
        script = (ROOT / "support/container/build-qemu.sh").read_text()
        reset = script.index('rm -f "$compile_checkpoint"')
        full_build = script.index('    -j"$(getconf _NPROCESSORS_ONLN)"')
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


if __name__ == "__main__":
    unittest.main()
