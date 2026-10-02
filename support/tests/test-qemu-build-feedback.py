#!/usr/bin/env python3
"""Regression contracts for early feedback and failed-guest diagnostics."""

import pathlib
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
