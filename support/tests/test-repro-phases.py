#!/usr/bin/env python3
"""Host-only named independent-build diagnostics; no actual build runs."""

import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DRIVER = ROOT / "support/container/run-repro-phase.sh"


class ReproPhases(unittest.TestCase):
    def invoke(self, phase, code=0):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            fake = directory / "docker"
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGUMENTS"\n'
                            'exit "$FAKE_EXIT"\n')
            fake.chmod(0o700)
            arguments = directory / "arguments"
            result = subprocess.run(
                ["sh", str(DRIVER), phase, "test-image", "isolated-volume"],
                cwd=directory, capture_output=True, text=True, timeout=3,
                env={**os.environ, "PATH": f"{directory}:{os.environ['PATH']}",
                     "FAKE_EXIT": str(code), "ARGUMENTS": str(arguments)},
            )
            return result, arguments.read_text() if arguments.exists() else ""

    def test_each_phase_has_its_own_budget_and_label(self):
        for phase, seconds in (("toolchain", 2400), ("kernel", 1200),
                               ("userspace", 3600), ("rootfs", 900),
                               ("boot", 1800)):
            with self.subTest(phase=phase):
                result, args = self.invoke(phase)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"PHANTOWD_REPRO_PHASE={phase}\n", args)
                self.assertIn(
                    f"\ntimeout\n--signal=TERM\n--kill-after=10\n{seconds}\n",
                    args)
                self.assertIn(
                    "/external/support/container/build-qemu.sh\n", args)
                self.assertIn(f"PHANTOWD_REPRO_PHASE_DONE phase={phase}",
                              result.stdout)
                self.assertNotIn("FAILED", result.stderr)

    def test_failure_is_named_and_original_status_is_retained(self):
        for phase in ("toolchain", "kernel", "userspace", "rootfs", "boot"):
            for code in (1, 42, 124, 137):
                with self.subTest(phase=phase, code=code):
                    result, _ = self.invoke(phase, code)
                    self.assertEqual(result.returncode, code)
                    self.assertIn(
                        f"PHANTOWD_REPRO_PHASE_FAILED phase={phase}",
                        result.stderr)
                    self.assertIn(f"status={code}", result.stderr)
                    self.assertNotIn("PHANTOWD_REPRO_PHASE_DONE",
                                     result.stdout)

    def test_unknown_phase_refuses_before_docker(self):
        result, args = self.invoke("all")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(args, "")

    def test_workflow_preserves_global_budget_and_full_original_boot(self):
        workflow = (ROOT / ".github/workflows/reproducibility.yml").read_text()
        self.assertIn("timeout-minutes: 120", workflow)
        self.assertIn("fail-fast: false", workflow)
        positions = [workflow.index(
            f'run-repro-phase.sh {phase} "$BUILD_IMAGE" "$BUILD_VOLUME"')
            for phase in (
                "toolchain", "kernel", "userspace", "rootfs", "boot")]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('ref: ${{ github.sha }}', workflow)
        self.assertNotIn("actions/cache", workflow)
        self.assertIn("timeout-minutes: 10", workflow)
        self.assertIn("PHANTOWD_REPRO_COMPARE_FAILED", workflow)
        script = (ROOT / "support/container/build-qemu.sh").read_text()
        # The default lane and the boot phase retain the original fixture tail.
        self.assertIn('repro_phase=${PHANTOWD_REPRO_PHASE:-all}', script)
        self.assertIn('target-finalize\n', script)
        self.assertIn('"$external_dir/support/qemu-smoke.sh"', script)
        self.assertIn('"$external_dir/support/tests/test-qemu-samba-root.sh"',
                      script)


if __name__ == "__main__":
    unittest.main()
