#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Run the real routing contract against disposable workflow mutations."""
from contextlib import contextmanager
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PARSER = "support/nfs-reboot-result.py"
UNIT = "support/tests/test-nfs-reboot-result.py"


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory(prefix="phantowd-nfs-workflow-") as directory:
        root = Path(directory)
        # Only the contract and workflow declarations are copied/mutated.
        # Other inputs remain read-only links to the original checkout.
        # The unmodified storage contract also reads tracked executable modes.
        # Keep the actual checkout metadata read-only; do not synthesize modes.
        for name in (".git", "src", "package", "configs", "board", "tools", "versions.env"):
            (root / name).symlink_to(ROOT / name)
        support = root / "support"
        support.mkdir()
        for source in (ROOT / "support").iterdir():
            target = support / source.name
            if source.name == "test-firmware-workflow-paths.sh":
                shutil.copyfile(source, target)
            else:
                target.symlink_to(source)
        workflows = root / ".github/workflows"
        workflows.mkdir(parents=True)
        for source in (ROOT / ".github/workflows").glob("*.yml"):
            shutil.copyfile(source, workflows / source.name)
        yield root


def change_event(root, workflow, event, change):
    path = root / ".github/workflows" / workflow
    text = path.read_text()
    start = text.index("  " + event + ":\n")
    end = next((position for position in range(start + 1, len(text))
                if text.startswith("\n  ", position) and
                position + 3 < len(text) and text[position + 3] != " "), len(text))
    before = text[start:end]
    after = change(before)
    if after == before:
        raise AssertionError("mutation did not change the selected event")
    path.write_text(text[:start] + after + text[end:])


def run_contract(root):
    return subprocess.run(["sh", str(root / "support/test-firmware-workflow-paths.sh")],
                          cwd=root, capture_output=True, text=True, timeout=20)


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("sh"),
                     "actual shell/symlink fixtures require Linux")
class NFSWorkflowRouting(unittest.TestCase):
    def test_original_contract_passes(self):
        with fixture() as root:
            completed = run_contract(root)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("Firmware workflow path-contract tests passed", completed.stdout)

    def test_each_event_requires_nfs_ownership_rules(self):
        for event in ("push", "pull_request"):
            for workflow, path in (("ex4-stage-b3.yml", PARSER),
                                   ("qemu-armv5.yml", UNIT), ("host-tools.yml", PARSER)):
                with self.subTest(event=event, workflow=workflow), fixture() as root:
                    change_event(root, workflow, event,
                                 lambda text: text.replace("      - '" + path + "'\n", "", 1))
                    completed = run_contract(root)
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn(path, completed.stderr)
                    self.assertIn("under " + event, completed.stderr)

    def test_wrong_filter_kind_cannot_satisfy_literal_path_checks(self):
        for workflow, original, replacement in (("ex4-stage-b3.yml", "paths-ignore", "paths"),
                                                 ("host-tools.yml", "paths", "paths-ignore")):
            with self.subTest(workflow=workflow), fixture() as root:
                change_event(root, workflow, "push", lambda text: text.replace(
                    "    " + original + ":\n", "    " + replacement + ":\n", 1))
                completed = run_contract(root)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("push." + original, completed.stderr)

    def test_qemu_qualification_parser_cannot_be_hidden(self):
        for event in ("push", "pull_request"):
            with self.subTest(event=event), fixture() as root:
                change_event(root, "qemu-armv5.yml", event, lambda text: text.replace(
                    "    paths-ignore:\n", "    paths-ignore:\n      - '" + PARSER + "'\n", 1))
                completed = run_contract(root)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("must not ignore build input pattern " + PARSER, completed.stderr)


if __name__ == "__main__":
    unittest.main()
