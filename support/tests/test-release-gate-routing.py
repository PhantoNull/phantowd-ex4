#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Declarative regression guards for the two release workflow entry points."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]

class RoutingTests(unittest.TestCase):
    def test_weekly_repro_and_build_input_pushes(self):
        text = (ROOT / '.github/workflows/reproducibility.yml').read_text()
        self.assertIn("cron: '17 3 * * 1'", text)
        push = text.split('  push:\n', 1)[1].split('  workflow_dispatch:', 1)[0]
        self.assertIn('branches: [develop]', push)
        for path in ('.github/workflows/reproducibility.yml', 'versions.env', 'configs/**', 'package/**', 'support/docker/**', 'support/container/build-qemu*', 'external.*'):
            self.assertIn("'"+path+"'", push)
        self.assertIn('  workflow_dispatch:', text)
        self.assertIn('timeout-minutes: 120', text)
        self.assertIn('PHANTOWD_REPRO_COMPARE_FAILED', text)

    def test_light_promotion_check_covers_pr_and_main_push(self):
        text = (ROOT / '.github/workflows/promotion-tree.yml').read_text()
        self.assertIn('  pull_request:\n    branches: [main]', text)
        self.assertIn('  push:\n    branches: [main]', text)
        self.assertIn('    name: Promotion tree identity', text)
        self.assertIn('fetch-depth: 0', text)
        self.assertIn('persist-credentials: false', text)
        self.assertIn('python3 support/verify-promotion-tree.py', text)
        qemu = (ROOT / '.github/workflows/qemu-armv5.yml').read_text()
        self.assertRegex(qemu, r'  qemu-and-dtb:\n    if:.*chore/promote-')
        self.assertIn('name: phantowd-qemu-research-source', qemu)
        self.assertIn('tree=$(git rev-parse', qemu)
        host = (ROOT / '.github/workflows/host-tools.yml').read_text()
        for name in ('test-promotion-tree.py', 'test-release-gate-routing.py'):
            self.assertIn('python3 support/tests/'+name, host)

if __name__ == '__main__':
    unittest.main()
