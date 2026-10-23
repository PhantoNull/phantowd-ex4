#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Use real temporary Git objects; hosted run metadata is the external boundary."""
import importlib.util
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

path = Path(__file__).resolve().parents[1] / 'verify-promotion-tree.py'
spec = importlib.util.spec_from_file_location('promotion', path)
promotion = importlib.util.module_from_spec(spec)
spec.loader.exec_module(promotion)

class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.repo / 'source').write_text('qualified firmware source\n')
        self.git('add', 'source')
        self.git('commit', '-qm', 'qualified source')
        self.qualified = self.git('rev-parse', 'HEAD')
        self.run = dict(id=42, head_sha=self.qualified, status='completed', conclusion='success', path='.github/workflows/qemu-armv5.yml')
        self.run['jobs'] = [dict(name='Build QEMU baseline and EX4 research DTB', conclusion='success', steps=[dict(name=name, conclusion='success') for name in ('Build and boot ARMv5 image', 'Compile EX4 device-tree research baseline', 'Upload non-flashable QEMU artifacts')])]
        self.run['research_source'] = dict(format='phantowd-qemu-research-source-v1', run='42', checkout=self.qualified, tree=self.git('rev-parse', self.qualified+'^{tree}'), flashable='no')
        self.message = f'Promote qualified snapshot\n\nQualified-Commit: {self.qualified}\nQualified-QEMU-Run: 42'
        self.git('commit', '--allow-empty', '-qm', self.message)
        self.head = self.git('rev-parse', 'HEAD')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], text=True, stderr=subprocess.DEVNULL).strip()

    def test_new_commit_with_exact_qualified_tree_passes(self):
        self.assertNotEqual(self.head, self.qualified)
        self.assertEqual(promotion.verify(self.repo, self.head, self.head, self.run), self.git('rev-parse', self.qualified+'^{tree}'))

    def test_malformed_extra_records_refuse(self):
        for extra in ('Qualified-Commit: malformed', 'Qualified-QEMU-Run: missing', 'Qualified-QEMU-Run: 42', '[skip ci]'):
            with self.subTest(extra=extra):
                self.git('commit', '--amend', '--allow-empty', '-qm', self.message+'\n'+extra)
                head = self.git('rev-parse', 'HEAD')
                with self.assertRaises(ValueError):
                    promotion.verify(self.repo, head, head, self.run)

    def test_wrong_or_incomplete_run_refuses(self):
        for field, value in (('id', 43), ('head_sha', '0'*40), ('status', 'in_progress'), ('conclusion', 'failure'), ('path', '.github/workflows/host-tools.yml')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                promotion.verify(self.repo, self.head, self.head, dict(self.run, **{field: value}))

    def test_changed_promotion_or_prospective_main_refuses(self):
        (self.repo / 'source').write_text('unqualified source change\n')
        self.git('commit', '-qam', self.message)
        changed = self.git('rev-parse', 'HEAD')
        for head, candidate in ((changed, changed), (self.head, changed)):
            with self.subTest(head=head), self.assertRaises(ValueError):
                promotion.verify(self.repo, head, candidate, self.run)

    def test_missing_skipped_or_wrong_tree_evidence_refuses(self):
        for case in ('missing-job', 'skipped-job', 'skipped-build', 'missing-receipt', 'wrong-tree', 'wrong-run', 'bad-checkout'):
            run = json.loads(json.dumps(self.run))
            if case == 'missing-job': run['jobs'] = []
            if case == 'skipped-job': run['jobs'][0]['conclusion'] = 'skipped'
            if case == 'skipped-build': run['jobs'][0]['steps'][0]['conclusion'] = 'skipped'
            if case == 'missing-receipt': run['research_source'] = {}
            if case == 'wrong-tree': run['research_source']['tree'] = '0'*40
            if case == 'wrong-run': run['research_source']['run'] = '43'
            if case == 'bad-checkout': run['research_source']['checkout'] = 'not-a-commit'
            with self.subTest(case=case), self.assertRaises(ValueError):
                promotion.verify(self.repo, self.head, self.head, run)

    def test_cli_checks_pr_merge_and_actual_main_merge(self):
        tree = self.git('rev-parse', self.qualified+'^{tree}')
        merged = self.git('commit-tree', tree, '-p', self.qualified, '-p', self.head, '-m', 'Merge snapshot')
        self.git('update-ref', 'HEAD', merged)
        event_path = self.repo / 'event.json'
        event_path.write_text(json.dumps({'pull_request': {'base': {'ref': 'main'}, 'head': {'sha': self.head}}}))
        real = subprocess.check_output
        def boundary(args, **kwargs):
            if args[:2] == ['gh', 'api']:
                return json.dumps({'jobs': self.run['jobs']} if '/jobs?' in args[2] else self.run)
            if args[:3] == ['gh', 'run', 'download']:
                (Path(args[-1]) / 'source.txt').write_text('\n'.join(k+'='+v for k, v in self.run['research_source'].items()))
                return ''
            return real(args, **kwargs)
        previous = Path.cwd()
        try:
            os.chdir(self.repo)
            for event in ('push', 'pull_request'):
                env = dict(GITHUB_EVENT_NAME=event, GITHUB_REF='refs/heads/main', GITHUB_SHA=merged, GITHUB_EVENT_PATH=str(event_path), GITHUB_REPOSITORY='example/firmware')
                output = io.StringIO()
                with patch.dict(os.environ, env), patch.object(subprocess, 'check_output', side_effect=boundary), redirect_stdout(output):
                    self.assertEqual(promotion.main(), 0)
                    self.run['conclusion'] = 'failure'
                    error = io.StringIO()
                    with redirect_stderr(error):
                        self.assertEqual(promotion.main(), 1)
                    self.assertIn('PROMOTION_TREE_IDENTITY_FAILED', error.getvalue())
                    self.run['conclusion'] = 'success'
                self.assertIn('main_candidate_tree='+tree, output.getvalue())
        finally:
            os.chdir(previous)

if __name__ == '__main__':
    unittest.main()
