#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Exercise the Docker RUN with private fake APT/timeout/cleanup tools."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
STUB = '''import json, os, pathlib, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
phase = 'cleanup' if name == 'rm' else (
    'update' if 'update' in args else 'install')
with open(os.environ['SDK_FIXTURE_EVENTS'], 'a') as stream:
    stream.write(json.dumps({'tool': name, 'phase': phase, 'args': args,
        'frontend': os.environ.get('DEBIAN_FRONTEND')}) + '\\n')
if name == 'timeout':
    code = int(os.environ.get('SDK_TIMEOUT_' + phase.upper(), '0'))
    if code:
        raise SystemExit(code)
    raise SystemExit(subprocess.call(args[3:]))
raise SystemExit(int(os.environ.get('SDK_EXIT_' + phase.upper(), '0')))
'''


@unittest.skipUnless(os.name == 'posix', 'actual POSIX shell required')
class SDKAptBudgets(unittest.TestCase):
    def test_https_bootstrap_has_a_dated_checksum_locked_public_bundle(self):
        text = (ROOT / 'support/docker/Dockerfile').read_text()
        before_apt = text.split('\nRUN ', 1)[0].replace('\\\n', '')
        pattern = (r'ADD --chmod=0644 --checksum=sha256:[a-f0-9]{64}\s+'
                   r'https://curl.se/ca/cacert-\d{4}-\d{2}-\d{2}\.pem\s+'
                   r'/usr/share/phantowd-sdk-bootstrap-ca.crt')
        self.assertRegex(before_apt, pattern)

    def test_snapshot_remains_dated_and_signed_over_https(self):
        text = (ROOT / 'support/docker/debian-snapshot.sources').read_text()
        uris = re.findall(r'^URIs: (.+)$', text, re.MULTILINE)
        self.assertEqual(len(uris), 2)
        for uri in uris:
            self.assertRegex(uri, r'^https://snapshot.debian.org/archive/'
                             r'debian(?:-security)?/20260925T000000Z/$')
        self.assertEqual(text.count('Signed-By: /usr/share/keyrings/'
                                    'debian-archive-keyring.gpg'), 2)
        self.assertNotRegex(text, r'(?im)^Trusted:')

    def invoke(self, **overrides):
        dockerfile = (ROOT / 'support/docker/Dockerfile').read_text()
        command = dockerfile.split('\nRUN ', 1)[1].split('\n\n', 1)[0]
        command = command.replace('\\\n', '')
        with tempfile.TemporaryDirectory(prefix='phantowd-sdk-apt-') as tmp:
            folder = Path(tmp)
            tools = folder / 'bin'
            tools.mkdir()
            for name in ('apt-get', 'timeout', 'rm'):
                executable = tools / name
                executable.write_text('#!' + sys.executable + '\n' + STUB)
                executable.chmod(0o700)
            events = folder / 'events'
            env = dict(os.environ, PATH=str(tools) + ':' + os.environ['PATH'],
                       SDK_FIXTURE_EVENTS=str(events))
            env.update({key: str(value) for key, value in overrides.items()})
            result = subprocess.run(['/bin/sh', '-c', command], env=env,
                                    capture_output=True, text=True, timeout=10)
            lines = events.read_text().splitlines() if events.exists() else []
            rows = [json.loads(line) for line in lines]
            return result, rows

    def assert_failure(self, phase, status, **overrides):
        result, rows = self.invoke(**overrides)
        self.assertEqual(result.returncode, status)
        self.assertIn('PHANTOWD_SDK_APT_FAILURE phase=' + phase +
                      ' status=' + str(status) + ' budget_seconds=' +
                      ('120' if phase == 'update' else '480'), result.stderr)
        self.assertNotIn('cleanup', [row['phase'] for row in rows])
        if phase == 'update':
            self.assertNotIn('install', [row['phase'] for row in rows])

    def test_success_has_two_bounded_phases_then_cleanup(self):
        result, rows = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([(row['tool'], row['phase']) for row in rows],
                         [('timeout', 'update'), ('apt-get', 'update'),
                          ('timeout', 'install'), ('apt-get', 'install'),
                          ('rm', 'cleanup'), ('rm', 'cleanup')])
        self.assertEqual(rows[4]['args'],
                         ['-f', '/usr/share/phantowd-sdk-bootstrap-ca.crt'])
        for row, budget in ((rows[0], '120s'), (rows[2], '480s')):
            self.assertEqual(row['args'][:4],
                             ['--signal=TERM', '--kill-after=5s', budget,
                              'apt-get'])
        for row in (rows[1], rows[3]):
            for option in ('Acquire::Retries=0', 'Acquire::http::Timeout=20',
                           'Acquire::https::Timeout=20',
                           'Acquire::https::CAInfo='
                           '/usr/share/phantowd-sdk-bootstrap-ca.crt'):
                self.assertIn(option, row['args'])
        self.assertIn('APT::Update::Error-Mode=any', rows[1]['args'])
        self.assertIn('--no-install-recommends', rows[3]['args'])
        self.assertEqual(rows[3]['frontend'], 'noninteractive')
        self.assertNotIn('PHANTOWD_SDK_APT_FAILURE', result.stderr)

    def test_update_failure_never_installs_or_cleans(self):
        self.assert_failure('update', 100, SDK_EXIT_UPDATE=100)

    def test_install_failure_never_cleans(self):
        self.assert_failure('install', 100, SDK_EXIT_INSTALL=100)

    def test_absolute_deadline_retains_distinct_phase_and_status(self):
        for phase in ('update', 'install'):
            with self.subTest(phase=phase):
                self.assert_failure(phase, 124,
                                    **{'SDK_TIMEOUT_' + phase.upper(): 124})

    def test_hard_kill_retains_distinct_phase_and_status(self):
        for phase in ('update', 'install'):
            with self.subTest(phase=phase):
                self.assert_failure(phase, 137,
                                    **{'SDK_TIMEOUT_' + phase.upper(): 137})

    def test_missing_timeout_is_not_success(self):
        self.assert_failure('update', 127, SDK_TIMEOUT_UPDATE=127)

    def test_cleanup_failure_is_not_success(self):
        result, _ = self.invoke(SDK_EXIT_CLEANUP=42)
        self.assertEqual(result.returncode, 42)


if __name__ == '__main__':
    unittest.main()
