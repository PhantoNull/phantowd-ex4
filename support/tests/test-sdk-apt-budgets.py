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
phase = ('update' if 'update' in args else
         'plan' if '--print-uris' in args else
         'fetch' if name == 'apt-helper' else 'install')
if name == 'rm':
    phase = ('cleanup' if any('/usr/share/' in a or '/var/lib/' in a
                             for a in args) else 'temporary-cleanup')
with open(os.environ['SDK_FIXTURE_EVENTS'], 'a') as stream:
    stream.write(json.dumps({'tool': name, 'phase': phase, 'args': args,
        'frontend': os.environ.get('DEBIAN_FRONTEND')}) + '\\n')
if name == 'timeout':
    code = int(os.environ.get('SDK_TIMEOUT_' + phase.upper(), '0'))
    if code:
        raise SystemExit(code)
    raise SystemExit(subprocess.call(args[3:]))
if phase == 'plan':
    print(os.environ['SDK_PLAN'])
raise SystemExit(int(os.environ.get('SDK_EXIT_' + phase.upper(), '0')))
'''

PLAN = ("'file:/tmp/sdk-snapshot/debian/pool/main/b/bc/bc_1_amd64.deb' "
        'bc_1_amd64.deb 100 SHA256:' + 'a' * 64)


@unittest.skipUnless(os.name == 'posix', 'actual POSIX shell required')
class SDKAptBudgets(unittest.TestCase):
    def test_https_bootstrap_has_a_dated_checksum_locked_public_bundle(self):
        text = (ROOT / 'support/docker/Dockerfile').read_text()
        before_apt = text.split('\nRUN ', 1)[0].replace('\\\n', '')
        pattern = (r'ADD --chmod=0644 --checksum=sha256:[a-f0-9]{64}\s+'
                   r'https://curl.se/ca/cacert-\d{4}-\d{2}-\d{2}\.pem\s+'
                   r'/usr/share/phantowd-sdk-bootstrap-ca.crt')
        self.assertRegex(before_apt, pattern)

    def test_local_snapshot_has_six_hash_locked_signed_metadata_inputs(self):
        text = (ROOT / 'support/docker/debian-snapshot.sources').read_text()
        uris = re.findall(r'^URIs: (.+)$', text, re.MULTILINE)
        self.assertEqual(len(uris), 2)
        self.assertEqual(uris, ['file:/tmp/sdk-snapshot/debian/',
                                'file:/tmp/sdk-snapshot/debian-security/'])
        docker = (ROOT / 'support/docker/Dockerfile').read_text()
        docker = docker.replace('\\\n', '')
        locked = re.findall(r'ADD --chmod=0644 --checksum=sha256:[a-f0-9]{64}'
                            r'\s+https://snapshot.debian.org/file/'
                            r'[a-f0-9]{40}/'
                            r'(?:InRelease|Packages\.xz)', docker)
        self.assertEqual(len(locked), 6)
        self.assertIn('Snapshot20260925T000000Z', text)
        self.assertEqual(text.count('Signed-By: /usr/share/keyrings/'
                                    'debian-archive-keyring.gpg'), 2)
        self.assertNotRegex(text, r'(?im)^Trusted:')

    def invoke(self, **overrides):
        dockerfile = (ROOT / 'support/docker/Dockerfile').read_text()
        command = 'set -eu;' + dockerfile.split('\nRUN set -eu;', 1)[1]
        command = command.split('\n\n', 1)[0]
        command = command.replace('\\\n', '')
        with tempfile.TemporaryDirectory(prefix='phantowd-sdk-apt-') as tmp:
            folder = Path(tmp)
            tools = folder / 'bin'
            tools.mkdir()
            for name in ('apt-get', 'apt-helper', 'timeout', 'rm'):
                executable = tools / name
                executable.write_text('#!' + sys.executable + '\n' + STUB)
                executable.chmod(0o700)
            helper = tools / 'phantowd-sdk-install'
            helper.write_bytes((ROOT / 'support/docker/sdk-install.sh')
                               .read_bytes())
            helper.chmod(0o700)
            events = folder / 'events'
            env = dict(os.environ, PATH=str(tools) + ':' + os.environ['PATH'],
                       SDK_FIXTURE_EVENTS=str(events), SDK_PLAN=PLAN)
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
        rows = [row for row in rows if row['phase'] != 'temporary-cleanup']
        self.assertEqual([(row['tool'], row['phase']) for row in rows],
                         [('timeout', 'update'), ('apt-get', 'update'),
                          ('timeout', 'install'), ('apt-get', 'plan'),
                          ('apt-helper', 'fetch'), ('apt-get', 'install'),
                          ('rm', 'cleanup'), ('rm', 'cleanup')])
        self.assertEqual(rows[6]['args'],
                         ['-f', '/usr/share/phantowd-sdk-bootstrap-ca.crt'])
        for row, budget, tool in ((rows[0], '120s', 'apt-get'),
                                  (rows[2], '480s', 'phantowd-sdk-install')):
            self.assertEqual(row['args'][:4],
                             ['--signal=TERM', '--kill-after=5s', budget,
                              tool])
        for row in (rows[1], rows[5]):
            for option in ('Acquire::Retries=0', 'Acquire::http::Timeout=20',
                           'Acquire::https::Timeout=20',
                           'Acquire::https::CAInfo='
                           '/usr/share/phantowd-sdk-bootstrap-ca.crt'):
                self.assertIn(option, row['args'])
        self.assertIn('APT::Update::Error-Mode=any', rows[1]['args'])
        self.assertIn('--no-install-recommends', rows[5]['args'])
        self.assertEqual(rows[5]['frontend'], 'noninteractive')
        self.assertIn('--no-download', rows[5]['args'])
        self.assertIn('Acquire::ForceHash=SHA256', rows[3]['args'])
        self.assertNotIn('PHANTOWD_SDK_APT_FAILURE', result.stderr)

    def test_invalid_prefetch_records_never_download_or_install(self):
        for bad in (PLAN[:-1], PLAN.rsplit(' ', 1)[0], PLAN + ' extra',
                    PLAN.replace('SHA256:', 'MD5Sum:'),
                    PLAN.replace('/sdk-snapshot/', '/other/'),
                    PLAN.replace("' bc_", "' ../bc_")):
            result, rows = self.invoke(SDK_PLAN=bad)
            self.assertEqual(result.returncode, 65)
            self.assertFalse(any(row['phase'] in ('fetch', 'install')
                                 and row['tool'] != 'timeout' for row in rows))

    def test_historical_objects_keep_expected_sha256(self):
        for digest, locator in (
                ('04405c19b977d19c5e0fd7210e452b80'
                 '44a065cb45a82012d45046738920ca75',
                 '4fd1e3742c4ad584c12ad55fa8a4b85a23d6ffe2'),
                ('ebcd139c31438e19f161bcf277a38708'
                 '402ddd0e3acbe208cbbb27bff1c52bb9',
                 '0ed67619a7af7e8e00326f6de6c9b60c95427201')):
            result, rows = self.invoke(SDK_PLAN=PLAN.replace('a' * 64, digest))
            self.assertEqual(result.returncode, 0, result.stderr)
            fetch = next(row for row in rows if row['tool'] == 'apt-helper')
            self.assertEqual(fetch['args'][-3],
                             'https://snapshot.debian.org/file/' + locator)
            self.assertEqual(fetch['args'][-1], 'SHA256:' + digest)

    def test_prefetch_errors_never_reach_install(self):
        for phase in ('plan', 'fetch'):
            result, rows = self.invoke(**{'SDK_EXIT_' + phase.upper(): 100})
            self.assertEqual(result.returncode, 100)
            self.assertFalse(any('--no-download' in row['args']
                                 for row in rows))

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
