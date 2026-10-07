#!/usr/bin/env python3
"""Build-only CPU budget regressions; no compiler or guest is started."""

import importlib.util
import os
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
HELPER = ROOT / "support/container/build_jobs.py"


class DriverJobsTests(unittest.TestCase):
    def test_real_parallel_calls_bound_make_and_package_jobs(self):
        driver = ROOT / "support/container/build-qemu.sh"
        lines = driver.read_text().splitlines()
        blocks = []
        for at, line in enumerate(lines):
            if '-j"' not in line:
                continue
            start = at
            while start >= 0 and not lines[start].lstrip().startswith(
                    'make -C '):
                start -= 1
            self.assertGreaterEqual(start, 0)
            blocks.append('\n'.join(lines[start:at + 1]))
        self.assertEqual(len(blocks), 2)
        prefix = '''
set -eu
buildroot_source=/synthetic-not-opened
external_dir=/synthetic-not-opened
download_dir=/synthetic-not-opened
output_dir=/synthetic-not-opened
build_jobs=4
getconf() { printf '24\\n'; }
make() {
  for argument do
    case "$argument" in -j*|PARALLEL_JOBS=*) printf '%s\\n' "$argument";; esac
  done
}
'''
        for block in blocks:
            with self.subTest(block=block):
                result = subprocess.run(
                    ['sh', '-ec', prefix + block], check=True,
                    capture_output=True, text=True, timeout=3,
                )
                self.assertEqual(result.stdout.splitlines(),
                                 ['PARALLEL_JOBS=4', '-j4'])

    def test_driver_selects_one_budget_before_any_make(self):
        source = (ROOT / "support/container/build-qemu.sh").read_text()
        call = ('build_jobs=$(python3 -B '
                '"$external_dir/support/container/build_jobs.py")')
        self.assertEqual(source.count(call), 1)
        self.assertLess(source.index(call), source.index('make -C '))

    def test_every_buildroot_invocation_receives_package_budget(self):
        source = (ROOT / "support/container/build-qemu.sh").read_text()
        blocks = []
        lines = source.splitlines()
        for at, line in enumerate(lines):
            if not line.lstrip().startswith(('make -C ',
                                            'make --no-print-directory -C ')):
                continue
            block = [line]
            while block[-1].endswith('\\'):
                at += 1
                block.append(lines[at])
            blocks.append('\n'.join(block))
        self.assertEqual(len(blocks), 9)
        for block in blocks:
            with self.subTest(block=block):
                self.assertIn('PARALLEL_JOBS="$build_jobs"', block)


class BudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('build_jobs', HELPER)
        cls.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.helper)

    def test_affinity_quotas_and_explicit_ceiling(self):
        for affinity, quotas, requested, expected in (
                (24, [], None, 24), (24, [(400000, 100000)], None, 4),
                (24, [(450000, 100000)], None, 4),
                (24, [(50000, 100000)], None, 1),
                (24, [(800000, 100000), (200000, 100000)], None, 2),
                (2, [(400000, 100000)], None, 2),
                (24, [(400000, 100000)], '2', 2),
                (24, [(400000, 100000)], '8', 4)):
            with self.subTest(affinity=affinity, quotas=quotas,
                              requested=requested):
                self.assertEqual(self.helper.select_jobs(
                    affinity, quotas, requested), expected)

    def test_invalid_override_and_quota_fail(self):
        for requested in ('', '0', '-1', '4.0', ' 4', '4 ', '4;true', '01'):
            with self.subTest(requested=requested):
                with self.assertRaises(ValueError):
                    self.helper.select_jobs(24, [], requested)
        for quotas in ([(0, 100000)], [(1, 0)], [(-1, 1)]):
            with self.assertRaises(ValueError):
                self.helper.select_jobs(24, quotas, None)

    def test_v2_hierarchy_and_v1_cpu_controller(self):
        for membership, mounts, files, expected in (
                ('0::/parent/child\n',
                 '1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n',
                 {'/sys/fs/cgroup/cpu.max': '800000 100000',
                  '/sys/fs/cgroup/parent/cpu.max': '200000 100000',
                  '/sys/fs/cgroup/parent/child/cpu.max': 'max 100000'},
                 [(200000, 100000), (800000, 100000)]),
                ('0::/\n',
                 '1 0 0:1 /docker/id /sys/fs/cgroup rw - cgroup2 cgroup rw\n',
                 {'/sys/fs/cgroup/cpu.max': '400000 100000'},
                 [(400000, 100000)]),
                ('2:cpu,cpuacct:/team\n',
                 '1 0 0:1 / /sys/fs/cgroup/cpu rw - '
                 'cgroup cgroup rw,cpu,cpuacct\n',
                 {'/sys/fs/cgroup/cpu/team/cpu.cfs_quota_us': '200000',
                  '/sys/fs/cgroup/cpu/team/cpu.cfs_period_us': '100000',
                  '/sys/fs/cgroup/cpu/cpu.cfs_quota_us': '-1',
                  '/sys/fs/cgroup/cpu/cpu.cfs_period_us': '100000'},
                 [(200000, 100000)])):
            def read(path):
                try:
                    return files[str(path)]
                except KeyError:
                    raise FileNotFoundError(str(path))
            self.assertEqual(self.helper.read_quotas(
                membership, mounts, read), expected)

    def test_missing_controller_is_unlimited_but_bad_data_is_not(self):
        def missing(path):
            raise FileNotFoundError(str(path))
        self.assertEqual(self.helper.read_quotas(
            '0::/\n', '1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n',
            missing), [])
        for membership, contents in (('0::/../escape\n', 'max 100000'),
                                     ('0::/\n', 'bad'),
                                     ('0::/\n', 'max 0')):
            with self.assertRaises(ValueError):
                self.helper.read_quotas(
                    membership,
                    '1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n',
                    lambda path: contents)

    def test_cli_read_only_live_budget(self):
        if not hasattr(os, 'sched_getaffinity'):
            self.skipTest('Linux only')
        result = subprocess.run(
            ['python3', '-B', str(HELPER)], check=True, capture_output=True,
            text=True, timeout=3,
            env={**os.environ, 'PHANTOWD_BUILD_JOBS': '1'},
        )
        self.assertEqual(result.stdout, '1\n')


if __name__ == '__main__':
    unittest.main()
