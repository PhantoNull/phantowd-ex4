#!/usr/bin/env python3
"""Select a build-only CPU ceiling from affinity and visible cgroup quotas."""

import os
import pathlib
import re
import sys


def select_jobs(affinity, quotas, requested):
    if affinity < 1:
        raise ValueError('empty CPU affinity')
    jobs = affinity
    for quota, period in quotas:
        if quota <= 0 or period <= 0:
            raise ValueError('invalid CPU quota')
        jobs = min(jobs, max(1, quota // period))
    if requested is not None:
        if not re.fullmatch(r'[1-9][0-9]{0,5}', requested):
            raise ValueError('PHANTOWD_BUILD_JOBS must be a positive integer')
        jobs = min(jobs, int(requested))
    return jobs


def kernel_path(value):
    # mountinfo escapes whitespace/backslashes in octal; membership does not.
    path = pathlib.PurePosixPath(value)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('invalid cgroup path')
    return path


def unescape_mount(value):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)


def read_quotas(membership, mountinfo, read):
    members = {}
    for line in membership.splitlines():
        _, controllers, member = line.split(':', 2)
        if not controllers or 'cpu' in controllers.split(','):
            kind = 'cgroup' if controllers else 'cgroup2'
            if kind in members:
                raise ValueError('duplicate CPU cgroup membership')
            members[kind] = kernel_path(member)
    quotas = []
    for line in mountinfo.splitlines():
        before, after = line.split(' - ', 1)
        fields, fs = before.split(), after.split()
        kind = fs[0]
        if kind not in members or (kind == 'cgroup' and
                                   'cpu' not in fs[2].split(',')):
            continue
        root = kernel_path(unescape_mount(fields[3]))
        mount = kernel_path(unescape_mount(fields[4]))
        member = members[kind]
        # A namespaced Docker process sees membership '/' even when the mount
        # root is a host-side subtree. Only the visible hierarchy is readable.
        relative = (pathlib.PurePosixPath('.') if member ==
                    pathlib.PurePosixPath('/') else member.relative_to(root))
        current = mount / relative
        while True:
            if kind == 'cgroup2':
                try:
                    value = read(current / 'cpu.max')
                except FileNotFoundError:
                    value = None  # CPU controller not enabled at this level.
                if value is not None:
                    quota, period = value.split()
                    period = int(period)
                    if period <= 0:
                        raise ValueError('invalid CPU period')
                    if quota != 'max':
                        quota = int(quota)
                        if quota <= 0:
                            raise ValueError('invalid CPU quota')
                        quotas.append((quota, period))
            else:
                try:
                    quota = read(current / 'cpu.cfs_quota_us')
                except FileNotFoundError:
                    quota = None
                if quota is not None:
                    quota = int(quota)
                    period = int(read(current / 'cpu.cfs_period_us'))
                    if period <= 0 or quota == 0 or quota < -1:
                        raise ValueError('invalid CPU quota')
                    if quota != -1:
                        quotas.append((quota, period))
            if current == mount:
                break
            current = current.parent
    return quotas


def main():
    def read(path):
        return pathlib.Path(path).read_text(encoding='ascii')
    try:
        quotas = read_quotas(read('/proc/self/cgroup'),
                             read('/proc/self/mountinfo'), read)
        jobs = select_jobs(len(os.sched_getaffinity(0)), quotas,
                           os.environ.get('PHANTOWD_BUILD_JOBS'))
    except (OSError, ValueError) as error:
        print(f'Cannot determine bounded build job budget: {error}',
              file=sys.stderr)
        return 1
    print(jobs)
    return 0


if __name__ == '__main__':
    sys.exit(main())
