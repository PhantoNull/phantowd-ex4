#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
"""Check exact QEMU source evidence; never build or write firmware."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True, stderr=subprocess.DEVNULL, timeout=30).strip()

def record(repo, commit):
    message = git(repo, 'show', '-s', '--format=%B', commit)
    commits = re.findall(r'^Qualified-Commit: ([0-9a-f]{40})$', message, re.M)
    runs = re.findall(r'^Qualified-QEMU-Run: ([1-9][0-9]{0,19})$', message, re.M)
    if (len(commits) != 1 or len(runs) != 1 or
        len(re.findall(r'^Qualified-Commit:', message, re.M)) != 1 or
        len(re.findall(r'^Qualified-QEMU-Run:', message, re.M)) != 1 or
        re.search(r'\[(skip ci|ci skip|no ci|skip actions|actions skip)\]|^skip-checks:\s*true', message, re.I | re.M)):
        raise ValueError('missing or ambiguous qualification record')
    return commits[0], int(runs[0])

def verify(repo, promotion, candidate, run):
    qualified, run_id = record(repo, promotion)
    if (run.get('id') != run_id or run.get('head_sha') != qualified or
        run.get('status') != 'completed' or run.get('conclusion') != 'success' or
        run.get('path') != '.github/workflows/qemu-armv5.yml'):
        raise ValueError('successful exact-head QEMU evidence required')
    expected = git(repo, 'rev-parse', qualified+'^{tree}')
    jobs = [j for j in run.get('jobs', []) if j.get('name') == 'Build QEMU baseline and EX4 research DTB']
    required = ('Build and boot ARMv5 image', 'Compile EX4 device-tree research baseline', 'Upload non-flashable QEMU artifacts')
    if len(jobs) != 1 or jobs[0].get('conclusion') != 'success' or any(
        len([s for s in jobs[0].get('steps', []) if s.get('name') == name and s.get('conclusion') == 'success']) != 1 for name in required):
        raise ValueError('executed successful QEMU build required')
    receipt = run.get('research_source', {})
    if (set(receipt) != {'format', 'run', 'checkout', 'tree', 'flashable'} or
        receipt['format'] != 'phantowd-qemu-research-source-v1' or receipt['run'] != str(run_id) or
        receipt['tree'] != expected or receipt['flashable'] != 'no' or not re.fullmatch('[0-9a-f]{40}', receipt['checkout'])):
        raise ValueError('actual tested source tree receipt required')
    if any(git(repo, 'rev-parse', commit+'^{tree}') != expected for commit in (promotion, candidate)):
        raise ValueError('promotion/main candidate tree differs from qualified tree')
    return expected

def main():
    try:
        repo = Path.cwd()
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        candidate = os.environ['GITHUB_SHA']
        if git(repo, 'rev-parse', 'HEAD') != candidate:
            raise ValueError('checkout differs from event commit')
        if os.environ['GITHUB_EVENT_NAME'] == 'pull_request':
            if event['pull_request']['base']['ref'] != 'main':
                raise ValueError('main promotion required')
            head = event['pull_request']['head']['sha']
        elif os.environ['GITHUB_EVENT_NAME'] == 'push' and os.environ['GITHUB_REF'] == 'refs/heads/main':
            parents = git(repo, 'rev-list', '--parents', '-n', '1', candidate).split()
            head = parents[2] if len(parents) == 3 else candidate
        else:
            raise ValueError('unsupported promotion event')
        qualified, run_id = record(repo, head)
        repository = os.environ['GITHUB_REPOSITORY']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
            raise ValueError('invalid repository')
        def gh(*args):
            return subprocess.check_output(['gh', *args], stderr=subprocess.DEVNULL, text=True, timeout=30)
        run = json.loads(gh('api', f'repos/{repository}/actions/runs/{run_id}'))
        run['jobs'] = json.loads(gh('api', f'repos/{repository}/actions/runs/{run_id}/jobs?per_page=100'))['jobs']
        with tempfile.TemporaryDirectory(prefix='phantowd-promotion-proof-') as directory:
            gh('run', 'download', str(run_id), '--repo', repository, '--name', 'phantowd-qemu-research-source', '--dir', directory)
            receipt = Path(directory) / 'source.txt'
            if {p.name for p in Path(directory).iterdir()} != {'source.txt'} or receipt.is_symlink() or receipt.stat().st_size > 512:
                raise ValueError('bounded source receipt required')
            rows = receipt.read_text().splitlines()
            if len(rows) != 5:
                raise ValueError('complete source receipt required')
            run['research_source'] = dict(row.split('=', 1) for row in rows)
        tree = verify(repo, head, candidate, run)
        print(f'PROMOTION_TREE_IDENTITY_OK qualified_commit={qualified} main_candidate_tree={tree} run={run_id}')
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('PROMOTION_TREE_IDENTITY_FAILED: invalid input, qualification or main candidate tree', file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
