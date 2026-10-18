// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { cachedRunArguments, runCached } from '../run-cached-qemu.mjs';

const fixture = fileURLToPath(new URL('./fixtures/cached-docker.mjs', import.meta.url));
const limits = { metadata: 700, startup: 1500, active: 1700, settle: 700, stop: 700, poll: 30 };
// Phase limits are not a single wall-clock cap. Include four preflights,
// both phase windows, an in-flight/final query, handoff/direct CLI settlement,
// up to six cleanup queries, and one stop. No runner/guest budget is increased.
const hostBound = 4 * (limits.metadata + limits.settle) + limits.startup + limits.active +
  2 * (limits.metadata + limits.settle) + limits.poll + 2 * limits.settle +
  6 * (limits.metadata + limits.settle) + limits.stop + limits.settle;
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'phantowd host runner '));
const configFor = repo => ({ repo, image: 'phantowd/buildroot:2025.02.18',
  workspace: 'phantowd-ex4-buildroot-2025-02-18', ccache: 'phantowd-ex4-buildroot-ccache-2025-02-18',
  command: 'fixed cached command with spaces & literal $characters' });
let count = 0;
const selected = process.argv.slice(2);
if (selected.length && (selected.length !== 2 || selected[0] !== '--case' || !['success', 'remove-before-cli'].includes(selected[1]))) {
  throw new Error('Only --case success/remove-before-cli is available for focused host diagnostics.');
}
try {
  const runArgs = cachedRunArguments(configFor(root), 'fixed-name', 'fixed-token', path.join(root, 'cid'));
  for (const [flag, expected] of [['--user', '1000:1000'], ['--cpus', '4'], ['--memory', '6g'],
    ['--pids-limit', '512'], ['--cap-drop', 'ALL'], ['--security-opt', 'no-new-privileges'],
    ['--entrypoint', '/usr/bin/timeout'], ['--pull', 'never']]) {
    assert.equal(runArgs[runArgs.indexOf(flag) + 1], expected);
  }
  assert.deepEqual(runArgs.slice(-6), ['--signal=TERM', '--kill-after=30', '1800', '/bin/sh', '-ec', configFor(root).command]);
  assert.equal(runArgs.filter(arg => arg.startsWith('type=volume,') && arg.endsWith(',volume-nocopy')).length, 2);
  assert.equal(runArgs.filter(arg => arg.startsWith('type=bind,')).length, 1);
  assert.equal(runArgs.filter(arg => arg.includes('size=768m,')).length, 2);
  assert(runArgs.includes('/tmp:rw,exec,nosuid,nodev,size=2048m,uid=1000,gid=1000'));
  assert(runArgs.includes('/phantowd-qemu-fixture-tmp:rw,exec,nosuid,nodev,size=512m,uid=1000,gid=1000'));
  assert(!runArgs.some(arg => ['--privileged', '--device', '--publish', '--force', '--network'].includes(arg)));
  for (const scenario of ['success', 'remove-before-cli', 'validation-fail', 'created', 'wrong-owner', 'no-id',
    'inspect-hang', 'bad-metadata', 'no-automatic-rm', 'stop-hang', 'rm-hang',
    'retirement-hang', 'preflight-hang', 'preflight-overflow', 'preflight-refuse-info',
    'preflight-refuse-image', 'preflight-refuse-workspace', 'preflight-refuse-ccache', 'canceled']) {
    if (selected.length && scenario !== selected[1]) continue;
    const repo = path.join(root, scenario);
    fs.mkdirSync(repo);
    const controller = new AbortController();
    let timer;
    if (scenario === 'canceled') timer = setInterval(() => {
      const calls = path.join(repo, 'calls.jsonl');
      if (fs.existsSync(calls) && fs.readFileSync(calls, 'utf8').includes('["container","inspect"')) {
        controller.abort(); clearInterval(timer);
      }
    }, 30);
    const started = performance.now();
    let result;
    try {
      result = await runCached(configFor(repo), {
        command: { file: process.execPath, prefix: [fixture, repo, scenario] }, limits, signal: controller.signal,
      });
    } finally { clearInterval(timer); }
    const elapsed = performance.now() - started;
    assert(elapsed < hostBound, `${scenario}: elapsed=${Math.ceil(elapsed)}ms exceeded derived host bound=${hostBound}ms`);
    const observedEvents = fs.readFileSync(path.join(result.directory, 'events.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const detail = observedEvents.map(({ kind, time, operation, timeout, settled, code }) => ({ kind, time, operation, timeout, settled, code }));
    const accepted = ['success', 'remove-before-cli'].includes(scenario);
    assert.equal(result.okay, accepted, `${scenario}: unexpected pass/refusal: ${result.reason}; ${JSON.stringify(detail)}`);
    const calls = fs.readFileSync(path.join(repo, 'calls.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const runs = calls.filter(call => call[0] === 'run');
    assert.equal(runs.length, scenario.startsWith('preflight-') ? 0 : 1, `${scenario}: retry or missing run`);
    assert(!calls.some(call => ['build', 'pull', 'system'].includes(call[0]) ||
      (call[0] === 'volume' && call[1] !== 'inspect') || call.includes('--force')));
    const mutated = calls.filter(call => call[0] === 'container' && ['stop', 'rm'].includes(call[1]));
    for (const call of mutated) assert.equal(call.at(-1), 'a'.repeat(64), `${scenario}: cleanup must use the full original ID`);
    const unproven = ['wrong-owner', 'no-id', 'inspect-hang', 'bad-metadata', 'stop-hang', 'rm-hang', 'retirement-hang'].includes(scenario);
    assert.equal(result.retired, !unproven, `${scenario}: false retirement claim`);
    const lock = path.join(repo, 'artifacts', '.cached-qemu-active.json');
    assert.equal(fs.existsSync(lock), unproven, `${scenario}: incorrect retry guard`);
    if (['wrong-owner', 'no-id', 'inspect-hang', 'bad-metadata', 'retirement-hang'].includes(scenario)) {
      assert.equal(mutated.length, 0, `${scenario}: must not mutate an unproven target`);
    }
    if (unproven) {
      const before = calls.length;
      await assert.rejects(runCached(configFor(repo), {
        command: { file: process.execPath, prefix: [fixture, repo, scenario] }, limits,
      }), /EEXIST/);
      assert.equal(fs.readFileSync(path.join(repo, 'calls.jsonl'), 'utf8').trim().split('\n').length, before);
    }
    const events = fs.readFileSync(path.join(result.directory, 'events.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(events.at(-1).kind, accepted ? 'complete' : 'refused');
    assert.notEqual(events.at(-1).uncertain, true, `${scenario}: fixture child did not settle`);
    for (const event of events.filter(event => event.kind === 'cli-settlement')) assert.equal(event.settled, true);
    count++;
    console.log(`PHANTOWD_CACHED_RUNNER_CASE scenario=${scenario} retired=${result.retired} elapsed_ms=${Math.ceil(elapsed)} bound_ms=${hostBound}`);
  }
  console.log(`PHANTOWD_CACHED_RUNNER_READY cases=${count} scope=local-fake-processes-only`);
} finally {
  // This is exclusively the test's freshly allocated regular-file tree.
  // No Docker resource, production path or live source snapshot is involved.
  fs.rmSync(root, { recursive: true });
}
