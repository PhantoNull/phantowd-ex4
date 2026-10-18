// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
// Host-side Docker bounds. This does not replace any guest/process-group timer.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

const label = 'org.phantowd.cached-run';
const defaults = Object.freeze({ metadata: 5000, startup: 60000, active: 1830000,
  settle: 2000, stop: 15000, poll: 1000 });
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const validID = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

// No shell or process tree. Only the directly spawned CLI may be terminated.
// Killing it is never evidence that Docker retired the container.
function launch(command, args, { stream = false, settle = defaults.settle } = {}) {
  const child = spawn(command.file, [...command.prefix, ...args], {
    shell: false, windowsHide: true, stdio: stream ? ['ignore', 'inherit', 'inherit'] : ['ignore', 'pipe', 'pipe'],
  });
  let result;
  let bytes = 0;
  let stdout = '';
  let stderr = '';
  let exceeded = false;
  let spawnError = false;
  const done = new Promise(resolve => {
    child.on('error', () => { spawnError = true; });
    child.on('close', (code, signal) => {
      result = { settled: true, code, signal, stdout, stderr, exceeded, spawnError };
      resolve(result);
    });
  });
  for (const [pipe, key] of [[child.stdout, 'stdout'], [child.stderr, 'stderr']]) {
    pipe?.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 65536) {
        exceeded = true;
        child.kill();
      } else if (key === 'stdout') stdout += chunk.toString('utf8');
      else stderr += chunk.toString('utf8');
    });
  }
  return {
    child, done, result: () => result,
    async terminate() {
      if (result) return result;
      child.kill();
      const settled = await Promise.race([done, pause(settle).then(() => null)]);
      if (settled) return settled;
      // Preserve the PID/report rather than keep the host wrapper hung forever.
      child.stdout?.destroy(); child.stderr?.destroy(); child.unref();
      return { settled: false };
    },
  };
}

async function bounded(command, args, milliseconds, limits) {
  const process = launch(command, args, limits);
  let timer;
  const result = await Promise.race([
    process.done,
    new Promise(resolve => { timer = setTimeout(() => resolve(null), milliseconds); }),
  ]);
  clearTimeout(timer);
  if (result) return { ...result, timeout: false, pid: process.child.pid };
  return { ...await process.terminate(), timeout: true, pid: process.child.pid };
}

const okay = result => result.settled && !result.timeout && !result.spawnError &&
  !result.exceeded && result.code === 0;

export function cachedRunArguments(config, name, token, cidfile) {
  return ['run', '--rm', '--pull', 'never', '--name', name, '--cidfile', cidfile,
    '--label', `${label}=${token}`, '--user', '1000:1000', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--cpus', '4', '--memory', '6g', '--pids-limit', '512',
    '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=2048m,uid=1000,gid=1000',
    '--tmpfs', '/phantowd-qemu-fixture-tmp:rw,exec,nosuid,nodev,size=512m,uid=1000,gid=1000',
    '--tmpfs', '/workspace/api-host-cache:rw,exec,nosuid,nodev,size=768m,uid=1000,gid=1000',
    '--tmpfs', '/workspace/lab-tools-host-cache:rw,exec,nosuid,nodev,size=768m,uid=1000,gid=1000',
    '--mount', `type=bind,source=${config.repo},target=/external`,
    '--mount', `type=volume,source=${config.workspace},target=/workspace,volume-nocopy`,
    '--mount', `type=volume,source=${config.ccache},target=/ccache,volume-nocopy`,
    '--env', 'PHANTOWD_CCACHE_DIR=/ccache', '--env', 'GOMAXPROCS=4',
    '--env', 'GIT_CONFIG_COUNT=1', '--env', 'GIT_CONFIG_KEY_0=safe.directory',
    '--env', 'GIT_CONFIG_VALUE_0=/external', '--entrypoint', '/usr/bin/timeout',
    config.image, '--signal=TERM', '--kill-after=30', '1800', '/bin/sh', '-ec', config.command];
}

// Dependency/clock limits are injectable only by importing this host-test module.
// The user-facing CLI has no alternate executable or budget switches.
export async function runCached(config, { command = { file: 'docker', prefix: [] },
  limits = defaults, signal } = {}) {
  for (const name of ['metadata', 'startup', 'active', 'settle', 'stop', 'poll']) {
    if (!Number.isSafeInteger(limits[name]) || limits[name] <= 0) throw new Error('Invalid host budget.');
  }
  if (!path.isAbsolute(config.repo) || !/^phantowd\/buildroot:\d{4}\.\d{2}(?:\.\d{1,2})?$/.test(config.image) ||
      !/^phantowd-ex4-buildroot-\d{4}-\d{2}(?:-\d{1,2})?$/.test(config.workspace) ||
      !/^phantowd-ex4-buildroot-ccache-\d{4}-\d{2}(?:-\d{1,2})?$/.test(config.ccache) ||
      typeof config.command !== 'string' || !config.command || config.command.length > 16384) {
    throw new Error('Invalid cached-run inputs.');
  }
  const token = randomUUID().replaceAll('-', '');
  const name = `phantowd-cached-${token}`;
  const artifacts = path.join(config.repo, 'artifacts');
  fs.mkdirSync(artifacts, { recursive: true });
  const lock = path.join(artifacts, '.cached-qemu-active.json');
  const record = { schema_version: 1, name, token, repo: config.repo,
    created: new Date().toISOString(), hostPID: process.pid };
  // An uncertain old run must be reconciled explicitly, never silently replaced.
  const lockFD = fs.openSync(lock, 'wx', 0o600);
  let logFD;
  let cli;
  let id;
  let requested = false;
  let uncertain = false;
  let reason;
  let safe = false;
  const directory = path.join(artifacts, 'cached-qemu-runs', token);
  const cidfile = path.join(directory, 'container.id');
  const event = (kind, detail = {}) => {
    fs.writeFileSync(logFD, `${JSON.stringify({ kind, time: new Date().toISOString(), ...detail })}\n`);
    fs.fsyncSync(logFD);
  };
  const note = (kind, detail) => {
    try { event(kind, detail); } catch { uncertain = true; }
  };
  const query = async args => {
    const result = await bounded(command, args, limits.metadata, limits);
    if (!okay(result)) note('metadata-refusal', { operation: args.slice(0, 2).join(' '),
      pid: result.pid, settled: result.settled, timeout: result.timeout,
      code: result.code, exceeded: result.exceeded, spawnError: result.spawnError });
    return result;
  };
  async function inspect() {
    const result = await query(['container', 'inspect', id]);
    if (!result.settled) uncertain = true;
    if (!okay(result)) {
      const error = new Error('Container metadata unavailable.');
      error.mayHaveRetired = result.settled && !result.timeout && !result.exceeded && !result.spawnError;
      throw error;
    }
    let value;
    try { value = JSON.parse(result.stdout); } catch { throw new Error('Invalid container metadata.'); }
    const item = value?.[0];
    if (!Array.isArray(value) || value.length !== 1 || item?.Id !== id ||
        item?.Name !== `/${name}` || item?.Config?.Labels?.[label] !== token ||
        typeof item?.State?.Running !== 'boolean' || typeof item?.State?.Status !== 'string') {
      throw new Error('Container ownership not established.');
    }
    return item.State;
  }
  async function absent() {
    const result = await query(['container', 'ls', '--all', '--quiet', '--no-trunc', '--filter', `id=${id}`]);
    if (!result.settled) uncertain = true;
    if (!okay(result)) throw new Error('Container retirement observation unavailable.');
    const text = result.stdout.trim();
    if (text && text !== id) throw new Error('Ambiguous container retirement observation.');
    return !text;
  }
  try {
    fs.writeFileSync(lockFD, JSON.stringify(record)); fs.fsyncSync(lockFD);
    fs.mkdirSync(directory, { recursive: true });
    logFD = fs.openSync(path.join(directory, 'events.jsonl'), 'wx', 0o600);
    event('request', record);
    for (const args of [['info'], ['image', 'inspect', config.image],
      ['volume', 'inspect', config.workspace], ['volume', 'inspect', config.ccache]]) {
      if (signal?.aborted) throw new Error('Host request canceled before Docker run.');
      const result = await query(args);
      if (!result.settled) uncertain = true;
      event('preflight', { operation: args.slice(0, 2).join(' '), okay: okay(result),
        settled: result.settled, timeout: result.timeout, pid: result.pid });
      if (!okay(result)) throw new Error('Bounded cached Docker preflight failed.');
    }
    if (signal?.aborted) throw new Error('Host request canceled before Docker run.');
    event('launch');
    requested = true;
    cli = launch(command, cachedRunArguments(config, name, token, cidfile), { stream: true, settle: limits.settle });
    event('cli', { pid: cli.child.pid });
    const launched = performance.now();
    let started;
    while (!cli.result()) {
      if (signal?.aborted) throw new Error('Host request canceled.');
      if (performance.now() - (started ?? launched) >= (started === undefined ? limits.startup : limits.active)) {
        throw new Error(started === undefined ? 'Docker startup deadline exceeded.' : 'Docker active host deadline exceeded.');
      }
      if (fs.existsSync(cidfile)) {
        const stat = fs.lstatSync(cidfile);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65) throw new Error('Invalid container ID file.');
        const current = fs.readFileSync(cidfile, 'utf8').trim();
        if (!validID(current) || (id && current !== id)) throw new Error('Container ID changed or invalid.');
        id = current;
        let state;
        try { state = await inspect(); }
        catch (error) {
          // --rm can finish between the loop check and the metadata request.
          // Only a settled ordinary metadata refusal can use final retirement
          // observation; malformed/timeout/ownership failures remain failures.
          if (error.mayHaveRetired) {
            let timer;
            const original = cli.result() ?? await Promise.race([cli.done,
              new Promise(resolve => { timer = setTimeout(() => resolve(null), limits.settle); })]);
            clearTimeout(timer);
            event('retirement-handoff', { settled: original !== null });
            if (original) break;
          }
          throw error;
        }
        if (state.Running && started === undefined) {
          started = performance.now(); event('running', { id });
        }
      }
      await Promise.race([cli.done, pause(limits.poll)]);
    }
    const result = cli.result();
    event('cli-exit', { code: result.code, signal: result.signal });
    if (!id && fs.existsSync(cidfile)) {
      const stat = fs.lstatSync(cidfile);
      if (stat.isFile() && !stat.isSymbolicLink() && stat.size <= 65) id = fs.readFileSync(cidfile, 'utf8').trim();
    }
    if (!validID(id)) throw new Error('No valid container ID; retirement remains unproven.');
    if (!await absent()) throw new Error('Container was not automatically retired.');
    safe = true;
    if (!okay(result)) throw new Error('Cached full validation failed.');
    event('complete', { retired: true });
    return { okay: true, directory, retired: true };
  } catch (error) {
    reason = error.message;
    if (logFD !== undefined) note('failure', { reason });
    if (cli) {
      const settled = await cli.terminate();
      if (!settled.settled) uncertain = true;
      note('cli-settlement', { settled: settled.settled, pid: cli.child.pid });
    }
    if (requested && !safe && validID(id)) {
      // Mutations require the originally generated ID AND matching name/label.
      // Never stop/remove an unverified target, use --force, or touch volumes.
      try {
        if (!await absent()) {
          let state = await inspect();
          if (state.Running) {
            const stopped = await bounded(command, ['container', 'stop', '--time', '10', id], limits.stop, limits);
            note('stop-result', { pid: stopped.pid, settled: stopped.settled,
              timeout: stopped.timeout, code: stopped.code });
            if (!stopped.settled) uncertain = true;
            if (!okay(stopped)) throw new Error('Owned container stop uncertain.');
          }
          if (!await absent()) {
            state = await inspect();
            if (state.Running) throw new Error('Owned container is still running.');
            const removed = await query(['container', 'rm', id]);
            if (!removed.settled) uncertain = true;
            if (!okay(removed)) throw new Error('Owned container removal uncertain.');
          }
        }
        safe = await absent();
      } catch (cleanup) { note('cleanup-uncertain', { reason: cleanup.message }); }
    }
    if (!requested) safe = true;
    if (logFD !== undefined) note('refused', { retired: safe, uncertain, containerID: id ?? null });
    return { okay: false, directory, retired: safe && !uncertain, reason };
  } finally {
    if (logFD !== undefined) fs.closeSync(logFD);
    fs.closeSync(lockFD);
    if (safe && !uncertain) fs.unlinkSync(lock);
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 10 || args[0] !== '--repo' || args[2] !== '--image' ||
      args[4] !== '--workspace' || args[6] !== '--ccache' || args[8] !== '--command') {
    throw new Error('Expected fixed cached-run arguments.');
  }
  const controller = new AbortController();
  const cancel = () => controller.abort();
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  try {
    const result = await runCached({ repo: args[1], image: args[3], workspace: args[5],
      ccache: args[7], command: args[9] }, { signal: controller.signal });
    if (!result.okay) {
      console.error(`${result.reason} No retry. Retired=${result.retired}; retain source and review ${result.directory}`);
      process.exitCode = 1;
    }
  } finally { process.off('SIGINT', cancel); process.off('SIGTERM', cancel); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => { console.error('Cached host controller refused; inspect the retained local run record.'); process.exitCode = 1; });
}
