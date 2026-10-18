// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
// Local child-process fixture. Never invokes Docker or another program.
import fs from 'node:fs';
import path from 'node:path';

const [root, scenario, ...args] = process.argv.slice(2);
const statePath = path.join(root, 'fake-state.json');
const id = 'a'.repeat(64);
const value = flag => args[args.indexOf(flag) + 1];
const load = () => fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath, 'utf8')) : null;
const save = state => fs.writeFileSync(statePath, JSON.stringify(state));
const hang = () => setInterval(() => {}, 1000);
fs.appendFileSync(path.join(root, 'calls.jsonl'), `${JSON.stringify(args)}\n`);

if ((scenario === 'preflight-refuse-info' && args[0] === 'info') ||
    (scenario === 'preflight-refuse-image' && args[0] === 'image') ||
    (scenario === 'preflight-refuse-workspace' && args[2] === 'phantowd-ex4-buildroot-2025-02-18') ||
    (scenario === 'preflight-refuse-ccache' && args[2] === 'phantowd-ex4-buildroot-ccache-2025-02-18')) process.exit(1);

if (args[0] === 'info' && scenario === 'preflight-hang') {
  hang();
} else if (args[0] === 'info' && scenario === 'preflight-overflow') {
  process.stdout.write('x'.repeat(70000));
} else if (args[0] === 'run') {
  const state = { Id: id, Name: `/${value('--name')}`,
    Config: { Labels: { 'org.phantowd.cached-run': value('--label').split('=')[1] } },
    State: { Running: !['created', 'wrong-owner', 'no-id'].includes(scenario), Status: 'created' } };
  if (scenario === 'wrong-owner') state.Config.Labels['org.phantowd.cached-run'] = 'unrelated';
  if (scenario !== 'no-id') fs.writeFileSync(value('--cidfile'), `${id}\n`);
  save(state);
  if (scenario === 'success' || scenario === 'validation-fail') {
    setTimeout(() => { fs.unlinkSync(statePath); process.exit(scenario === 'success' ? 0 : 7); }, 400);
  } else if (scenario === 'remove-before-cli') {
    setTimeout(() => {
      fs.unlinkSync(statePath);
      const interval = setInterval(() => {
        if (fs.existsSync(path.join(root, 'release-cli'))) {
          clearInterval(interval); setTimeout(() => process.exit(0), 200);
        }
      }, 10);
    }, 400);
  } else if (scenario === 'bad-metadata') {
    state.Id = 'b'.repeat(64); save(state); hang();
  } else if (scenario === 'no-automatic-rm') {
    state.State = { Running: false, Status: 'exited' }; save(state); process.exit(0);
  } else hang();
} else if (args[0] === 'container' && args[1] === 'inspect') {
  if (scenario === 'inspect-hang') hang();
  else {
    const state = load();
    if (!state) {
      if (scenario === 'remove-before-cli') fs.writeFileSync(path.join(root, 'release-cli'), 'release');
      process.exit(1);
    }
    process.stdout.write(JSON.stringify([state]));
  }
} else if (args[0] === 'container' && args[1] === 'ls') {
  if (scenario === 'retirement-hang') hang();
  else if (load()) process.stdout.write(`${id}\n`);
} else if (args[0] === 'container' && args[1] === 'stop') {
  if (scenario === 'stop-hang') hang();
  else { const state = load(); state.State = { Running: false, Status: 'exited' }; save(state); }
} else if (args[0] === 'container' && args[1] === 'rm') {
  if (scenario === 'rm-hang') hang();
  else fs.unlinkSync(statePath);
} else if (!['info', 'image', 'volume'].includes(args[0])) {
  throw new Error('Unexpected fake Docker command.');
}
