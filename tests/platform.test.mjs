import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { stateDirectory, existingStateDirectory, platformInfo, sameDirectory } from '../src/agent/platform.mjs';
import { posixStartupPlan } from '../src/agent/startup.mjs';
import { startController } from '../src/agent/main.mjs';
import { approveRoot } from '../src/agent/files.mjs';

async function temporary(t) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-platform-'));
  t.after(() => fs.rm(base, { recursive: true, force: true }));
  return base;
}

test('platform metadata is descriptive, not a hostname-based authorization identity', () => {
  assert.deepEqual(platformInfo({ platform: 'darwin', arch: 'arm64', hostname: 'Studio Mac' }), { platform: 'darwin', arch: 'arm64', system: 'macOS', name: 'Studio Mac' });
  assert.equal(platformInfo({ platform: 'win32' }).system, 'Windows');
  assert.equal(platformInfo({ platform: 'linux' }).system, 'Linux');
});
// Explicitly fictional user paths; no owner or installed state is inspected.
test('each OS uses a per-user state location, without inheriting Windows path rules', () => {
  assert.equal(stateDirectory({ platform: 'win32', home: 'C:\\Users\\fixture-user', env: {} }), 'C:\\Users\\fixture-user\\AppData\\Local\\Chat2Local');
  assert.equal(stateDirectory({ platform: 'darwin', home: '/Users/fixture-user', env: {} }), '/Users/fixture-user/Library/Application Support/Chat2Local');
  assert.equal(stateDirectory({ platform: 'linux', home: '/home/fixture-user', env: {} }), '/home/fixture-user/.local/state/chat2local');
  assert.equal(stateDirectory({ platform: 'linux', home: '/home/fixture-user', env: { XDG_STATE_HOME: '/data/state' } }), '/data/state/chat2local');
});
test('existing POSIX identity is reused and conflicting configurations are not silently merged', async t => {
  const home = await temporary(t); const options = { platform: 'linux', home, env: {} };
  const legacy = path.join(home, '.local', 'share', 'Chat2Local');
  await fs.mkdir(legacy, { recursive: true }); await fs.writeFile(path.join(legacy, 'settings.json'), '{}');
  assert.equal(existingStateDirectory(options), legacy);
  const preferred = stateDirectory(options); await fs.mkdir(preferred, { recursive: true }); await fs.writeFile(path.join(preferred, 'vault.json'), '{}');
  assert.throws(() => existingStateDirectory(options), /两套/);
  assert.equal(existingStateDirectory({ ...options, env: { CHAT2LOCAL_STATE_DIR: legacy } }), legacy);
});
test('directory equivalence follows the actual filesystem, not unconditional lowercasing', async t => {
  const base = await temporary(t); const upper = path.join(base, 'Project'); const lower = path.join(base, 'project');
  await fs.mkdir(upper); await fs.mkdir(lower, { recursive: true });
  const a = await fs.stat(upper, { bigint: true }); const b = await fs.stat(lower, { bigint: true });
  assert.equal(await sameDirectory(upper, lower), a.dev === b.dev && a.ino === b.ino);
  assert.equal(await sameDirectory(upper, path.join(upper, '.')), true);
});
test('private state stays blocked when a parent path is an OS alias/junction', async t => {
  const base = await temporary(t); const actual = path.join(base, 'real'); const alias = path.join(base, 'alias');
  await fs.mkdir(path.join(actual, 'private'), { recursive: true });
  await fs.symlink(actual, alias, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(() => approveRoot(path.join(actual, 'private'), path.join(alias, 'private'), true), /private state/);
});
test('macOS login job has escaped argv, user scope, and no looping background restart', () => {
  const plan = posixStartupPlan({ platform: 'darwin', home: '/Users/fixture-user', node: '/Users/fixture-user/App & Tools/runtime/node', launcher: '/Users/fixture-user/App & Tools/scripts/launch.mjs' });
  assert.equal(plan.file, '/Users/fixture-user/Library/LaunchAgents/io.chat2local.agent.plist');
  assert.match(plan.content, /App &amp; Tools/); assert.match(plan.content, /<key>RunAtLoad<\/key><true\/>/);
  assert.match(plan.content, /<string>--no-browser<\/string>/); assert.doesNotMatch(plan.content, /KeepAlive|sudo|deviceKey|token/);
});
test('Linux desktop startup escapes field codes and does not interpolate a shell command', () => {
  const plan = posixStartupPlan({ platform: 'linux', home: '/home/fixture-user', env: {}, node: '/opt/50% $tools/node', launcher: '/opt/App Name/scripts/launch.mjs' });
  assert.equal(plan.file, '/home/fixture-user/.config/autostart/chat2local.desktop');
  assert.match(plan.content, /50%% \\\$tools/); assert.match(plan.content, /Terminal=false/); assert.match(plan.content, /--no-browser/);
  assert.throws(() => posixStartupPlan({ platform: 'linux', home: '/home/fixture-user', node: '/node\nExec=bad', launcher: '/a.mjs' }));
});
test('repeat directory registration is idempotent and preserves existing review grants and IDs', async t => {
  const base = await temporary(t); const folder = path.join(base, 'sample'); await fs.mkdir(folder);
  const app = await startController({ port: 0, stateDir: path.join(base, 'private') });
  t.after(() => app.close());
  const post = async body => {
    const response = await fetch(`${app.origin}/api/root/add`, { method: 'POST', headers: { Origin: app.origin, 'Content-Type': 'application/json', 'X-Chat2Local-Token': app.token }, body: JSON.stringify(body) });
    assert.equal(response.status, 200); return response.json();
  };
  const first = await post({ path: folder, write: true });
  const again = await post({ path: folder, write: true });
  assert.equal(first.id, again.id); assert.equal(again.alreadyAuthorized, true); assert.equal(again.writeMode, 'review');
  const roots = await app.files.invoke('list_roots'); assert.equal(roots.length, 1);
  assert.equal(roots[0].directWriteAllowed, false); assert.equal(roots[0].device.platform, process.platform);
  assert.ok(roots[0].device.installationId); assert.equal(roots[0].device.deviceId, null);
  const before = roots[0].device.installationId;
  await app.close();
  const next = await startController({ port: 0, stateDir: path.join(base, 'private') });
  try { assert.equal((await next.files.invoke('list_roots'))[0].device.installationId, before); }
  finally { await next.close(); }
});
