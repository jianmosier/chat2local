import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { startController } from '../src/agent/main.mjs';
import { NetworkManager } from '../src/agent/network.mjs';

test('network settings require local authorization and survive a controller restart', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'chat2local-network-settings-'));
  let app = await startController({ port: 0, stateDir: directory });
  t.after(async () => { await app.close(); await fs.rm(directory, { recursive: true, force: true }); });
  const call = async (route, data, authorized = true) => fetch(`${app.origin}/api/${route}`, {
    method: data === undefined ? 'GET' : 'POST', headers: { Origin: app.origin, 'Content-Type': 'application/json', ...(authorized ? { 'X-Chat2Local-Token': app.token } : {}) },
    ...(data === undefined ? {} : { body: JSON.stringify(data) }),
  });
  assert.equal((await call('network/set', { mode: 'direct' }, false)).status, 401);
  assert.equal((await call('network/set', { mode: 'proxy', proxy: 'http://user:secret@localhost:5' })).status, 400);
  assert.equal((await call('network/set', { mode: 'direct' })).status, 200);
  assert.deepEqual((await (await call('status')).json()).networkSettings, { mode: 'direct' });
  await app.close();
  app = await startController({ port: 0, stateDir: directory });
  const state = await (await call('status')).json();
  assert.equal(state.networkSettings.mode, 'direct'); assert.equal(state.lastRemoteCallAt, null);
  assert.equal(state.roots.length, 0); assert.equal(state.pending.length, 0);
  assert.equal((await call('network/set', { mode: 'auto' })).status, 200);
});
test('stale system resolution cannot override newer settings or revive a closed controller', async () => {
  let settings = { mode: 'auto' }; let resolveSystem; let applied = 0;
  const manager = new NetworkManager(() => settings, { env: {}, systemProxy: () => new Promise(resolve => { resolveSystem = resolve; }), apply: () => { applied++; return () => {}; } });
  const pending = manager.prepare('https://relay.invalid');
  settings = { mode: 'direct' };
  await manager.prepare('https://relay.invalid', true);
  resolveSystem({ proxy: 'http://localhost:3' });
  await assert.rejects(() => pending, /替代/);
  assert.equal(manager.status().source, 'direct'); assert.equal(applied, 1); manager.close();
  await assert.rejects(() => manager.prepare('https://relay.invalid'), /关闭/);
  let finish;
  const closing = new NetworkManager(() => ({ mode: 'auto' }), { env: {}, systemProxy: () => new Promise(resolve => { finish = resolve; }), apply: () => { throw Error('must not apply after close'); } });
  const late = closing.prepare('https://relay.invalid'); closing.close(); finish({ proxy: '' });
  await assert.rejects(() => late, /替代/);
});
