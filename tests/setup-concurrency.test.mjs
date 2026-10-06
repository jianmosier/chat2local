import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { startController } from '../src/agent/main.mjs';
import { SetupManager } from '../src/agent/setup.mjs';
import { Store } from '../src/agent/store.mjs';

function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
const metadata = () => Response.json({ name: 'chat2local-relay', setupVersion: 1, browserHandoff: true, selfService: true, installUrl: 'https://chatgpt.com/plugins/setup-fixture' });

test('slow first connection cannot block pause or last-root revocation; late metadata grants nothing', { timeout: 30000 }, async t => {
  for (const cancelRoute of ['pause', 'root/remove']) await t.test(cancelRoute, async t => {
    const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-setup-cancel-'));
    const folder = path.join(base, 'sample'); await fs.mkdir(folder);
    const entered = deferred(); const response = deferred(); const calls = []; let opened = 0;
    const app = await startController({ port: 0, defaultRelay: 'https://relay.example.test', stateDir: path.join(base, 'private'), networkOptions: { env: {}, systemProxy: async () => ({ proxy: '' }) },
      setupFetch: async url => { calls.push(new URL(url).pathname); entered.resolve(); return response.promise; }, openBrowser: async () => { opened++; } });
    t.after(async () => { response.resolve(metadata()); await app.close(); await fs.rm(base, { recursive: true, force: true }); });
    const post = (route, body) => fetch(`${app.origin}/api/${route}`, { method: 'POST', headers: { Origin: app.origin, 'X-Chat2Local-Token': app.token, 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(3000) });
    const root = await (await post('root/add', { path: folder, write: false })).json();
    const connection = post('setup/start', {}); await entered.promise;
    assert.equal((await post('setup/start', {})).status, 409, 'A second setup cannot create another enrollment flow.');
    const cancelled = await post(cancelRoute, cancelRoute === 'pause' ? { paused: true } : { id: root.id });
    assert.equal(cancelled.status, 200, 'Local control must finish while network metadata is still stalled.');
    assert.equal((await connection).status, 409);
    response.resolve(metadata()); await delay(50);
    assert.deepEqual(calls, ['/setup-info']); assert.equal(opened, 0);
    const stored = await new Store(path.join(base, 'private')).load();
    assert.equal(stored.secrets.identity, undefined); assert.equal(stored.secrets.enrollmentPending, undefined);
    if (cancelRoute === 'pause') {
      assert.equal(stored.config.paused, true);
      assert.equal((await post('root/add', { path: folder, writeMode: 'direct', confirmDirect: true })).status, 409);
      assert.equal(stored.config.roots[0].write, false);
    } else assert.equal(stored.config.roots.length, 0);
  });
});

test('cancelling uncertain enrollment never accepts late credentials and preserves one pending identity for explicit retry', async () => {
  const entered = deferred(); const response = deferred(); let pending; let identity; let attempts = 0; let browserCalls = 0; const ids = [];
  const manager = new SetupManager({ defaultRelay: 'https://relay.example.test', identity: () => identity, pending: () => pending, prepareNetwork: async () => {},
    savePending: async (next, signal) => { signal.throwIfAborted(); pending = next; },
    acceptIdentity: async (next, signal) => { signal.throwIfAborted(); identity = next; pending = undefined; },
    bridge: { state: 'connected' }, openBrowser: async () => { browserCalls++; },
    fetch: async (url, options) => {
      if (url.endsWith('/setup-info')) return metadata();
      if (url.endsWith('/enroll-device')) { ids.push(JSON.parse(options.body).deviceId); if (++attempts === 1) { entered.resolve(); return response.promise; } return Response.json({ ok: true }); }
      if (url.endsWith('/browser-handoff')) return Response.json({ secret: 'a'.repeat(64), expiresAt: Date.now() + 10000 });
      assert.fail('Unexpected setup request.');
    } });
  const first = manager.start(); await entered.promise;
  const rejection = assert.rejects(() => first, /连接已取消/);
  manager.cancel(); await rejection;
  response.resolve(Response.json({ ok: true })); await delay(10);
  assert.equal(identity, undefined); assert.ok(pending); assert.equal(browserCalls, 0);
  const original = pending.deviceId;
  assert.equal((await manager.start()).ok, true); assert.equal(identity.deviceId, original);
  assert.deepEqual(ids, [original, original]); assert.equal(browserCalls, 1);
});

test('closing the initiating HTTP request cancels stalled setup without granting a device identity', { timeout: 15000 }, async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-setup-abort-')); const folder = path.join(base, 'sample'); await fs.mkdir(folder);
  const entered = deferred(); const delayed = deferred(); let opened = 0;
  const app = await startController({ port: 0, defaultRelay: 'https://relay.example.test', stateDir: path.join(base, 'private'), networkOptions: { env: {}, systemProxy: async () => ({ proxy: '' }) }, setupFetch: async () => { entered.resolve(); return delayed.promise; }, openBrowser: async () => { opened++; } });
  t.after(async () => { delayed.resolve(metadata()); await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  const headers = { Origin: app.origin, 'X-Chat2Local-Token': app.token, 'Content-Type': 'application/json' };
  await fetch(`${app.origin}/api/root/add`, { method: 'POST', headers, body: JSON.stringify({ path: folder, write: false }) });
  const abort = new AbortController();
  const request = fetch(`${app.origin}/api/setup/start`, { method: 'POST', headers, body: '{}', signal: abort.signal });
  await entered.promise; const rejection = assert.rejects(() => request, /abort/i); abort.abort(); await rejection;
  await delay(50); delayed.resolve(metadata()); await delay(50);
  assert.equal(opened, 0); assert.equal((await new Store(path.join(base, 'private')).load()).secrets.identity, undefined);
});
