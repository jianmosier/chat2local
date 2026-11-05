import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { once } from 'node:events';
import { startController } from '../src/agent/main.mjs';
import { Store, atomicJson } from '../src/agent/store.mjs';
import { raw, request, freePort } from './controller-fixture.mjs';
const deferred = () => { let resolve; const promise = new Promise(r => resolve = r); return { promise, resolve }; };
async function directory(t) { const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-owner-')); t.after(() => fs.rm(dir, { recursive: true, force: true })); return dir; }
test('JS reserves before mkdir/load and refuses a live prior owner even on a free port', async t => {
  const dir = await directory(t), busy = net.createServer(); busy.listen(0, '127.0.0.1'); await once(busy, 'listening'); t.after(() => new Promise(resolve => busy.close(resolve)));
  const missing = path.join(dir, 'absent'); await assert.rejects(startController({ stateDir: missing, port: busy.address().port }), { code: 'EADDRINUSE' }); await assert.rejects(fs.stat(missing), { code: 'ENOENT' });
  const store = new Store(dir); await store.saveSession({ pid: process.pid, instanceId: 'old', origin: 'http://127.0.0.1:1234', token: 'a'.repeat(64) }); const before = await fs.readFile(path.join(dir, 'session.json'));
  await assert.rejects(startController({ store, port: 0 }), { code: 'EOWNER' }); assert.deepEqual(await fs.readFile(path.join(dir, 'session.json')), before); await assert.rejects(fs.stat(path.join(dir, 'settings.json')), { code: 'ENOENT' });
  await assert.rejects(startController({ store, port: 0, inspectOwner() { throw Object.assign(Error('denied'), { code: 'EPERM' }); } }), { code: 'EOWNER' });
});
test('JS inactive reservation rejects valid requests while session publication is stalled; exact completed generation permits restart', async t => {
  const dir = await directory(t), store = new Store(dir), held = deferred(), entered = deferred(), port = await freePort(); const save = store.saveSession.bind(store);
  store.saveSession = async value => { entered.resolve(); await held.promise; await save(value); };
  const starting = startController({ store, port }); await entered.promise;
  assert.equal((await fetch(`http://127.0.0.1:${port}/api/status`)).status, 503); held.resolve(); const app = await starting;
  await app.close(); await assert.rejects(store.saveConfig({ version: 1, roots: [], paused: false }), { code: 'EOWNER' });
  const next = await startController({ store: new Store(dir), port }); assert.notEqual(next.instanceId, app.instanceId); await next.close();
});
test('JS close returns bounded uncertainty while actual save retains selected port; only real completion allows restart', async t => {
  const dir = await directory(t), store = new Store(dir), app = await startController({ store, port: 0, closeWaitMs: 30 }); const held = deferred(), entered = deferred(), save = store.saveConfig.bind(store);
  store.saveConfig = async value => { entered.resolve(); await held.promise; return save(value); };
  const pending = fetch(`${app.origin}/api/pause`, { method: 'POST', headers: { Origin: app.origin, 'Content-Type': 'application/json', 'X-Chat2Local-Token': app.token }, body: '{"paused":true}' }); await entered.promise; app.lifecycle.poison();
  const closing = app.close(); assert.equal(closing, app.close()); await assert.rejects(closing, error => error.errors.some(e => e.code === 'EPERSISTENCE')); assert.equal(app.server.listening, true);
  await assert.rejects(startController({ stateDir: dir, port: Number(new URL(app.origin).port) }), { code: 'EADDRINUSE' });
  held.resolve(); await pending; for (let i = 0; i < 200 && app.server.listening; i++) await new Promise(resolve => setTimeout(resolve, 10)); assert.equal(app.server.listening, false);
  const next = await startController({ store: new Store(dir), port: Number(new URL(app.origin).port) }); await next.close();
});
test('Store rechecks a captured generation at actual atomic rename after awaited work', async t => {
  const dir = await directory(t); let checks = 0;
  await assert.rejects(atomicJson(path.join(dir, 'never.json'), { changed: true }, async () => { if (++checks === 2) throw Object.assign(Error('stale'), { code: 'EOWNER' }); }), { code: 'EOWNER' });
  await assert.rejects(fs.stat(path.join(dir, 'never.json')), { code: 'ENOENT' }); assert.deepEqual(await fs.readdir(dir), []);
  const store = new Store(dir), entered = deferred(), held = deferred(); let allowed = true; store.publicationGuard = async () => { entered.resolve(); await held.promise; if (!allowed) throw Object.assign(Error('stale'), { code: 'EOWNER' }); };
  const saving = store.saveConfig({ changed: true }); await entered.promise; store.publicationGuard = undefined; allowed = false; held.resolve(); await assert.rejects(saving, { code: 'EOWNER' }); await store.drainPublications();
});
test('JS rejects duplicate security headers before normal navigation or mutation', async t => {
  const dir = await directory(t), app = await startController({ stateDir: dir, port: 0 }); t.after(() => app.close());
  const f = { port: Number(new URL(app.origin).port), ready: { origin: app.origin }, session: { token: app.token } };
  for (const headers of [`Host: 127.0.0.1:${f.port}\r\n`, 'Sec-Fetch-Site: cross-site\r\nSec-Fetch-Site: same-origin\r\n', 'X-Chat2Local-Token: ' + app.token + '\r\n']) assert.match(await raw(f.port, request(f, '/api/status', { headers })), /^HTTP\/1.1 400/);
  assert.match(await raw(f.port, request(f, '/account-connect', { headers: 'Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\n' })), /^HTTP\/1.1 200/);
});
