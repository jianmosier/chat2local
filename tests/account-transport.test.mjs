import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { startController } from '../src/agent/main.mjs';
import { ACCESS_CAPABILITY } from '../src/shared/connection-access.mjs';

async function until(check) { const end = Date.now() + 8000; while (Date.now() < end) { if (await check()) return; await new Promise(resolve => setTimeout(resolve, 40)); } throw Error('Condition timed out.'); }
async function json(response, status = 200) { assert.equal(response.status, status, await response.clone().text()); return response.json(); }

test('real Durable Object/WebSocket/agent transports preserve connection scope and reject a reconnected legacy agent', { timeout: 40000 }, async t => {
  const bundle = await build({ entryPoints: ['src/relay/worker.mjs'], bundle: true, write: false, format: 'esm', platform: 'neutral', mainFields: ['module', 'main'], external: ['cloudflare:workers'] });
  const enrollmentKey = randomBytes(32).toString('hex');
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundle.outputFiles[0].text, compatibilityDate: '2026-09-20', compatibilityFlags: ['nodejs_compat', 'global_fetch_strictly_public'], host: '127.0.0.1', port: 0, kvNamespaces: ['OAUTH_KV'], durableObjects: { DEVICES: { className: 'Device', useSQLite: true }, REGISTRY: { className: 'Registry', useSQLite: true } }, bindings: { ALLOW_LOOPBACK: 'true', ENROLLMENT_KEY: enrollmentKey } }));
  t.after(() => mf.dispose()); const origin = (await mf.ready).origin;
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-scope-wire-')); const folder = path.join(base, 'sample'); await fs.mkdir(folder);
  const app = await startController({ port: 0, stateDir: path.join(base, 'private'), allowLocalRelay: true });
  t.after(async () => { await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  const local = async (route, body) => json(await fetch(`${app.origin}/api/${route}`, { method: 'POST', headers: { Origin: app.origin, 'Content-Type': 'application/json', 'X-Chat2Local-Token': app.token }, body: JSON.stringify(body) }));
  const root = await local('root/add', { path: folder, writeMode: 'direct', confirmDirect: true });
  await local('enroll', { origin, enrollmentToken: enrollmentKey }); await until(() => app.bridge.state === 'connected');
  const identity = app.bridge.identity;
  const namespace = await mf.getDurableObjectNamespace('DEVICES'); const stub = namespace.get(namespace.idFromName(identity.deviceId));
  const request = (route, body) => stub.fetch(new Request(`http://internal${route}`, { method: 'POST', body: JSON.stringify(body) }));
  // An isolated, one-use device proof gives the fixture its own epoch. This is
  // not a public bypass endpoint and no real user/device/token is involved.
  const pair = await app.bridge.pairCode();
  const { epoch } = await json(await request('/consume-pair', { secret: pair.code.split('.')[1] }));
  assert.ok((await json(await request('/describe', { epoch }))).capabilities.includes(ACCESS_CAPABILITY));
  const access = { version: 1, connectionId: '1'.repeat(32), deviceId: identity.deviceId, resource: `${origin}/mcp`, roots: [{ rootId: root.id, mode: 'direct' }], scopes: ['files:read', 'files:write'] };
  const invoke = (tool, args, context = access) => request('/invoke', { epoch, tool, args, ...(context === undefined ? {} : { connectionAccess: context }) });
  const created = (await json(await invoke('write_file', { rootId: root.id, path: 'scoped.txt', content: 'scope remains on wire', expectedHash: null }))).result;
  assert.equal(created.status, 'written');
  const read = (await json(await invoke('read_file', { rootId: root.id, path: 'scoped.txt' }))).result;
  assert.equal(read.content, 'scope remains on wire');
  assert.equal((await json(await invoke('operation_status', { operationId: created.operationId }, { ...access, connectionId: '2'.repeat(32) }))).result.status, 'unknown');
  const denied = await json(await invoke('write_file', { rootId: root.id, path: 'scoped.txt', content: 'must not change', expectedHash: created.sha256 }, { ...access, scopes: ['files:read'] }), 422);
  assert.match(denied.error, /read-only/);
  assert.equal(await fs.readFile(path.join(folder, 'scoped.txt'), 'utf8'), 'scope remains on wire');
  await json(await invoke('list_roots', {}, { ...access, deviceId: 'f'.repeat(32) }), 422);
  app.bridge.stop(); await until(async () => !(await json(await request('/describe', { epoch }))).online);
  app.bridge.connectionAccess = false; app.bridge.start(identity); await until(() => app.bridge.state === 'connected');
  assert.deepEqual((await json(await request('/describe', { epoch }))).capabilities, []);
  const outdated = await json(await invoke('read_file', { rootId: root.id, path: 'scoped.txt' }), 409); assert.match(outdated.error, /cannot enforce/);
  // The compatibility path still works, but cannot pretend to enforce v3.
  const legacy = await json(await request('/invoke', { epoch, tool: 'read_file', args: { rootId: root.id, path: 'scoped.txt' } }));
  assert.equal(legacy.result.content, 'scope remains on wire');
});
