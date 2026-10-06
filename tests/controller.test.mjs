import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { startController } from '../src/agent/main.mjs';

async function fixture(t) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'chat2local-http-test-'));
  const demoDir = path.join(base, 'demo');
  const root = path.join(base, 'project'); await fs.mkdir(root);
  const startupCalls = [];
  const app = await startController({ port: 0, stateDir: path.join(base, 'private'), demoDir, pickFolder: async () => root, setStartup: async enabled => startupCalls.push(enabled) });
  t.after(async () => { await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  const api = (route, body, extra = {}) => fetch(`${app.origin}/api/${route}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'X-Chat2Local-Token': app.token, Origin: app.origin, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...extra },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { app, api, root, demoDir, base, startupCalls };
}
async function ok(response) { assert.equal(response.status, 200, await response.clone().text()); return response.json(); }

test('HTTP panel is loopback-only, authenticated, and returns security headers', async t => {
  const { app, api } = await fixture(t);
  assert.equal(app.server.address().address, '127.0.0.1');
  const page = await fetch(app.origin);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /chat2local/i);
  assert.equal(page.headers.get('x-frame-options'), 'DENY');
  assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal((await fetch(`${app.origin}/api/status`)).status, 401);
  assert.equal((await api('status', undefined, { 'X-Chat2Local-Token': '0'.repeat(64) })).status, 401);
  const state = await ok(await api('status'));
  assert.equal(state.instanceId, app.instanceId); assert.deepEqual(state.roots, []);
  assert.equal(state.bridge, 'not-configured'); assert.equal(state.mcpUrl, '');
  assert.equal(JSON.stringify(state).includes(app.token), false);
  assert.equal((await fetch(`${app.origin}/store.mjs`)).status, 404);
  assert.equal((await fetch(`${app.origin}/?token=bad`)).status, 400);
});

test('HTTP rejects hostile Host, Origin, fetch metadata and missing POST Origin', async t => {
  const { app, api } = await fixture(t);
  assert.equal((await api('status', undefined, { Origin: 'https://attacker.invalid' })).status, 403);
  assert.equal((await api('status', undefined, { 'Sec-Fetch-Site': 'cross-site' })).status, 403);
  const noOrigin = await fetch(`${app.origin}/api/pause`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Chat2Local-Token': app.token }, body: '{"paused":true}' });
  assert.equal(noOrigin.status, 403);
  const badHost = await new Promise((resolve, reject) => {
    const request = http.get(`${app.origin}/api/status`, { headers: { Host: 'attacker.invalid', 'X-Chat2Local-Token': app.token } }, response => { response.resume(); resolve(response.statusCode); }); request.on('error', reject);
  });
  assert.equal(badHost, 403);
  assert.equal((await api('pause', { paused: 'true' })).status, 400);
  assert.equal((await api('pause', { paused: true, extra: 1 })).status, 400);
  assert.equal((await api('pause', { paused: true }, { 'Content-Type': 'text/plain' })).status, 415);
  assert.equal((await api('pause', { paused: false, padding: 'x'.repeat(530000) })).status, 413);
  assert.equal((await ok(await api('status'))).paused, false);
});

test('real HTTP demo reads and proposes; only local approval changes the file and saves a backup', async t => {
  const { api, demoDir, base } = await fixture(t);
  const proposal = await ok(await api('demo', {}));
  assert.equal(proposal.status, 'pending');
  const file = path.join(demoDir, 'hello-chat2local.txt');
  const before = await fs.readFile(file, 'utf8');
  const state = await ok(await api('status'));
  assert.equal(state.pending.length, 1);
  assert.equal(state.pending[0].before, before);
  assert.notEqual(state.pending[0].content, before);
  assert.equal(await fs.readFile(file, 'utf8'), before);
  const decided = await ok(await api('approve', { operationId: proposal.operationId, approved: true }));
  assert.equal(decided.status, 'approved');
  assert.equal(await fs.readFile(file, 'utf8'), state.pending[0].content);
  assert.equal(await fs.readFile(path.join(base, 'private', 'backups', `${proposal.operationId}.before`), 'utf8'), before);
  assert.equal((await api('approve', { operationId: proposal.operationId, approved: true })).status, 400);
});

test('pause and revoke invalidate pending HTTP approvals; readonly stays readonly', async t => {
  const { api, app, root } = await fixture(t);
  const permission = await ok(await api('root/add', { path: root, write: false }));
  assert.equal(permission.write, false);
  const repeated = await ok(await api('root/add', { path: root, write: true }));
  assert.equal(repeated.alreadyAuthorized, true);
  assert.equal(repeated.id, permission.id);
  assert.equal(repeated.write, false);
  assert.equal(repeated.writeMode, 'read-only');
  assert.equal((await ok(await api('status'))).roots.length, 1);
  // Repeated setup is not a permission update, even if another tab requests more.
  const directAttempt = await ok(await api('root/add', { path: root, writeMode: 'direct', confirmDirect: true }));
  assert.equal(directAttempt.id, permission.id);
  assert.equal(directAttempt.writeMode, 'read-only');
  await assert.rejects(() => app.files.invoke('write_file', { rootId: permission.id, path: 'x.txt', content: 'x', expectedHash: null }), /read-only/);
  await assert.rejects(() => app.files.invoke('propose_write', { rootId: permission.id, path: 'x.txt', content: 'x', expectedHash: null }), /read-only/);
  const proposal = await ok(await api('demo', {}));
  await ok(await api('pause', { paused: true }));
  assert.equal((await ok(await api('status'))).pending.length, 0);
  assert.equal((await api('approve', { operationId: proposal.operationId, approved: true })).status, 400);
  assert.equal((await api('demo', {})).status, 409);
  await ok(await api('pause', { paused: false }));
  await ok(await api('root/remove', { id: permission.id }));
  await assert.rejects(() => app.files.invoke('read_file', { rootId: permission.id, path: 'x.txt' }), /not authorized/);
});

test('picker and startup are explicit local actions; unknown remote command routes do not exist', async t => {
  const { api, root, startupCalls } = await fixture(t);
  assert.deepEqual(await ok(await api('pick-folder', {})), { path: root });
  assert.equal((await api('startup', { enabled: 'yes' })).status, 400);
  await ok(await api('startup', { enabled: true }));
  assert.deepEqual(startupCalls, [true]);
  assert.equal((await api('shell', { command: 'whoami' })).status, 404);
  assert.equal((await api('mcp', { method: 'tools/call' })).status, 404);
});

test('a second controller cannot take over a busy port or overwrite the live encrypted session', async t => {
  const { app, base } = await fixture(t);
  const vault = await fs.readFile(path.join(base, 'private', 'session.json'), 'utf8');
  await assert.rejects(() => startController({ port: app.server.address().port, stateDir: path.join(base, 'private') }), { code: 'EADDRINUSE' });
  assert.equal(await fs.readFile(path.join(base, 'private', 'session.json'), 'utf8'), vault);
  assert.equal((await fetch(`${app.origin}/api/status`, { headers: { 'X-Chat2Local-Token': app.token } })).status, 200);
});
