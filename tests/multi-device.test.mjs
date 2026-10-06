import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { randomBytes, createHash } from 'node:crypto';
import { build } from 'esbuild';
import { chromium } from 'playwright-core';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { startController } from '../src/agent/main.mjs';

const secret = () => randomBytes(32).toString('hex');
const post = (url, body, headers = {}) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body), redirect: 'manual' });
async function data(response, status = 200) { assert.equal(response.status, status, await response.clone().text()); return response.json(); }
async function until(check) { const end = Date.now() + 8000; while (Date.now() < end) { if (await check()) return; await new Promise(resolve => setTimeout(resolve, 40)); } throw new Error('Fixture condition timed out.'); }

test('one real OAuth token routes two independent agents without cross-device access or offline fallback', { timeout: 120000 }, async t => {
  const bundle = await build({ entryPoints: ['src/relay/worker.mjs'], bundle: true, write: false, format: 'esm', platform: 'neutral', mainFields: ['module', 'main'], external: ['cloudflare:workers'] });
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundle.outputFiles[0].text, compatibilityDate: '2026-09-20', compatibilityFlags: ['nodejs_compat', 'global_fetch_strictly_public'], host: '127.0.0.1', port: 0, kvNamespaces: ['OAUTH_KV'], durableObjects: { DEVICES: { className: 'Device', useSQLite: true }, REGISTRY: { className: 'Registry', useSQLite: true } }, bindings: { ALLOW_LOOPBACK: 'true', ENROLLMENT_KEY: secret(), CUSTOM_CONNECTOR_ENABLED: 'true', SELF_SERVICE_ENROLLMENT: 'true', MULTI_DEVICE: 'true' } }));
  const origin = (await mf.ready).origin;
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-multi-e2e-'));
  const apps = []; const browser = await chromium.launch({ channel: 'msedge', headless: true });
  const callbackServer = http.createServer((request, response) => { response.writeHead(200, { 'Content-Type': 'text/plain' }); response.end('Synthetic OAuth callback, not ChatGPT.'); });
  await new Promise(resolve => callbackServer.listen(0, '127.0.0.1', resolve));
  const callback = `http://127.0.0.1:${callbackServer.address().port}/callback`;
  t.after(async () => { await browser.close(); for (const app of apps) await app.close(); await new Promise(resolve => callbackServer.close(resolve)); await mf.dispose(); await fs.rm(base, { recursive: true, force: true }); });
  const context = await browser.newContext(); const page = await context.newPage();
  const client = await data(await post(`${origin}/oauth/register`, { client_name: 'Multi-device test client', redirect_uris: [callback], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] }), 201);

  async function computer(label, description) {
    const folder = path.join(base, label, 'same-project'); await fs.mkdir(folder, { recursive: true });
    await fs.writeFile(path.join(folder, 'same.txt'), `original-${label}`);
    const opened = [];
    const app = await startController({ port: 0, stateDir: path.join(base, label, 'private'), allowLocalRelay: true, defaultRelay: origin, openBrowser: async url => opened.push(url) });
    apps.push(app); app.bridge.description = () => description; const calls = [];
    const invoke = app.bridge.invoke; app.bridge.invoke = async (name, args) => { calls.push({ name, args }); return invoke(name, args); };
    const local = (route, body) => fetch(`${app.origin}/api/${route}`, { method: body === undefined ? 'GET' : 'POST', headers: { Origin: app.origin, 'X-Chat2Local-Token': app.token, 'Content-Type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: 'error' });
    const root = await data(await local('root/add', { path: folder, writeMode: 'direct', confirmDirect: true }));
    const setup = await data(await local('setup/start', {})); assert.equal(setup.ok, true); assert.equal(opened.length, 1);
    const state = await data(await local('status')); assert.equal(state.lastRemoteCallAt, null, 'metadata and setup must not masquerade as a remote file call');
    return { app, folder, root, opened, local, calls, id: state.device.deviceId };
  }
  async function bind(computer) {
    await page.goto(computer.opened[0]);
    await page.locator('#continue:enabled').waitFor();
    await page.locator('#continue').click();
    await page.locator('#custom-connection').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#mcp-url').inputValue(), `${origin}/mcp`);
  }
  async function begin(scope = 'files:read files:write offline_access') {
    const verifier = secret(); const state = secret();
    const query = new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: callback, scope, state, code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url'), resource: `${origin}/mcp` });
    await page.goto(`${origin}/authorize?${query}`);
    const ticket = await page.locator('input[name=ticket]').inputValue();
    return { verifier, state, ticket, query };
  }
  async function authorize(selection, write = true) {
    const flow = await begin();
    if (selection) {
      const choices = page.locator('input[name=device]'); assert.ok(await choices.count() > 1);
      for (const input of await choices.all()) await input.setChecked(selection.includes(await input.inputValue()));
    }
    assert.equal(await page.locator('input[name=directWrite]').isChecked(), true);
    if (!write) { await page.getByText('其他权限选项', { exact: true }).click(); await page.locator('input[name=directWrite]').uncheck(); }
    await page.locator('#approve').click(); await page.waitForURL(`${callback}*`);
    const url = new URL(page.url()); assert.equal(url.searchParams.get('state'), flow.state);
    return data(await fetch(`${origin}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: client.client_id, redirect_uri: callback, code: url.searchParams.get('code'), code_verifier: flow.verifier, resource: `${origin}/mcp` }) }));
  }
  const call = async (tokens, name, args = {}) => (await data(await post(`${origin}/mcp`, { jsonrpc: '2.0', id: secret(), method: 'tools/call', params: { name, arguments: args } }, { Authorization: `Bearer ${tokens.access_token}` }))).result;
  const okCall = async (tokens, name, args = {}) => { const result = await call(tokens, name, args); assert.equal(result.isError, false, result.content[0].text); return JSON.parse(result.content[0].text); };
  const rejectCall = async (tokens, name, args, pattern) => { const result = await call(tokens, name, args); assert.equal(result.isError, true); assert.match(result.content[0].text, pattern); };
  const A = await computer('A', { name: 'same-name', platform: 'win32', system: 'Windows', arch: 'x64' });
  let legacy; let full; let B; let C;

  await t.test('controlled new-device setup works without an official listing or operator-key entry', async () => {
    const info = await data(await fetch(`${origin}/setup-info`)); assert.equal(info.installUrl, null); assert.equal(info.customConnector, true); assert.equal(info.multiDevice, true);
    assert.equal((await post(`${origin}/enroll`, {})).status, 401);
    await bind(A); legacy = await authorize();
    assert.equal((await okCall(legacy, 'list_devices')).devices.length, 1);
  });
  await t.test('a second verified computer is added only after its own browser confirmation', async () => {
    B = await computer('B', { name: 'same-name', platform: 'darwin', system: 'macOS', arch: 'arm64' }); // descriptive fixture, not a native Mac test
    await page.goto(B.opened[0]); await page.locator('#continue:enabled').waitFor();
    assert.equal((await okCall(legacy, 'list_devices')).devices.length, 1);
    await page.locator('#continue').click(); await page.locator('#custom-connection').waitFor({ state: 'visible' });
    assert.equal((await okCall(legacy, 'list_devices')).devices.length, 1);
    await rejectCall(legacy, 'list_roots', { deviceId: B.id }, /not included/);
    full = await authorize([A.id, B.id]);
    const result = await okCall(full, 'list_devices');
    assert.equal(result.selectionRequired, true); assert.equal(result.devices.length, 2);
    assert.ok(result.devices.some(item => item.deviceId === A.id && item.system === 'Windows'));
    assert.ok(result.devices.some(item => item.deviceId === B.id && item.system === 'macOS'));
    assert.equal(JSON.stringify(result).includes('epoch'), false);
    // This provider replaces a same-user/same-client grant on explicit reauthorization.
    // The old token is invalidated, not silently expanded to the new device set.
    assert.equal((await post(`${origin}/mcp`, { jsonrpc: '2.0', id: secret(), method: 'tools/call', params: { name: 'list_devices' } }, { Authorization: `Bearer ${legacy.access_token}` })).status, 401);
  });
  await t.test('ambiguous targets and roots from another computer fail before any write', async () => {
    const before = [A.calls.length, B.calls.length];
    await rejectCall(full, 'write_file', { rootId: A.root.id, path: 'x.txt', content: 'no', expectedHash: null }, /More than one/);
    await rejectCall(full, 'list_roots', { deviceId: 'f'.repeat(32) }, /not included/);
    assert.deepEqual([A.calls.length, B.calls.length], before);
    await rejectCall(full, 'read_file', { deviceId: B.id, rootId: A.root.id, path: 'same.txt' }, /not authorized/);
    assert.equal(await fs.readFile(path.join(A.folder, 'same.txt'), 'utf8'), 'original-A');
    assert.equal(await fs.readFile(path.join(B.folder, 'same.txt'), 'utf8'), 'original-B');
  });
  await t.test('parallel writes to identically named files remain bound to different computers and backups', async () => {
    await Promise.all([A, B].map(async comp => {
      const roots = await okCall(full, 'list_roots', { deviceId: comp.id }); assert.equal(roots[0].deviceId, comp.id); assert.equal(roots[0].id, comp.root.id);
      const before = await okCall(full, 'read_file', { deviceId: comp.id, rootId: comp.root.id, path: 'same.txt' });
      const written = await okCall(full, 'write_file', { deviceId: comp.id, rootId: comp.root.id, path: 'same.txt', content: `updated-${comp.id}`, expectedHash: before.sha256 });
      assert.equal(written.status, 'written'); assert.equal(written.backupSaved, true); assert.equal(written.deviceId, comp.id);
      assert.equal((await okCall(full, 'read_file', { deviceId: comp.id, rootId: comp.root.id, path: 'same.txt' })).content, `updated-${comp.id}`);
      assert.equal((await okCall(full, 'operation_status', { deviceId: comp.id, operationId: written.operationId })).status, 'written');
    }));
    assert.ok(A.calls.every(call => call.args.deviceId === undefined)); assert.ok(B.calls.every(call => call.args.deviceId === undefined));
  });
  await t.test('declining a computer and narrowing OAuth scope restrict independently', async () => {
    const refresh = await data(await fetch(`${origin}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'refresh_token', client_id: client.client_id, refresh_token: full.refresh_token, scope: 'files:read', resource: `${origin}/mcp` }) }));
    assert.equal((await okCall(refresh, 'list_devices')).devices.length, 2);
    await rejectCall(refresh, 'write_file', { deviceId: A.id, rootId: A.root.id, path: 'no.txt', content: 'no', expectedHash: null }, /scope/);
    const onlyA = await authorize([A.id]);
    assert.equal((await okCall(onlyA, 'list_devices')).devices.length, 1);
    await rejectCall(onlyA, 'list_roots', { deviceId: B.id }, /not included/);
    full = await authorize([A.id, B.id]);
  });
  await t.test('newly bound devices do not expand existing OAuth grants; stale consent rejects a changed collection', async () => {
    const stale = await begin(); const oldCsrf = (await context.cookies(`${origin}/authorize`)).find(item => item.name === 'c2l_csrf').value;
    C = await computer('C', { name: 'third', platform: 'linux', system: 'Linux', arch: 'x64' }); await bind(C);
    const cookie = (await context.cookies(`${origin}/authorize`)).filter(item => item.name !== 'c2l_csrf').map(item => `${item.name}=${item.value}`).concat(`c2l_csrf=${oldCsrf}`).join('; ');
    const form = new URLSearchParams({ ticket: stale.ticket, source: 'browser' }); form.append('device', A.id); form.append('device', B.id);
    const response = await fetch(`${origin}/authorize`, { method: 'POST', headers: { Origin: origin, Cookie: cookie, 'Content-Type': 'application/x-www-form-urlencoded' }, body: form, redirect: 'manual' });
    assert.equal(response.status, 403);
    assert.equal((await okCall(full, 'list_devices')).devices.length, 2);
    await rejectCall(full, 'list_roots', { deviceId: C.id }, /not included/);
    assert.equal((await post(`${origin}/mcp`, { jsonrpc: '2.0', id: secret(), method: 'tools/call', params: { name: 'list_devices' } }, { Authorization: `Bearer ${legacy.access_token}` })).status, 401);
  });
  await t.test('forged device selections, duplicate choices and public internal routes are rejected', async () => {
    for (const choices of [[], ['e'.repeat(32)], [A.id, A.id]]) {
      const flow = await begin();
      const form = new URLSearchParams({ ticket: flow.ticket, source: 'browser' }); for (const id of choices) form.append('device', id);
      const response = await context.request.post(`${origin}/authorize`, { headers: { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' }, data: form.toString(), maxRedirects: 0 });
      assert.equal(response.status(), choices.length === 2 ? 400 : 403);
    }
    assert.equal((await post(`${origin}/roster/append`, { devices: [A.id, B.id] })).status, 404);
    assert.equal((await post(`${origin}/device/${A.id}/describe`, { epoch: secret() })).status, 404);
    assert.equal((await post(`${origin}/device/${A.id}/metadata`, { name: 'forged' })).status, 401);
  });
  await t.test('link confirmation binds CSRF to the exact computer proof and consumes it only once', async () => {
    await data(await A.local('setup/start', {})); await data(await C.local('setup/start', {}));
    const proofA = new URL(A.opened.at(-1)).hash.slice(1); const proofC = new URL(C.opened.at(-1)).hash.slice(1);
    const inspectA = await context.request.post(`${origin}/link/inspect`, { headers: { Origin: origin }, data: { proof: proofA } }); assert.equal(inspectA.status(), 200);
    const inspected = await context.request.post(`${origin}/link/inspect`, { headers: { Origin: origin }, data: { proof: proofC } }); assert.equal(inspected.status(), 200);
    const { csrf } = await inspected.json();
    const switched = await context.request.post(`${origin}/link/confirm`, { headers: { Origin: origin }, data: { proof: proofA, csrf } }); assert.equal(switched.status(), 403);
    const accepted = await context.request.post(`${origin}/link/confirm`, { headers: { Origin: origin }, data: { proof: proofC, csrf } }); assert.equal(accepted.status(), 200);
    const replay = await context.request.post(`${origin}/link/confirm`, { headers: { Origin: origin }, data: { proof: proofC, csrf } }); assert.equal(replay.status(), 403);
    assert.equal((await okCall(full, 'list_devices')).devices.length, 2);
  });
  await t.test('offline device is still listed and a write never falls back or replays on reconnect', async () => {
    B.app.bridge.stop(); await until(async () => (await okCall(full, 'list_devices')).devices.find(item => item.deviceId === B.id).status === 'offline');
    const before = A.calls.length;
    await rejectCall(full, 'write_file', { deviceId: B.id, rootId: B.root.id, path: 'offline.txt', content: 'no', expectedHash: null }, /offline/);
    assert.equal(A.calls.length, before);
    B.app.bridge.start(B.app.bridge.identity); await until(() => B.app.bridge.state === 'connected');
    await assert.rejects(() => fs.access(path.join(B.folder, 'offline.txt')), { code: 'ENOENT' });
    assert.equal((await okCall(full, 'list_roots', { deviceId: A.id }))[0].id, A.root.id);
  });
  await t.test('local pause and revocation affect only their device; a different browser sees no collection', async () => {
    await data(await B.local('pause', { paused: true }));
    await rejectCall(full, 'read_file', { deviceId: B.id, rootId: B.root.id, path: 'same.txt' }, /paused/);
    assert.equal((await okCall(full, 'read_file', { deviceId: A.id, rootId: A.root.id, path: 'same.txt' })).content, `updated-${A.id}`);
    await data(await B.local('disconnect', {}));
    const status = await okCall(full, 'list_devices'); assert.equal(status.devices.find(item => item.deviceId === B.id).status, 'revoked');
    await rejectCall(full, 'list_roots', { deviceId: B.id }, /revoked/);
    const flow = await begin();
    const unrelated = await fetch(`${origin}/authorize?${flow.query}`);
    assert.equal((await unrelated.text()).includes('name="device"'), false);
    assert.equal((await okCall(full, 'list_roots', { deviceId: A.id }))[0].id, A.root.id);
  });
});
