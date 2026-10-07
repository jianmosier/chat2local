import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { randomBytes, createHash } from 'node:crypto';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { chromium } from 'playwright-core';
import { startController } from '../src/agent/main.mjs';
import { Store } from '../src/agent/store.mjs';
import { connectFromInstance } from '../scripts/install-from-instance.mjs';

const secret = () => randomBytes(32).toString('hex');
const data = async (response, expected = 200) => { assert.equal(response.status, expected, await response.clone().text()); return response.json(); };
const post = (url, body, headers = {}) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body), redirect: 'manual' });
async function until(fn) { const end = Date.now() + 10000; while (Date.now() < end) { if (await fn()) return; await new Promise(r => setTimeout(r, 50)); } throw new Error('Private test state not reached.'); }

test('private instance: NO IdP, owner invitation -> ONE native consent -> original OAuth; second device joins the SAME token', { timeout: 120000 }, async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-private-http-'));
  const folderA = path.join(base, 'A'), folderB = path.join(base, 'B'); await fs.mkdir(folderA); await fs.mkdir(folderB);
  const storeA = new Store(path.join(base, 'private-a')), storeB = new Store(path.join(base, 'private-b'));
  let picksA = 0, picksB = 0, confirmationsA = 0, confirmationsB = 0, loss = false, enrollA = 0;
  let appA = await startController({ port: 0, store: storeA, allowLocalRelay: true, pickFolder: async () => { picksA++; return folderA; }, accountFetch: async (url, options) => {
    if (url.endsWith('/enroll')) enrollA++;
    const response = await fetch(url, options);
    if (url.endsWith('/activate') && response.ok && !loss) { loss = true; await response.text(); throw new Error('Fixture loss AFTER activation commit'); }
    return response;
  } });
  const appB = await startController({ port: 0, store: storeB, allowLocalRelay: true, pickFolder: async () => { picksB++; return folderB; } });
  t.after(async () => { await appA.close(); await appB.close(); await fs.rm(base, { recursive: true, force: true }); });
  const bundle = await build({ entryPoints: ['src/relay/worker.mjs'], bundle: true, write: false, format: 'esm', platform: 'neutral', mainFields: ['module','main'], external: ['cloudflare:workers'] });
  const ownerKey = secret();
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundle.outputFiles[0].text, host: '127.0.0.1', port: 0, compatibilityDate: '2026-09-20', compatibilityFlags: ['nodejs_compat','global_fetch_strictly_public'], kvNamespaces: ['OAUTH_KV'], durableObjects: { DEVICES: { className: 'Device', useSQLite: true }, REGISTRY: { className: 'Registry', useSQLite: true } }, bindings: { PRIVATE_INSTANCE: 'true', ALLOW_LOOPBACK: 'true', ENROLLMENT_KEY: ownerKey, TEST_RECOVERY_ORIGIN: appA.origin } }));
  t.after(() => mf.dispose()); const origin = (await mf.ready).origin;
  const callbackServer = http.createServer((_req, res) => { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('Original MCP client'); });
  await new Promise(r => callbackServer.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { callbackServer.close(r); callbackServer.closeIdleConnections(); }));
  const callback = `http://127.0.0.1:${callbackServer.address().port}/callback`;
  const client = await data(await post(origin + '/oauth/register', { client_name: 'My original chat2local', redirect_uris: [callback], token_endpoint_auth_method: 'none', grant_types: ['authorization_code','refresh_token'], response_types: ['code'] }), 201);
  const owner = (action, input = {}) => post(origin + '/instance/owner/' + action, input, { Authorization: 'Bearer ' + ownerKey });
  const importInvite = (app, url) => post(app.origin + '/api/instance/import-invitation', { url }, { Origin: app.origin, 'X-Chat2Local-Token': app.token });
  assert.equal((await post(origin + '/instance/owner/invitations', { purpose: 'connect' })).status, 401);
  assert.equal((await fetch(origin + '/account/add')).status, 404);
  const info = await data(await fetch(origin + '/setup-info')); assert.equal(info.privateInstance, true); assert.equal(info.accountConnections, false);
  const inviteA = await data(await owner('invitations', { purpose: 'connect', clientId: client.client_id }), 201);
  assert.equal((await importInvite(appA, inviteA.inviteUrl)).status, 200);
  assert.deepEqual((await storeA.load()).config.roots, []);
  const browser = await chromium.launch({ channel: 'msedge', headless: true }); t.after(() => browser.close());
  const contextA = await browser.newContext({ viewport: { width: 420, height: 900 } }), pageA = await contextA.newPage();
  const contextB = await browser.newContext(), pageB = await contextB.newPage();
  let forbiddenRequests = 0, tokenExchanges = 0;
  for (const context of [contextA, contextB]) context.on('request', request => {
    const url = new URL(request.url());
    if (/accounts\.google|identity\.|\/account\/(callback|add)/.test(url.href)) forbiddenRequests++;
    if (url.pathname === '/oauth/token') tokenExchanges++;
  });
  const errors = [], trace = [];
  pageA.on('pageerror', e => errors.push(e.message));
  pageA.on('response', r => trace.push([new URL(r.url()).pathname, r.status()]));
  const verifier = secret(), state = secret();
  const query = new URLSearchParams({ client_id: client.client_id, redirect_uri: callback, response_type: 'code', scope: 'files:read files:write offline_access', state, code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', resource: origin + '/mcp' });
  await pageA.goto(origin + '/authorize?' + query);
  await pageA.waitForFunction(() => !document.querySelector('#account-choose')?.disabled && !document.querySelector('#account-summary')?.hidden, { timeout: 15000 }).catch(async () => { throw new Error(JSON.stringify(trace) + ' ' + await pageA.locator('body').innerText()); });
  assert.equal((await storeA.load()).config.accountRoots, undefined); assert.equal(enrollA, 1);
  const identityA = (await storeA.load()).secrets.identity;
  assert.ok(identityA?.deviceId); assert.notEqual(identityA.deviceKey, ownerKey);
  await pageA.locator('#account-choose').click(); await pageA.locator('#account-confirm').waitFor({ state: 'visible' });
  assert.equal(picksA, 1); assert.equal((await storeA.load()).config.accountRoots, undefined);
  assert.match(await pageA.locator('body').innerText(), /私人实例/);
  assert.equal(await pageA.locator('input[type=password]').count(), 0);
  assert.equal(await pageA.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  await fs.mkdir('.artifacts', { recursive: true }); await pageA.screenshot({ path: '.artifacts/private-instance-one-consent.png', fullPage: true });
  pageA.on('request', r => { if (new URL(r.url()).pathname === '/instance-connect/confirm') confirmationsA++; });
  await pageA.locator('#account-confirm').click(); await pageA.waitForURL(callback + '*', { timeout: 30000 });
  assert.equal(confirmationsA, 1); assert.equal(contextA.pages().length, 1); assert.equal(new URL(pageA.url()).searchParams.get('state'), state);
  const tokens = await data(await fetch(origin + '/oauth/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: client.client_id, redirect_uri: callback, code: new URL(pageA.url()).searchParams.get('code'), code_verifier: verifier, resource: origin + '/mcp' }) }));
  const call = async (name, args = {}) => (await data(await post(origin + '/mcp', { jsonrpc: '2.0', id: secret(), method: 'tools/call', params: { name, arguments: args } }, { Authorization: 'Bearer ' + tokens.access_token }))).result;
  const ok = async (name, args = {}) => { const result = await call(name, args); assert.equal(result.isError, false, result.content[0].text); return JSON.parse(result.content[0].text); };
  await until(() => appA.bridge.state === 'connected');
  const rootA = (await ok('list_roots'))[0];
  assert.equal((await ok('list_devices')).devices.length, 1);
  assert.equal((await post(origin + '/instance/owner/connections', {}, { Authorization: 'Bearer ' + tokens.access_token })).status, 401);
  const list = await data(await owner('connections')); assert.equal(list.connections.length, 1);
  const inviteB = await data(await owner('invitations', { purpose: 'join', connectionId: list.connections[0].connectionId }), 201);
  await data(await importInvite(appB, inviteB.inviteUrl));
  // Two physical machines would use the SAME loopback port. Test-only response
  // translation points the second independent browser at its independent agent.
  await pageB.route('**/instance/join/start', async route => {
    const response = await route.fetch(); const result = await response.json();
    if (result.localUrl) { const local = new URL(result.localUrl); local.host = new URL(appB.origin).host; result.localUrl = local.href; }
    await route.fulfill({ response, json: result });
  });
  await pageB.goto(inviteB.inviteUrl);
  await pageB.waitForFunction(() => !document.querySelector('#account-choose')?.disabled && !document.querySelector('#account-summary')?.hidden);
  assert.equal((await ok('list_devices')).devices.length, 1, 'registration alone grants nothing');
  await pageB.locator('#account-choose').click(); await pageB.locator('#account-confirm').waitFor({ state: 'visible' });
  pageB.on('request', r => { if (new URL(r.url()).pathname === '/instance-connect/confirm') confirmationsB++; });
  await pageB.locator('#account-confirm').click(); await pageB.waitForURL(origin + '/instance/finish?*');
  await pageB.getByRole('heading', { name: '共享目录已更新' }).waitFor();
  assert.equal(confirmationsB, 1); assert.equal(picksB, 1); assert.equal(contextB.pages().length, 1);
  assert.equal(tokenExchanges, 0, 'No browser-side OAuth exchange or second-device token issuance');
  const identityB = (await storeB.load()).secrets.identity;
  assert.notEqual(identityB.deviceKey, identityA.deviceKey); assert.notEqual(identityB.deviceId, identityA.deviceId);
  await until(() => appB.bridge.state === 'connected');
  const devices = await ok('list_devices'); assert.equal(devices.devices.length, 2);
  const rootB = (await ok('list_roots', { deviceId: identityB.deviceId }))[0];
  assert.equal((await call('list_roots')).isError, true);
  for (const [identity, root, content] of [[identityA, rootA, 'A\n'], [identityB, rootB, 'B\n']]) {
    const args = { deviceId: identity.deviceId, rootId: root.id, path: 'same.txt' };
    assert.equal((await ok('write_file', { ...args, content, expectedHash: null })).status, 'written');
    const read = await ok('read_file', args); assert.equal(read.content, content);
    const updated = await ok('write_file', { ...args, content: content + 'updated\n', expectedHash: read.sha256 }); assert.equal(updated.backupSaved, true);
  }
  assert.equal((await call('read_file', { deviceId: identityB.deviceId, rootId: rootA.id, path: 'same.txt' })).isError, true);
  assert.deepEqual((await storeA.load()).config.roots, []); assert.deepEqual((await storeB.load()).config.roots, []);
  assert.equal(forbiddenRequests, 0); assert.deepEqual(errors, []);
  const rootOnDisk = (await storeA.load()).config.accountRoots[0];
  assert.equal((await storeA.readPrivateRecord('onboarding-intent-' + rootOnDisk.intentId)).confirmations, 1);
  await appA.close();
  appA = await startController({ port: 0, store: storeA, allowLocalRelay: true });
  await until(() => appA.bridge.state === 'connected');
  assert.equal((await ok('read_file', { deviceId: identityA.deviceId, rootId: rootA.id, path: 'same.txt' })).content, 'A\nupdated\n');
  assert.equal(confirmationsA, 1);
  // Revoked/local removed share is not made live again by the old invitation.
  await data(await post(appB.origin + '/api/account-root/remove', { id: rootB.id }, { Origin: appB.origin, 'X-Chat2Local-Token': appB.token }));
  assert.equal((await call('read_file', { deviceId: identityB.deviceId, rootId: rootB.id, path: 'same.txt' })).isError, true);
  assert.equal(await fs.readFile(path.join(folderB, 'same.txt'), 'utf8'), 'B\nupdated\n');
  // Independent installation gate: BOTH old computers are offline. A NEW
  // native runner installs/joins using only the owner's cloud password page;
  // there is no old-device RPC, exported invitation file or second plugin.
  await appA.close(); await appB.close();
  const folderC = path.join(base, 'C'); await fs.mkdir(folderC);
  const storeC = new Store(path.join(base, 'private-c')); let pickerC = 0, consentC = 0, startsC = 0;
  let selectedFolderC = folderC;
  const appC = await startController({ port: 0, store: storeC, allowLocalRelay: true, pickFolder: async () => { pickerC++; return selectedFolderC; } });
  t.after(() => appC.close());
  const password = 'Isolated private install password 9471';
  assert.equal((await post(origin + '/install/owner/configure', { password })).status, 401);
  await data(await post(origin + '/install/owner/configure', { password }, { Authorization: 'Bearer ' + ownerKey }));
  const contextC = await browser.newContext({ viewport: { width: 390, height: 844 } }), pageC = await contextC.newPage();
  await pageC.route('**/instance/join/start', async route => {
    const response = await route.fetch(); const value = await response.json();
    if (value.localUrl) { const target = new URL(value.localUrl); target.host = new URL(appC.origin).host; value.localUrl = target.href; }
    await route.fulfill({ response, json: value });
  });
  const installWork = connectFromInstance(origin, { store: storeC, localOrigin: appC.origin, allowLocal: true, pollMs: 80, network: { prepare: async () => {} }, openBrowser: url => pageC.goto(url), request: async (url, options) => {
    const response = await fetch(url, options);
    if (url.endsWith('/install/start') && ++startsC === 1) { await response.text(); throw new Error('Fixture: response lost after start commit'); }
    return response;
  } });
  await pageC.locator('#password').waitFor({ state: 'visible' });
  assert.equal(new URL(pageC.url()).hash, ''); assert.equal((await storeC.load()).secrets.identity, undefined);
  const crossSite = await post(origin + '/install/login', { password }, { Origin: 'https://attacker.invalid' }); assert.equal(crossSite.status, 403);
  const noCsrf = await post(origin + '/install/login', { password }, { Origin: origin }); assert.equal(noCsrf.status, 403);
  assert.equal(await pageC.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  await pageC.screenshot({ path: '.artifacts/independent-install-login.png', fullPage: true });
  await pageC.locator('#password').fill(password); await pageC.locator('#login').click();
  const installed = await installWork; assert.equal(installed.imported, true); assert.equal(installed.foldersGranted, false); assert.equal(startsC, 2);
  await pageC.waitForFunction(() => !document.querySelector('#account-choose')?.disabled && !document.querySelector('#account-summary')?.hidden);
  assert.equal((await storeC.load()).config.accountRoots, undefined);
  const beforeC = await ok('list_devices'); assert.equal(beforeC.devices.length, 2);
  assert.equal(beforeC.devices.find(d => d.deviceId === identityA.deviceId).status, 'offline');
  await pageC.locator('#account-choose').click(); await pageC.locator('#account-confirm').waitFor({ state: 'visible' });
  pageC.on('request', request => { if (new URL(request.url()).pathname === '/instance-connect/confirm') consentC++; });
  await pageC.screenshot({ path: '.artifacts/independent-install-folder.png', fullPage: true });
  await pageC.locator('#account-confirm').click(); await pageC.getByRole('heading', { name: '共享目录已更新' }).waitFor();
  assert.equal(pickerC, 1); assert.equal(consentC, 1); assert.equal(contextC.pages().length, 1);
  const identityC = (await storeC.load()).secrets.identity; assert.notEqual(identityC.deviceKey, identityA.deviceKey); assert.notEqual(identityC.deviceKey, ownerKey);
  await until(() => appC.bridge.state === 'connected');
  assert.equal((await ok('list_devices')).devices.length, 3);
  const rootC = (await ok('list_roots', { deviceId: identityC.deviceId }))[0];
  const cArgs = { deviceId: identityC.deviceId, rootId: rootC.id, path: 'independent.txt' };
  assert.equal((await ok('write_file', { ...cArgs, content: 'Old computers are offline', expectedHash: null })).status, 'written');
  assert.equal((await ok('read_file', cArgs)).content, 'Old computers are offline');
  assert.equal((await call('read_file', { ...cArgs, rootId: rootA.id })).isError, true);
  assert.equal((await data(await owner('connections'))).connections.length, 1);
  // A paired computer can use the already-installed --connect entry to add a
  // different folder without reinstalling, enrolling another device, replacing
  // its identity, or reauthorizing the original MCP client. This is a regression
  // for the supported interim route; the old /manage root/add UI is not used.
  const originalConnection = (await data(await owner('connections'))).connections[0].connectionId;
  const retainedIdentityC = structuredClone((await storeC.load()).secrets.identity);
  selectedFolderC = path.join(base, 'Additional-project'); await fs.mkdir(selectedFolderC);
  const anotherFolder = await connectFromInstance(origin, {
    store: storeC, localOrigin: appC.origin, allowLocal: true, pollMs: 80,
    network: { prepare: async () => {} }, openBrowser: url => pageC.goto(url),
  });
  assert.equal(anotherFolder.imported, true); assert.equal(anotherFolder.foldersGranted, false);
  await pageC.waitForFunction(() => !document.querySelector('#account-choose')?.disabled && !document.querySelector('#account-summary')?.hidden);
  assert.equal(await pageC.locator('#account-confirm').isHidden(), true);
  assert.deepEqual((await storeC.load()).secrets.identity, retainedIdentityC);
  assert.equal((await ok('list_roots', { deviceId: identityC.deviceId })).length, 1);
  assert.equal((await ok('list_devices')).devices.length, 3);
  await pageC.locator('#account-choose').click(); await pageC.locator('#account-confirm').waitFor({ state: 'visible' });
  assert.equal((await ok('list_roots', { deviceId: identityC.deviceId })).length, 1, 'Folder browsing/preparation does not share it');
  await pageC.locator('#account-confirm').click(); await pageC.getByRole('heading', { name: '共享目录已更新' }).waitFor();
  const expanded = await ok('list_roots', { deviceId: identityC.deviceId });
  assert.equal(expanded.length, 2); assert.ok(expanded.some(root => root.id === rootC.id));
  const added = expanded.find(root => root.id !== rootC.id);
  const addedArgs = { deviceId: identityC.deviceId, rootId: added.id, path: 'additional.txt' };
  assert.equal((await ok('write_file', { ...addedArgs, content: 'Same computer, additional shared folder', expectedHash: null })).status, 'written');
  assert.equal((await ok('read_file', addedArgs)).content, 'Same computer, additional shared folder');
  assert.equal((await ok('read_file', cArgs)).content, 'Old computers are offline');
  assert.deepEqual((await storeC.load()).secrets.identity, retainedIdentityC);
  assert.equal((await ok('list_devices')).devices.length, 3);
  assert.equal((await data(await owner('connections'))).connections[0].connectionId, originalConnection);
  assert.equal(pickerC, 2); assert.equal(consentC, 2); assert.equal(contextC.pages().length, 1);
  assert.equal(tokenExchanges, 0);
  // Daily management is a separate local-control flow: clear all installer
  // cookies, keep old computers OFFLINE, and batch-add two folders with ONE
  // consent to the same token. No password, invitation, or OAuth request.
  const batchA = path.join(base, 'Batch-A'), batchB = path.join(base, 'Batch-B');
  await fs.mkdir(batchA); await fs.mkdir(batchB);
  await contextC.clearCookies();
  let managementConfirms = 0, installerCalls = 0;
  pageC.on('request', request => {
    const route = new URL(request.url()).pathname;
    if (route === '/api/shares/confirm') managementConfirms++;
    if (route.startsWith('/install/') || route === '/authorize') installerCalls++;
  });
  assert.equal((await post(appC.origin + '/api/shares/connections', {}, { Origin: appC.origin })).status, 401);
  assert.equal((await post(appC.origin + '/api/shares/connections', {}, { Origin: 'https://attacker.invalid', 'X-Chat2Local-Token': appC.token })).status, 403);
  assert.equal((await post(origin + '/instance/manage/connections', { deviceId: identityC.deviceId, input: {} }, { Authorization: 'Bearer ' + tokens.access_token })).status, 401);
  // Regression: the old global setup bucket (200/hour) was exhausted by
  // ordinary management polling. Cross that boundary on the real Worker with
  // the exact device credential, then continue the existing one-consent flow.
  const beforePolling = JSON.stringify(await storeC.load());
  for (let i = 0; i < 202; i++) {
    const polled = await data(await post(origin + '/instance/manage/connections', { deviceId: identityC.deviceId, input: {} }, { Authorization: 'Bearer ' + identityC.deviceKey }));
    assert.ok(polled.connections.some(c => c.connectionId === originalConnection));
  }
  assert.equal(JSON.stringify(await storeC.load()), beforePolling, 'Polling never changes local identity or grants');
  assert.equal((await data(await owner('connections'))).connections.length, 1, 'Polling did not consume setup capacity');
  await pageC.goto(appC.origin + '/folders#' + appC.token);
  await pageC.locator('#connection option').waitFor({ state: 'attached' });
  await pageC.locator('#open-add').click();
  await pageC.locator('#path').fill(base); await pageC.locator('#browse').click();
  await pageC.getByRole('checkbox', { name: '加入待授权列表 Batch-A', exact: true }).check();
  await pageC.getByRole('checkbox', { name: '加入待授权列表 Batch-B', exact: true }).check();
  assert.equal(await pageC.locator('#pending select').count(), 0);
  assert.match(await pageC.locator('#editor .consent').innerText(), /目录外文件/);
  assert.equal((await storeC.load()).config.terminalGrants?.length || 0, 0);
  await pageC.route('**/api/shares/confirm', async route => {
    const body = route.request().postDataJSON();
    assert.equal(body.confirmation, 'allow-project-files-and-terminal-v1');
    const rejected = await post(appC.origin + '/api/shares/confirm', { ...body, confirmation: 'allow-shared-folders-v1' }, { Origin: appC.origin, 'X-Chat2Local-Token': appC.token });
    assert.equal(rejected.status, 403, 'A former file-only consent cannot approve a complete project');
    assert.equal((await storeC.load()).config.terminalGrants?.length || 0, 0);
    await route.continue();
  });
  assert.equal((await ok('list_roots', { deviceId: identityC.deviceId })).length, 2);
  await pageC.screenshot({ path: '.artifacts/folder-management-batch.png', fullPage: true });
  // One labelled decision covers the visibly selected batch. The UI verifies
  // prepared paths/modes match this exact decision before sending one consent.
  await pageC.locator('#prepare').click(); await pageC.locator('#done').waitFor({ state: 'visible' });
  assert.equal(managementConfirms, 1); assert.equal(installerCalls, 0);
  assert.equal(await pageC.locator('input[type=password]').count(), 0);
  const managed = await ok('list_roots', { deviceId: identityC.deviceId });
  assert.equal(managed.length, 4);
  assert.ok(managed.some(r => r.id === rootC.id));
  const writable = managed.find(r => r.label === 'Batch-A'), second = managed.find(r => r.label === 'Batch-B');
  assert.equal(writable.writeMode, 'direct'); assert.equal(second.writeMode, 'direct');
  for (const root of [writable, second]) {
    assert.equal(root.terminalLocalEnabled, true);
    assert.equal(root.terminalScopeGranted, false);
    assert.equal(root.terminalAllowed, false, 'Complete local consent does not enlarge an old OAuth token');
  }
  assert.equal((await storeC.load()).config.terminalGrants.length, 2);
  assert.equal(managed.find(r => r.id === rootC.id).terminalLocalEnabled, false, 'Existing file-only roots were not upgraded');
  const batchArgs = { deviceId: identityC.deviceId, rootId: writable.id, path: 'batch.txt' };
  assert.equal((await ok('write_file', { ...batchArgs, content: 'One batch consent', expectedHash: null })).status, 'written');
  assert.equal((await ok('read_file', batchArgs)).content, 'One batch consent');
  assert.equal((await call('terminal_execute', { deviceId: identityC.deviceId, rootId: writable.id, requestId: '11111111-1111-4111-8111-111111111111', command: 'must-not-execute' })).isError, true);
  assert.deepEqual((await storeC.load()).secrets.identity, retainedIdentityC);
  assert.equal((await data(await owner('connections'))).connections.length, 1);
  assert.equal(await pageC.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  await pageC.screenshot({ path: '.artifacts/folder-management-complete.png', fullPage: true });
  // Revoke one live shared folder through the native UI API. The SAME old
  // token must immediately lose file access; unrelated shares and files stay.
  const removePost = (action, body) => post(appC.origin + '/api/shares/' + action, body, { Origin: appC.origin, 'X-Chat2Local-Token': appC.token });
  assert.equal((await post(appC.origin + '/api/shares/remove-prepare', { connectionId: originalConnection, rootId: writable.id }, { Origin: appC.origin })).status, 401);
  const removal = await data(await removePost('remove-prepare', { connectionId: originalConnection, rootId: writable.id }));
  assert.equal((await ok('list_roots', { deviceId: identityC.deviceId })).length, 4);
  const removed = await data(await removePost('remove-confirm', { requestId: removal.requestId, snapshotDigest: removal.snapshotDigest, confirmation: 'remove-shares-keep-files-v1' }));
  assert.equal(removed.localRevoked, true); assert.equal(removed.cloudSynced, true);
  assert.equal((await call('read_file', batchArgs)).isError, true);
  assert.equal((await call('write_file', { ...batchArgs, content: 'forbidden', expectedHash: null })).isError, true);
  assert.equal((await ok('list_roots', { deviceId: identityC.deviceId })).length, 3);
  assert.equal(await fs.readFile(path.join(batchA, 'batch.txt'), 'utf8'), 'One batch consent');
  assert.equal((await storeC.load()).config.terminalGrants?.some(g => g.rootId === writable.id) || false, false);
  assert.equal((await ok('read_file', cArgs)).content, 'Old computers are offline');
  // The original browser can renew the SAME client/resource/scope without a
  // second folder picker or private-instance consent. No Google cookie involved.
  const renewedQuery = new URLSearchParams(query); renewedQuery.set('state', secret()); renewedQuery.set('scope', 'files:read');
  const renewal = await contextA.request.get(origin + '/authorize?' + renewedQuery, { maxRedirects: 0 });
  assert.equal(renewal.status(), 303);
  assert.ok(renewal.headers().location.startsWith(callback + '?'));
  assert.equal(new URL(renewal.headers().location).searchParams.get('state'), renewedQuery.get('state'));
  assert.equal(picksA, 1); assert.equal(confirmationsA, 1); assert.equal(forbiddenRequests, 0);
});
