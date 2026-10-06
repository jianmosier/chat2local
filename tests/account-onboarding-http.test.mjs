import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import http from 'node:http';
import path from 'node:path';
import { createHash, randomBytes, generateKeyPairSync, sign } from 'node:crypto';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { chromium } from 'playwright-core';
import { startController } from '../src/agent/main.mjs';
import { Store } from '../src/agent/store.mjs';

const secret = () => randomBytes(32).toString('hex');
const data = async (response, status = 200) => { assert.equal(response.status, status, await response.clone().text()); return response.json(); };
async function until(fn) { const deadline = Date.now() + 12000; while (Date.now() < deadline) { if (await fn()) return; await new Promise(r => setTimeout(r, 60)); } throw new Error('Timed out waiting for fixture.'); }

test('complete account HTTP flow: signed OIDC login -> real local selection/journal -> ONE approval -> original OAuth code -> scoped MCP write', { timeout: 120000 }, async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-account-http-')), folder = path.join(base, 'selected-folder');
  await fs.mkdir(folder);
  const keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicKey = { ...keyPair.publicKey.export({ format: 'jwk' }), kid: 'isolated-idp', alg: 'RS256', use: 'sig' };
  const idp = 'https://identity.example.test', idpClient = 'fixture-oidc-client', codes = new Map();
  let identityExchanges = 0, pickerCalls = 0, cloudConfirmations = 0, cloudActivations = 0, lostCloudActivation = false;
  const store = new Store(path.join(base, 'private'));
  let app = await startController({ port: 0, store, allowLocalRelay: true, pickFolder: async () => { pickerCalls++; return folder; }, accountFetch: async (url, options) => {
    if (url.endsWith('/confirm')) cloudConfirmations++;
    if (url.endsWith('/activate')) cloudActivations++;
    const response = await fetch(url, options);
    if (url.endsWith('/activate') && response.ok && !lostCloudActivation) { lostCloudActivation = true; await response.text(); throw new Error('Injected loss AFTER cloud activation'); }
    return response;
  } });
  t.after(async () => { await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  const bundle = await build({ entryPoints: ['src/relay/worker.mjs'], bundle: true, write: false, format: 'esm', platform: 'neutral', mainFields: ['module','main'], external: ['cloudflare:workers'] });
  const enrollmentKey = secret();
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundle.outputFiles[0].text, host: '127.0.0.1', port: 0, compatibilityDate: '2026-09-20', compatibilityFlags: ['nodejs_compat','global_fetch_strictly_public'],
    kvNamespaces: ['OAUTH_KV'], durableObjects: { DEVICES: { className: 'Device', useSQLite: true }, REGISTRY: { className: 'Registry', useSQLite: true } },
    bindings: { ALLOW_LOOPBACK: 'true', ENROLLMENT_KEY: enrollmentKey, ACCOUNT_CONNECTIONS: 'true', ACCOUNT_ENROLLMENT: 'true', TEST_RECOVERY_ORIGIN: app.origin,
      OIDC_ISSUER: idp, OIDC_CLIENT_ID: idpClient, OIDC_AUTHORIZATION_ENDPOINT: idp + '/authorize', OIDC_TOKEN_ENDPOINT: idp + '/token', OIDC_JWKS_URI: idp + '/keys' },
    serviceBindings: { TEST_IDENTITY_HTTP: async request => {
      const url = new URL(request.url);
      if (url.href === idp + '/keys') return Response.json({ keys: [publicKey] });
      assert.equal(url.href, idp + '/token'); assert.equal(request.method, 'POST');
      const form = new URLSearchParams(await request.text()), record = codes.get(form.get('code'));
      assert.ok(record, 'Only an issued code is accepted'); codes.delete(form.get('code'));
      assert.equal(form.get('client_id'), idpClient); assert.equal(form.get('redirect_uri'), record.redirect);
      assert.equal(createHash('sha256').update(form.get('code_verifier')).digest('base64url'), record.challenge);
      identityExchanges++;
      const now = Math.floor(Date.now() / 1000);
      const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid: publicKey.kid })).toString('base64url');
      const p = Buffer.from(JSON.stringify({ iss: idp, sub: 'same-test-owner', aud: idpClient, nonce: record.nonce, iat: now, exp: now + 300, name: 'Isolated signed identity' })).toString('base64url');
      return Response.json({ id_token: h + '.' + p + '.' + sign('RSA-SHA256', Buffer.from(h + '.' + p), keyPair.privateKey).toString('base64url'), token_type: 'Bearer', access_token: 'upstream-token-not-for-native' });
    } },
  }));
  t.after(() => mf.dispose());
  const origin = (await mf.ready).origin;
  const local = (route, body) => fetch(app.origin + '/api/' + route, { method: body === undefined ? 'GET' : 'POST', headers: { 'X-Chat2Local-Token': app.token, Origin: app.origin, 'Content-Type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  await data(await local('enroll', { origin, enrollmentToken: enrollmentKey }));
  await until(() => app.bridge.state === 'connected');
  const before = await store.load();
  const callbackServer = http.createServer((_request, response) => { response.writeHead(200, { 'Content-Type': 'text/plain' }); response.end('Original client callback reached'); });
  await new Promise(resolve => callbackServer.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { callbackServer.close(resolve); callbackServer.closeIdleConnections(); }));
  const callback = `http://127.0.0.1:${callbackServer.address().port}/callback`;
  const client = await data(await fetch(origin + '/oauth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client_name: 'Original test client', redirect_uris: [callback], token_endpoint_auth_method: 'none', grant_types: ['authorization_code','refresh_token'], response_types: ['code'] }) }), 201);
  const verifier = secret(), state = secret();
  const query = new URLSearchParams({ client_id: client.client_id, redirect_uri: callback, response_type: 'code', scope: 'files:read files:write offline_access', state, code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url'), resource: origin + '/mcp' });
  const browser = await chromium.launch({ channel: 'msedge', headless: true }); t.after(() => browser.close());
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } }), page = await context.newPage();
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  const signedLogin = async route => {
    const url = new URL(route.request().url()), q = url.searchParams, code = secret();
    assert.equal(q.get('client_id'), idpClient); assert.equal(q.get('response_type'), 'code'); assert.equal(q.get('code_challenge_method'), 'S256');
    codes.set(code, { redirect: q.get('redirect_uri'), challenge: q.get('code_challenge'), nonce: q.get('nonce') });
    await route.fulfill({ status: 303, headers: { Location: q.get('redirect_uri') + '?' + new URLSearchParams({ code, state: q.get('state'), iss: idp }) } });
  };
  await context.route(idp + '/authorize*', signedLogin);
  const trace = [];
  page.on('response', response => trace.push([new URL(response.url()).pathname, response.status()]));
  page.on('requestfailed', request => trace.push([new URL(request.url()).pathname, request.failure()?.errorText]));
  // Route the fixture IdP as a navigation entry: Playwright does not consistently
  // intercept a redirected HTTPS request under this host's system proxy. The
  // original OAuth GET and Set-Cookie are still handled by the real Worker in
  // this browser context; no account claim/session is inserted by the test.
  const beginning = await context.request.get(origin + '/authorize?' + query, { maxRedirects: 0 });
  assert.equal(beginning.status(), 303);
  await page.goto(beginning.headers().location).catch(error => { throw new Error(JSON.stringify(trace) + ' ' + error.message); });
  await page.waitForFunction(() => !document.querySelector('#account-choose')?.disabled && document.querySelector('#account-summary')?.hidden === false);
  assert.equal(identityExchanges, 1); assert.equal(new URL(page.url()).origin, app.origin); assert.equal(new URL(page.url()).hash, '');
  assert.equal(await page.evaluate(() => sessionStorage.getItem('chat2local-control')), null);
  assert.notEqual(await page.locator('#account-nonce').inputValue(), app.token);
  assert.equal(await page.locator('#account-confirm').isHidden(), true);
  assert.deepEqual((await store.load()).config, before.config); assert.deepEqual((await store.load()).secrets, before.secrets);
  // Genuine file-picker result is stubbed here; actual path checks, persistence,
  // identity signatures, HTTP/OAuth, WebSocket and file operations are NOT stubbed.
  await page.locator('#account-choose').click();
  await page.locator('#account-confirm').waitFor({ state: 'visible' });
  assert.equal(pickerCalls, 1); assert.equal(cloudConfirmations, 0); assert.equal(cloudActivations, 0);
  assert.equal((await fetch(origin + '/onboarding/start', { method: 'POST', body: '{}' })).status, 404);
  assert.equal((await fetch(origin + '/account/native/status', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ flowId: 'a'.repeat(32), deviceId: 'b'.repeat(32), secret: 'c'.repeat(64), input: {} }) })).status, 401);
  assert.match(await page.locator('#account-name').textContent(), /Isolated signed identity/);
  assert.equal(await page.locator('input[type=password]').count(), 0); assert.equal(context.pages().length, 1);
  assert.deepEqual((await store.load()).config, before.config);
  const bootstrap = await page.evaluate(() => JSON.parse(sessionStorage.getItem('chat2local-account-flow')));
  const flowId = bootstrap.flow.split('.')[0], nonce = await page.locator('#account-nonce').inputValue();
  const bad = await fetch(app.origin + '/account-connect/confirm', { method: 'POST', headers: { Origin: 'https://attacker.example', 'Content-Type': 'application/json' }, body: JSON.stringify({ nonce, flowId, snapshotDigest: 'a'.repeat(64), confirmation: 'allow-shared-folders-v1' }) }); assert.equal(bad.status, 403);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  await fs.mkdir('.artifacts', { recursive: true });
  await page.screenshot({ path: '.artifacts/account-http-one-consent.png', fullPage: true });
  let approvalRequests = 0;
  await page.route('**/account-connect/confirm', async route => { approvalRequests++; await route.fetch(); await route.abort('failed'); });
  await page.locator('#account-confirm').click();
  await page.waitForURL(callback + '*', { timeout: 30000 });
  assert.equal(approvalRequests, 1); assert.equal(cloudConfirmations, 1); assert.equal(cloudActivations, 1); assert.equal(context.pages().length, 1);
  const returned = new URL(page.url()); assert.equal(returned.searchParams.get('state'), state);
  const tokens = await data(await fetch(origin + '/oauth/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: client.client_id, redirect_uri: callback, code: returned.searchParams.get('code'), code_verifier: verifier, resource: origin + '/mcp' }) }));
  const after = await store.load(); assert.deepEqual(after.config.roots, before.config.roots); assert.deepEqual(after.secrets, before.secrets); assert.equal(after.config.accountRoots.length, 1);
  const journal = await store.readPrivateRecord('onboarding-intent-' + flowId); assert.equal(journal.confirmations, 1); assert.equal(journal.phase, 'connected');
  const raw = await fs.readFile(store.privateRecordPath('onboarding-flow-' + flowId), 'utf8');
  assert.doesNotMatch(raw, /upstream-token-not-for-native|Isolated signed identity/);
  const call = async (name, args = {}) => (await data(await fetch(origin + '/mcp', { method: 'POST', headers: { Authorization: 'Bearer ' + tokens.access_token, 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: secret(), method: 'tools/call', params: { name, arguments: args } }) }))).result;
  const roots = await call('list_roots'); assert.equal(roots.isError, false, roots.content[0].text);
  const root = JSON.parse(roots.content[0].text)[0]; assert.equal(root.id, after.config.accountRoots[0].id);
  const write = await call('write_file', { rootId: root.id, path: 'one-confirmation.txt', content: 'Real scoped write after one app approval\n', expectedHash: null });
  assert.equal(write.isError, false, write.content[0].text); assert.equal(JSON.parse(write.content[0].text).status, 'written');
  const read = await call('read_file', { rootId: root.id, path: 'one-confirmation.txt' }); assert.equal(JSON.parse(read.content[0].text).content, 'Real scoped write after one app approval\n');
  assert.deepEqual(errors, []);

  // A SECOND browser/computer has no device credentials and no browser account
  // cookie. It signs into the same issuer/sub, enrolls independently, then adds
  // its selected root to the SAME OAuth reference without token exchange.
  const secondFolder = path.join(base, 'second-selected-folder'); await fs.mkdir(secondFolder);
  const secondStore = new Store(path.join(base, 'second-private'));
  let secondPickerCalls = 0, secondApprovals = 0, enrollmentRequests = 0;
  const second = await startController({ port: 0, store: secondStore, defaultRelay: origin, allowLocalRelay: true,
    pickFolder: async () => { secondPickerCalls++; return secondFolder; },
    accountFetch: async (url, options) => {
      if (url.endsWith('/enroll')) enrollmentRequests++;
      const response = await fetch(url, options);
      if (url.endsWith('/enroll') && enrollmentRequests === 1 && response.ok) { await response.text(); throw new Error('Injected loss AFTER independent device enrollment'); }
      return response;
    } });
  t.after(() => second.close());
  const secondContext = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const secondPage = await secondContext.newPage();
  // Two physical computers each use localhost:47631. In this single-host test,
  // drive the real callback/add GETs in the second browser's cookie jar, then
  // translate ONLY the final native port. This avoids relying on redirect-chain
  // interception under the development host's proxy. Login UI is the fixture;
  // JWT verification, sessions, native enrollment and consent remain real code.
  await secondContext.route(idp + '/authorize*', async route => {
    const q = new URL(route.request().url()).searchParams, code = secret();
    assert.equal(q.get('client_id'), idpClient); assert.equal(q.get('code_challenge_method'), 'S256');
    codes.set(code, { redirect: q.get('redirect_uri'), challenge: q.get('code_challenge'), nonce: q.get('nonce') });
    const callbackResponse = await secondContext.request.get(q.get('redirect_uri') + '?' + new URLSearchParams({ code, state: q.get('state'), iss: idp }), { maxRedirects: 0 });
    assert.equal(callbackResponse.status(), 303);
    const addResponse = await secondContext.request.get(callbackResponse.headers().location, { maxRedirects: 0 });
    assert.equal(addResponse.status(), 303);
    const location = new URL(addResponse.headers().location);
    assert.equal(location.origin, app.origin); assert.equal(location.pathname, '/account-connect');
    location.host = new URL(second.origin).host;
    await route.fulfill({ status: 303, headers: { Location: location.href } });
  });
  const join = await secondContext.request.get(origin + '/account/add', { maxRedirects: 0 });
  assert.equal(join.status(), 303);
  await secondPage.goto(join.headers().location);
  await secondPage.waitForFunction(() => !document.querySelector('#account-choose')?.disabled && document.querySelector('#account-summary')?.hidden === false);
  assert.equal(identityExchanges, 2); assert.equal(enrollmentRequests, 2, 'Same registration retried after a lost response, not a second identity');
  const secondIdentity = (await secondStore.load()).secrets.identity;
  assert.ok(secondIdentity?.deviceId); assert.notEqual(secondIdentity.deviceId, before.secrets.identity.deviceId);
  assert.notEqual(secondIdentity.deviceKey, before.secrets.identity.deviceKey);
  const beforeJoin = JSON.parse((await call('list_devices')).content[0].text);
  assert.equal(beforeJoin.devices.length, 1, 'Account sign-in/device registration alone exposes no extra computer');
  await secondPage.locator('#account-choose').click();
  await secondPage.locator('#account-confirm').waitFor({ state: 'visible' });
  assert.equal((await secondStore.load()).config.accountRoots, undefined);
  secondPage.on('request', request => { if (new URL(request.url()).pathname === '/account-connect/confirm') secondApprovals++; });
  let extraTokenExchanges = 0;
  secondPage.on('request', request => { if (new URL(request.url()).pathname === '/oauth/token') extraTokenExchanges++; });
  await secondPage.locator('#account-confirm').click();
  await secondPage.waitForURL(origin + '/account/finish?*');
  await secondPage.getByRole('heading', { name: '已加入原来的 chat2local', exact: true }).waitFor();
  assert.equal(secondApprovals, 1); assert.equal(secondPickerCalls, 1); assert.equal(extraTokenExchanges, 0); assert.equal(secondContext.pages().length, 1);
  await until(() => second.bridge.state === 'connected');
  const joined = JSON.parse((await call('list_devices')).content[0].text);
  assert.equal(joined.devices.length, 2); assert.equal(joined.selectionRequired, true);
  const secondRoots = JSON.parse((await call('list_roots', { deviceId: secondIdentity.deviceId })).content[0].text);
  assert.equal(secondRoots.length, 1);
  const secondWrite = await call('write_file', { deviceId: secondIdentity.deviceId, rootId: secondRoots[0].id, path: 'one-confirmation.txt', content: 'Second computer, original plugin token\n', expectedHash: null });
  assert.equal(JSON.parse(secondWrite.content[0].text).status, 'written');
  assert.equal(await fs.readFile(path.join(secondFolder, 'one-confirmation.txt'), 'utf8'), 'Second computer, original plugin token\n');
  assert.equal(await fs.readFile(path.join(folder, 'one-confirmation.txt'), 'utf8'), 'Real scoped write after one app approval\n');
  assert.equal((await call('read_file', { deviceId: secondIdentity.deviceId, rootId: root.id, path: 'one-confirmation.txt' })).isError, true);
  assert.equal((await call('list_roots')).isError, true, 'Multiple devices require an explicit target');
  const originalDeviceId = before.secrets.identity.deviceId;
  // Restart the real agent, not the browser component: persisted accountRoots
  // remain accessible through the SAME OAuth token without another confirmation.
  await app.close();
  app = await startController({ port: 0, store, allowLocalRelay: true, pickFolder: async () => { pickerCalls++; return folder; } });
  await until(() => app.bridge.state === 'connected');
  const retained = await call('read_file', { deviceId: originalDeviceId, rootId: root.id, path: 'one-confirmation.txt' });
  assert.equal(retained.isError, false, retained.content[0].text);
  assert.equal(pickerCalls, 1); assert.equal(cloudConfirmations, 1); assert.equal(cloudActivations, 1);
  // Ordinary local management has an actual revoke control, not just an API.
  await page.goto(app.origin + '/manage#' + app.token);
  await page.getByRole('button', { name: '撤销本机共享', exact: true }).click();
  await page.waitForFunction(() => document.getElementById('message').textContent.includes('已撤销'));
  assert.equal((await store.load()).config.accountRoots.length, 0);
  const denied = await call('read_file', { deviceId: originalDeviceId, rootId: root.id, path: 'one-confirmation.txt' }); assert.equal(denied.isError, true);
  assert.equal(await fs.readFile(path.join(folder, 'one-confirmation.txt'), 'utf8'), 'Real scoped write after one app approval\n');
  assert.equal((await store.readPrivateRecord('onboarding-intent-' + flowId)).confirmations, 1);
  // Reauthentication is deliberately LAST: the OAuth library replaces a previous
  // same-client/account grant. Device joining ABOVE used the unchanged original
  // token, whereas a new authorization request may invalidate it normally.
  const reauth = new URLSearchParams(query); reauth.set('state', secret());
  const remembered = await context.request.get(origin + '/authorize?' + reauth, { maxRedirects: 0 });
  assert.equal(remembered.status(), 303); assert.ok(remembered.headers().location.startsWith(callback));
  assert.equal(pickerCalls, 1); assert.equal(cloudConfirmations, 1);
});
