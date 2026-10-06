import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomBytes, createHash } from 'node:crypto';
import { chromium } from 'playwright-core';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { startController } from '../src/agent/main.mjs';
import { chooseFolder } from './choose-folder-helper.mjs';
import { SetupManager } from '../src/agent/setup.mjs';
import { Store } from '../src/agent/store.mjs';
import { installPage, setupAvailability, oauthCallbackOrigin } from '../src/shared/setup.mjs';

const secret = () => randomBytes(32).toString('hex');
const installUrl = 'https://chatgpt.com/plugins/chat2local-test-fixture'; // intercepted, NOT a real listing
const jsonRequest = (url, value, headers = {}) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(value), redirect: 'manual' });
async function value(response, status = 200) { assert.equal(response.status, status); return response.json(); }

test('validated callback CSP sources cannot inject policy directives', () => {
  assert.equal(oauthCallbackOrigin('https://chatgpt.com/callback'), 'https://chatgpt.com');
  assert.equal(oauthCallbackOrigin('http://127.0.0.1:54329/callback'), 'http://127.0.0.1:54329');
  for (const url of ['https://evil.com;script-src/callback', 'https://user@evil.com/callback', 'javascript:alert(1)', 'data:text/html,x']) assert.throws(() => oauthCallbackOrigin(url));
});

test('publication is a hard gate, not a fake automatic ChatGPT install link', () => {
  for (const url of ['', 'https://attacker.invalid/plugins/x', 'https://chatgpt.com/', 'https://user@chatgpt.com/plugins/x', 'https://chatgpt.com/plugins/x?token=a']) assert.equal(installPage(url), null);
  assert.equal(setupAvailability({ selfService: true }).code, 'PUBLICATION_REQUIRED');
  assert.equal(setupAvailability({ installUrl, selfService: false }).code, 'REGISTRATION_CLOSED');
  assert.equal(setupAvailability({ installUrl, alreadyEnrolled: true }).ready, true);
});

test('unpublished service never enrolls, opens a fake page, or asks users for credentials', async () => {
  let calls = 0;
  const manager = new SetupManager({ defaultRelay: 'https://relay.example.test', identity: () => undefined, prepareNetwork: async () => {}, fetch: async url => { calls++; assert.ok(url.endsWith('/setup-info')); return Response.json({ name: 'chat2local-relay', setupVersion: 1, browserHandoff: true, selfService: true, installUrl: null }); }, openBrowser: () => assert.fail('must not open') });
  assert.equal((await manager.start()).code, 'PUBLICATION_REQUIRED'); assert.equal(calls, 1);
});

test('uncertain registration keeps one identity for an explicit retry, without task replay', async () => {
  let pending; let identity; let lost = true; const ids = []; const opened = [];
  const manager = new SetupManager({ defaultRelay: 'https://relay.example.test', identity: () => identity, pending: () => pending, prepareNetwork: async () => {}, savePending: async next => { pending = next; }, acceptIdentity: async next => { identity = next; pending = undefined; }, bridge: { state: 'connected' }, openBrowser: async url => opened.push(url), fetch: async (url, options) => {
    if (url.endsWith('/setup-info')) return Response.json({ name: 'chat2local-relay', setupVersion: 1, browserHandoff: true, selfService: true, installUrl });
    if (url.endsWith('/enroll-device')) { ids.push(JSON.parse(options.body).deviceId); if (lost) { lost = false; throw new Error('Synthetic lost response'); } return Response.json({ ok: true }); }
    if (url.endsWith('/browser-handoff')) return Response.json({ secret: secret(), expiresAt: Date.now() + 300000 });
    assert.fail('Unexpected request');
  } });
  await assert.rejects(() => manager.start(), /lost response/); assert.ok(pending); assert.equal(identity, undefined);
  assert.equal((await manager.start()).ok, true); assert.equal(ids.length, 2); assert.equal(ids[0], ids[1]); assert.equal(pending, undefined); assert.equal(opened.length, 1);
});

test('simple home identifies an old relay explicitly rather than asking for codes or publication', async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-home-')); const folder = path.join(base, 'sample'); await fs.mkdir(folder);
  const app = await startController({ port: 0, defaultRelay: 'https://relay.example.test', stateDir: path.join(base, 'private'), pickFolder: async () => folder, setupFetch: async () => new Response(null, { status: 404 }), networkOptions: { env: {}, systemProxy: async () => ({ proxy: '' }) } });
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  t.after(async () => { await browser.close(); await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  const page = await browser.newPage(); await page.goto(`${app.origin}/manage#${app.token}`);
  await page.waitForFunction(() => document.querySelector('#localState').textContent.includes('正在运行'));
  assert.equal(new URL(page.url()).hash, '');
  assert.equal(await page.locator('input[type=password]').count(), 0); assert.equal(await page.locator('#writePermission').count(), 0);
  assert.equal(await page.locator('#connectChatGPT').isDisabled(), true);
  await chooseFolder(page, folder);
  await page.waitForFunction(() => document.querySelector('#message').textContent.includes('旧版本'));
  assert.match(await page.locator('#message').textContent(), /目录授权已保存/);
  assert.equal(await page.locator('#publication').isVisible(), false);
  assert.equal(await page.locator('#connectChatGPT').isDisabled(), false);
  assert.match(await page.locator('#message').textContent(), /维护者/);
  assert.equal((await new Store(path.join(base, 'private')).load()).secrets.identity, undefined);
  await fs.mkdir('.artifacts', { recursive: true }); await page.screenshot({ path: '.artifacts/simple-home.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 }); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
});

test('single folder consent -> browser binding -> OAuth -> actual direct write and reviewed proposal', { timeout: 90000 }, async t => {
  const bundle = await build({ entryPoints: ['src/relay/worker.mjs'], bundle: true, write: false, format: 'esm', platform: 'neutral', mainFields: ['module', 'main'], external: ['cloudflare:workers'] });
  const enrollmentKey = secret();
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundle.outputFiles[0].text, compatibilityDate: '2026-09-20', compatibilityFlags: ['nodejs_compat', 'global_fetch_strictly_public'], host: '127.0.0.1', port: 0, kvNamespaces: ['OAUTH_KV'], durableObjects: { DEVICES: { className: 'Device', useSQLite: true }, REGISTRY: { className: 'Registry', useSQLite: true } }, bindings: { ALLOW_LOOPBACK: 'true', SELF_SERVICE_ENROLLMENT: 'true', SELF_SERVICE_DEVICE_LIMIT: '10', ENROLLMENT_KEY: enrollmentKey, CHATGPT_INSTALL_URL: installUrl } }));
  const origin = (await mf.ready).origin;
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-simple-e2e-'));
  const folder = path.join(base, 'sample'); await fs.mkdir(folder); await fs.writeFile(path.join(folder, 'test.txt'), 'Before.');
  const opened = [];
  const app = await startController({ port: 0, stateDir: path.join(base, 'private'), defaultRelay: origin, allowLocalRelay: true, pickFolder: async () => folder, openBrowser: async url => opened.push(url) });
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  t.after(async () => { await browser.close(); await app.close(); await mf.dispose(); await fs.rm(base, { recursive: true, force: true }); });
  const context = await browser.newContext();
  await context.route(installUrl, route => route.fulfill({ status: 200, contentType: 'text/plain', body: 'Synthetic official-directory navigation test. Not real ChatGPT.' }));
  const page = await context.newPage(); await page.goto(`${app.origin}/manage#${app.token}`);
  const local = (route, body) => fetch(`${app.origin}/api/${route}`, { method: body === undefined ? 'GET' : 'POST', headers: { 'X-Chat2Local-Token': app.token, Origin: app.origin, 'Content-Type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  let identity; let authPage; let handoff; let tokens; let rootId;
  await t.test('self-service cannot be used until the operator enables and publishes it', async () => {
    const closed = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundle.outputFiles[0].text, compatibilityDate: '2026-09-20', compatibilityFlags: ['global_fetch_strictly_public'], host: '127.0.0.1', port: 0, kvNamespaces: ['OAUTH_KV'], durableObjects: { DEVICES: { className: 'Device', useSQLite: true }, REGISTRY: { className: 'Registry', useSQLite: true } }, bindings: { ALLOW_LOOPBACK: 'true', ENROLLMENT_KEY: enrollmentKey } }));
    try {
      const unavailableOrigin = (await closed.ready).origin;
      const info = await value(await fetch(`${unavailableOrigin}/setup-info`)); assert.equal(info.installUrl, null); assert.equal(info.selfService, false);
      assert.equal((await jsonRequest(`${unavailableOrigin}/enroll-device`, { deviceId: randomBytes(16).toString('hex'), deviceKey: secret() })).status, 503);
    } finally { await closed.dispose(); }
  });
  await t.test('one labelled folder consent automatically starts setup without a separate connect click', async () => {
    await page.waitForFunction(() => document.querySelector('#localState').textContent.includes('正在运行'));
    await chooseFolder(page, folder);
    await page.waitForFunction(() => document.querySelector('#message').textContent.includes('已打开本机配对确认页'));
    assert.equal(await page.getByRole('combobox', { name: 'sample 目录权限' }).inputValue(), 'direct');
    assert.equal(opened.length, 1); handoff = opened[0]; assert.match(new URL(handoff).hash, /^#[a-f0-9]{32}\.[a-f0-9]{64}$/);
    const stored = await new Store(path.join(base, 'private')).load(); identity = stored.secrets.identity;
    assert.ok(identity); assert.equal(stored.secrets.enrollmentPending, undefined); assert.equal(JSON.stringify(stored).includes(enrollmentKey), false);
    const status = await value(await local('status')); assert.equal(status.lastRemoteCallAt, null); rootId = status.roots[0].id;
    assert.equal(JSON.stringify(status).includes(identity.deviceKey), false);
  });
  await t.test('registration retry is idempotent, never replacing an existing device secret', async () => {
    const body = { deviceId: identity.deviceId, deviceKey: identity.deviceKey };
    assert.equal((await jsonRequest(`${origin}/enroll-device`, body)).status, 200);
    assert.equal((await jsonRequest(`${origin}/enroll-device`, { ...body, deviceKey: secret() })).status, 409);
  });
  await t.test('browser binding needs same-origin explicit consent and consumes the handoff once', async () => {
    const proof = new URL(handoff).hash.slice(1);
    assert.equal((await jsonRequest(`${origin}/link/confirm`, { proof, csrf: secret() }, { Origin: origin })).status, 403);
    assert.equal((await jsonRequest(`${origin}/link/inspect`, { proof }, { Origin: 'https://attacker.invalid' })).status, 403);
    authPage = await context.newPage(); await authPage.goto(handoff);
    await authPage.waitForFunction(() => !document.querySelector('#continue').disabled);
    assert.equal(new URL(authPage.url()).hash, '');
    await authPage.locator('#continue').click(); await authPage.waitForURL(installUrl);
    assert.ok((await context.cookies(origin)).some(item => item.name === 'c2l_browser' && item.httpOnly));
    assert.equal((await jsonRequest(`${origin}/link/inspect`, { proof }, { Origin: origin })).status, 403);
  });
  await t.test('OAuth identifies the same browser without any copied pairing code', async () => {
    const callback = 'http://127.0.0.1:54329/callback';
    await context.route(`${callback}*`, route => route.fulfill({ body: 'Synthetic OAuth callback', contentType: 'text/plain' }));
    const client = await value(await jsonRequest(`${origin}/oauth/register`, { client_name: 'Synthetic MCP client', redirect_uris: [callback], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] }), 201);
    const verifier = secret();
    const query = new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: callback, scope: 'files:read files:propose files:write', state: secret(), code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url'), resource: `${origin}/mcp` });
    const authResponse = await authPage.goto(`${origin}/authorize?${query}`);
    assert.match(authResponse.headers()['content-security-policy'], /form-action 'self' http:\/\/127\.0\.0\.1:54329/);
    assert.equal(authResponse.headers()['referrer-policy'], 'same-origin');
    assert.equal(await authPage.locator('input[name=pair]').count(), 0);
    assert.equal(await authPage.locator('input[name=source]').inputValue(), 'browser');
    const ticket = await authPage.locator('input[name=ticket]').inputValue();
    const cookies = await context.cookies(`${origin}/authorize`);
    const withoutDevice = cookies.filter(item => item.name !== 'c2l_browser').map(item => `${item.name}=${item.value}`).join('; ');
    const spoof = await fetch(`${origin}/authorize`, { method: 'POST', headers: { Origin: origin, Cookie: withoutDevice, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ ticket, source: 'browser' }), redirect: 'manual' });
    assert.equal(spoof.status, 403); // CSRF ticket alone cannot authorize another browser.
    assert.equal(await authPage.locator('#approve').textContent(), '允许读写并继续');
    assert.equal(await authPage.locator('input[name=directWrite]').isChecked(), true);
    await authPage.getByText('其他权限选项', { exact: true }).click();
    await authPage.locator('input[name=propose]').check();
    const observations = [];
    authPage.on('request', request => observations.push({ type: 'request', path: new URL(request.url()).pathname, method: request.method(), origin: request.headers()['origin'] }));
    authPage.on('response', response => observations.push({ type: 'response', path: new URL(response.url()).pathname, status: response.status() }));
    authPage.on('requestfailed', request => observations.push({ type: 'failed', path: new URL(request.url()).pathname, reason: request.failure()?.errorText }));
    const posted = authPage.waitForResponse(response => new URL(response.url()).pathname === '/authorize' && response.request().method() === 'POST', { timeout: 7000 });
    await authPage.locator('#approve').click();
    const consentResponse = await posted.catch(() => assert.fail(JSON.stringify(observations)));
    assert.equal(consentResponse.request().headers()['origin'], origin, 'Browser form must preserve its actual same-origin Origin header.');
    assert.equal(consentResponse.status(), 303, consentResponse.status() === 303 ? '' : await consentResponse.text());
    await authPage.waitForURL(`${callback}*`, { timeout: 5000 });
    const code = new URL(authPage.url()).searchParams.get('code'); assert.ok(code);
    const response = await fetch(`${origin}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: client.client_id, redirect_uri: callback, code, code_verifier: verifier, resource: `${origin}/mcp` }) }); tokens = await value(response); assert.ok(tokens.access_token);
  });
  const call = async (name, args = {}) => { const response = await jsonRequest(`${origin}/mcp`, { jsonrpc: '2.0', id: secret(), method: 'tools/call', params: { name, arguments: args } }, { Authorization: `Bearer ${tokens.access_token}` }); return (await value(response)).result; };
  await t.test('direct write crosses the relay with explicit OAuth scope and reads back without a local approval', async () => {
    const roots = JSON.parse((await call('list_roots')).content[0].text);
    assert.equal(roots[0].directWriteAllowed, true);
    const written = await call('write_file', { rootId, path: 'direct.txt', content: 'One folder consent; explicit OAuth; direct write.', expectedHash: null });
    assert.equal(written.isError, false); assert.equal(JSON.parse(written.content[0].text).status, 'written');
    const read = JSON.parse((await call('read_file', { rootId, path: 'direct.txt' })).content[0].text);
    assert.equal(read.content, await fs.readFile(path.join(folder, 'direct.txt'), 'utf8'));
    assert.equal((await value(await local('status'))).pending.length, 0);
    // Adding a second directory after real remote use must not start pairing again.
    const extra = path.join(base, 'extra'); await fs.mkdir(extra);
    await page.reload(); await page.waitForFunction(() => document.querySelector('#setupActions').hidden);
    await chooseFolder(page, extra); assert.equal(opened.length, 1);
  });
  await t.test('real remote proposal still waits for a local approval click and reads back correctly', async () => {
    const read = await call('read_file', { rootId, path: 'test.txt' }); assert.equal(read.isError, false);
    const proposed = await call('propose_write', { rootId, path: 'test.txt', content: 'After approval.', expectedHash: JSON.parse(read.content[0].text).sha256 }); assert.equal(proposed.isError, false);
    assert.equal(await fs.readFile(path.join(folder, 'test.txt'), 'utf8'), 'Before.');
    await page.getByRole('button', { name: '确认写入', exact: true }).waitFor(); await page.getByRole('button', { name: '确认写入', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('#message').textContent.includes('已写入'));
    assert.equal(await fs.readFile(path.join(folder, 'test.txt'), 'utf8'), 'After approval.');
    assert.equal(JSON.parse((await call('read_file', { rootId, path: 'test.txt' })).content[0].text).content, 'After approval.');
  });
  await t.test('registration is quota-bounded and revocation cannot be undone by retrying enrollment', async () => {
    for (let i = 0; i < 2; i++) assert.equal((await jsonRequest(`${origin}/enroll-device`, { deviceId: randomBytes(16).toString('hex'), deviceKey: secret() })).status, 200);
    assert.equal((await jsonRequest(`${origin}/enroll-device`, { deviceId: randomBytes(16).toString('hex'), deviceKey: secret() })).status, 429);
    assert.equal((await value(await local('disconnect', {}))).remoteRevoked, true);
    assert.equal((await jsonRequest(`${origin}/enroll-device`, { deviceId: identity.deviceId, deviceKey: identity.deviceKey })).status, 409);
    assert.equal((await call('list_roots')).isError, true);
  });
});
