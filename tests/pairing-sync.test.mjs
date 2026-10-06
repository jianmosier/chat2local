import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { randomBytes, createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright-core';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { startController } from '../src/agent/main.mjs';
import { chooseFolder } from './choose-folder-helper.mjs';
import { SetupManager } from '../src/agent/setup.mjs';
import { setupAvailability } from '../src/shared/setup.mjs';

const secret = () => randomBytes(32).toString('hex');
async function data(response, status = 200) { assert.equal(response.status, status, await response.clone().text()); return response.json(); }
const post = (url, body, headers = {}) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body), redirect: 'manual' });

test('developer binding requires both operator enablement and an existing identity; it cannot enable public enrollment', () => {
  assert.equal(setupAvailability({ developerHandoff: true }).ready, false);
  assert.equal(setupAvailability({ alreadyEnrolled: true }).ready, false);
  assert.equal(setupAvailability({ developerHandoff: 'true', alreadyEnrolled: true }).ready, false);
  assert.equal(setupAvailability({ developerHandoff: true, alreadyEnrolled: true }).code, 'DEVELOPER_READY');
});

test('an old relay and a mismatched handshake return a version error, with no enrollment or browser launch', async () => {
  for (const response of [() => new Response(null, { status: 404 }), () => Response.json({ name: 'chat2local-relay', setupVersion: 99, browserHandoff: true })]) {
    let calls = 0;
    const manager = new SetupManager({ defaultRelay: 'https://relay.example.test', identity: () => undefined, prepareNetwork: async () => {}, fetch: async url => { calls++; assert.ok(url.endsWith('/setup-info')); return response(); }, openBrowser: () => assert.fail('must not open') });
    assert.equal((await manager.start()).code, 'RELAY_UPDATE_REQUIRED');
    assert.equal(calls, 1);
  }
});

test('slow proxy discovery times out before credentials can be sent, even when discovery later completes', async () => {
  let fetchCalls = 0;
  const manager = new SetupManager({ defaultRelay: 'https://relay.example.test', identity: () => undefined, requestTimeoutMs: 20, prepareNetwork: async () => delay(80), fetch: async () => { fetchCalls++; assert.fail('late request'); } });
  const result = await manager.start();
  assert.equal(result.code, 'SERVICE_UNREACHABLE');
  await delay(100); assert.equal(fetchCalls, 0);
});

test('failed setup and status fetches always release the homepage buttons', { timeout: 30000 }, async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-pair-buttons-'));
  const folder = path.join(base, 'sample'); await fs.mkdir(folder);
  const app = await startController({ port: 0, stateDir: path.join(base, 'private'), pickFolder: async () => folder });
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  t.after(async () => { await browser.close(); await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  const page = await browser.newPage(); await page.goto(`${app.origin}/manage#${app.token}`);
  await page.waitForFunction(() => document.querySelector('#localState').textContent.includes('正在运行'));
  await page.route('**/api/setup/start', route => route.abort('failed'));
  await chooseFolder(page, folder);
  await page.waitForFunction(() => document.querySelector('#message').textContent.includes('目录授权已保存，无需重新选择'));
  await page.waitForFunction(() => !document.querySelector('#connectChatGPT').disabled);
  await page.route('**/api/status', route => route.abort('failed'));
  await page.locator('#connectChatGPT').click();
  await page.waitForFunction(() => document.querySelector('#message').textContent.includes('无法连接'));
  assert.equal(await page.locator('#chooseFolder').isDisabled(), false);
  assert.equal(await page.locator('#connectChatGPT').isDisabled(), false);
  assert.doesNotMatch(await page.locator('#connection').textContent(), /正在准备连接/);
});

test('ChatGPT-first OAuth ordering: an enrolled developer device binds without a listing or copied code', { timeout: 90000 }, async t => {
  const bundle = await build({ entryPoints: ['src/relay/worker.mjs'], bundle: true, write: false, format: 'esm', platform: 'neutral', mainFields: ['module', 'main'], external: ['cloudflare:workers'] });
  const key = secret();
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundle.outputFiles[0].text, compatibilityDate: '2026-09-20', compatibilityFlags: ['nodejs_compat', 'global_fetch_strictly_public'], host: '127.0.0.1', port: 0, kvNamespaces: ['OAUTH_KV'], durableObjects: { DEVICES: { className: 'Device', useSQLite: true }, REGISTRY: { className: 'Registry', useSQLite: true } }, bindings: { ALLOW_LOOPBACK: 'true', DEVELOPER_HANDOFF: 'true', ENROLLMENT_KEY: key } }));
  t.after(() => mf.dispose());
  const origin = (await mf.ready).origin;
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-developer-bind-'));
  const folder = path.join(base, 'sample'); await fs.mkdir(folder); await fs.writeFile(path.join(folder, 'probe.txt'), 'Independent pairing fixture.');
  const opened = [];
  const app = await startController({ port: 0, stateDir: path.join(base, 'private'), allowLocalRelay: true, defaultRelay: origin, openBrowser: async url => opened.push(url) });
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  t.after(async () => { await browser.close(); await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  const local = (route, body) => post(`${app.origin}/api/${route}`, body, { Origin: app.origin, 'X-Chat2Local-Token': app.token });
  const root = await data(await local('root/add', { path: folder, write: false }));
  await data(await local('enroll', { origin, enrollmentToken: key }));
  const info = await data(await fetch(`${origin}/setup-info`));
  assert.equal(info.developerHandoff, true); assert.equal(info.installUrl, null); assert.equal(info.selfService, false);
  assert.equal((await post(`${origin}/enroll-device`, { deviceId: randomBytes(16).toString('hex'), deviceKey: secret() })).status, 503);
  assert.equal((await fetch(`${origin}/authorize/device-status`)).status, 403);
  const callbackServer = http.createServer((request, response) => {
    response.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
    response.end('Synthetic callback; not a real ChatGPT invocation.');
  });
  await new Promise(resolve => callbackServer.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { callbackServer.close(resolve); callbackServer.closeIdleConnections(); }));
  const callback = `http://127.0.0.1:${callbackServer.address().port}/callback`;
  const client = await data(await post(`${origin}/oauth/register`, { client_name: 'Synthetic ChatGPT-order fixture', redirect_uris: [callback], token_endpoint_auth_method: 'none', grant_types: ['authorization_code'], response_types: ['code'] }), 201);
  const verifier = secret();
  const query = new URLSearchParams({ client_id: client.client_id, redirect_uri: callback, response_type: 'code', code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url'), scope: 'files:read', state: secret(), resource: `${origin}/mcp` });
  const context = await browser.newContext();
  // A real loopback callback avoids mocking redirected navigations. No real AI
  // account or cookies are involved in this acceptance fixture.
  const auth = await context.newPage(); let consentPosts = 0; const diagnostics = [];
  auth.on('requestfailed', request => diagnostics.push({ path: new URL(request.url()).pathname, error: request.failure()?.errorText }));
  auth.on('console', message => { if (message.type() === 'error') diagnostics.push({ error: message.text().replace(/\?[^\s\"']+/g, '?[redacted]') }); });
  auth.on('request', request => { if (new URL(request.url()).pathname === '/authorize' && request.method() === 'POST') consentPosts++; });
  await auth.goto(`${origin}/authorize?${query}`);
  assert.equal(await auth.locator('#waiting-device').isVisible(), true);
  assert.equal(await auth.locator('input[name=pair]').isVisible(), false);
  const oldTicket = await auth.locator('input[name=ticket]').inputValue();
  const oldCookie = (await context.cookies(`${origin}/authorize`)).find(item => item.name === 'c2l_csrf').value;
  const setup = await data(await local('setup/start', {}));
  assert.equal(setup.ok, true); assert.equal(opened.length, 1); assert.equal(setup.websiteClientVerified, false);
  const bind = await context.newPage(); await bind.goto(opened[0]);
  await bind.waitForFunction(() => !document.querySelector('#continue').disabled);
  await bind.locator('#continue').click(); await bind.waitForFunction(() => document.querySelector('#message').textContent.includes('本机已配对'));
  await auth.waitForFunction(() => document.querySelector('input[name=source]')?.value === 'browser', { timeout: 10000 });
  assert.equal(await auth.locator('input[name=pair]').count(), 0);
  assert.equal(consentPosts, 0, 'Browser binding must not auto-approve OAuth');
  const deviceCookie = (await context.cookies(origin)).find(item => item.name === 'c2l_browser').value;
  const spoof = await fetch(`${origin}/authorize`, { method: 'POST', headers: { Origin: origin, Cookie: `c2l_csrf=${oldCookie}; c2l_browser=${deviceCookie}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ ticket: oldTicket, source: 'browser' }), redirect: 'manual' });
  assert.equal(spoof.status, 403, 'An unbound old ticket cannot be silently upgraded');
  const otherContext = await browser.newContext(); const other = await otherContext.newPage();
  await other.goto(`${origin}/authorize?${query}`);
  assert.equal(await other.locator('#waiting-device').isVisible(), true); await otherContext.close();
  const consentResponse = auth.waitForResponse(response => new URL(response.url()).pathname === '/authorize' && response.request().method() === 'POST', { timeout: 7000 });
  await auth.locator('#approve').click();
  const submitted = await consentResponse;
  assert.equal(submitted.status(), 303, submitted.status() === 303 ? '' : await submitted.text());
  assert.equal(new URL(submitted.headers().location).origin, new URL(callback).origin);
  await auth.waitForURL(`${callback}*`, { timeout: 5000 }).catch(() => assert.fail(JSON.stringify(diagnostics)));
  assert.equal(consentPosts, 1);
  const authCode = new URL(auth.url()).searchParams.get('code');
  const tokens = await data(await fetch(`${origin}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: client.client_id, redirect_uri: callback, code: authCode, code_verifier: verifier, resource: `${origin}/mcp` }) }));
  const read = await data(await post(`${origin}/mcp`, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { rootId: root.id, path: 'probe.txt' } } }, { Authorization: `Bearer ${tokens.access_token}` }));
  assert.equal(read.result.isError, false);
  assert.equal(JSON.parse(read.result.content[0].text).content, 'Independent pairing fixture.');
});
