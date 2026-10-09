import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright-core';
import { ManagementSessions, managerRoute } from '../src/agent/management-session.mjs';
import { startController } from '../src/agent/main.mjs';
import { Store } from '../src/agent/store.mjs';
import { approveRoot } from '../src/agent/files.mjs';
import { rootPermission } from '../src/agent/permissions.mjs';

test('management proof survives controller replacement but expires, is revocable, and never grants general control', async () => {
  let record, clock = Date.now(), binding = 'installation:fixture:device:one';
  const store = { readPrivateRecord: async () => structuredClone(record), savePrivateRecord: async (_key, value) => { record = structuredClone(value); } };
  const create = () => new ManagementSessions({ store, now: () => clock, binding: () => binding });
  const first = create();
  await assert.rejects(() => first.establish('', false), { status: 401 }); assert.equal(record, undefined);
  const session = await first.establish('', true), cookie = session.cookie.split(';')[0];
  assert.match(session.cookie, /HttpOnly; SameSite=Strict; Path=\/api; Max-Age=/);
  assert.equal(JSON.stringify(record).includes(cookie.split('=')[1]), false, 'Persist digests, not bearer proof');
  const second = create(), request = { method: 'GET', url: '/api/status', headers: { cookie, 'x-chat2local-manager': '1' } };
  assert.equal(await second.accepts(request), true);
  assert.equal((await second.establish(cookie, false)).expiresAt, session.expiresAt, 'Read/reload never extends lifetime');
  for (const route of ['/api/shutdown','/api/startup','/api/pause','/api/root/add','/api/decision','/mcp']) {
    assert.equal(managerRoute('POST', route), false);
    assert.equal(await second.accepts({ ...request, method: 'POST', url: route }), false);
  }
  assert.equal(await second.accepts({ ...request, headers: { cookie } }), false);
  assert.equal(await second.accepts({ ...request, headers: { ...request.headers, cookie: cookie + '; ' + cookie } }), false);
  binding = 'other-device'; assert.equal(await second.accepts(request), false); binding = 'installation:fixture:device:one';
  clock += 7 * 86400000 + 1; assert.equal(await second.accepts(request), false);
  const next = await second.establish('', true); await second.logout(next.cookie.split(';')[0]);
  assert.equal(await create().accepts({ ...request, headers: { ...request.headers, cookie: next.cookie.split(';')[0] } }), false);
});

async function fixture(t) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-session-restart-'));
  const folder = path.join(base, 'project'); await fs.mkdir(folder);
  const store = new Store(path.join(base, 'private'));
  const root = { ...await approveRoot(folder, store.directory, true), ...rootPermission('direct') };
  const identity = { deviceId: '1'.repeat(32), deviceKey: '2'.repeat(64), origin: 'https://session-fixture.example.test' };
  await store.saveConfig({ version: 1, roots: [root], paused: false, startup: false, relay: identity.origin, installationId: 'stable-test-installation' });
  await store.saveSecrets({ identity });
  const before = JSON.stringify(await store.load());
  const connection = { connectionId: '3'.repeat(32), clientId: 'fixture-client', clientName: 'Test Client', callbackOrigin: 'https://client.example.test', scopes: ['files:read','files:write'], revision: 1, roots: [{ rootId: root.id, mode: 'direct' }] };
  const options = { store, bridge: { state: 'connected', start() {}, stop() {} }, network: { prepare: async () => {}, status: () => ({}), close() {} }, accountFetch: async (url) => {
    if (new URL(url).pathname === '/instance/manage/connections') return Response.json({ connections: [connection] });
    throw Error('Unexpected cloud request; this fixture cannot mutate cloud state.');
  } };
  let app, browser;
  t.after(async () => { await browser?.close(); await app?.close(); await fs.rm(base, { recursive: true, force: true }); });
  app = await startController({ ...options, port: 0 });
  browser = await chromium.launch({ channel: 'msedge', headless: true });
  return { store, root, browser, before, app: () => app, restart: async () => { const port = new URL(app.origin).port; await app.close(); app = await startController({ ...options, port: Number(port) }); } };
}

test('real browser: old tab, reload and new tab keep management after controller token rotates; unverified browsers stay locked', { timeout: 90000 }, async t => {
  const f = await fixture(t), context = await f.browser.newContext();
  const page = await context.newPage(), initial = f.app();
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  const proofRequests = []; page.on('request', r => { if (/\/api\/(?:shares\/(?:confirm|prepare|remove-confirm)|terminal\/set-permission)/.test(r.url())) proofRequests.push(r.url()); });
  await page.goto(initial.origin + '/folders#' + initial.token);
  await page.waitForFunction(() => document.querySelectorAll('.shared-row').length === 1);
  assert.equal(await page.evaluate(() => sessionStorage.getItem('chat2local-control')), null);
  const cookies = await context.cookies(); const proof = cookies.find(c => c.name === 'c2l_management');
  assert.ok(proof?.httpOnly); assert.equal(proof.sameSite, 'Strict');
  assert.equal(await page.evaluate(() => document.cookie.includes('c2l_management')), false);
  await f.restart(); assert.notEqual(f.app().token, initial.token);
  const stale = await fetch(f.app().origin + '/api/status', { headers: { 'X-Chat2Local-Token': initial.token } });
  assert.equal(stale.status, 401, 'An old process token alone remains invalid');
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await page.waitForFunction(() => document.querySelector('#connection-status').textContent === '已连接');
  await page.reload(); await page.waitForFunction(() => document.querySelectorAll('.shared-row').length === 1);
  assert.equal(await page.locator('#management-recovery').isVisible(), false);
  const nextTab = await context.newPage(); await nextTab.goto(f.app().origin + '/folders');
  await nextTab.waitForFunction(() => document.querySelectorAll('.shared-row').length === 1);
  assert.equal(await nextTab.locator('#management-recovery').isVisible(), false);
  const cookie = 'c2l_management=' + proof.value;
  const denied = await fetch(f.app().origin + '/api/shutdown', { method: 'POST', headers: { Origin: f.app().origin, Cookie: cookie, 'X-Chat2Local-Manager': '1', 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(denied.status, 401);
  const wrongOrigin = await fetch(f.app().origin + '/api/management/session', { method: 'POST', headers: { Origin: 'https://attacker.invalid', Cookie: cookie, 'X-Chat2Local-Manager': '1', 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(wrongOrigin.status, 403);
  const anonymousContext = await f.browser.newContext(), anonymous = await anonymousContext.newPage();
  await anonymous.goto(f.app().origin + '/folders');
  await anonymous.locator('#management-recovery').waitFor({ state: 'visible' });
  assert.equal(await anonymous.locator('#shared-panel').isVisible(), false);
  assert.equal(await anonymous.locator('#connection-status').textContent(), '管理页待验证');
  assert.equal(await anonymous.getByText('正在读取…', { exact: true }).count(), 0);
  assert.equal(await anonymous.locator('#open-add').isEnabled(), false);
  assert.match(await anonymous.locator('#management-entry').inputValue(), /Chat2Local/);
  assert.equal(proofRequests.length, 0, 'Restoring management never grants files, terminal or OAuth');
  assert.equal(JSON.stringify(await f.store.load()), f.before);
  assert.deepEqual(errors, []);
  // Clear browser proof explicitly; a saved URL must no longer unlock it.
  await page.locator('#details').evaluate(node => { node.open = true; });
  await page.locator('#forget-management').click(); await page.locator('#management-recovery').waitFor({ state: 'visible' });
  await nextTab.reload(); await nextTab.locator('#management-recovery').waitFor({ state: 'visible' });
  await fs.mkdir('.artifacts/ui-review', { recursive: true });
  await anonymous.screenshot({ path: '.artifacts/ui-review/session-recovery-locked.png', fullPage: true });
  await anonymous.setViewportSize({ width: 390, height: 844 });
  assert.equal(await anonymous.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
});
