import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID, randomInt } from 'node:crypto';
import { chromium } from 'playwright-core';
import { Store } from '../src/agent/store.mjs';
import { startController } from '../src/agent/main.mjs';
import { approveRoot } from '../src/agent/files.mjs';
import { rootPermission } from '../src/agent/permissions.mjs';
import { newGuide, guideProbe, guideView, observeGuide } from '../src/agent/connection-guide.mjs';

const identity = { deviceId: '1'.repeat(32), deviceKey: '2'.repeat(64), origin: 'https://relay.example.test' };
async function fixture(t, { mode = 'review', existing = true, registered = true } = {}) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-guide-'));
  const folder = path.join(base, 'sample'); const other = path.join(base, 'other');
  await fs.mkdir(folder); await fs.mkdir(other);
  const store = new Store(path.join(base, 'private'));
  const root = { ...await approveRoot(folder, store.directory), ...rootPermission(mode) };
  await store.saveConfig({ version: 1, paused: false, startup: false, roots: existing ? [root] : [], relay: registered ? identity.origin : '', remoteUseConfirmed: registered });
  if (registered) await store.saveSecrets({ identity });
  // Transport state is a fixture, not native/public connectivity acceptance.
  const bridge = { state: registered ? 'connected' : 'not-configured', start() { this.state = 'connected'; }, stop() { this.state = 'disconnected'; }, revokeIdentity: async () => ({ remoteRevoked: true }) };
  const opened = [];
  let app;
  // This Windows host can assign port 1720 for port=0, which the browser refuses.
  // Bind a fresh high port without disabling browser protections or touching
  // any existing listener. Only genuine address-in-use conflicts are retried.
  for (let attempt = 0; attempt < 12 && !app; attempt++) {
    try { app = await startController({ port: randomInt(49152, 65536), store, bridge, defaultRelay: identity.origin, openBrowser: async url => opened.push(url), setupFetch: async () => new Response(null, { status: 404 }), networkOptions: { env: {}, systemProxy: async () => ({ proxy: '' }) } }); }
    catch (error) { if (error.code !== 'EADDRINUSE') throw error; }
  }
  if (!app) throw new Error('No unoccupied high test port found; existing listeners were not changed.');
  const api = (route, body, extra = {}) => fetch(`${app.origin}/api/${route}`, { method: body === undefined ? 'GET' : 'POST', headers: { 'X-Chat2Local-Token': app.token, Origin: app.origin, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...extra }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  t.after(async () => { await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  return { base, folder, other, root, store, app, api, opened };
}
const ok = async response => { assert.equal(response.status, 200, await response.clone().text()); return response.json(); };
const request = f => ({ path: f.folder, expectedRootId: f.root.id, expectedWriteMode: f.root.writeMode, requestId: randomUUID(), confirmDirect: true });

test('guide API requires explicit, current, same-origin consent; repeated request preserves one intent', async t => {
  const f = await fixture(t); const intent = request(f);
  assert.equal((await f.api('guide', undefined, { 'X-Chat2Local-Token': '0'.repeat(64) })).status, 401);
  assert.equal((await f.api('guide/authorize', intent, { Origin: 'https://untrusted.test' })).status, 403);
  assert.equal((await f.api('guide/authorize', { ...intent, confirmDirect: false })).status, 400);
  assert.equal((await f.api('guide/authorize', { ...intent, expectedWriteMode: 'read-only' })).status, 409);
  assert.equal((await ok(await f.api('status'))).roots[0].writeMode, 'review');
  const before = (await f.store.load()).secrets;
  const first = await ok(await f.api('guide/authorize', intent)); const again = await ok(await f.api('guide/authorize', intent));
  assert.equal(first.stage, 'check-tools'); assert.equal(again.attemptId, first.attemptId);
  const stored = await f.store.load(); assert.deepEqual(stored.secrets, before);
  assert.equal(stored.config.roots.length, 1); assert.equal(stored.config.roots[0].id, f.root.id); assert.equal(stored.config.roots[0].writeMode, 'direct');
  assert.equal(stored.config.startup, false); assert.equal(f.opened.length, 0);
});
test('pause/revoke and concurrent permission changes cannot be overridden by stale guide requests', async t => {
  const f = await fixture(t); const intent = request(f);
  await ok(await f.api('pause', { paused: true })); assert.equal((await f.api('guide/authorize', intent)).status, 409);
  await ok(await f.api('pause', { paused: false }));
  await ok(await f.api('guide/authorize', intent));
  await ok(await f.api('root/set-mode', { id: f.root.id, expectedWriteMode: 'direct', writeMode: 'read-only' }));
  assert.equal((await ok(await f.api('guide'))).stage, 'choose-folder');
  assert.equal((await f.api('guide/authorize', intent)).status, 409);
  await ok(await f.api('root/remove', { id: f.root.id }));
  assert.equal((await f.api('guide/authorize', { ...intent, expectedWriteMode: 'read-only' })).status, 409);
  assert.equal((await ok(await f.api('status'))).roots.length, 0);
});
test('local direct writes and reads never turn the remote-acceptance indicator green', async t => {
  const f = await fixture(t); const state = await ok(await f.api('guide/authorize', request(f)));
  const guide = (await f.store.load()).config.connectionGuide; const probe = guideProbe(guide);
  const created = await f.app.files.invoke('write_file', { rootId: f.root.id, path: probe.path, content: probe.created, expectedHash: null });
  assert.equal(created.status, 'written');
  await f.app.files.invoke('write_file', { rootId: f.root.id, path: probe.path, content: probe.updated, expectedHash: created.sha256 });
  await f.app.files.invoke('read_file', { rootId: f.root.id, path: probe.path });
  const after = await ok(await f.api('guide'));
  assert.equal(after.attemptId, state.attemptId); assert.equal(after.complete, false);
  assert.equal(after.evidence.createdAt, null); assert.equal(after.evidence.readBackAt, null);
});
test('completion requires matching create, backup-backed replacement and readback on the same device/root/attempt', () => {
  const guide = newGuide(randomUUID()); const p = guideProbe(guide);
  const createArgs = { rootId: guide.rootId, path: p.path, expectedHash: null, content: p.created };
  const replaceArgs = { ...createArgs, expectedHash: p.createdHash, content: p.updated };
  assert.equal(observeGuide(guide, 'propose_write', createArgs, { status: 'pending' }, identity), guide);
  assert.equal(observeGuide(guide, 'write_file', { ...createArgs, rootId: randomUUID() }, { status: 'written', sha256: p.createdHash }, identity), guide);
  assert.equal(observeGuide(guide, 'read_file', createArgs, { sha256: p.updatedHash, content: p.updated }, identity), guide);
  const created = observeGuide(guide, 'write_file', createArgs, { status: 'written', sha256: p.createdHash }, identity);
  assert.equal(observeGuide(created, 'write_file', replaceArgs, { status: 'written', sha256: p.updatedHash, backupSaved: false }, identity), created);
  const updated = observeGuide(created, 'write_file', replaceArgs, { status: 'written', sha256: p.updatedHash, backupSaved: true }, identity);
  const complete = observeGuide(updated, 'read_file', replaceArgs, { sha256: p.updatedHash, content: p.updated }, identity);
  assert.ok(complete.evidence.readBackAt);
  const config = { roots: [{ id: guide.rootId, label: 'sample', path: '/sample', ...rootPermission('direct') }], relay: identity.origin, connectionGuide: complete, paused: false, remoteUseConfirmed: true };
  assert.equal(guideView(config, { device: identity, bridge: 'connected' }).stage, 'ready');
  assert.equal(guideView(config, { device: { ...identity, deviceId: '3'.repeat(32) }, bridge: 'connected' }).complete, false);
  assert.equal(guideView({ ...config, paused: true }, { device: identity, bridge: 'connected' }).stage, 'paused');
  assert.equal(guideView(config, { device: identity, bridge: 'disconnected' }).stage, 'reconnecting');
});
test('default homepage is a single guide; existing review folder needs one labelled consent, not legacy toggles or pairing', async t => {
  const f = await fixture(t); const browser = await chromium.launch({ channel: 'msedge', headless: true }); t.after(() => browser.close());
  const page = await browser.newPage({ viewport: { width: 1120, height: 950 } }); const errors = []; page.on('pageerror', error => errors.push(error.message));
  let setupCalls = 0; page.on('request', request => { if (request.url().endsWith('/api/setup/start')) setupCalls++; });
  await page.goto(`${f.app.origin}/#${f.app.token}`);
  await page.waitForFunction(() => !document.querySelector('#primary').disabled);
  assert.equal(new URL(page.url()).hash, ''); assert.equal(await page.locator('select').count(), 0);
  assert.match(await page.locator('#selectedMode').textContent(), /逐次确认/);
  assert.equal((await ok(await f.api('status'))).roots[0].writeMode, 'review');
  await page.getByRole('button', { name: '允许读写并继续', exact: true }).click();
  await page.locator('#verification').waitFor({ state: 'visible' });
  assert.equal(setupCalls, 0); assert.equal(f.opened.length, 0);
  assert.equal((await ok(await f.api('status'))).roots[0].writeMode, 'direct');
  assert.equal(await page.locator('#primary').isHidden(), true);
  assert.match(await page.locator('#heading').textContent(), /先检查网页工具/);
  assert.match(await page.locator('#capSaved').textContent(), /未知/);
  assert.match(await page.locator('#prompt').inputValue(), /不创建或修改文件/);
  assert.equal(await page.locator('#stepConnection').evaluate(node => node.classList.contains('done')), false);
  const saved = await ok(await f.api('guide'));
  await page.reload(); await page.locator('#verification').waitFor({ state: 'visible' });
  assert.equal((await ok(await f.api('guide'))).attemptId, saved.attemptId); assert.equal(setupCalls, 0);
  await fs.mkdir('.artifacts', { recursive: true }); await page.screenshot({ path: '.artifacts/guide-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  await page.screenshot({ path: '.artifacts/guide-mobile.png', fullPage: true });
  assert.deepEqual(errors, []);
});
test('fresh guide browsing grants nothing; one folder consent starts connection and preserves progress on failure', async t => {
  const f = await fixture(t, { existing: false, registered: false }); const browser = await chromium.launch({ channel: 'msedge', headless: true }); t.after(() => browser.close());
  const page = await browser.newPage(); let setupCalls = 0;
  page.on('request', request => { if (request.url().endsWith('/api/setup/start')) setupCalls++; });
  await page.goto(`${f.app.origin}/#${f.app.token}`);
  await page.getByRole('button', { name: '选择文件夹', exact: true }).click();
  await page.locator('#path').fill(f.folder); await page.locator('#go').click();
  await page.waitForFunction(() => !document.querySelector('#selectFolder').disabled);
  assert.equal((await ok(await f.api('status'))).roots.length, 0); assert.equal(setupCalls, 0);
  await page.locator('#cancelBrowse').click(); assert.equal((await ok(await f.api('status'))).roots.length, 0);
  await page.locator('#choose').click(); await page.locator('#path').fill(f.folder); await page.locator('#go').click();
  await page.waitForFunction(() => !document.querySelector('#selectFolder').disabled);
  await page.getByRole('button', { name: '选择并允许读写', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#notice').textContent.includes('旧版本'));
  assert.equal(setupCalls, 1); const state = await ok(await f.api('guide'));
  assert.equal(state.directoryGranted, true); assert.equal(state.complete, false);
  await page.reload(); await page.waitForFunction(() => document.querySelector('#heading').textContent.includes('继续连接'));
  assert.equal((await ok(await f.api('guide'))).attemptId, state.attemptId); assert.equal(setupCalls, 1);
});
test('an uncertain consent response restores committed progress instead of repeating authorization', async t => {
  const f = await fixture(t); const browser = await chromium.launch({ channel: 'msedge', headless: true }); t.after(() => browser.close());
  const page = await browser.newPage(); let grants = 0;
  await page.route('**/api/guide/authorize', async route => { grants++; await route.fetch(); await route.abort('failed'); });
  await page.goto(`${f.app.origin}/#${f.app.token}`); await page.waitForFunction(() => !document.querySelector('#primary').disabled);
  await page.locator('#primary').click(); await page.locator('#verification').waitFor({ state: 'visible' });
  assert.equal(grants, 1); assert.equal((await ok(await f.api('status'))).roots.length, 1);
  assert.equal((await ok(await f.api('guide'))).stage, 'check-tools');
});
