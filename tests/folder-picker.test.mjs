import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { FolderPicker } from '../src/agent/folder-picker.mjs';
import { startController } from '../src/agent/main.mjs';
import { chromium } from 'playwright-core';

async function fixture(t) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-picker-'));
  const first = path.join(base, 'existing'); const second = path.join(base, 'new-folder');
  await fs.mkdir(first); await fs.mkdir(second);
  let finish; let started;
  const entered = new Promise(resolve => { started = resolve; });
  let signals = [];
  const app = await startController({ port: 0, stateDir: path.join(base, 'private'),
    pickFolder: ({ signal }) => { signals.push(signal); started(); return new Promise(resolve => { finish = resolve; }); }
  });
  const local = (route, body, extra = {}, timeoutMs = 6000) => fetch(`${app.origin}/api/${route}`, {
    method: body === undefined ? 'GET' : 'POST', redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
    headers: { Origin: app.origin, 'X-Chat2Local-Token': app.token, 'Content-Type': 'application/json', ...extra },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const root = await (await local('root/add', { path: first, write: true })).json();
  t.after(async () => { await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  return { app, local, entered, root, first, second, finish: value => finish(value), signals };
}
const ok = async response => { assert.equal(response.status, 200, await response.clone().text()); return response.json(); };

test('pending picker does not block MCP, permission changes, pause or cancellation; late choice grants nothing', { timeout: 15000 }, async t => {
  const f = await fixture(t);
  const pending = f.local('folder/select', { write: false }); await f.entered;
  assert.equal((await ok(await f.local('status'))).folderPickerActive, true);
  assert.equal((await f.app.bridge.invoke('list_roots', {})).length, 1);
  await ok(await f.local('root/set-mode', { id: f.root.id, writeMode: 'read-only', expectedWriteMode: 'review', confirmDirect: false }));
  await ok(await f.local('pause', { paused: true }));
  assert.equal((await ok(await pending)).cancelled, true);
  assert.equal(f.signals[0].aborted, true);
  await ok(await f.local('pause', { paused: false }));
  f.finish(f.second); await new Promise(resolve => setTimeout(resolve, 30));
  const state = await ok(await f.local('status'));
  assert.equal(state.roots.length, 1); assert.equal(state.roots[0].writeMode, 'read-only');
  assert.equal(state.hasRemoteUse, true); assert.equal(state.folderPickerActive, false);
});

test('cancel requires the same local authorization, duplicate dialogs are rejected, existing folder is not downgraded', { timeout: 15000 }, async t => {
  const f = await fixture(t);
  const pending = f.local('folder/select', { write: false }); await f.entered;
  assert.equal((await f.local('pick-folder', {})).status, 409);
  assert.equal((await f.local('folder/cancel', {}, { 'X-Chat2Local-Token': '0'.repeat(64) })).status, 401);
  f.finish(f.first);
  const result = await ok(await pending);
  assert.equal(result.alreadyAuthorized, true); assert.equal(result.id, f.root.id); assert.equal(result.writeMode, 'review');
  assert.equal((await ok(await f.local('status'))).roots.length, 1);
});

test('disconnecting the picker HTTP request cancels the native task and cannot add a folder later', { timeout: 15000 }, async t => {
  const f = await fixture(t); const abort = new AbortController();
  const pending = fetch(`${f.app.origin}/api/folder/select`, { method: 'POST', signal: abort.signal, headers: { Origin: f.app.origin, 'X-Chat2Local-Token': f.app.token, 'Content-Type': 'application/json' }, body: '{"write":false}' });
  const failed = assert.rejects(pending, error => error.name === 'AbortError');
  await f.entered; abort.abort(); await failed;
  for (let i = 0; i < 40 && !f.signals[0].aborted; i++) await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(f.signals[0].aborted, true);
  f.finish(f.second); await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal((await ok(await f.local('status'))).roots.length, 1);
});

test('picker deadline discards a late result and shutdown stops waiting for a human', { timeout: 15000 }, async t => {
  let done; const picker = new FolderPicker(() => new Promise(resolve => { done = resolve; }), 40);
  const result = await picker.run(); assert.equal(result.expired, true); assert.equal(picker.busy, false); done('late');
  const f = await fixture(t); const pending = f.local('pick-folder', {}); await f.entered;
  await f.app.close();
  assert.equal(f.signals[0].aborted, true);
  assert.equal((await ok(await pending)).path, null);
});

test('actual browser: picker waits independently; one permission change saves immediately; online state does not ask to reconnect', { timeout: 45000 }, async t => {
  const f = await fixture(t); const browser = await chromium.launch({ channel: 'msedge', headless: true });
  t.after(() => browser.close());
  // This invokes the bridge's local callback, not a real ChatGPT request; UI fixture only.
  await f.app.bridge.invoke('list_roots', {}); f.app.bridge.state = 'connected';
  // This request intentionally remains open while the browser exercises the UI.
  // The ordinary 6s API deadline must not cancel it before the explicit click;
  // the overall test remains bounded by 45s and cancellation is still asserted.
  const pendingNative = f.local('pick-folder', {}, {}, 40000); await f.entered;
  const page = await browser.newPage({ viewport: { width: 1150, height: 1000 } });
  await page.goto(`${f.app.origin}/manage#${f.app.token}`); // Test the retained management route.
  await page.waitForFunction(() => document.querySelector('.effective-permission')?.textContent.includes('每次修改前确认'));
  assert.equal(await page.locator('#setupActions').isHidden(), true);
  assert.match(await page.locator('#connection').textContent(), /无需再次点击连接/);
  let setups = 0; page.on('request', request => { if (request.url().endsWith('/api/setup/start')) setups++; });
  await page.locator('#cancelPicker').waitFor();
  assert.equal(await page.locator('#pauseAccess').isEnabled(), true);
  await page.locator('#connectionHelp > summary').click();
  assert.equal(await page.locator('#repairConnection').isEnabled(), true);
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('combobox', { name: 'existing 目录权限' }).selectOption('direct');
  await page.waitForFunction(() => document.querySelector('.effective-permission')?.textContent.includes('当前已生效：允许直接读写'));
  assert.equal((await f.app.files.invoke('list_roots'))[0].directWriteAllowed, true);
  assert.equal(await page.getByRole('button', { name: '保存权限', exact: true }).count(), 0);
  await page.locator('#cancelPicker').click();
  await page.waitForFunction(() => document.querySelector('#pickerNotice').hidden === true);
  assert.equal(setups, 0); assert.equal(f.signals[0].aborted, true); assert.equal((await ok(await pendingNative)).path, null);
  f.finish(f.second); await page.reload();
  await page.waitForFunction(() => document.querySelector('#folders select')?.value === 'direct');
  assert.equal(await page.locator('#folders .folder').count(), 1);
  await fs.mkdir('.artifacts', { recursive: true });
  await page.screenshot({ path: '.artifacts/ux-connected-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  await page.screenshot({ path: '.artifacts/ux-connected-mobile.png', fullPage: true });
});
