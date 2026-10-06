import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { chromium } from 'playwright-core';
import { startController } from '../src/agent/main.mjs';

async function fixture(t) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-inline-browser-'));
  const root = path.join(base, 'existing'); const next = path.join(base, 'next');
  await fs.mkdir(root); await fs.mkdir(next); await fs.mkdir(path.join(base, '.ssh'));
  await fs.writeFile(path.join(base, 'not-visible.txt'), 'must not be listed or read');
  const app = await startController({ port: 0, stateDir: path.join(base, 'private'), pickFolder: () => assert.fail('The ordinary UI must not invoke Windows GUI.') });
  const local = (route, body, extra = {}) => fetch(`${app.origin}/api/${route}`, { method: 'POST', headers: { Origin: app.origin, 'X-Chat2Local-Token': app.token, 'Content-Type': 'application/json', ...extra }, body: JSON.stringify(body), signal: AbortSignal.timeout(6000) });
  await local('root/add', { path: root, write: false });
  t.after(async () => { await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  return { base, root, next, app, local };
}

test('directory browser is local-authenticated, names-only, bounded and never an authorization action', { timeout: 15000 }, async t => {
  const f = await fixture(t);
  assert.equal((await f.local('folder/browse', { path: f.base }, { 'X-Chat2Local-Token': '0'.repeat(64) })).status, 401);
  assert.equal((await f.local('folder/browse', { path: f.base }, { Origin: 'https://attacker.invalid' })).status, 403);
  const result = await f.local('folder/browse', { path: f.base }); assert.equal(result.status, 200);
  const value = await result.json();
  assert.deepEqual(value.entries.map(entry => entry.name), ['existing', 'next']);
  assert.equal(value.selectable, false); // It contains private state; cannot grant the parent.
  assert.equal((await f.app.files.invoke('list_roots')).length, 1);
  assert.equal((await f.local('folder/browse', { path: path.join(f.base, 'private') })).status, 400);
  assert.equal((await f.local('folder/browse', { path: '\\\\server\\share' })).status, 400);
  assert.equal((await f.local('folder/browse', { path: f.root, recursive: true })).status, 400);
  const selectable = await (await f.local('folder/browse', { path: f.next })).json();
  assert.equal(selectable.selectable, true);
});

test('real browser adds a folder entirely on-page; cancel, permissions and existing connection are independent', { timeout: 45000 }, async t => {
  const f = await fixture(t); await f.app.bridge.invoke('list_roots', {}); f.app.bridge.state = 'connected';
  const browser = await chromium.launch({ channel: 'msedge', headless: true }); t.after(() => browser.close());
  const page = await browser.newPage({ viewport: { width: 1150, height: 1000 } });
  await page.goto(`${f.app.origin}/manage#${f.app.token}`); // Retained advanced directory manager.
  await page.waitForFunction(() => document.querySelector('#folders select'));
  let setupRequests = 0; page.on('request', request => { if (request.url().endsWith('/api/setup/start')) setupRequests++; });
  await page.locator('#chooseFolder').click(); await page.locator('#browsePath').fill(f.base); await page.locator('#browseGo').click();
  await page.getByRole('button', { name: 'next　›', exact: true }).waitFor();
  assert.equal(await page.locator('#pauseAccess').isEnabled(), true);
  await page.locator('#connectionHelp > summary').click(); assert.equal(await page.locator('#repairConnection').isEnabled(), true);
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('combobox', { name: 'existing 目录权限' }).selectOption('direct');
  await page.waitForFunction(() => document.querySelector('.effective-permission').textContent.includes('当前已生效：允许直接读写'));
  await page.locator('#cancelPicker').click();
  assert.equal((await f.app.files.invoke('list_roots')).length, 1);
  await page.locator('#chooseFolder').click(); await page.locator('#browsePath').fill(f.base); await page.locator('#browseGo').click();
  await page.getByRole('button', { name: 'next　›', exact: true }).click();
  await page.waitForFunction(expected => document.querySelector('#browsePath').value === expected && !document.querySelector('#useFolder').disabled, f.next);
  await page.locator('#useFolder').click(); await page.waitForFunction(() => document.querySelectorAll('#folders .folder').length === 2);
  assert.equal((await f.app.files.invoke('list_roots')).find(root => root.label === 'next').writeMode, 'direct');
  assert.equal(setupRequests, 0); assert.equal(await page.locator('#setupActions').isHidden(), true);
  await page.reload(); await page.waitForFunction(() => document.querySelectorAll('#folders .folder').length === 2);
  assert.equal(await page.getByRole('combobox', { name: 'existing 目录权限' }).inputValue(), 'direct');
  assert.equal(await page.locator('#writePermission').count(), 0);
  await fs.mkdir('.artifacts', { recursive: true });
  await page.screenshot({ path: '.artifacts/ux-inline-connected.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 }); await page.locator('#chooseFolder').click();
  await page.locator('#browsePath').fill(f.base); await page.locator('#browseGo').click();
  await page.getByRole('button', { name: 'next　›', exact: true }).waitFor();
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  await page.screenshot({ path: '.artifacts/ux-inline-mobile.png', fullPage: true });
});
