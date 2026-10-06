import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { chromium } from 'playwright-core';
import { startController } from '../src/agent/main.mjs';
import { chooseFolder } from './choose-folder-helper.mjs';

async function fixture(t) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-consent-'));
  const folder = path.join(base, 'project'); const legacy = path.join(base, 'legacy');
  await fs.mkdir(folder); await fs.mkdir(legacy);
  const app = await startController({ port: 0, defaultRelay: 'https://relay.example.test', stateDir: path.join(base, 'private'), setupFetch: async () => new Response(null, { status: 404 }), networkOptions: { env: {}, systemProxy: async () => ({ proxy: '' }) } });
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  t.after(async () => { await browser.close(); await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
  const calls = [];
  page.on('request', request => { if (request.method() === 'POST') calls.push({ route: new URL(request.url()).pathname, body: request.postDataJSON() }); });
  const local = async (route, body) => {
    const response = await fetch(`${app.origin}/api/${route}`, { method: 'POST', headers: { Origin: app.origin, 'X-Chat2Local-Token': app.token, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    assert.equal(response.status, 200); return response.json();
  };
  await page.goto(`${app.origin}/manage#${app.token}`); // Legacy management remains covered separately from the default guide.
  await page.waitForFunction(() => document.querySelector('#localState').textContent.includes('正在运行'));
  return { base, folder, legacy, app, page, calls, local };
}
async function browse(page, folder) {
  await page.locator('#chooseFolder').click(); await page.locator('#browsePath').fill(folder); await page.locator('#browseGo').click();
  await page.waitForFunction(expected => document.querySelector('#browsePath').value === expected && !document.querySelector('#useFolder').disabled, folder);
}

test('new-folder defaults grant nothing until the labelled consent; cancellation never starts pairing', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  assert.deepEqual(await f.app.files.invoke('list_roots'), []);
  await browse(f.page, f.folder);
  assert.equal(await f.page.locator('#newFolderMode').inputValue(), 'direct');
  assert.equal(await f.page.locator('#newFolderOptions').getAttribute('open'), null);
  assert.equal(await f.page.locator('#useFolder').textContent(), '选择并允许读写');
  assert.match(await f.page.locator('#folderConsent').textContent(), /不包括删除、执行命令/);
  assert.deepEqual(await f.app.files.invoke('list_roots'), []);
  await f.page.locator('#cancelPicker').click(); await f.page.reload();
  await f.page.waitForFunction(() => document.querySelector('#localState').textContent.includes('正在运行'));
  assert.deepEqual(await f.app.files.invoke('list_roots'), []);
  assert.equal(f.calls.filter(call => ['/api/root/add', '/api/setup/start'].includes(call.route)).length, 0);
});

test('single visible consent saves direct permission then auto-connects once; failure retains progress', { timeout: 30000 }, async t => {
  const f = await fixture(t); let dialogs = 0;
  f.page.on('dialog', async dialog => { dialogs++; await dialog.dismiss(); });
  await chooseFolder(f.page, f.folder);
  await f.page.waitForFunction(() => document.querySelector('#message').textContent.includes('旧版本'));
  assert.equal(dialogs, 0, 'The labelled folder-confirmation button is the consent; no second dialog.');
  const grant = f.calls.find(call => call.route === '/api/root/add');
  assert.deepEqual(grant.body, { path: f.folder, writeMode: 'direct', confirmDirect: true });
  assert.equal(f.calls.filter(call => call.route === '/api/setup/start').length, 1);
  assert.match(await f.page.locator('#message').textContent(), /目录授权已保存/);
  assert.equal(await f.page.locator('#connectChatGPT').isEnabled(), true);
  const root = (await f.app.files.invoke('list_roots'))[0]; assert.equal(root.directWriteAllowed, true);
  await f.page.reload(); await f.page.waitForFunction(() => document.querySelector('#folders .folder'));
  assert.equal((await f.app.files.invoke('list_roots'))[0].id, root.id);
  assert.equal(f.calls.filter(call => call.route === '/api/setup/start').length, 1, 'Reload alone cannot reopen pairing.');
  await chooseFolder(f.page, f.folder);
  await f.page.waitForFunction(() => document.querySelector('#message').textContent.includes('原权限保持不变'));
  assert.equal((await f.app.files.invoke('list_roots')).length, 1);
  assert.equal(f.calls.filter(call => call.route === '/api/setup/start').length, 1, 'Reselecting an existing folder is not setup.');
  await fs.mkdir('.artifacts', { recursive: true }); await f.page.screenshot({ path: '.artifacts/alpha8-folder-consent.png', fullPage: true });
});

test('selecting an existing review directory never promotes it to the new direct default', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  const existing = await f.local('root/add', { path: f.legacy, write: true });
  await f.page.reload(); await f.page.waitForFunction(() => document.querySelector('#folders .folder'));
  await chooseFolder(f.page, f.legacy);
  await f.page.waitForFunction(() => document.querySelector('#message').textContent.includes('原权限保持不变'));
  const roots = await f.app.files.invoke('list_roots');
  assert.equal(roots.length, 1); assert.equal(roots[0].id, existing.id); assert.equal(roots[0].writeMode, 'review');
  assert.equal(f.calls.filter(call => call.route === '/api/setup/start').length, 0);
  await assert.rejects(() => f.app.files.invoke('write_file', { rootId: existing.id, path: 'no.txt', content: 'denied', expectedHash: null }), /not authorized/);
});

test('advanced read-only choice remains read-only and the confirmation label follows that choice', { timeout: 30000 }, async t => {
  const f = await fixture(t); await browse(f.page, f.folder);
  await f.page.locator('#newFolderOptions > summary').click(); await f.page.locator('#newFolderMode').selectOption('read-only');
  assert.equal(await f.page.locator('#useFolder').textContent(), '选择并仅允许查看');
  await f.page.locator('#useFolder').click();
  await f.page.waitForFunction(() => document.querySelector('#message').textContent.includes('旧版本'));
  const root = (await f.app.files.invoke('list_roots'))[0]; assert.equal(root.writeMode, 'read-only');
  await assert.rejects(() => f.app.files.invoke('write_file', { rootId: root.id, path: 'no.txt', content: 'denied', expectedHash: null }), /read-only/);
});

test('an uncertain folder-save response is reconciled from status without duplicate grants or setup', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  await f.page.route('**/api/root/add', async route => { await route.fetch(); await route.abort('failed'); });
  await browse(f.page, f.folder); await f.page.locator('#useFolder').click();
  await f.page.waitForFunction(() => document.querySelector('#folders .folder'));
  assert.equal((await f.app.files.invoke('list_roots')).length, 1);
  assert.equal(f.calls.filter(call => call.route === '/api/root/add').length, 1);
  assert.equal(f.calls.filter(call => call.route === '/api/setup/start').length, 0);
  await f.page.unroute('**/api/root/add'); await f.page.reload();
  await f.page.waitForFunction(() => document.querySelector('#folders .folder'));
  assert.equal((await f.app.files.invoke('list_roots')).length, 1);
});
