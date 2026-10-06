import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { chromium } from 'playwright-core';
import { startController } from '../src/agent/main.mjs';
import { chooseFolder } from './choose-folder-helper.mjs';

test('folder direct-write permission is explicit once, remains after reload, and does not create per-write approvals', { timeout: 60000 }, async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-direct-ui-'));
  const folder = path.join(base, 'example-project'); await fs.mkdir(folder);
  const app = await startController({ port: 0, defaultRelay: 'https://relay.example.test', stateDir: path.join(base, 'private'), pickFolder: async () => folder, setupFetch: async () => new Response(null, { status: 404 }), networkOptions: { env: {}, systemProxy: async () => ({ proxy: '' }) } });
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  t.after(async () => { await browser.close(); await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  const page = await browser.newPage({ viewport: { width: 1150, height: 1000 } });
  await page.goto(`${app.origin}/manage#${app.token}`); // Advanced-management compatibility; default guide has separate tests.
  await page.waitForFunction(() => document.querySelector('#localState').textContent.includes('正在运行'));
  assert.equal(await page.locator('#writePermission').count(), 0); // No misleading second permission selector.
  await chooseFolder(page, folder, { mode: 'read-only' }); await page.locator('#folders .folder').waitFor();
  await page.waitForFunction(() => document.querySelector('#message').textContent.includes('旧版本'));
  const select = page.getByRole('combobox', { name: 'example-project 目录权限' });
  assert.equal(await select.inputValue(), 'read-only');
  page.once('dialog', dialog => dialog.dismiss());
  await select.selectOption('direct');
  assert.equal(await select.inputValue(), 'read-only');
  assert.equal((await app.files.invoke('list_roots'))[0].directWriteAllowed, false);
  page.once('dialog', async dialog => { assert.match(dialog.message(), /example-project/); assert.match(dialog.message(), /不允许.*删除/); await dialog.accept(); });
  await select.selectOption('direct');
  assert.equal(await page.getByRole('button', { name: '保存权限', exact: true }).count(), 0);
  await page.waitForFunction(() => document.querySelector('#message').textContent.includes('该目录已允许直接读写'));
  await page.reload(); await page.waitForFunction(() => document.querySelector('#folders select')?.value === 'direct');
  const root = (await app.files.invoke('list_roots'))[0];
  const op = await app.files.invoke('write_file', { rootId: root.id, path: 'direct.txt', content: 'direct-ui-test', expectedHash: null });
  assert.equal(op.status, 'written'); assert.equal(await fs.readFile(path.join(folder, 'direct.txt'), 'utf8'), 'direct-ui-test');
  await page.reload(); await page.waitForFunction(() => document.querySelector('#folders select')?.value === 'direct');
  assert.equal(await page.locator('#approvals').isHidden(), true);
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  await fs.mkdir('.artifacts', { recursive: true });
  await page.screenshot({ path: '.artifacts/direct-permissions.png', fullPage: true });
  await select.selectOption('read-only');
  await page.waitForFunction(() => document.querySelector('#message').textContent.includes('目录权限已保存'));
  await assert.rejects(() => app.files.invoke('write_file', { rootId: root.id, path: 'again.txt', content: 'denied', expectedHash: null }), /read-only/);
});
