import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { chromium } from 'playwright-core';
import { startController } from '../src/agent/main.mjs';

// Uses the installed Edge in an isolated temporary browser profile. Does not install a browser.
test('new-user browser flow: isolated Edge profile, real UI and real HTTP', { timeout: 90000 }, async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'chat2local-browser-'));
  const root = path.join(base, 'example-project'); await fs.mkdir(root);
  const startup = [];
  const app = await startController({ port: 0, stateDir: path.join(base, 'private'), demoDir: path.join(base, 'demo'), pickFolder: async () => root, setStartup: async value => startup.push(value) });
  let browser;
  t.after(async () => { await browser?.close(); await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  browser = await chromium.launch({ channel: 'msedge', headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage(); const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const waitText = (selector, text) => page.waitForFunction(({ selector, text }) => document.querySelector(selector)?.textContent.includes(text), { selector, text });

  await t.test('authorized launcher URL boots; secret is removed from address bar', async () => {
    await page.goto(`${app.origin}/developer#${app.token}`);
    await waitText('#status', '本地已就绪');
    assert.equal(new URL(page.url()).hash, '');
    assert.equal(await page.locator('#allowWrite').isChecked(), false);
    assert.equal(await page.locator('#startup').isChecked(), false);
    assert.equal(await page.locator('#clientBadge').textContent(), '尚未验证');
    assert.equal(await page.locator('#advancedRelay').getAttribute('open'), null);
  });
  await t.test('missing control token shows an actionable message in a separate browser context', async () => {
    const anonymous = await browser.newContext();
    try {
      const tab = await anonymous.newPage(); await tab.goto(`${app.origin}/developer`);
      await tab.waitForFunction(() => document.querySelector('#notice').textContent.includes('缺少本机访问令牌'));
      assert.equal(await tab.locator('#roots .root').count(), 0);
    } finally { await anonymous.close(); }
  });
  await t.test('sample content remains unchanged until the actual approval button is clicked', async () => {
    await page.locator('#demo').click(); await page.getByRole('button', { name: '确认写入', exact: true }).waitFor();
    const file = path.join(base, 'demo', 'hello-chat2local.txt'); const before = await fs.readFile(file, 'utf8');
    const proposed = await page.getByLabel('建议写入的完整内容').inputValue();
    assert.notEqual(before, proposed); assert.equal(await page.getByLabel('原文', { exact: true }).inputValue(), before);
    await page.getByRole('button', { name: '确认写入', exact: true }).click(); await waitText('#notice', '已写入');
    assert.equal(await fs.readFile(file, 'utf8'), proposed);
    assert.equal(await page.locator('#clientBadge').textContent(), '尚未验证');
  });
  await t.test('folder control, defaults, revoke and startup UI use explicit actions', async () => {
    // The Windows-native dialog and OS startup mutation are deliberately stubbed, not claimed tested here.
    await page.locator('#browse').click(); await page.waitForFunction(expected => document.querySelector('#folderPath').value === expected, root);
    await page.locator('#addFolder').click(); await waitText('#roots', 'example-project');
    const row = page.locator('.root').filter({ hasText: 'example-project' }); assert.match(await row.textContent(), /只读/);
    await row.getByRole('button', { name: '撤销授权' }).click(); await page.waitForFunction(() => !document.querySelector('#roots').textContent.includes('example-project'));
    await page.locator('#startup').check(); await waitText('#notice', '启动设置已更新'); assert.deepEqual(startup, [true]);
    await page.locator('#startup').uncheck(); await page.waitForFunction(() => !document.querySelector('#startup').checked); assert.deepEqual(startup, [true, false]);
  });
  await t.test('invitation preview is local only, bad invitation never sends enrollment', async () => {
    let enrollmentRequests = 0; page.on('request', request => { if (request.url().endsWith('/api/enroll')) enrollmentRequests++; });
    await page.locator('#invitation').fill(`https://trusted.invalid/#enroll=${'a'.repeat(64)}`);
    assert.match(await page.locator('#invitePreview').textContent(), /https:\/\/trusted.invalid/);
    assert.equal(enrollmentRequests, 0);
    await page.locator('#invitation').fill('not-an-invitation'); await page.locator('#connectInvite').click();
    await waitText('#notice', '邀请格式不正确'); assert.equal(enrollmentRequests, 0);
    await page.locator('#invitation').fill('');
  });
  await t.test('pause cancels pending suggestions and does not imply connection success', async () => {
    await page.locator('#demo').click(); await page.getByRole('button', { name: '确认写入', exact: true }).waitFor();
    await page.locator('#pause').click(); await waitText('#status', '已暂停');
    assert.equal(await page.locator('#pending .proposal').count(), 0);
    await page.locator('#pause').click(); await waitText('#status', '本地已就绪');
    await page.reload(); await waitText('#status', '本地已就绪');
    assert.equal(await page.locator('#clientBadge').textContent(), '尚未验证');
  });
  await t.test('network choices are optional, persist across reload and reject unsafe proxy input', async () => {
    await page.locator('#networkOptions > summary').click();
    assert.equal(await page.locator('#networkMode').inputValue(), 'auto');
    await page.locator('#networkMode').selectOption('proxy');
    await page.locator('#networkProxy').fill('socks5://localhost:7890');
    await page.locator('#saveNetwork').click(); await waitText('#notice', 'SOCKS');
    await page.locator('#networkMode').selectOption('direct');
    await page.locator('#saveNetwork').click(); await waitText('#notice', '网络选择已保存');
    await page.reload(); await waitText('#status', '本地已就绪');
    assert.equal(await page.locator('#networkMode').inputValue(), 'direct');
    assert.equal(await page.locator('#networkProxy').isDisabled(), true);
    await page.locator('#networkOptions > summary').click();
    await page.locator('#networkMode').selectOption('auto');
    await page.locator('#saveNetwork').click(); await waitText('#notice', '网络选择已保存');
    assert.equal(await page.locator('#clientBadge').textContent(), '尚未验证');
  });
  await t.test('desktop and narrow layouts do not overflow horizontally; screenshots saved', async () => {
    await fs.mkdir('.artifacts', { recursive: true });
    await page.screenshot({ path: '.artifacts/ui-desktop.png', fullPage: true });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
    await page.screenshot({ path: '.artifacts/ui-mobile.png', fullPage: true });
    assert.deepEqual(errors, []);
  });
  await t.test('exit is confirmed locally and really stops this HTTP listener', async () => {
    page.once('dialog', dialog => dialog.accept());
    await page.locator('#shutdown').click(); await waitText('#status', '已退出');
    await new Promise(resolve => setTimeout(resolve, 500));
    await assert.rejects(() => fetch(`${app.origin}/api/status`, { signal: AbortSignal.timeout(1500) }));
  });
});
