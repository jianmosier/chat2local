import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright-core';
import { Store } from '../src/agent/store.mjs';
import { startController } from '../src/agent/main.mjs';

async function fixture(t, configured) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-account-entry-'));
  const store = new Store(path.join(base, 'private')), origin = 'https://relay.example.test';
  const network = { prepare: async () => {}, status: () => ({ mode: 'fixture', source: 'isolated-test' }), close() {} };
  const app = await startController({ port: 0, store, defaultRelay: origin, network, setupFetch: async () => Response.json({ name: 'chat2local-relay', version: '0.1.0-alpha.13', setupVersion: 1, browserHandoff: true, accountConnections: true, accountLoginConfigured: configured, accountEnrollment: true }) });
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  t.after(async () => { await browser.close(); await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  return { store, app, browser, origin };
}

test('fresh default launcher page enters the same configured account flow before granting a directory', async t => {
  const f = await fixture(t, true), context = await f.browser.newContext(), page = await context.newPage();
  let legacyConsents = 0, entryGets = 0;
  page.on('request', request => { if (/\/api\/(root\/add|guide\/authorize|setup\/start)$/.test(new URL(request.url()).pathname)) legacyConsents++; });
  await context.route(f.origin + '/account/add', async route => {
    entryGets++; assert.equal(route.request().method(), 'GET');
    assert.equal(route.request().headers()['x-chat2local-token'], undefined);
    assert.equal(route.request().url().includes(f.app.token), false);
    await route.fulfill({ status: 200, contentType: 'text/html', body: '<h1>Fixture account sign-in entry reached</h1>' });
  });
  await page.goto(f.app.origin + '/#' + f.app.token);
  await page.getByRole('heading', { name: 'Fixture account sign-in entry reached' }).waitFor();
  assert.equal(entryGets, 1); assert.equal(legacyConsents, 0); assert.equal(context.pages().length, 1);
  const saved = await f.store.load(); assert.deepEqual(saved.config.roots, []); assert.equal(saved.config.accountRoots, undefined); assert.deepEqual(saved.secrets, {});
});

test('unconfigured account provider blocks the old grant path instead of asking the user for secrets', async t => {
  const f = await fixture(t, false), page = await f.browser.newPage();
  await page.goto(f.app.origin + '/#' + f.app.token);
  await page.waitForFunction(() => document.getElementById('notice').textContent.includes('尚未由维护者配置'));
  assert.equal(await page.locator('#choose').isDisabled(), true);
  assert.equal(await page.locator('#primary').isDisabled(), true);
  assert.deepEqual((await f.store.load()).config.roots, []);
});
