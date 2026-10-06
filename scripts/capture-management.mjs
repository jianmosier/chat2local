import fs from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright-core';
import { Store } from '../src/agent/store.mjs';
import { localNetworkOnly } from '../src/agent/network.mjs';

// Read-only visual inspection of this installation. Never click a permission
// control, print the control token or publish screenshots with private paths.
const name = process.argv[2];
const preview = process.argv[3] === '--preview';
if (process.argv.length > (preview ? 4 : 3)) throw Error('Unexpected capture argument.');
if (!/^[a-z0-9-]+$/.test(name || '')) throw Error('Use a simple capture label.');
localNetworkOnly();
const store = new Store(), session = await store.readSession();
if (session.origin !== 'http://127.0.0.1:47631' || !/^[a-f0-9]{64}$/.test(session.token || '')) throw Error('Unexpected local endpoint.');
const before = JSON.stringify(await store.load());
const response = await fetch(session.origin + '/api/status', { headers: { 'X-Chat2Local-Token': session.token }, redirect: 'error', signal: AbortSignal.timeout(3000) });
const state = await response.json();
if (!response.ok || state.name !== 'chat2local' || state.instanceId !== session.instanceId) throw Error('Local app was not verified.');
const browser = await chromium.launch({ channel: 'msedge', headless: true });
const output = path.join('.artifacts', 'ui-review'); await fs.mkdir(output, { recursive: true });
try {
  const page = await browser.newPage({ viewport: { width: 1360, height: 900 } });
  if (preview) {
    // Visual test only: render reviewed source over READ-ONLY status from the
    // unchanged installed app. No substitute controller or mutation is allowed.
    const assets = { '/folders': ['folders.html','text/html'], '/folders.js': ['folders.js','text/javascript'], '/folders.css': ['folders.css','text/css'] };
    await page.route(session.origin + '/**', async route => {
      const request = route.request(), resource = new URL(request.url()).pathname, asset = assets[resource];
      if (asset && request.method() === 'GET') return route.fulfill({ status: 200, contentType: asset[1], body: await fs.readFile(path.join('src/agent/ui', asset[0])) });
      if ((resource === '/api/status' && request.method() === 'GET') || (['/api/shares/connections','/api/terminal/permissions'].includes(resource) && request.method() === 'POST')) return route.continue();
      return route.abort('blockedbyclient');
    });
  }
  await page.goto(session.origin + '/folders#' + session.token);
  await page.waitForFunction(() => document.querySelector('#connection')?.options.length > 0);
  await page.waitForTimeout(800);
  const desktopHeight = await page.evaluate(() => document.documentElement.scrollHeight);
  await page.screenshot({ path: path.join(output, name + '-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: path.join(output, name + '-narrow.png'), fullPage: true });
  if (JSON.stringify(await store.load()) !== before) throw Error('Local settings changed during inspection; not attributed to screenshot actions.');
  console.log(JSON.stringify({ captured: true, label: name, sourcePreview: preview, installedVersion: state.version, desktopHeight, settingsUnchanged: true }));
} finally { await browser.close(); }
