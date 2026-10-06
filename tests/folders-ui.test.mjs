import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import { chromium } from 'playwright-core';
import { annotateCoverage } from '../src/shared/share-tree.mjs';

const rootA = { rootId: 'a', label: 'Project Alpha', path: '/projects/alpha', mode: 'direct', locallyPresent: true, terminalAllowed: true };
const rootB = { rootId: 'b', label: 'Reference', path: '/projects/reference', mode: 'read-only', locallyPresent: true, terminalAllowed: false };
const rootC = { rootId: 'c', label: 'Tools', path: '/projects/tools', mode: 'direct', locallyPresent: true, terminalAllowed: false };
async function fixture(t, options = {}) {
  const calls = [], errors = [];
  let prepared, removal, consented = false, loginStartup = false;
  const connections = [
    { connectionId: 'a'.repeat(32), clientName: 'ChatGPT', callbackOrigin: 'https://chatgpt.com', scopes: ['files:read','files:write'], roots: structuredClone([rootA, rootB, rootC]) },
    ...(options.twoConnections ? [{ connectionId: 'b'.repeat(32), clientName: 'Other client', callbackOrigin: 'https://client.example.test', scopes: ['files:read','files:write','terminal:execute'], roots: [{ ...rootC, rootId: 'other-c', label: 'Other tools', path: '/other/tools', terminalAllowed: false }] }] : []),
  ];
  const assets = { '/folders': ['folders.html','text/html'], '/folders.js': ['folders.js','text/javascript'], '/folders.css': ['folders.css','text/css'] };
  const server = http.createServer((request, response) => {
    const asset = assets[request.url]; if (!asset) { response.writeHead(404); response.end(); return; }
    fs.readFile(path.join('src/agent/ui',asset[0])).then(bytes => { response.writeHead(200, { 'Content-Type': asset[1] }); response.end(bytes); });
  });
  let browser;
  t.after(async () => {
    try { await browser?.close(); }
    finally { await new Promise(resolve => server.close(resolve)); }
  });
  // Let the OS allocate an available loopback port atomically instead of
  // guessing a high port that Windows may refuse before the UI test starts.
  await new Promise((resolve, reject) => {
    const failed = error => reject(error);
    server.once('error', failed);
    server.listen(0, '127.0.0.1', () => { server.off('error', failed); resolve(); });
  });
  const origin = 'http://127.0.0.1:' + server.address().port;
  browser = await chromium.launch({ channel: 'msedge', headless: true });
  const page = await browser.newPage({ viewport: { width: 1360, height: 900 } });
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/api/**', async route => {
    const request = route.request(), action = new URL(request.url()).pathname.slice('/api/'.length);
    const input = request.postDataJSON() || {};
    calls.push({ action, input });
    const send = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (action === 'management/session') return send({ ready: true, expiresAt: Date.now() + 86400000 });
    if (action === 'status') return send({ name: 'chat2local', device: { name: 'TEST-DESKTOP', system: 'Windows', platform: 'win32' }, bridge: 'connected', paused: false, startup: loginStartup, startupAvailable: true, version: 'fixture', setupOrigin: 'https://instance.example.test' });
    const snapshot = () => connections.map(c => ({ ...c, roots: annotateCoverage(c.roots.map(r => ({ ...r, terminalLocalEnabled: r.terminalAllowed, terminalAllowed: Boolean(r.terminalAllowed && c.scopes.includes('terminal:execute')) })), 'linux') }));
    if (options.slowSync && ['shares/connections','terminal/permissions'].includes(action)) await new Promise(resolve => setTimeout(resolve, 450));
    if (action === 'management/startup') { assert.equal(typeof input.enabled, 'boolean'); loginStartup = input.enabled; return send({ enabled: loginStartup }); }
    if (action === 'shares/connections') return send({ connections: snapshot() });
    if (action === 'shares/removals') return send({ pending: [] });
    if (action === 'shares/remove-prepare') {
      const c = connections.find(c => c.connectionId === input.connectionId), r = c?.roots.find(r => r.rootId === input.rootId);
      removal = { ...input, requestId: 'e'.repeat(32), snapshotDigest: 'f'.repeat(64), folders: [r], target: r.path, includesOverlaps: false };
      return send(removal);
    }
    if (action === 'shares/remove-confirm') {
      assert.equal(input.confirmation, 'remove-shares-keep-files-v1'); assert.equal(input.snapshotDigest, removal.snapshotDigest);
      const c = connections.find(c => c.connectionId === removal.connectionId); c.roots = c.roots.filter(r => r.rootId !== removal.rootId);
      return send({ localRevoked: true, cloudSynced: true, filesDeleted: false });
    }
    if (action === 'terminal/permissions') return options.terminalError ? send({ error: 'fixture unavailable' }, 503) : send({ connections: snapshot() });
    if (action === 'terminal/set-permission') {
      const connection = connections.find(c => c.connectionId === input.connectionId), root = connection?.roots.find(r => r.rootId === input.rootId);
      if (!root) return send({ error: 'Unexpected target' }, 409);
      if (input.enabled && input.confirmation !== 'allow-unsandboxed-terminal-v1') return send({ error: 'No consent' }, 403);
      root.terminalAllowed = input.enabled;
      return send({ saved: true, enabled: input.enabled, oauthScopeGranted: connection.scopes.includes('terminal:execute') });
    }
    if (action === 'folder/browse') {
      if (options.slowBrowse && input.path === '/stale') { await new Promise(resolve => setTimeout(resolve, 250)); }
      const current = input.path || '/projects';
      return send({ path: current, parent: '/', selectable: true, locations: [{ label: '项目', path: '/projects' }], entries: [{ name: 'Project Alpha', path: '/projects/alpha' }, { name: 'New project', path: current + '/new' }, { name: 'New reference', path: current + '/ref' }], truncated: false });
    }
    if (action === 'shares/prepare') {
      prepared = { ...input, selections: input.folders.map(f => ({ ...f })), deviceName: 'TEST-DESKTOP', clientName: 'ChatGPT', callbackOrigin: 'https://chatgpt.com', snapshotDigest: 'd'.repeat(64), requiresConsent: !consented, connected: consented };
      if (options.mismatch) prepared.selections[0].path = '/changed/server/path';
      return send(prepared);
    }
    if (action === 'shares/confirm') {
      assert.ok(prepared); assert.equal(input.confirmation, prepared.accessProfile === 'project' ? 'allow-project-files-and-terminal-v1' : 'allow-shared-folders-v1');
      if (options.unknownOutcome) return route.abort('failed');
      consented = true;
      for (const [i, f] of prepared.selections.entries()) connections[0].roots.push({ rootId: 'added-' + i, label: path.posix.basename(f.path), path: f.path, mode: f.mode, locallyPresent: true, terminalAllowed: prepared.accessProfile === 'project' });
      prepared = { ...prepared, requiresConsent: false, connected: true }; return send(prepared);
    }
    if (action === 'shares/status' || action === 'shares/resume') {
      if (options.unknownOutcome) return send({ error: '结果暂不可用' }, 503);
      return send(prepared);
    }
    return send({ error: 'Unexpected route: ' + action }, 400);
  });
  await page.goto(origin + '/folders#' + 'a'.repeat(64));
  await page.waitForFunction(() => document.querySelectorAll('.shared-row').length >= 3);
  await fs.mkdir('.artifacts/ui-review', { recursive: true });
  return { page, calls, errors, connections, origin };
}
test('unchanged background polls keep row/button identity, focus, opacity and expanded shares stable', async t => {
  const { page, calls, connections } = await fixture(t, { slowSync: true });
  connections[0].roots.push({ ...rootC, rootId: 'child', path: '/projects/tools/child', label: 'Child' });
  await page.locator('#refresh').click();
  await page.locator('.covered-shares summary').click();
  const button = page.getByRole('button', { name: '移除共享 Tools', exact: true });
  await button.focus();
  await page.evaluate(() => {
    window.retainedRow = document.querySelector('[data-root-id="c"]');
    window.retainedButton = document.activeElement;
    window.disabledChanges = 0; window.rowChanges = 0;
    new MutationObserver(records => { window.disabledChanges += records.filter(r => r.attributeName === 'disabled' && r.oldValue !== r.target.getAttribute('disabled')).length; }).observe(document.querySelector('main'), { attributes: true, attributeOldValue: true, subtree: true, attributeFilter: ['disabled'] });
    new MutationObserver(records => { window.rowChanges += records.length; }).observe(document.querySelector('#shared'), { childList: true, subtree: true });
  });
  const count = calls.filter(c => c.action === 'shares/connections').length;
  await page.waitForTimeout(11200);
  assert.ok(calls.filter(c => c.action === 'shares/connections').length >= count + 2);
  assert.deepEqual(await page.evaluate(() => ({ row: window.retainedRow === document.querySelector('[data-root-id="c"]'), button: window.retainedButton === document.activeElement, expanded: document.querySelector('.covered-shares').open, opacity: getComputedStyle(document.activeElement).opacity, disabled: window.disabledChanges, mutations: window.rowChanges })), { row: true, button: true, expanded: true, opacity: '1', disabled: 0, mutations: 0 });
});

test('lifecycle controls show partial capability honestly and login startup changes only on a user decision', async t => {
  const { page, calls } = await fixture(t);
  const row = page.locator('.shared-row').first();
  assert.equal(await row.getByText('可读写', { exact: true }).count(), 1);
  assert.equal(await row.getByText('命令待授权', { exact: true }).count(), 1);
  await page.locator('#authorization-help').click();
  await page.locator('#authorization-dialog').waitFor({ state: 'visible' });
  await page.locator('#authorization-done').click();
  await page.locator('#lifecycle summary').click();
  assert.equal(await page.locator('#login-startup').isChecked(), false);
  assert.equal(calls.filter(c => c.action === 'management/startup').length, 0);
  assert.equal(await page.locator('#daily-entry').inputValue(), '%LOCALAPPDATA%\\Chat2Local\\Chat2Local.cmd');
  assert.match(await page.locator('#update-command').inputValue(), /-Instance 'https:\/\/instance\.example\.test'/);
  await page.locator('#login-startup').check();
  await page.waitForFunction(() => !document.querySelector('#login-startup').disabled);
  assert.equal(await page.locator('#login-startup').isChecked(), true);
  assert.equal(calls.filter(c => c.action === 'management/startup').length, 1);
  assert.equal(calls.filter(c => /set-permission|shares\/confirm/.test(c.action)).length, 0);
});
async function openAndSelect(page) {
  await page.locator('#open-add').click();
  await page.getByRole('checkbox', { name: '加入待授权列表 New project', exact: true }).check();
}

test('automatic polling refreshes changed connection scopes without granting anything or user clicks', async t => {
  const {page,connections,calls} = await fixture(t);
  const before = calls.filter(c => c.action === 'shares/connections').length;
  connections[0].scopes.push('terminal:execute');
  await page.waitForFunction(() => document.querySelector('.project-permission')?.textContent.includes('完整共享'), { timeout: 12000 });
  assert.ok(calls.filter(c => c.action === 'shares/connections').length > before);
  assert.equal(calls.filter(c => /confirm|set-permission/.test(c.action)).length, 0);
  assert.equal(await page.getByRole('button', { name: '关闭终端 Project Alpha', exact: true }).count(), 0);
});
test('removal requires confirmation, retains disk-files wording, then removes exactly the selected row', async t => {
  const {page,calls,errors} = await fixture(t);
  await page.getByRole('button', { name: '移除共享 Tools', exact: true }).click();
  await page.locator('#confirm-remove').waitFor({state:'visible'});
  await page.locator('#cancel-remove').click();
  assert.equal(calls.filter(c => c.action === 'shares/remove-confirm').length,0);
  assert.equal(await page.locator('.shared-row').count(),3);
  await page.getByRole('button', { name: '移除共享 Tools', exact: true }).click();
  await page.locator('#confirm-remove').click();
  await page.waitForFunction(() => document.querySelectorAll('.shared-row').length === 2);
  assert.equal(calls.filter(c => c.action === 'shares/remove-confirm').length,1);
  assert.match(await page.locator('#message-text').innerText(), /磁盘文件保留/);
  assert.deepEqual(errors,[]);
});

test('compact dashboard shows each directory once; picker/details stay closed with no unsolicited browse or mutation', async t => {
  const f = await fixture(t), { page, calls } = f;
  assert.equal(await page.locator('#folder-dialog').isVisible(), false);
  assert.equal(await page.locator('#connection-picker').isVisible(), false);
  assert.equal(await page.locator('#message').isVisible(), false);
  assert.equal(await page.locator('#details').evaluate(el => el.open), false);
  assert.equal(await page.getByText('/projects/alpha', { exact: true }).count(), 1);
  assert.equal(calls.filter(c => c.action === 'folder/browse').length, 0);
  assert.equal(calls.filter(c => /confirm|prepare|set-permission/.test(c.action)).length, 0);
  assert.equal(await page.locator('.shared-row').first().getByText('命令待授权', { exact: true }).count(), 1);
  assert.ok(await page.evaluate(() => document.documentElement.scrollHeight <= 900));
  await page.screenshot({ path: '.artifacts/ui-review/after-fixture-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.screenshot({ path: '.artifacts/ui-review/after-fixture-narrow.png', fullPage: true });
  assert.deepEqual(f.errors, []);
});

test('one complete-share decision batches two displayed folders without auto-upgrading old roots', async t => {
  const { page, calls, errors } = await fixture(t);
  await openAndSelect(page);
  await page.getByRole('checkbox', { name: '加入待授权列表 New reference', exact: true }).check();
  assert.equal(await page.locator('#pending select').count(), 0);
  assert.match(await page.locator('#editor .consent').innerText(), /目录外文件/);
  assert.equal(calls.filter(c => c.action === 'shares/prepare' || c.action === 'shares/confirm').length, 0);
  assert.equal(await page.getByRole('checkbox', { name: '加入待授权列表 Project Alpha', exact: true }).isDisabled(), true);
  await page.screenshot({ path: '.artifacts/ui-review/add-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.locator('#folder-dialog').evaluate(el => el.scrollWidth <= el.clientWidth), true);
  await page.screenshot({ path: '.artifacts/ui-review/add-narrow.png', fullPage: true });
  await page.locator('#prepare').click(); await page.locator('#done').waitFor({ state: 'visible' });
  assert.equal(calls.filter(c => c.action === 'shares/confirm').length, 1);
  assert.deepEqual(calls.find(c => c.action === 'shares/prepare').input.folders, [{ path: '/projects/new', mode: 'direct' }, { path: '/projects/ref', mode: 'direct' }]);
  await page.locator('#another').click();
  assert.equal(await page.locator('#folder-dialog').isVisible(), false);
  assert.equal(await page.locator('.shared-row').count(), 5);
  assert.deepEqual(errors, []);
});

test('cancel, deselect and keyboard dismissal grant nothing and leave no misleading checkmarks', async t => {
  const { page, calls } = await fixture(t);
  await openAndSelect(page);
  await page.getByRole('button', { name: '移除 new', exact: true }).click();
  assert.equal(await page.getByRole('checkbox', { name: '加入待授权列表 New project', exact: true }).isChecked(), false);
  await page.keyboard.press('Escape'); assert.equal(await page.locator('#folder-dialog').isVisible(), false);
  assert.equal(calls.filter(c => /confirm|prepare|set-permission/.test(c.action)).length, 0);
});

test('changed server snapshot requires review; the prior Add click cannot authorize an undisplayed path', async t => {
  const { page, calls } = await fixture(t, { mismatch: true });
  await openAndSelect(page); await page.locator('#prepare').click();
  await page.locator('#review').waitFor({ state: 'visible' });
  assert.equal(calls.filter(c => c.action === 'shares/confirm').length, 0);
  assert.match(await page.locator('#summary').innerText(), /\/changed\/server\/path/);
  await page.locator('#back-edit').click();
  assert.equal(await page.locator('#editor').isVisible(), true);
  await page.locator('#cancel-add').click();
});

test('uncertain consent stays pending, never shows success or submits twice', async t => {
  const { page, calls } = await fixture(t, { unknownOutcome: true });
  await openAndSelect(page); await page.locator('#prepare').click();
  await page.locator('#recovering').waitFor({ state: 'visible' });
  await page.locator('#retry-result').click();
  assert.equal(await page.locator('#done').isVisible(), false);
  assert.equal(calls.filter(c => c.action === 'shares/confirm').length, 1);
  assert.ok(await page.evaluate(() => sessionStorage.getItem('chat2local-folder-draft')));
});

test('terminal warning is contextual; cancel grants nothing and enable preserves independent OAuth status', async t => {
  const { page, calls, errors } = await fixture(t);
  await page.getByRole('button', { name: '升级共享 Tools', exact: true }).click();
  await page.locator('#terminal-dialog').waitFor({ state: 'visible' });
  assert.match(await page.locator('#terminal-dialog .warning').innerText(), /目录外文件/);
  assert.equal(calls.filter(c => c.action === 'terminal/set-permission').length, 0);
  await page.screenshot({ path: '.artifacts/ui-review/terminal-confirm.png', fullPage: true });
  await page.locator('#cancel-terminal').click();
  await page.getByRole('button', { name: '升级共享 Tools', exact: true }).click();
  await page.locator('#confirm-terminal').click();
  await page.waitForFunction(() => !document.querySelector('#terminal-dialog').open);
  assert.equal(calls.filter(c => c.action === 'terminal/set-permission').length, 1);
  assert.equal(await page.locator('.shared-row').filter({ has: page.getByText('Tools', { exact: true }) }).getByText('命令待授权', { exact: true }).count(), 1);
  assert.equal(calls.some(c => c.action.startsWith('terminal_execute')), false);
  assert.deepEqual(errors, []);
});

test('switching connections refreshes row terminal targets instead of keeping the previous connection', async t => {
  const { page, calls } = await fixture(t, { twoConnections: true });
  await page.locator('#connection').selectOption('b'.repeat(32));
  await page.getByRole('button', { name: '升级共享 Other tools', exact: true }).click();
  await page.locator('#confirm-terminal').click();
  await page.waitForFunction(() => !document.querySelector('#terminal-dialog').open);
  const changed = calls.filter(c => c.action === 'terminal/set-permission');
  assert.equal(changed.length, 1); assert.equal(changed[0].input.connectionId, 'b'.repeat(32)); assert.equal(changed[0].input.rootId, 'other-c');
});

test('terminal lookup failure is unknown rather than a false disabled/authorized state', async t => {
  const { page } = await fixture(t, { terminalError: true });
  assert.equal(await page.getByText('未读取', { exact: true }).count(), 2);
  assert.equal(await page.getByRole('button', { name: '升级共享 Tools', exact: true }).isDisabled(), true);
  assert.match(await page.locator('#message-text').innerText(), /读取失败/);
});

test('late folder results cannot change the selected path or grant a folder after dismissal', async t => {
  const { page, calls } = await fixture(t, { slowBrowse: true });
  await page.locator('#open-add').click();
  await page.locator('#path').fill('/stale'); await page.locator('#browse').click();
  await page.locator('#path').fill('/desired');
  await page.waitForTimeout(400);
  assert.equal(await page.locator('#path').inputValue(), '/desired');
  assert.equal(await page.locator('#add-current').isDisabled(), true);
  await page.locator('#cancel-add').click();
  assert.equal(calls.filter(c => /confirm|prepare|set-permission/.test(c.action)).length, 0);
});
