import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import { chromium } from 'playwright-core';
import { closeBrowserFixture } from './browser-cleanup-fixture.mjs';

test('native management panel distinguishes faults and handles unavailable browser storage', { timeout: 90000 }, async t => {
  const html = await fs.readFile(new URL('../crates/agent-controller/ui/index.html', import.meta.url));
  const script = await fs.readFile(new URL('../crates/agent-controller/ui/panel.js', import.meta.url));
  const token = 'a'.repeat(64), calls = [];
  let status, browser, browserServer;
  const browserState = { exitObserved: false, closeObserved: false, stdoutEnded: false, stderrEnded: false };
  const server = http.createServer(async (req, res) => {
    const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
    const send = (value, code = 200) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
    if (pathname.startsWith('/api/')) {
      if (req.headers['x-chat2local-token'] !== token) return send({ error: 'Fixture authorization required' }, 401);
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks)) : undefined;
      calls.push({ route: pathname, method: req.method, body });
      if (pathname === '/api/status') return send(status);
      if (pathname === '/api/guide') return send({ stage: 'connect' });
      if (pathname === '/api/pause') { if (status.nativeFault) return send({ error: 'Fixture permanent fault' }, 409); status.paused = body.paused; return send({ ok: true }); }
      if (pathname === '/api/root/remove') { status.roots = status.roots.filter(root => root.id !== body.id); return send({ ok: true }); }
      if (pathname === '/api/shutdown') return send({ ok: true });
      return send({ error: 'Unexpected fixture operation' }, 400);
    }
    if (pathname === '/native-panel.js') { res.writeHead(200, { 'Content-Type': 'text/javascript' }); return res.end(script); }
    if (pathname === '/native-panel.css') { res.writeHead(200, { 'Content-Type': 'text/css' }); return res.end(''); }
    res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(pathname === '/shares' ? '<main id="sharing-ready">Fixture sharing page</main>' : html);
  });
  t.after(async () => {
    const outcomes = [];
    async function cleanup(name, work, ms) {
      let timer; const record = { name, confirmed: false }; outcomes.push(record);
      await Promise.race([Promise.resolve().then(work).then(() => { record.confirmed = true; }, () => {}), new Promise(resolve => { timer = setTimeout(resolve, ms); })]);
      clearTimeout(timer);
    }
    await closeBrowserFixture(browser, browserServer, browserState, cleanup);
    await cleanup('fixture-http', () => new Promise((resolve, reject) => { server.close(error => error && error.code !== 'ERR_SERVER_NOT_RUNNING' ? reject(error) : resolve()); server.closeAllConnections(); }), 3000);
    assert.ok(outcomes.every(item => item.confirmed), JSON.stringify(outcomes));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  browserServer = await chromium.launchServer({ channel: 'msedge', headless: true, host: '127.0.0.1', timeout: 30000 });
  const child = browserServer.process(); browserState.stdoutEnded = !child.stdout; browserState.stderrEnded = !child.stderr;
  child.once('exit', () => { browserState.exitObserved = true; }); child.once('close', () => { browserState.closeObserved = true; });
  child.stdout?.once('end', () => { browserState.stdoutEnded = true; }); child.stderr?.once('end', () => { browserState.stderrEnded = true; });
  browser = await chromium.connect(browserServer.wsEndpoint(), { timeout: 30000 });
  async function open(blockStorage = false) {
    calls.length = 0;
    status = { paused: true, nativeFault: false, bridge: 'connected', startupAvailable: true, startup: false, roots: [], pending: [], events: [] };
    const context = await browser.newContext();
    if (blockStorage) await context.addInitScript(() => { Storage.prototype.setItem = () => { throw new DOMException('Fixture storage denied', 'SecurityError'); }; });
    const page = await context.newPage(), errors = []; page.on('pageerror', error => errors.push(error.name));
    return { context, page, errors, ready: async () => { await page.goto(origin + '/#' + token); await idle(page); } };
  }
  const idle = page => page.waitForFunction(() => document.querySelector('#controls').getAttribute('aria-busy') === 'false');
  await t.test('ordinary pause remains resumable', async () => {
    const f = await open(); await f.ready();
    assert.equal(await f.page.locator('#pause').isEnabled(), true);
    await f.page.locator('#pause').click(); await idle(f.page);
    assert.deepEqual(calls.filter(c => c.route === '/api/pause').map(c => c.body), [{ paused: false }]);
    assert.equal(await f.page.locator('#pause').textContent(), '暂停远程访问');
    await f.context.close();
  });
  await t.test('permanent fault stays disabled after refresh; restriction and Quit remain available', async () => {
    const f = await open(); status.nativeFault = true; status.bridge = 'failed'; status.lifecycleWarning = 'Fixture lifecycle warning';
    status.roots = [{ id: 'fixture-root', label: 'Fixture', path: '/fixture-project', writeMode: 'read-only' }]; await f.ready();
    assert.match(await f.page.locator('#connection').textContent(), /永久故障.*正常退出并重新启动.*Fixture lifecycle warning/);
    assert.equal(await f.page.locator('#pause').isDisabled(), true);
    await f.page.locator('#pause').evaluate(button => button.onclick());
    await f.page.locator('#refresh').click(); await idle(f.page);
    assert.equal(await f.page.locator('#pause').isDisabled(), true);
    assert.equal(calls.some(c => c.route === '/api/pause'), false);
    await f.page.getByRole('button', { name: '移除授权', exact: true }).click(); await idle(f.page);
    assert.deepEqual(calls.filter(c => c.route === '/api/root/remove').map(c => c.body), [{ id: 'fixture-root' }]);
    await f.page.locator('#quit').click(); await f.page.waitForFunction(() => document.querySelector('#controls').hidden);
    assert.equal(calls.filter(c => c.route === '/api/shutdown').length, 1);
    assert.deepEqual(f.errors, []); await f.context.close();
  });
  await t.test('sharing preserves normal session handoff without putting a token in the target URL', async () => {
    const f = await open(); await f.ready(); await f.page.locator('#manage-shares').click();
    await f.page.locator('#sharing-ready').waitFor(); assert.equal(f.page.url(), origin + '/shares');
    assert.equal(await f.page.evaluate(() => sessionStorage.getItem('chat2local-control')), token);
    assert.equal(calls.some(c => c.method === 'POST'), false); await f.context.close();
  });
  await t.test('blocked storage produces an actionable message without navigation, permission calls or page errors', async () => {
    const f = await open(true); await f.ready(); await f.page.locator('#manage-shares').click();
    assert.match(await f.page.locator('#message').textContent(), /禁止本地会话存储.*本机启动入口/);
    assert.equal(f.page.url(), origin + '/'); assert.equal(calls.some(c => c.method === 'POST'), false);
    assert.deepEqual(f.errors, []); await f.context.close();
  });
});
