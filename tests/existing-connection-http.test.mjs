import { relayEntry, relayRuntime } from './relay-runtime.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { chromium } from 'playwright-core';
import { startController } from '../src/agent/main.mjs';
import { Store } from '../src/agent/store.mjs';
import { setTimeout as delay } from 'node:timers/promises';
import { closeBrowserFixture } from './browser-cleanup-fixture.mjs';

const secret = () => randomBytes(32).toString('hex');
async function data(response, status = 200) { assert.equal(response.status, status, 'Unexpected fixture response status.'); return response.json(); }
async function until(check, signal) { const end = Date.now() + 15000; while (Date.now() < end) { signal.throwIfAborted(); if (await check()) return; await delay(50, undefined, { signal }); } throw new Error('Fixture did not become ready.'); }
function observed(work, signal, timeout = 30000) {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(timeout)]);
  return new Promise((resolve, reject) => {
    const abort = () => reject(Object.assign(Error('Fixture deadline reached.'), { name: 'AbortError' }));
    deadline.addEventListener('abort', abort, { once: true });
    if (deadline.aborted) { abort(); return; }
    Promise.resolve().then(work).then(resolve, reject).finally(() => deadline.removeEventListener('abort', abort));
  });
}
function failureDetails(stage, error) {
  return { stage, name: ['Error', 'AssertionError', 'TimeoutError', 'AbortError'].includes(error?.name) ? error.name : 'Error', frames: String(error?.stack || '').split('\n').filter(line => /^\s+at /.test(line)).map(line => line.match(/([^\\/()\s]+\.(?:mjs|js)):(\d+):(\d+)/)?.slice(1).join(':')).filter(Boolean).slice(0, 8) };
}
async function controller(options) {
  return startController({ ...options, port: 0 });
}

test('original enrolled Windows recovery: NO invitation, NO picker, ONE client consent, unchanged directories/identity and real scoped read/write', { timeout: 120000 }, async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-existing-http-'));
  let stage = 'setup', app, mf, browser, browserServer, callbackServer;
  const browserState = { exitObserved: false, closeObserved: false, stdoutEnded: false, stderrEnded: false };
  const note = value => process.stdout.write('existing-http-' + value + '\n');
  const mark = value => { stage = value; note('stage:' + value); };
  const request = (url, options = {}) => fetch(url, { ...options, signal: AbortSignal.any([t.signal, AbortSignal.timeout(30000), ...(options.signal ? [options.signal] : [])]) });
  const poll = check => observed(() => until(check, t.signal), t.signal);
  t.after(async () => {
    const outcomes = [];
    async function cleanup(name, work, timeout) {
      const record = { name, outcome: 'pending' }; outcomes.push(record);
      let timer;
      const task = Promise.resolve().then(work).then(() => { record.outcome = 'confirmed'; }, () => { record.outcome = 'failed'; });
      await Promise.race([task, new Promise(resolve => { timer = setTimeout(() => { record.deadlineReached = true; resolve(); }, timeout); })]);
      clearTimeout(timer); note('cleanup:' + name + ':' + record.outcome);
    }
    await closeBrowserFixture(browser, browserServer, browserState, cleanup);
    note('cleanup:browser-observation:' + JSON.stringify(browserState));
    await cleanup('controller', () => app?.close(), 8000);
    await cleanup('callback', () => callbackServer && new Promise((resolve, reject) => { callbackServer.close(error => error && error.code !== 'ERR_SERVER_NOT_RUNNING' ? reject(error) : resolve()); callbackServer.closeAllConnections(); }), 3000);
    await cleanup('miniflare', () => mf?.dispose(), 8000);
    if (outcomes.every(record => record.outcome === 'confirmed')) await cleanup('temporary-state', () => fs.rm(base, { recursive: true, force: true }), 3000);
    else note('cleanup:temporary-state:retained');
    assert.ok(outcomes.every(record => record.outcome === 'confirmed'), 'Fixture cleanup was not confirmed; temporary state was retained.');
  });
  try {
  mark('create-controller');
  const project = path.join(base, 'actual-project'), reference = path.join(base, 'reference-read-only');
  await fs.mkdir(project); await fs.mkdir(reference); await fs.writeFile(path.join(reference, 'reference.txt'), 'Keep read-only\n');
  const store = new Store(path.join(base, 'private'));
  let pickerCalls = 0, nativeConfirms = 0, cloudActivations = 0, lostActivation = false;
  app = await controller({ store, allowLocalRelay: true, pickFolder: async () => { pickerCalls++; throw new Error('Existing recovery must never open a picker'); }, accountFetch: async (url, options) => {
    if (url.endsWith('/confirm')) nativeConfirms++;
    if (url.endsWith('/activate')) cloudActivations++;
    const response = await request(url, options);
    if (url.endsWith('/activate') && response.ok && !lostActivation) { lostActivation = true; await response.text(); throw new Error('Fixture: lost committed activation reply'); }
    return response;
  } });
  mark('create-relay');
  const bundle = await build({ entryPoints: [await relayEntry()], bundle: true, write: false, format: 'esm', platform: 'neutral', mainFields: ['module', 'main'], external: ['cloudflare:workers', '*.wasm'] });
  const enrollmentKey = secret();
  mf = new Miniflare(convertV4MiniflareOptions({ ...await relayRuntime(bundle), host: '127.0.0.1', port: 0, compatibilityDate: '2026-09-20', compatibilityFlags: ['nodejs_compat', 'global_fetch_strictly_public'], kvNamespaces: ['OAUTH_KV'], durableObjects: { DEVICES: { className: 'Device', useSQLite: true }, REGISTRY: { className: 'Registry', useSQLite: true } }, bindings: { ALLOW_LOOPBACK: 'true', PRIVATE_INSTANCE: 'true', ENROLLMENT_KEY: enrollmentKey, TEST_RECOVERY_ORIGIN: app.origin } }));
  const origin = (await observed(() => mf.ready, t.signal)).origin;
  const local = (route, body) => request(app.origin + '/api/' + route, { method: body === undefined ? 'GET' : 'POST', headers: { 'X-Chat2Local-Token': app.token, Origin: app.origin, 'Content-Type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  // The OLD, operator-enrolled installation and user-selected projects are fixtures.
  // No private invitation, IdP session or file access token is inserted by this test.
  const writable = await data(await local('root/add', { path: project, writeMode: 'direct', confirmDirect: true }));
  const readonly = await data(await local('root/add', { path: reference, writeMode: 'read-only' }));
  await data(await local('enroll', { origin, enrollmentToken: enrollmentKey }));
  await poll(() => app.bridge.state === 'connected');
  const before = await store.load(); assert.equal(before.secrets.privateInstanceInvitation, undefined);
  mark('create-client-callback');
  callbackServer = http.createServer((_request, response) => { response.writeHead(200, { 'Content-Type': 'text/plain' }); response.end('Original client callback'); });
  await new Promise((resolve, reject) => { callbackServer.once('error', reject); callbackServer.listen(0, '127.0.0.1', () => { callbackServer.removeListener('error', reject); resolve(); }); });
  const callback = `http://127.0.0.1:${callbackServer.address().port}/callback`;
  const client = await data(await request(origin + '/oauth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client_name: 'Original test client', redirect_uris: [callback], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] }) }), 201);
  const verifier = secret(), state = secret();
  const query = new URLSearchParams({ client_id: client.client_id, redirect_uri: callback, response_type: 'code', scope: 'files:read files:write offline_access', state, code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url'), resource: origin + '/mcp' });
  mark('open-recovery-page');
  browserServer = await chromium.launchServer({ channel: 'msedge', headless: true, host: '127.0.0.1', timeout: 30000 });
  const ownedBrowser = browserServer.process();
  browserState.stdoutEnded = !ownedBrowser.stdout;
  browserState.stderrEnded = !ownedBrowser.stderr;
  ownedBrowser.once('exit', () => { browserState.exitObserved = true; });
  ownedBrowser.once('close', () => { browserState.closeObserved = true; });
  ownedBrowser.stdout?.once('end', () => { browserState.stdoutEnded = true; });
  ownedBrowser.stderr?.once('end', () => { browserState.stderrEnded = true; });
  browser = await chromium.connect(browserServer.wsEndpoint(), { timeout: 30000 });
  const context = await browser.newContext({ viewport: { width: 390, height: 900 } }), page = await context.newPage();
  const errors = []; page.on('pageerror', e => errors.push(failureDetails('browser-script', e).name));
  let approvalPosts = 0;
  page.on('request', request => { if (new URL(request.url()).pathname === '/instance-connect/confirm') approvalPosts++; });
  await page.goto(origin + '/authorize?' + query);
  await page.locator('#account-confirm').waitFor({ state: 'visible', timeout: 20000 });
  assert.equal(await page.locator('h1').textContent(), '恢复已有连接');
  assert.equal(await page.locator('#account-choose').isHidden(), true);
  assert.equal(pickerCalls, 0); assert.equal(nativeConfirms, 0); assert.equal(cloudActivations, 0);
  const displayed = await page.locator('#account-folder').textContent();
  assert.ok(displayed.includes(project)); assert.ok(displayed.includes(reference)); assert.ok(displayed.includes('只读'));
  assert.equal(displayed.includes('Chat2LocalDemo'), false);
  assert.deepEqual((await store.load()).config, before.config);
  assert.deepEqual((await store.load()).secrets, before.secrets);
  const flow = await page.evaluate(() => JSON.parse(sessionStorage.getItem('chat2local-instance-flow')));
  const flowId = flow.flow.split('.')[0];
  const counterfeit = await request(origin + '/instance/native/start', { method: 'POST', headers: { Authorization: 'Bearer ' + secret(), 'Content-Type': 'application/json' }, body: JSON.stringify({ flowId, secret: flow.flow.split('.')[1], deviceId: before.secrets.identity.deviceId, input: { sessionSecret: secret(), reuseExisting: true } }) });
  assert.equal(counterfeit.status, 401);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  await fs.mkdir('.artifacts', { recursive: true });
  await page.screenshot({ path: '.artifacts/existing-connection-recovery.png', fullPage: true });
  mark('confirm-original-recovery');
  await page.getByRole('button', { name: '确认以上范围并恢复连接', exact: true }).click();
  mark('wait-original-callback');
  await page.waitForURL(callback + '*', { timeout: 30000 });
  assert.equal(approvalPosts, 1); assert.equal(nativeConfirms, 1); assert.equal(cloudActivations, 1); assert.equal(pickerCalls, 0); assert.equal(context.pages().length, 1);
  const returned = new URL(page.url()); assert.equal(returned.searchParams.get('state'), state);
  mark('exchange-file-token');
  const tokens = await data(await request(origin + '/oauth/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: client.client_id, redirect_uri: callback, code: returned.searchParams.get('code'), code_verifier: verifier, resource: origin + '/mcp' }) }));
  const call = async (name, args = {}) => (await data(await request(origin + '/mcp', { method: 'POST', headers: { Authorization: 'Bearer ' + tokens.access_token, 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: secret(), method: 'tools/call', params: { name, arguments: args } }) }))).result;
  mark('exercise-scoped-files');
  const rootResult = await call('list_roots'); assert.equal(rootResult.isError, false, rootResult.content[0].text);
  const roots = JSON.parse(rootResult.content[0].text);
  assert.deepEqual(roots.map(r => r.id).sort(), [writable.id, readonly.id].sort());
  assert.equal(roots.find(r => r.id === readonly.id).directWriteAllowed, false);
  const write = await call('write_file', { rootId: writable.id, path: 'recovery-test.txt', content: 'Restored without choosing folders again\n', expectedHash: null });
  assert.equal(write.isError, false, write.content[0].text); assert.equal(JSON.parse(write.content[0].text).status, 'written');
  const denied = await call('write_file', { rootId: readonly.id, path: 'forbidden.txt', content: 'No', expectedHash: null }); assert.equal(denied.isError, true);
  assert.deepEqual((await store.load()).config.roots, before.config.roots);
  assert.deepEqual((await store.load()).secrets, before.secrets);
  assert.equal((await store.load()).config.accountRoots, undefined);
  const journal = await store.readPrivateRecord('onboarding-intent-' + flowId); assert.equal(journal.confirmations, 1); assert.equal(journal.phase, 'connected');
  mark('restart-controller-stop');
  const oldPort = new URL(app.origin).port; await observed(() => app.close(), t.signal);
  mark('restart-controller-start');
  app = await startController({ port: Number(oldPort), store, allowLocalRelay: true, pickFolder: async () => { pickerCalls++; throw Error('No repeated picker'); } });
  await poll(() => app.bridge.state === 'connected');
  const read = await call('read_file', { rootId: writable.id, path: 'recovery-test.txt' }); assert.equal(read.isError, false, read.content[0].text);
  assert.equal(pickerCalls, 0); assert.equal(approvalPosts, 1);
  // A new browser has no remember cookie, yet the existing device/reference is
  // recoverable without a new invitation or picker. Browsing alone grants nothing.
  mark('recover-in-fresh-browser');
  const freshContext = await browser.newContext(), freshPage = await freshContext.newPage();
  await freshPage.goto(origin + '/authorize?' + query);
  await freshPage.locator('#account-confirm').waitFor({ state: 'visible', timeout: 20000 });
  assert.equal(await freshPage.locator('#account-choose').isHidden(), true);
  assert.equal(pickerCalls, 0); assert.equal(nativeConfirms, 1);
  assert.deepEqual((await store.load()).config.roots, before.config.roots);
  assert.deepEqual(errors, []);
  // Adding terminal permission is a separately displayed OAuth authorization;
  // old tokens keep their original file-only ceiling and cannot execute.
  mark('request-terminal-scope');
  const tq = new URLSearchParams(query); tq.set('scope', 'files:read files:write terminal:execute offline_access'); tq.set('state', secret());
  const terminalPage = await (await browser.newContext()).newPage();
  await terminalPage.goto(origin + '/authorize?' + tq);
  await terminalPage.locator('#account-confirm').waitFor({ state: 'visible' });
  assert.match(await terminalPage.locator('#account-permission').textContent(), /terminal:execute/);
  await terminalPage.locator('#account-confirm').click(); await terminalPage.waitForURL(callback + '*');
  const terminalTokens = await data(await request(origin + '/oauth/token', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:new URLSearchParams({grant_type:'authorization_code',client_id:client.client_id,redirect_uri:callback,code:new URL(terminalPage.url()).searchParams.get('code'),code_verifier:verifier,resource:origin+'/mcp'}) }));
  const execute = async (name,args) => (await data(await request(origin+'/mcp',{method:'POST',headers:{Authorization:'Bearer '+terminalTokens.access_token,'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:secret(),method:'tools/call',params:{name,arguments:args}})}))).result;
  const ta = { rootId:writable.id,requestId:randomUUID(),command:"Write-Output 'mcp-terminal-ok'" };
  assert.equal((await execute('terminal_execute',ta)).isError,true,'OAuth terminal scope alone does not authorize native execution');
  mark('explicit-terminal-permission');
  const choices = await data(await local('terminal/permissions',{})); const connectionId = choices.connections[0].connectionId;
  assert.equal((await local('terminal/set-permission',{connectionId,rootId:writable.id,enabled:true})).status,400);
  await data(await local('terminal/set-permission',{connectionId,rootId:writable.id,enabled:true,confirmation:'allow-unsandboxed-terminal-v1'}));
  const oldTokenAttempt = await request(origin+'/mcp',{method:'POST',headers:{Authorization:'Bearer '+tokens.access_token,'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:secret(),method:'tools/call',params:{name:'terminal_execute',arguments:ta}})});
  assert.ok(oldTokenAttempt.status === 401 || (await oldTokenAttempt.json()).result?.isError === true,'Old token is rejected (revoked or file-only), never silently upgraded');
  mark('run-scoped-terminal');
  const started = await execute('terminal_execute',ta); assert.equal(started.isError,false,started.content[0].text);
  let terminalResult;
  await poll(async()=>{const r=await execute('terminal_status',{rootId:writable.id,requestId:ta.requestId});assert.equal(r.isError,false,r.content[0].text);terminalResult=JSON.parse(r.content[0].text);return terminalResult.status==='succeeded';});
  assert.match(terminalResult.stdout,/mcp-terminal-ok/); assert.equal(terminalResult.exitCode,0);
  mark('revoke-terminal-permission');
  await data(await local('terminal/set-permission',{connectionId,rootId:writable.id,enabled:false}));
  assert.equal((await execute('terminal_execute',{...ta,requestId:randomUUID()})).isError,true);
  mark('body-complete');
  } catch (error) {
    const detail = failureDetails(stage, error);
    note('failure:' + JSON.stringify(detail));
    const failure = Error(`Existing connection fixture failed at ${detail.stage} (${detail.name}); only sanitized stack locations were recorded.`);
    failure.name = detail.name;
    throw failure;
  }
});
