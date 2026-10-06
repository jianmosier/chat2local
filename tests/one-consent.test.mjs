import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { chromium } from 'playwright-core';
import { ConsentCoordinator } from '../src/agent/consent-coordinator.mjs';
import { accountFixture } from './account-fixture.mjs';

async function fixture() {
  const account = await accountFixture(); const { intent } = await account.prepare();
  const records = new Map(), activations = new Set();
  const counters = { human: 0, cloudConsent: 0, cloudActivation: 0, localActivation: 0 };
  let paused = false, digest = intent.policyDigest, loseConsent = false, loseActivation = false;
  const journal = { load: async id => structuredClone(records.get(id)), save: async (id, data) => { records.set(id, structuredClone(data)); } };
  const cloud = {
    status: id => account.repository.act(account.principal, 'status', { intentId: id }),
    confirm: async (id, snapshotDigest, proof) => {
      counters.cloudConsent++;
      const result = await account.repository.act(account.principal, 'confirm', { intentId: id, snapshotDigest, proof });
      if (loseConsent) { loseConsent = false; throw Error('Simulated lost consent response AFTER commit.'); }
      return result;
    },
    activate: async (id, snapshotDigest, proof) => {
      counters.cloudActivation++;
      const result = await account.repository.act(account.principal, 'activate', { intentId: id, snapshotDigest, proof });
      if (loseActivation) { loseActivation = false; throw Error('Simulated lost activation response AFTER commit.'); }
      return result;
    },
  };
  const local = {
    assertCurrent: async value => { if (paused || value.policyDigest !== digest) throw Error('Local selection or pause changed; stale consent refused.'); },
    consentProof: async value => account.proof(value, 'consented'),
    activate: async value => {
      await local.assertCurrent(value);
      if (!activations.has(value.intentId)) { activations.add(value.intentId); counters.localActivation++; }
      return account.proof(value, 'activated');
    },
  };
  const adapters = { journal, cloud, local }; const coordinator = new ConsentCoordinator(adapters);
  await coordinator.stage(intent);
  const confirm = () => { counters.human++; return coordinator.confirm(intent.intentId, { snapshotDigest: intent.snapshotDigest, confirmation: 'allow-shared-folders-v1' }); };
  return { account, intent, journal, adapters, coordinator, confirm, counters, pause: () => { paused = true; }, change: () => { digest = 'f'.repeat(64); }, loseConsent: () => { loseConsent = true; }, loseActivation: () => { loseActivation = true; } };
}

test('one explicit confirmation runs preparation/consent/local activation/cloud activation without a second decision', async () => {
  const f = await fixture(); const before = await f.coordinator.resume(f.intent.intentId);
  assert.equal(before.requiresConsent, true); assert.equal(before.confirmationCount, 0);
  assert.equal(f.counters.localActivation, 0); assert.equal(f.counters.cloudConsent, 0);
  const result = await f.confirm(); assert.equal(result.connected, true); assert.equal(result.confirmationCount, 1);
  assert.equal(result.fileReadWriteVerified, false);
  assert.deepEqual(f.counters, { human: 1, cloudConsent: 1, cloudActivation: 1, localActivation: 1 });
  const restored = new ConsentCoordinator(f.adapters);
  assert.equal((await restored.resume(f.intent.intentId)).connected, true);
  assert.deepEqual(f.counters, { human: 1, cloudConsent: 1, cloudActivation: 1, localActivation: 1 });
});
test('lost cloud responses resume the SAME durable intent without another consent or duplicate activation', async () => {
  for (const fault of ['loseConsent', 'loseActivation']) {
    const f = await fixture(); f[fault]();
    await assert.rejects(f.confirm, /lost/);
    assert.equal((await f.journal.load(f.intent.intentId)).userConfirmed, true);
    const restored = new ConsentCoordinator(f.adapters);
    const result = await restored.resume(f.intent.intentId);
    assert.equal(result.connected, true); assert.equal(result.confirmationCount, 1);
    assert.deepEqual(f.counters, { human: 1, cloudConsent: 1, cloudActivation: 1, localActivation: 1 });
  }
});
test('wrong digest, pause, changed policy and remote cancellation cannot become a completed connection', async () => {
  const f = await fixture();
  await assert.rejects(() => f.coordinator.confirm(f.intent.intentId, { snapshotDigest: 'f'.repeat(64), confirmation: 'allow-shared-folders-v1' }), /changed/);
  await assert.rejects(() => f.coordinator.confirm(f.intent.intentId, { snapshotDigest: f.intent.snapshotDigest, confirmation: true }), /button/);
  f.pause(); await assert.rejects(f.confirm, /pause/); assert.equal(f.counters.cloudConsent, 0);
  const g = await fixture(); g.change(); await assert.rejects(g.confirm, /changed/); assert.equal(g.counters.localActivation, 0);
  const h = await fixture(); await h.account.repository.act(h.account.principal, 'cancel', { intentId: h.intent.intentId });
  await assert.rejects(h.confirm, /cancelled/); assert.equal(h.counters.localActivation, 0);
});
test('pause arriving after cloud consent prevents local activation; duplicate submissions share one transaction', async () => {
  const f = await fixture(); const original = f.adapters.cloud.confirm;
  f.adapters.cloud.confirm = async (...args) => { const value = await original(...args); f.pause(); return value; };
  await assert.rejects(f.confirm, /pause/); assert.equal(f.counters.localActivation, 0);
  const g = await fixture();
  const args = { snapshotDigest: g.intent.snapshotDigest, confirmation: 'allow-shared-folders-v1' };
  const first = g.coordinator.confirm(g.intent.intentId, args);
  await assert.rejects(() => g.coordinator.confirm(g.intent.intentId, { ...args, snapshotDigest: '0'.repeat(64) }), /different/);
  const second = g.coordinator.confirm(g.intent.intentId, args);
  const results = await Promise.all([first, second]);
  assert.deepEqual(results[0], results[1]); assert.equal(g.counters.cloudConsent, 1); assert.equal(g.counters.localActivation, 1);
});

test('real browser component: one consent click, zero manual pairing/tab switches; a lost response does not add a click', async t => {
  const f = await fixture(); f.loseConsent();
  const secret = randomBytes(32).toString('hex');
  const component = await fs.readFile(new URL('../src/agent/ui/consent-card.js', import.meta.url), 'utf8');
  const layout = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>chat2local — isolated account consent test</title><style>*{box-sizing:border-box}body{font:16px/1.65 system-ui;margin:0;background:#f5f6f8;color:#1b2434;padding:24px 16px}main{max-width:520px;margin:4vh auto;background:white;border:1px solid #dde4ed;border-radius:16px;padding:24px}h1{font-size:25px}dt{font-size:13px;color:#627187;margin-top:10px}dd{margin:0;overflow-wrap:anywhere;white-space:pre-wrap}button{font:inherit;border:0;border-radius:8px;background:#2155be;color:white;width:100%;padding:14px;cursor:pointer}p{overflow-wrap:anywhere}[hidden]{display:none!important}</style><main><small>chat2local · 隔离测试，不是已登录的真实账号</small><section id="card"></section></main><script type="module" src="/page.js"></script></html>`;
  const script = `import { mountConsentCard } from '/consent-card.js'; const api=async(route,body)=>{const r=await fetch(route,{method:body===undefined?'GET':'POST',headers:{'X-Fixture-CSRF':'${secret}','Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});const v=await r.json();if(!r.ok)throw Error(v.error);return v};mountConsentCard(document.getElementById('card'),{load:()=>api('/view'),confirm:value=>api('/confirm',value),resume:intentId=>api('/resume',{intentId})});`;
  let origin; const requests = [];
  const server = http.createServer((request, response) => {
    void (async () => {
      const send = (status, data, type = 'application/json') => { response.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' }); response.end(type === 'application/json' ? JSON.stringify(data) : data); };
      if (request.url === '/') return send(200, layout, 'text/html; charset=utf-8');
      if (request.url === '/page.js') return send(200, script, 'text/javascript');
      if (request.url === '/consent-card.js') return send(200, component, 'text/javascript');
      if (request.headers['x-fixture-csrf'] !== secret || (request.method === 'POST' && request.headers.origin !== origin)) return send(403, { error: 'Unauthorized fixture request.' });
      if (request.url === '/view' && request.method === 'GET') {
        const record = await f.journal.load(f.intent.intentId);
        return send(200, { ...f.coordinator.view(record), snapshotDigest: f.intent.snapshotDigest, accountLabel: '测试账号（身份适配器 fixture）', clientLabel: '同一个 chat2local 插件', deviceLabel: '已验证的测试电脑', folderLabels: ['已选测试文件夹'], scopes: f.intent.scopes });
      }
      const chunks = []; for await (const part of request) chunks.push(part); const input = JSON.parse(Buffer.concat(chunks));
      if (request.url === '/confirm') { requests.push('confirm'); try { return send(200, await f.coordinator.confirm(input.intentId, input)); } catch (error) { return send(503, { error: error.message }); } }
      if (request.url === '/resume') { requests.push('resume'); return send(200, await f.coordinator.resume(input.intentId)); }
      send(404, { error: 'Not found.' });
    })().catch(error => { response.writeHead(500); response.end(JSON.stringify({ error: error.message })); });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); origin = `http://127.0.0.1:${server.address().port}`;
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const browser = await chromium.launch({ channel: 'msedge', headless: true }); t.after(() => browser.close());
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  const errors = [], documents = []; page.on('pageerror', error => errors.push(error.message)); page.on('request', request => { if (request.isNavigationRequest()) documents.push(request.url()); });
  await page.goto(origin); await page.getByRole('button', { name: '允许读写并连接' }).waitFor();
  assert.equal(await page.locator('input[type=password]').count(), 0); assert.equal(requests.length, 0);
  await fs.mkdir('.artifacts', { recursive: true }); await page.screenshot({ path: '.artifacts/account-consent-one-click.png', fullPage: true });
  await page.getByRole('button', { name: '允许读写并连接' }).click();
  await page.getByRole('heading', { name: '文件夹已连接', exact: true }).waitFor();
  assert.deepEqual(requests, ['confirm', 'resume']);
  assert.equal((await f.journal.load(f.intent.intentId)).confirmations, 1);
  assert.equal(documents.length, 1); assert.equal(browser.contexts()[0].pages().length, 1);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  await page.reload(); await page.getByRole('heading', { name: '文件夹已连接', exact: true }).waitFor();
  assert.deepEqual(requests, ['confirm', 'resume']); assert.deepEqual(errors, []);
});
