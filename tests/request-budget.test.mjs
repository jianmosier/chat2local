import test from 'node:test';
import assert from 'node:assert/strict';
import { consumeBudget, requestBudget } from '../src/relay/request-budget.mjs';
import { instanceRoute } from '../src/relay/instance-http.mjs';

const A = 'a'.repeat(32), B = 'b'.repeat(32);
function storage() {
  const records = new Map(); let tail = Promise.resolve();
  const tx = { get: async key => structuredClone(records.get(key)), put: async (key, value) => records.set(key, structuredClone(value)) };
  return { records, transaction(work) { const result = tail.then(() => work(tx)); tail = result.catch(() => {}); return result; } };
}
test('only exact authenticated private routes leave the anonymous setup bucket; enrollment is unchanged', () => {
  for (const name of ['connections','start','remove']) assert.equal(requestBudget('/instance/manage/' + name, 'POST'), 'device-transport');
  for (const name of ['start','prepare','status','confirm','activate','cancel']) assert.equal(requestBudget('/instance/native/' + name, 'POST'), 'device-transport');
  for (const route of ['/instance/native/enroll','/instance/owner/invitations','/instance/join/start','/instance/manage/connections/','/instance/native/status/extra','/install/start','/enroll-device']) assert.equal(requestBudget(route, 'POST'), 'setup');
  assert.equal(requestBudget('/instance/manage/connections', 'GET'), 'setup');
  assert.equal(requestBudget('/instance/finish', 'GET'), 'authorize');
  assert.equal(requestBudget('/instance/finish', 'POST'), 'setup');
  assert.equal(requestBudget('/oauth/token', 'POST'), 'token');
  assert.equal(requestBudget('/authorize', 'GET'), 'authorize');
  assert.equal(requestBudget('/mcp', 'POST'), null);
});
test('an hour of two five-second status polls never spends setup or device-change capacity, even with the old setup bucket exhausted', async () => {
  const s = storage(), now = 1000;
  s.records.set('budget:setup', { count: 200, until: now + 3600000 });
  const original = structuredClone(s.records.get('budget:setup'));
  for (let i = 0; i < 1440; i++) {
    assert.equal((await consumeBudget(s, { bucket: 'device-transport' }, now)).status, 200);
    assert.equal((await consumeBudget(s, { bucket: 'device-read', deviceId: A }, now)).status, 200);
  }
  assert.deepEqual(s.records.get('budget:setup'), original);
  assert.equal((await consumeBudget(s, { bucket: 'setup' }, now)).status, 429, 'Old enrollment protection was not reset');
  assert.equal((await consumeBudget(s, { bucket: 'device-change', deviceId: A }, now)).status, 200);
  assert.equal((await consumeBudget(s, { bucket: 'authorize' }, now)).status, 200);
  assert.equal(s.records.get('budget:device-read:' + A).count, 1440);
});
test('read limits are per verified device and independent from permission mutations; rejection gives a bounded retry time', async () => {
  const s = storage(), now = 5000;
  s.records.set('budget:device-read:' + A, { count: 3600, until: now + 2500 });
  const rejected = await consumeBudget(s, { bucket: 'device-read', deviceId: A }, now);
  assert.equal(rejected.status, 429); assert.equal(rejected.headers.get('Retry-After'), '3');
  assert.equal((await rejected.json()).retryAfterSeconds, 3);
  assert.equal((await consumeBudget(s, { bucket: 'device-read', deviceId: B }, now)).status, 200);
  assert.equal((await consumeBudget(s, { bucket: 'device-change', deviceId: A }, now)).status, 200);
  assert.equal((await consumeBudget(s, { bucket: 'device-read', deviceId: A }, now + 2500)).status, 200);
  assert.equal(s.records.get('budget:device-read:' + A).count, 1);
});
test('concurrent mutation requests cannot exceed the retained 200-per-hour device ceiling', async () => {
  const s = storage();
  const responses = await Promise.all(Array.from({ length: 205 }, () => consumeBudget(s, { bucket: 'device-change', deviceId: A }, 1000)));
  assert.equal(responses.filter(r => r.status === 200).length, 200);
  assert.equal(responses.filter(r => r.status === 429).length, 5);
  assert.equal(s.records.get('budget:device-change:' + A).count, 200);
  assert.equal((await consumeBudget(s, { bucket: 'device-change', deviceId: B }, 1000)).status, 200);
});
test('global transport protection remains and invalid budget keys cannot allocate storage', async () => {
  const s = storage(); s.records.set('budget:device-transport', { count: 24000, until: 3601000 });
  assert.equal((await consumeBudget(s, { bucket: 'device-transport' }, 1000)).status, 429);
  for (const value of [{ bucket: '__proto__' }, { bucket: 'device-read' }, { bucket: 'device-change', deviceId: '../other' }, { bucket: 'setup', deviceId: A }]) assert.equal((await consumeBudget(s, value, 1000)).status, 400);
  assert.equal(s.records.size, 1);
});
test('native device authentication precedes per-device charging; read and mutation routes keep their actual classification', async () => {
  const calls = [], key = 'c'.repeat(64), origin = 'https://budget.example.test';
  let authorized = false;
  const env = { PRIVATE_INSTANCE: 'true',
    DEVICES: { idFromName: id => id, get: id => ({ fetch: async request => {
      calls.push(['auth', id]); assert.equal(new URL(request.url).pathname, '/account-auth');
      return Response.json(authorized && request.headers.get('Authorization') === 'Bearer ' + key ? { epoch: 'e'.repeat(32) } : { error: 'Denied' }, { status: authorized ? 200 : 401 });
    } }) },
    REGISTRY: { idFromName: name => name, get: () => ({ fetch: async request => {
      const route = new URL(request.url).pathname, value = await request.json(); calls.push([route, value]);
      return Response.json(route === '/budget' ? { ok: true } : { connections: [] });
    } }) },
  };
  const request = (route, body) => new Request(origin + route, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + key }, body: JSON.stringify(body) });
  const input = { deviceId: A, input: {} };
  await assert.rejects(() => instanceRoute(request('/instance/manage/connections', input), env, origin), { status: 401 });
  assert.deepEqual(calls.map(c => c[0]), ['auth']); calls.length = 0; authorized = true;
  for (const [route, readOnly] of [['/instance/manage/connections', true], ['/instance/manage/start', false], ['/instance/manage/remove', false], ['/instance/native/status', true], ['/instance/native/start', false], ['/instance/native/confirm', false]]) {
    calls.length = 0;
    const body = route.includes('/native/') ? { ...input, flowId: B, secret: key } : input;
    assert.equal((await instanceRoute(request(route, body), env, origin)).status, 200);
    assert.equal(calls[0][0], 'auth');
    assert.deepEqual(calls[1], ['/budget', { bucket: readOnly ? 'device-read' : 'device-change', deviceId: A }]);
  }
});
