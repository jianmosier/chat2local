import test from 'node:test';
import assert from 'node:assert/strict';
import { ensureSubdomain } from '../scripts/workers-subdomain.mjs';
const base = { accountId: 'a'.repeat(32), token: 'synthetic-only' };
const present = name => Response.json({ success: true, result: { subdomain: name } });
const absent = () => Response.json({ success: false, errors: [{ code: 10007 }] }, { status: 404 });

test('subdomain status is read-only and restricted to the official account endpoint', async () => {
  const calls = [];
  const value = await ensureSubdomain(base, async (url, init) => { calls.push(init.method); assert.equal(url, `https://api.cloudflare.com/client/v4/accounts/${base.accountId}/workers/subdomain`); assert.equal(init.redirect, 'error'); return absent(); });
  assert.deepEqual(calls, ['GET']); assert.equal(value.registered, false);
});
test('register never replaces an existing account subdomain', async () => {
  const calls = [];
  const value = await ensureSubdomain({ ...base, mode: 'register', name: 'new-name' }, async (_, init) => { calls.push(init.method); return present('existing-name'); });
  assert.deepEqual(calls, ['GET']); assert.equal(value.changed, false); assert.equal(value.subdomain, 'existing-name');
});
test('new registration checks absence, submits once and verifies readback', async () => {
  const calls = [];
  const value = await ensureSubdomain({ ...base, mode: 'register', name: 'chat2local-test' }, async (_, init) => { calls.push(init.method); if (calls.length === 1) return absent(); if (init.method === 'PUT') assert.deepEqual(JSON.parse(init.body), { subdomain: 'chat2local-test' }); return present('chat2local-test'); });
  assert.deepEqual(calls, ['GET', 'PUT', 'GET']); assert.equal(value.changed, true);
});
test('authentication errors are not treated as absence and never trigger registration', async () => {
  const calls = [];
  await assert.rejects(ensureSubdomain({ ...base, mode: 'register', name: 'test' }, async (_, init) => { calls.push(init.method); return Response.json({ success: false, errors: [{ code: 10000 }] }, { status: 403 }); }), /refused/);
  assert.deepEqual(calls, ['GET']);
});
test('uncertain creation is not retried or reported as success', async () => {
  const calls = [];
  await assert.rejects(ensureSubdomain({ ...base, mode: 'register', name: 'test' }, async (_, init) => { calls.push(init.method); if (init.method === 'GET') return absent(); throw new Error('network'); }), /no automatic replay/);
  assert.deepEqual(calls, ['GET', 'PUT']);
});
test('invalid account or subdomain never reaches the network', async () => {
  const noNetwork = () => { throw new Error('unexpected call'); };
  await assert.rejects(ensureSubdomain({ ...base, accountId: '../other' }, noNetwork), /Invalid account/);
  await assert.rejects(ensureSubdomain({ ...base, mode: 'register', name: 'https://wrong.invalid' }, noNetwork), /Invalid requested/);
});
