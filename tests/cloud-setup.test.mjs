import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalOrigin, publicCheck, verifiedLocalSession } from '../scripts/cloud-setup.mjs';

const origin = 'https://relay.example.test';
const config = { vars: { PUBLIC_ORIGIN: origin } };
const reply = (value, status = 200, headers = {}) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json', ...headers } });
function fixture(overrides = {}) {
  const responses = {
    '/healthz': () => reply({ ok: true, name: 'chat2local-relay' }),
    '/mcp': () => reply({}, 401, { 'WWW-Authenticate': `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"` }),
    '/.well-known/oauth-protected-resource/mcp': () => reply({ resource: `${origin}/mcp`, authorization_servers: [origin] }),
    '/.well-known/oauth-authorization-server': () => reply({ issuer: origin, code_challenge_methods_supported: ['S256'] }),
    '/enroll': () => reply({}, 401),
    ...overrides,
  };
  return async (url, options) => { assert.equal(options.redirect, 'error'); return responses[new URL(url).pathname](); };
}
test('cloud readiness refuses placeholders, HTTP, credentials and non-origin URLs', () => {
  assert.equal(canonicalOrigin(config), origin);
  for (const value of ['https://not-configured.invalid', 'http://127.0.0.1:8080', 'https://user:pass@example.test', `${origin}/mcp`, `${origin}/?token=a`, `${origin}/#secret`]) {
    assert.throws(() => canonicalOrigin({ vars: { PUBLIC_ORIGIN: value } }));
  }
});
test('public readiness verifies boundaries without claiming website interoperability', async () => {
  const status = await publicCheck(config, fixture());
  assert.equal(status.mcpUrl, `${origin}/mcp`);
  assert.equal(status.websiteClientVerified, false);
  for (const overrides of [
    { '/mcp': () => reply({}, 200) },
    { '/healthz': () => reply({ name: 'another-server' }) },
    { '/enroll': () => reply({}, 200) },
    { '/.well-known/oauth-authorization-server': () => reply({ issuer: 'https://other.example.test', code_challenge_methods_supported: ['S256'] }) },
    { '/.well-known/oauth-protected-resource/mcp': () => reply({ resource: `${origin}/other`, authorization_servers: [origin] }) },
  ]) await assert.rejects(() => publicCheck(config, fixture(overrides)));
});
test('operator setup never sends a local control token to a non-loopback or unverified server', async () => {
  let requests = 0;
  const fetcher = async () => { requests++; return reply({ name: 'chat2local', instanceId: 'right' }); };
  for (const address of ['https://relay.example.test', 'http://localhost:47631', 'http://127.0.0.1:7676']) {
    await assert.rejects(() => verifiedLocalSession({ readSession: async () => ({ origin: address, token: 'a'.repeat(64), instanceId: 'right' }) }, fetcher));
  }
  assert.equal(requests, 0);
  await assert.rejects(() => verifiedLocalSession({ readSession: async () => ({ origin: 'http://127.0.0.1:47631', token: 'a'.repeat(64), instanceId: 'wrong' }) }, fetcher));
  assert.equal(requests, 1);
});
