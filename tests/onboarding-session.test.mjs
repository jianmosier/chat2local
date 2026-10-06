import test from 'node:test';
import assert from 'node:assert/strict';
import { OnboardingStore } from '../src/relay/onboarding-store.mjs';
import { randomSecret, sha256 } from '../src/shared/protocol.mjs';

// Storage/session fixture ONLY. Signed OIDC and actual HTTP/PKCE are exercised
// in oidc-login.test and account-onboarding-http.test, not replaced by this file.
class Storage {
  constructor() { this.data = new Map(); this.tail = Promise.resolve(); }
  async get(key) { return structuredClone(this.data.get(key)); }
  transaction(fn) {
    const work = this.tail.then(async () => {
      const copy = structuredClone(this.data);
      const tx = { get: async key => structuredClone(copy.get(key)), put: async (key, value) => { copy.set(key, structuredClone(value)); }, delete: async key => copy.delete(key), list: async ({ prefix, limit }) => new Map([...copy].filter(([key]) => key.startsWith(prefix)).sort(([a],[b]) => a.localeCompare(b)).slice(0, limit)) };
      const result = await fn(tx); this.data = copy; return structuredClone(result);
    });
    this.tail = work.catch(() => {}); return work;
  }
}
async function fixture(scope = ['files:read','files:write']) {
  const storage = new Storage(); let now = Date.now(); const api = new OnboardingStore(storage, () => now);
  const secret = randomSecret(), claims = { issuer: 'https://idp.example.test', subject: 'alice', sessionId: randomSecret(), expiresAt: now + 3600000 };
  await api.records({ action: 'put', kind: 'session', secret, value: claims, ttl: 3600 });
  const actor = { identityKey: await sha256(JSON.stringify([claims.issuer, claims.subject])), sessionBinding: await sha256(JSON.stringify([claims.issuer, claims.subject, claims.sessionId])) };
  const request = { actor, displayName: 'Test account', clientName: 'Original app', authRequest: { clientId: 'original-client', scope, redirectUri: 'https://client.example.test/callback' }, resource: 'https://relay.example.test/mcp' };
  const flow = await api.start(request), sessionSecret = randomSecret(), device = { deviceId: 'a'.repeat(32), epoch: 'b'.repeat(64) };
  await api.native({ action: 'start', flowId: flow.flowId, secret: flow.bootstrap, device, input: { sessionSecret } });
  const native = (action, input = {}) => api.native({ action, flowId: flow.flowId, secret: sessionSecret, device, input });
  const roots = [{ rootId: 'selected-root', mode: scope.includes('files:write') ? 'direct' : 'read-only' }];
  const prepared = await native('prepare', { roots, policyDigest: randomSecret() });
  const approve = () => native('confirm', { snapshotDigest: prepared.snapshotDigest });
  const activate = () => native('activate', { snapshotDigest: prepared.snapshotDigest });
  const logout = () => api.records({ action: 'delete', kind: 'session', secret });
  return { storage, api, actor, request, flow, device, roots, prepared, native, approve, activate, logout, tick: value => { now += value; } };
}

test('logout or session expiry blocks pending native consent, enrollment, and activation', async () => {
  const first = await fixture(); await first.logout();
  await assert.rejects(() => first.approve(), /signed out/);
  await assert.rejects(() => first.api.provision({ flowId: first.flow.flowId, bootstrap: first.flow.bootstrap, deviceId: 'c'.repeat(32), keyHash: randomSecret(), sessionHash: randomSecret() }), /signed out/);
  const second = await fixture(); await second.approve(); await second.logout();
  await assert.rejects(() => second.activate(), /signed out/);
  assert.equal((await second.storage.get('accounts:v3:intent:' + second.flow.flowId)).phase, 'consented');
  assert.equal(await second.storage.get('accounts:v3:connection:' + second.prepared.connectionId), undefined);
  const third = await fixture(); third.tick(3600001);
  await assert.rejects(() => third.approve(), /expired/);
  await assert.rejects(() => third.api.start(third.request), /expired/);
});

test('authenticated enrollment reservations are idempotent and cannot replace another device or key', async () => {
  const f = await fixture(); const request = { flowId: f.flow.flowId, bootstrap: f.flow.bootstrap, deviceId: 'c'.repeat(32), keyHash: randomSecret(), sessionHash: randomSecret() };
  await assert.rejects(() => f.api.provision({ ...request, bootstrap: randomSecret() }), /Sign in/);
  // A flow already bound to the existing device must not provision a new one.
  await assert.rejects(() => f.api.provision(request), /another native|already bound/);
  const fresh = await f.api.start(f.request); const next = { ...request, flowId: fresh.flowId, bootstrap: fresh.bootstrap };
  await f.api.provision(next); await f.api.provision(next);
  assert.equal(await f.storage.get('deviceCount'), 1);
  await assert.rejects(() => f.api.provision({ ...next, keyHash: randomSecret() }), /another native/);
  await assert.rejects(() => f.api.provision({ ...next, deviceId: 'd'.repeat(32) }), /another native/);
});

test('remembered consent reuses the exact account/client/resource and never expands a token scope', async () => {
  const f = await fixture(['files:read']); await f.approve(); const active = await f.activate();
  const remembered = await f.api.reuse({ actor: f.actor, authRequest: f.request.authRequest, resource: f.request.resource });
  assert.equal(remembered.reusable, true); assert.equal(remembered.grant.connectionId, active.grant.connectionId);
  const extra = { ...f.request.authRequest, scope: ['files:read','files:write'] };
  assert.equal((await f.api.reuse({ actor: f.actor, authRequest: extra, resource: f.request.resource })).reusable, false);
  assert.equal((await f.api.reuse({ actor: f.actor, authRequest: { ...extra, clientId: 'other-client' }, resource: f.request.resource })).reusable, false);
  assert.equal((await f.api.reuse({ actor: f.actor, authRequest: f.request.authRequest, resource: 'https://other.example.test/mcp' })).reusable, false);
  const upgrade = await f.api.start({ ...f.request, authRequest: extra });
  const sessionSecret = randomSecret();
  await f.api.native({ action: 'start', flowId: upgrade.flowId, secret: upgrade.bootstrap, device: f.device, input: { sessionSecret } });
  const call = (action, input) => f.api.native({ action, flowId: upgrade.flowId, secret: sessionSecret, device: f.device, input });
  const prepared = await call('prepare', { roots: [{ rootId: 'new-explicit-root', mode: 'direct' }], policyDigest: randomSecret() });
  assert.deepEqual((await f.api.directory().execute({ action: 'resolve', grant: active.grant })).scopes, ['files:read']);
  await call('confirm', { snapshotDigest: prepared.snapshotDigest });
  const upgraded = await call('activate', { snapshotDigest: prepared.snapshotDigest });
  assert.equal(upgraded.grant.connectionId, active.grant.connectionId);
  assert.ok(upgraded.grant.scopes.includes('files:write'));
  assert.deepEqual((await f.api.directory().execute({ action: 'resolve', grant: active.grant })).scopes, ['files:read']);
  await f.logout();
  await assert.rejects(() => f.api.reuse({ actor: f.actor, authRequest: extra, resource: f.request.resource }), /signed out/);
  // Signing out of setup is NOT silently revoking established plugin tokens.
  assert.equal((await f.api.directory().execute({ action: 'resolve', grant: upgraded.grant })).connectionId, active.grant.connectionId);
});

test('revoked original connections cannot be remembered or joined again', async () => {
  const f = await fixture(); await f.approve(); const active = await f.activate();
  await f.api.directory().execute({ action: 'revoke-connection', actor: f.actor, input: { connectionId: active.grant.connectionId } });
  assert.equal((await f.api.reuse({ actor: f.actor, authRequest: f.request.authRequest, resource: f.request.resource })).reusable, false);
  await assert.rejects(() => f.api.start({ ...f.request, mode: 'join', connectionId: active.grant.connectionId }), /owned by this account/);
});
