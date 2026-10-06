import test from 'node:test';
import assert from 'node:assert/strict';
import { PrivateInstance } from '../src/relay/private-instance.mjs';
import { AccountDirectory } from '../src/relay/account-directory.mjs';
import { randomSecret, sha256 } from '../src/shared/protocol.mjs';
import { parseInstanceInvitation } from '../src/shared/instance-invitation.mjs';

class Storage {
  constructor() { this.data = new Map(); this.tail = Promise.resolve(); }
  async get(k) { return structuredClone(this.data.get(k)); }
  async put(k, v) { return this.transaction(tx => tx.put(k, v)); }
  transaction(fn) {
    const work = this.tail.then(async () => {
      const draft = structuredClone(this.data);
      const tx = { get: async k => structuredClone(draft.get(k)), put: async (k,v) => draft.set(k, structuredClone(v)), delete: async k => draft.delete(k), list: async ({prefix,limit}) => new Map([...draft].filter(([k]) => k.startsWith(prefix)).slice(0,limit)) };
      const value = await fn(tx); this.data = draft; return structuredClone(value);
    }); this.tail = work.catch(() => {}); return work;
  }
}
async function fixture() {
  let clock = Date.now();
  const storage = new Storage(), instance = new PrivateInstance(storage, 'https://private.example.test/mcp', () => clock);
  const authRequest = { clientId: 'original-plugin', scope: ['files:read','files:write','offline_access'], redirectUri: 'https://client.example.test/callback', state: randomSecret(), codeChallengeMethod: 'S256', codeChallenge: 'test-only-checked-before-private-route' };
  const invite = await instance.createInvitation({ purpose: 'connect', clientId: authRequest.clientId });
  const flow = await instance.makeFlow({ authRequest, clientName: 'My client' });
  const device = { deviceId: 'a'.repeat(32), epoch: 'b'.repeat(64), keyHash: 'c'.repeat(64) }, nativeSecret = randomSecret();
  const claim = { flowId: flow.flowId, bootstrap: flow.bootstrap, invitation: invite.invitation, deviceId: device.deviceId, keyHash: device.keyHash, sessionHash: await sha256(nativeSecret), registering: true };
  const call = (action, input = {}) => instance.native({ action, flowId: flow.flowId, secret: action === 'start' ? flow.bootstrap : nativeSecret, device, input, ...(action === 'start' ? { invitation: invite.invitation } : {}) });
  const start = async () => { await instance.claim(claim); return call('start', { sessionSecret: nativeSecret }); };
  const prepare = () => call('prepare', { roots: [{ rootId: 'selected-root', mode: 'direct' }], policyDigest: 'd'.repeat(64) });
  return { storage, instance, authRequest, invite, flow, device, claim, call, start, prepare, tick: ms => { clock += ms; } };
}

test('private installation link is fragment-only and cannot replace the intended origin', () => {
  const url = 'https://private.example.test/instance/invite#' + 'a'.repeat(32) + '.' + 'b'.repeat(64);
  assert.equal(parseInstanceInvitation(url).origin, 'https://private.example.test');
  for (const wrong of [url.replace('https:', 'http:'), url.replace('/instance/invite#', '/instance/invite?token=#'), url.replace('/instance/invite#', '/mcp#'), url.replace('https://', 'https://user:password@'), url + '&other=1']) assert.throws(() => parseInstanceInvitation(wrong));
});
test('one private invitation binds atomically to one flow/device/key; exact retries do not enroll twice', async () => {
  const f = await fixture();
  await Promise.all([f.instance.claim(f.claim), f.instance.claim(f.claim)]);
  assert.equal(await f.storage.get('deviceCount'), 1);
  for (const changes of [{ deviceId: 'e'.repeat(32) }, { keyHash: 'e'.repeat(64) }, { sessionHash: 'f'.repeat(64) }]) await assert.rejects(() => f.instance.claim({ ...f.claim, ...changes }), /different device|already bound|another/);
  const other = await f.instance.makeFlow({ authRequest: f.authRequest, clientName: 'same client' });
  await assert.rejects(() => f.instance.claim({ ...f.claim, flowId: other.flowId, bootstrap: other.bootstrap }), /another setup/);
  const separate = new PrivateInstance(new Storage(), 'https://another.example.test/mcp');
  const otherFlow = await separate.makeFlow({ authRequest: f.authRequest, clientName: 'other instance' });
  await assert.rejects(() => separate.claim({ ...f.claim, flowId: otherFlow.flowId, bootstrap: otherFlow.bootstrap }), /invalid|revoked/i);
});
test('expired or revoked invitations cannot enroll; client and scope substitution are rejected', async () => {
  const expired = await fixture(); expired.tick(601000); await assert.rejects(() => expired.instance.claim(expired.claim), /expired/);
  const revoked = await fixture(); await revoked.instance.revokeInvitation({ invitationId: revoked.invite.invitationId }); await assert.rejects(() => revoked.start(), /revoked/);
  const f = await fixture();
  const foreign = await f.instance.makeFlow({ authRequest: { ...f.authRequest, clientId: 'attacker-client' }, clientName: 'ChatGPT' });
  await assert.rejects(() => f.instance.claim({ ...f.claim, flowId: foreign.flowId, bootstrap: foreign.bootstrap }), /client|permissions/);
  const extra = await f.instance.makeFlow({ authRequest: { ...f.authRequest, scope: ['files:read','files:write','files:propose'] }, clientName: 'same' });
  await assert.rejects(() => f.instance.claim({ ...f.claim, flowId: extra.flowId, bootstrap: extra.bootstrap }), /permissions/);
});
test('register/prepare/confirm expose no folders; only exact native activation creates the reference', async () => {
  const f = await fixture(); await f.start();
  assert.equal((await f.instance.connections()).connections.length, 0);
  const prepared = await f.prepare(); assert.equal(prepared.phase, 'prepared');
  assert.equal((await f.instance.connections()).connections.length, 0);
  await assert.rejects(() => f.call('activate', { snapshotDigest: prepared.snapshotDigest }), /explicit consent/);
  await assert.rejects(() => f.call('confirm', { snapshotDigest: '1'.repeat(64) }), /belong|snapshot|match/);
  await f.call('confirm', { snapshotDigest: prepared.snapshotDigest });
  assert.equal((await f.instance.connections()).connections.length, 0);
  const activated = await f.call('activate', { snapshotDigest: prepared.snapshotDigest }); assert.equal(activated.phase, 'active');
  const resolved = await new AccountDirectory(f.storage).execute({ action: 'resolve', grant: activated.grant });
  assert.equal(resolved.devices.length, 1); assert.deepEqual(resolved.devices[0].roots, [{ rootId: 'selected-root', mode: 'direct' }]);
  assert.equal((await f.call('activate', { snapshotDigest: prepared.snapshotDigest })).connectionId, activated.connectionId);
});
test('revoking an invitation between native consent and activation cannot be lost in a later transaction', async () => {
  const f = await fixture(); await f.start(); const prepared = await f.prepare(); await f.call('confirm', { snapshotDigest: prepared.snapshotDigest });
  await f.instance.revokeInvitation({ invitationId: f.invite.invitationId });
  await assert.rejects(() => f.call('activate', { snapshotDigest: prepared.snapshotDigest }), /revoked/);
  assert.equal((await f.instance.connections()).connections.length, 0);
});
test('concurrent bootstrap requests cannot replace the original plugin connection', async () => {
  const f = await fixture(); await f.start(); const first = await f.prepare();
  const invite = await f.instance.createInvitation({ purpose: 'connect', clientId: f.authRequest.clientId });
  const flow = await f.instance.makeFlow({ authRequest: f.authRequest, clientName: 'same original client' });
  const device = { deviceId: 'e'.repeat(32), epoch: 'f'.repeat(64), keyHash: '1'.repeat(64) }, nativeSecret = randomSecret();
  await f.instance.claim({ flowId: flow.flowId, bootstrap: flow.bootstrap, invitation: invite.invitation, deviceId: device.deviceId, keyHash: device.keyHash, sessionHash: await sha256(nativeSecret), registering: true });
  await f.instance.native({ action: 'start', flowId: flow.flowId, secret: flow.bootstrap, invitation: invite.invitation, device, input: { sessionSecret: nativeSecret } });
  const other = (action, input) => f.instance.native({ action, flowId: flow.flowId, secret: nativeSecret, device, input });
  const second = await other('prepare', { roots: [{ rootId: 'other-root', mode: 'direct' }], policyDigest: '2'.repeat(64) });
  await f.call('confirm', { snapshotDigest: first.snapshotDigest }); await other('confirm', { snapshotDigest: second.snapshotDigest });
  await f.call('activate', { snapshotDigest: first.snapshotDigest });
  await assert.rejects(() => other('activate', { snapshotDigest: second.snapshotDigest }), /already has a private connection/);
  assert.equal((await f.instance.connections()).connections.length, 1);
});

test('finish is bound to original browser; remembered authorization is exact, scoped, expiring and revocable', async () => {
  const f = await fixture(); await f.start(); const intent = await f.prepare();
  await f.call('confirm', { snapshotDigest: intent.snapshotDigest }); await f.call('activate', { snapshotDigest: intent.snapshotDigest });
  await assert.rejects(() => f.instance.finish({ flowId: f.flow.flowId, browser: randomSecret() }), /browser/);
  const finished = await f.instance.finish({ flowId: f.flow.flowId, browser: f.flow.browser });
  await assert.rejects(() => f.instance.finish({ flowId: f.flow.flowId, browser: f.flow.browser }), /used/);
  assert.ok(await f.instance.remembered({ secret: finished.remember, authRequest: f.authRequest }));
  for (const changes of [{ clientId: 'other' }, { redirectUri: 'https://elsewhere.example/callback' }, { scope: ['files:read','files:write','files:propose'] }]) assert.equal(await f.instance.remembered({ secret: finished.remember, authRequest: { ...f.authRequest, ...changes } }), null);
  const narrowed = await f.instance.remembered({ secret: finished.remember, authRequest: { ...f.authRequest, scope: ['files:read'] } }); assert.deepEqual(narrowed.grant.scopes, ['files:read']);
  await assert.rejects(() => f.instance.createInvitation({ purpose: 'join', connectionId: finished.grant.connectionId, scopes: ['files:read','files:write','files:propose'] }), /expand/);
  const owner = await f.instance.owner();
  await new AccountDirectory(f.storage).execute({ action: 'revoke-connection', actor: owner.actor, input: { connectionId: finished.grant.connectionId } });
  assert.equal(await f.instance.remembered({ secret: finished.remember, authRequest: f.authRequest }), null);
  await assert.rejects(() => f.instance.createInvitation({ purpose: 'join', connectionId: finished.grant.connectionId }), /unavailable/);
});
