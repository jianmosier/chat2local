import test from 'node:test';
import assert from 'node:assert/strict';
import { PrivateInstance } from '../src/relay/private-instance.mjs';
import { AccountDirectory } from '../src/relay/account-directory.mjs';
import { randomSecret } from '../src/shared/protocol.mjs';

// Private aggregate fixture: HTTP device-key verification is exercised separately.
class Storage {
  constructor() { this.data = new Map(); this.tail = Promise.resolve(); }
  async get(key) { return structuredClone(this.data.get(key)); }
  async put(key, value) { return this.transaction(tx => tx.put(key, value)); }
  transaction(work) {
    const next = this.tail.then(async () => {
      const draft = structuredClone(this.data);
      const tx = { get: async k => structuredClone(draft.get(k)), put: async (k, v) => draft.set(k, structuredClone(v)), delete: async k => draft.delete(k), list: async ({ prefix, limit }) => new Map([...draft].filter(([k]) => k.startsWith(prefix)).slice(0, limit)) };
      const result = await work(tx); this.data = draft; return structuredClone(result);
    });
    this.tail = next.catch(() => {}); return next;
  }
}
async function fixture() {
  const storage = new Storage(), instance = new PrivateInstance(storage, 'https://private.example.test/mcp');
  const device = { deviceId: 'a'.repeat(32), epoch: 'b'.repeat(64), keyHash: 'c'.repeat(64) };
  const request = { clientId: 'original-client', scope: ['files:read', 'files:write'], redirectUri: 'https://client.example.test/callback', state: randomSecret(), codeChallengeMethod: 'S256', codeChallenge: 'validated-by-original-oauth-handler' };
  const open = async (changes = {}, target = device) => {
    const flow = await instance.makeFlow({ authRequest: { ...request, ...changes }, clientName: 'Requested client' });
    const sessionSecret = randomSecret();
    const call = (action, input = {}) => instance.native({ action, flowId: flow.flowId, secret: action === 'start' ? flow.bootstrap : sessionSecret, device: target, input });
    return { flow, call, start: () => call('start', { sessionSecret, reuseExisting: true }) };
  };
  return { storage, instance, device, request, open };
}
const prepare = session => session.call('prepare', { roots: [{ rootId: 'real-project', mode: 'direct' }], policyDigest: 'd'.repeat(64) });
async function activate(session) {
  const intent = await prepare(session);
  await session.call('confirm', { snapshotDigest: intent.snapshotDigest });
  return session.call('activate', { snapshotDigest: intent.snapshotDigest });
}

test('existing owner-enrolled device can prepare recovery without invitations, but cannot skip explicit consent', async () => {
  const f = await fixture(); await f.storage.put('device:' + f.device.deviceId, true);
  const session = await f.open(), context = await session.start();
  assert.equal(context.reuseExisting, true); assert.equal(context.recoveryRoots, null);
  assert.equal((await f.instance.connections()).connections.length, 0);
  const intent = await prepare(session);
  await assert.rejects(() => session.call('activate', { snapshotDigest: intent.snapshotDigest }), /explicit consent/);
  assert.equal((await f.instance.connections()).connections.length, 0);
  await assert.rejects(() => f.instance.finish({ flowId: session.flow.flowId, browser: session.flow.browser }), /not been activated/);
  await session.call('confirm', { snapshotDigest: intent.snapshotDigest });
  const done = await session.call('activate', { snapshotDigest: intent.snapshotDigest });
  assert.equal(done.phase, 'active');
  assert.equal([...f.storage.data.keys()].some(k => k.startsWith('instance:v1:invite:')), false);
});

test('a new, self-enrolled, or join-only device cannot impersonate an existing owner-enrolled device', async () => {
  const f = await fixture();
  for (const registration of [undefined, { kind: 'self', keyHash: f.device.keyHash }, { kind: 'private-instance', keyHash: f.device.keyHash }]) {
    await f.storage.put('device:' + f.device.deviceId, registration);
    const session = await f.open(); await assert.rejects(() => session.start(), /invitation/);
  }
  assert.equal((await f.instance.connections()).connections.length, 0);
});

test('recovery keeps the same reference and refuses other devices, additional scopes, roots, or revoked shares', async () => {
  const f = await fixture(); await f.storage.put('device:' + f.device.deviceId, true);
  const first = await f.open(); await first.start(); const active = await activate(first);
  const second = await f.open(), context = await second.start();
  assert.equal(context.connectionId, active.connectionId);
  assert.deepEqual(context.recoveryRoots, [{ rootId: 'real-project', mode: 'direct' }]);
  await assert.rejects(() => second.call('prepare', { roots: [{ rootId: 'unapproved-project', mode: 'direct' }], policyDigest: 'd'.repeat(64) }), /cannot add/);
  const stronger = await f.open({ scope: ['files:read', 'files:write', 'files:propose'] });
  await assert.rejects(() => stronger.start(), /not in the existing connection/);
  const otherDevice = { ...f.device, deviceId: 'e'.repeat(32) };
  await f.storage.put('device:' + otherDevice.deviceId, true);
  const other = await f.open({}, otherDevice); await assert.rejects(() => other.start(), /not in the existing connection/);
  const owner = await f.instance.owner();
  await new AccountDirectory(f.storage).execute({ action: 'revoke-share', actor: owner.actor, input: { connectionId: active.connectionId, deviceId: f.device.deviceId, rootId: 'real-project' } });
  await assert.rejects(() => prepare(second), /changed/);
  const after = await f.open(); await assert.rejects(() => after.start(), /not in the existing connection/);
});

test('revoked device registration and revoked connections cannot be resurrected by recovery', async () => {
  const f = await fixture(); await f.storage.put('device:' + f.device.deviceId, true);
  const session = await f.open(); await session.start(); const intent = await prepare(session);
  await f.storage.put('device:' + f.device.deviceId, false);
  await assert.rejects(() => session.call('confirm', { snapshotDigest: intent.snapshotDigest }), /unavailable/);
  await f.storage.put('device:' + f.device.deviceId, true);
  await session.call('confirm', { snapshotDigest: intent.snapshotDigest });
  const active = await session.call('activate', { snapshotDigest: intent.snapshotDigest });
  const owner = await f.instance.owner();
  await new AccountDirectory(f.storage).execute({ action: 'revoke-connection', actor: owner.actor, input: { connectionId: active.connectionId } });
  const again = await f.open(); await assert.rejects(() => again.start(), /revoked/);
});
