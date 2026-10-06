import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { AccountIdentity, accountPrincipal } from '../src/relay/account-identity.mjs';
import { AccountDirectory } from '../src/relay/account-directory.mjs';
import { checkedReferenceGrant, ACCESS_CAPABILITY } from '../src/shared/connection-access.mjs';
import { routeDeviceTool } from '../src/relay/device-router.mjs';
import { FileService, approveRoot } from '../src/agent/files.mjs';
import { rootPermission } from '../src/agent/permissions.mjs';
import { accountFixture } from './account-fixture.mjs';

test('account identity fails closed without a verifier; public headers and Codex claims cannot create a principal', async () => {
  const request = new Request('https://relay.example.test/account', { headers: { 'X-User-Id': 'alice', 'X-Codex-Logged-In': 'true' } });
  await assert.rejects(() => new AccountIdentity().authenticate(request), /not configured/);
  await assert.rejects(() => new AccountIdentity({ verifySession: async () => null }).authenticate(request), /Sign in/);
  assert.throws(() => accountPrincipal({ identityKey: 'a'.repeat(64), authenticated: true }), /verified account/);
});
test('durable account is independent of devices and browser sessions; exact issuer and subject define the identity index', async () => {
  const f = await accountFixture(); const anotherBrowser = await f.login('alice');
  assert.deepEqual(await f.repository.act(anotherBrowser, 'account'), f.account);
  const anotherIssuer = await f.login('alice', 'https://other.example.test');
  assert.notEqual((await f.repository.act(anotherIssuer, 'account')).accountId, f.account.accountId);
  const anotherSubject = await f.login('Alice');
  assert.notEqual((await f.repository.act(anotherSubject, 'account')).accountId, f.account.accountId);
  assert.notEqual(f.account.accountId, 'a'.repeat(32));
});
test('preparing/browsing and cloud confirmation alone never activate a share; native verifier cannot be omitted', async () => {
  const f = await accountFixture(); const { intent } = await f.prepare();
  assert.equal(intent.phase, 'prepared');
  assert.equal([...f.storage.data.keys()].some(key => key.includes(':connection:')), false);
  const disabled = new AccountDirectory(f.storage);
  await assert.rejects(() => disabled.execute({ action: 'confirm', actor: accountPrincipal(f.principal), input: { intentId: intent.intentId, snapshotDigest: intent.snapshotDigest, proof: 'not-an-authenticated-native-receipt' } }), /not configured/);
  await assert.rejects(() => f.activate(intent), /explicit consent/);
  assert.equal((await f.confirm(intent)).phase, 'consented');
  assert.equal([...f.storage.data.keys()].some(key => key.includes(':connection:')), false);
  const active = await f.activate(intent); assert.equal(active.phase, 'active');
  const repeated = await f.activate(intent); assert.deepEqual(repeated.grant, active.grant);
  assert.equal((await f.repository.resolve(active.grant)).devices.length, 1);
});
test('the same reference grant sees only explicitly activated additions; another account/client/resource cannot attach', async () => {
  const f = await accountFixture(); const { intent } = await f.prepare(); await f.confirm(intent); const first = await f.activate(intent);
  const grant = structuredClone(first.grant);
  const second = await f.prepare({ connectionId: first.connectionId, deviceId: 'd'.repeat(32), deviceEpoch: 'e'.repeat(64), roots: [{ rootId: 'mac-root', mode: 'direct' }] });
  assert.equal((await f.repository.resolve(grant)).devices.length, 1);
  await f.confirm(second.intent); assert.equal((await f.repository.resolve(grant)).devices.length, 1);
  await f.activate(second.intent); assert.equal((await f.repository.resolve(grant)).devices.length, 2);
  assert.deepEqual(grant, first.grant); // No token rewriting or new plugin.
  const bob = await f.login('bob'); await f.repository.act(bob, 'account');
  await assert.rejects(() => f.prepare({ connectionId: first.connectionId }, bob), /does not belong/);
  await assert.rejects(() => f.prepare({ connectionId: first.connectionId, clientId: 'other-client' }), /does not belong/);
  await assert.rejects(() => f.prepare({ connectionId: first.connectionId, resource: 'https://other.example.test/mcp' }), /does not belong/);
  await assert.rejects(() => f.prepare({}, bob), /ownership/);
});
test('one consent is immutable and browser-bound; stale, swapped, cancelled or expired proofs cannot grant', async () => {
  const f = await accountFixture(); const { input, intent } = await f.prepare();
  assert.deepEqual(await f.repository.act(f.principal, 'prepare', input), intent);
  await assert.rejects(() => f.repository.act(f.principal, 'prepare', { ...input, roots: [{ rootId: 'other-root', mode: 'direct' }] }), /another request/);
  await assert.rejects(() => f.repository.act(f.principal, 'confirm', { intentId: intent.intentId, snapshotDigest: intent.snapshotDigest, proof: f.proof({ ...intent, deviceId: 'f'.repeat(32) }, 'consented') }), /does not match/);
  const changedSession = await f.login('alice');
  await assert.rejects(() => f.confirm(intent, changedSession), /session changed/);
  await f.repository.act(f.principal, 'cancel', { intentId: intent.intentId });
  await assert.rejects(() => f.confirm(intent), /cancelled/);
  const next = await f.prepare(); f.tick(300001);
  await assert.rejects(() => f.confirm(next.intent), /expired/);
});
test('revocation and concurrent share updates invalidate stale attempts without affecting other connections', async () => {
  const f = await accountFixture(); const a = await f.prepare(); await f.confirm(a.intent); const active = await f.activate(a.intent);
  const b = await f.prepare({ clientId: 'independent-client' }); await f.confirm(b.intent); const separate = await f.activate(b.intent);
  const stale = await f.prepare({ connectionId: active.connectionId, deviceId: 'd'.repeat(32) });
  await f.repository.act(f.principal, 'revoke-share', { connectionId: active.connectionId, deviceId: a.intent.deviceId, rootId: a.intent.roots[0].rootId });
  assert.equal((await f.repository.resolve(active.grant)).devices.length, 0);
  assert.equal((await f.repository.act(f.principal, 'status', { intentId: a.intent.intentId })).phase, 'revoked');
  await assert.rejects(() => f.activate(a.intent), /revoked/);
  await assert.rejects(() => f.confirm(stale.intent), /changed/);
  await f.repository.act(f.principal, 'revoke-connection', { connectionId: active.connectionId });
  await assert.rejects(() => f.repository.resolve(active.grant), /revoked/);
  assert.equal((await f.repository.resolve(separate.grant)).devices.length, 1);
});
test('token scope remains a ceiling; legacy/mixed grants cannot masquerade as account grants', async () => {
  const f = await accountFixture(); const { intent } = await f.prepare(); await f.confirm(intent); const active = await f.activate(intent);
  const narrowed = { ...active.grant, scopes: ['files:read'] };
  assert.deepEqual((await f.repository.resolve(narrowed)).scopes, ['files:read']);
  assert.throws(() => checkedReferenceGrant({ ...active.grant, deviceId: intent.deviceId }), /fields/);
  assert.throws(() => checkedReferenceGrant({ ...active.grant, grantVersion: 2 }), /grant/);
  let invoked = 0;
  const base = { props: narrowed, tool: 'write_file', args: { rootId: 'project-root' }, origin: 'https://relay.example.test', resolveConnection: grant => f.repository.resolve(grant), describe: async () => { throw Error('must not inspect device'); }, invoke: async () => { invoked++; } };
  await assert.rejects(() => routeDeviceTool(base), error => error.wwwAuthenticate?.includes('insufficient_scope'));
  assert.equal(invoked, 0);
});
test('account router requires a specific device and a current agent scope capability; offline never falls back', async () => {
  const f = await accountFixture(); const a = await f.prepare(); await f.confirm(a.intent); const active = await f.activate(a.intent);
  const b = await f.prepare({ connectionId: active.connectionId, deviceId: 'd'.repeat(32) }); await f.confirm(b.intent); await f.activate(b.intent);
  let invoked = 0;
  const base = { props: active.grant, tool: 'list_roots', args: {}, origin: 'https://relay.example.test', resolveConnection: grant => f.repository.resolve(grant), describe: async () => ({ online: true, capabilities: [ACCESS_CAPABILITY] }), invoke: async () => { invoked++; return []; } };
  await assert.rejects(() => routeDeviceTool(base), /device|computer/i);
  await assert.rejects(() => routeDeviceTool({ ...base, args: { deviceId: a.intent.deviceId }, describe: async () => ({ online: false }) }), /offline/);
  await assert.rejects(() => routeDeviceTool({ ...base, args: { deviceId: a.intent.deviceId }, describe: async () => ({ online: true, capabilities: [] }) }), /update/);
  await assert.rejects(() => routeDeviceTool({ ...base, tool: 'read_file', args: { deviceId: a.intent.deviceId, rootId: 'not-shared', path: 'a.txt' } }), /not shared/);
  assert.equal(invoked, 0);
});
test('actual local files enforce concurrent connection fences, status ownership, backups and legacy isolation', async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-account-files-')); t.after(() => fs.rm(base, { recursive: true, force: true }));
  const folderA = path.join(base, 'a'), folderB = path.join(base, 'b'); await fs.mkdir(folderA); await fs.mkdir(folderB);
  const state = path.join(base, 'private');
  const a = { ...await approveRoot(folderA, state), ...rootPermission('direct'), connectionId: '1'.repeat(32) };
  const b = { ...await approveRoot(folderB, state), ...rootPermission('direct') };
  const policy = { paused: false, roots: [b], accountRoots: [a] }, deviceId = 'a'.repeat(32);
  const files = new FileService(() => policy, state, () => ({ deviceId }));
  const access = (connectionId, root, scopes = ['files:read', 'files:write']) => ({ version: 1, connectionId, deviceId, resource: 'https://relay.example.test/mcp', roots: [{ rootId: root.id, mode: 'direct' }], scopes });
  const x = access('1'.repeat(32), a), y = access('2'.repeat(32), b);
  assert.deepEqual((await files.invoke('list_roots')).map(r => r.id), [b.id]);
  await assert.rejects(() => files.invoke('read_file', { rootId: a.id, path: 'same.txt' }), /not authorized/);
  assert.deepEqual(policy.roots.map(root => root.id), [b.id]); // Older binaries read this legacy array only.
  const [first, second] = await Promise.all([files.invoke('write_file', { rootId: a.id, path: 'same.txt', content: 'a', expectedHash: null }, x), files.invoke('write_file', { rootId: b.id, path: 'same.txt', content: 'b', expectedHash: null }, y)]);
  assert.equal(first.status, 'written'); assert.equal(second.status, 'written');
  assert.equal(await fs.readFile(path.join(folderA, 'same.txt'), 'utf8'), 'a'); assert.equal(await fs.readFile(path.join(folderB, 'same.txt'), 'utf8'), 'b');
  assert.equal((await files.invoke('operation_status', { operationId: first.operationId }, y)).status, 'unknown');
  assert.equal((await files.invoke('operation_status', { operationId: first.operationId })).status, 'unknown');
  assert.equal((await files.invoke('operation_status', { operationId: first.operationId }, x)).status, 'written');
  // Even a well-formed relay envelope naming A's root cannot override its
  // locally saved connection binding. This is independent of the cloud fence.
  const foreign = { ...x, connectionId: '2'.repeat(32) };
  assert.deepEqual(await files.invoke('list_roots', {}, foreign), []);
  await assert.rejects(() => files.invoke('read_file', { rootId: a.id, path: 'same.txt' }, foreign), /not authorized/);
  assert.equal((await files.invoke('operation_status', { operationId: first.operationId }, foreign)).status, 'unknown');
  await assert.rejects(() => files.invoke('read_file', { rootId: b.id, path: 'same.txt' }, x), /not shared/);
  await assert.rejects(() => files.invoke('write_file', { rootId: a.id, path: 'same.txt', content: 'bad', expectedHash: first.sha256 }, { ...x, scopes: ['files:read'] }), /read-only/);
  const updated = await files.invoke('write_file', { rootId: a.id, path: 'same.txt', content: 'updated', expectedHash: first.sha256 }, x);
  assert.equal(updated.status, 'written'); assert.equal(updated.backupSaved, true);
  assert.equal((await files.invoke('read_file', { rootId: a.id, path: 'same.txt' }, x)).content, 'updated');
  await assert.rejects(() => files.invoke('read_file', { rootId: a.id, path: 'same.txt', connectionAccess: x }), /Unexpected argument/);
  policy.accountRoots = []; await assert.rejects(() => files.invoke('read_file', { rootId: a.id, path: 'same.txt' }, x), /not authorized/);
  assert.equal((await files.invoke('operation_status', { operationId: first.operationId }, x)).status, 'unknown');
});
