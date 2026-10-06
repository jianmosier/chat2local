import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ownerClient, writeInvitationFile } from '../scripts/private-instance-owner.mjs';
import { readInstanceFile, joinInstance } from '../scripts/join-instance.mjs';
import { Store } from '../src/agent/store.mjs';
import { startController } from '../src/agent/main.mjs';

const value = () => ({ purpose: 'join', inviteUrl: 'https://owner.example.test/instance/invite#' + 'a'.repeat(32) + '.' + 'b'.repeat(64), expiresAt: Date.now() + 600000 });
async function temp(t) { const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-invite-file-')); t.after(() => fs.rm(base, { recursive: true, force: true })); return base; }

test('invitation export contains only a temporary capability; reads are bounded, private and non-overwriting', async t => {
  const base = await temp(t), file = path.join(base, 'computer.chat2local.json');
  const result = await writeInvitationFile(file, { ...value(), operatorKey: 'must-not-be-exported' });
  assert.equal(result.operatorCredentialIncluded, false); assert.equal(result.foldersGranted, false);
  assert.doesNotMatch(JSON.stringify(result), /bbbbbbbb|must-not-be-exported/);
  const record = await readInstanceFile(file); assert.equal(record.origin, 'https://owner.example.test');
  assert.doesNotMatch(await fs.readFile(file, 'utf8'), /operatorKey|must-not-be-exported/);
  await assert.rejects(() => writeInvitationFile(file, value()), /EEXIST/);
  await assert.rejects(() => readInstanceFile(file, { now: Date.now() + 700000 }), /expired/);
  const malformed = path.join(base, 'bad.json'); await fs.writeFile(malformed, 'SECRET-not-json');
  await assert.rejects(() => readInstanceFile(malformed), error => !error.message.includes('SECRET') && /invalid/.test(error.message));
});
test('instance management authenticates only to its exact configured origin and never activates a mode', async () => {
  const config = { account_id: 'a'.repeat(32), name: 'chat2local-fixture', vars: { PUBLIC_ORIGIN: 'https://owner.example.test', PRIVATE_INSTANCE: 'true' } };
  const secret = 'c'.repeat(64), calls = [];
  const vault = { load: async () => ({ secrets: { installation: 'confirmed', origin: config.vars.PUBLIC_ORIGIN, enrollmentKey: secret } }) };
  const call = await ownerClient({ config, vault, request: async (url, options) => {
    calls.push(url); assert.equal(options.headers.Authorization, 'Bearer ' + secret); assert.equal(options.redirect, 'error'); return Response.json({ connections: [] });
  } });
  assert.deepEqual(await call('connections'), { connections: [] }); assert.deepEqual(calls, ['https://owner.example.test/instance/owner/connections']);
  await assert.rejects(() => call('arbitrary-path'));
  await assert.rejects(() => ownerClient({ config: { ...config, vars: { ...config.vars, PRIVATE_INSTANCE: 'false' } }, vault }), /review\/enable/);
  await assert.rejects(() => ownerClient({ config, vault: { load: async () => ({ secrets: { installation: 'confirmed', origin: 'https://other.example.test', enrollmentKey: secret } }) } }), /unavailable/);
});
test('one local import command verifies the listener, seals the invitation and opens joining without granting files', async t => {
  const base = await temp(t), file = path.join(base, 'join.chat2local.json');
  await writeInvitationFile(file, value());
  const store = new Store(path.join(base, 'state'));
  const app = await startController({ port: 0, store, networkOptions: { env: {}, systemProxy: async () => ({ proxy: '' }) } });
  t.after(() => app.close());
  const opened = [], before = await store.load();
  const result = await joinInstance(file, { store, localOrigin: app.origin, launch: async () => {}, openBrowser: async url => opened.push(url) });
  assert.equal(result.imported, true); assert.equal(result.foldersGranted, false); assert.equal(opened.length, 1);
  const after = await store.load(); assert.deepEqual(after.config, before.config); assert.equal(after.secrets.identity, undefined);
  assert.equal(after.secrets.privateInstanceInvitation.origin, 'https://owner.example.test');
  assert.deepEqual(after.config.roots, []); assert.equal(after.config.accountRoots, undefined);
  await assert.rejects(() => joinInstance(file, { store, localOrigin: 'https://attacker.example', launch: async () => {}, openBrowser: async () => {} }), /verified local/);
  assert.equal((await fetch(app.origin + '/api/instance/import-invitation', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: app.origin }, body: JSON.stringify({ url: value().inviteUrl }) })).status, 401);
});
