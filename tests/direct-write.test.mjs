import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { FileService, approveRoot } from '../src/agent/files.mjs';
import { rootPermission, rootWriteMode } from '../src/agent/permissions.mjs';
import { startController } from '../src/agent/main.mjs';
import { Store } from '../src/agent/store.mjs';
import { checkArguments, TOOLS } from '../src/shared/protocol.mjs';

async function fixture(t, mode = 'direct') {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-direct-'));
  const folder = path.join(base, 'project'); await fs.mkdir(folder);
  const state = path.join(base, 'private');
  const root = { ...await approveRoot(folder, state, mode !== 'read-only'), ...rootPermission(mode) };
  const policy = { roots: [root], paused: false };
  const service = new FileService(() => policy, state);
  const args = (content = 'created', expectedHash = null, name = 'example.txt') => ({ rootId: root.id, path: name, content, expectedHash });
  t.after(() => fs.rm(base, { recursive: true, force: true }));
  return { base, folder, state, root, policy, service, args };
}

test('legacy permissions never acquire direct-write authority and invalid policies fail closed', () => {
  assert.equal(rootWriteMode({ write: true }), 'review'); assert.equal(rootWriteMode({ write: false }), 'read-only');
  assert.equal(rootWriteMode(rootPermission('direct')), 'direct');
  for (const root of [{ write: true, writeMode: 'other' }, { write: false, writeMode: 'direct' }, { write: 'true' }]) assert.throws(() => rootWriteMode(root));
  const tool = TOOLS.find(item => item.name === 'write_file');
  assert.equal(tool.annotations.readOnlyHint, false); assert.equal(tool.annotations.destructiveHint, true);
  assert.deepEqual(tool.securitySchemes[0].scopes, ['files:read', 'files:write']);
  assert.throws(() => checkArguments('write_file', { rootId: 'x', path: 'x', content: '', expectedHash: null, confirmDirect: true }));
});

test('direct write creates and replaces text without review; hashes, original backup and audit are retained', async t => {
  const { service, args, state, folder } = await fixture(t);
  const created = await service.invoke('write_file', args('first'));
  assert.equal(created.status, 'written'); assert.equal(created.authorization, 'directory-direct'); assert.equal(created.backupSaved, false);
  const replaced = await service.invoke('write_file', args('second', created.sha256));
  assert.equal(replaced.status, 'written'); assert.equal(replaced.backupSaved, true);
  assert.equal(await fs.readFile(path.join(folder, 'example.txt'), 'utf8'), 'second');
  assert.equal(await fs.readFile(path.join(state, 'backups', `${replaced.operationId}.before`), 'utf8'), 'first');
  assert.equal(service.status(replaced.operationId).status, 'written');
  assert.equal([...service.operations.values()].filter(item => item.status === 'pending').length, 0);
  const audit = await fs.readFile(path.join(state, 'audit.jsonl'), 'utf8');
  assert.match(audit, /directory-direct/); assert.equal(audit.includes('"content"'), false);
});

test('propose_write stays pending even with direct directory permission', async t => {
  const { service, args, folder } = await fixture(t);
  const proposal = await service.invoke('propose_write', args('not automatic'));
  assert.equal(proposal.status, 'pending'); await assert.rejects(() => fs.access(path.join(folder, 'example.txt')));
  assert.equal((await service.decide(proposal.operationId, true)).status, 'approved');
});

test('read-only and review roots reject direct tools; no remote parameter can promote permission', async t => {
  const { service, root, args } = await fixture(t, 'review');
  await assert.rejects(() => service.invoke('write_file', args()), /not authorized/);
  delete root.writeMode; // Existing write=true migrated in memory, never direct.
  await assert.rejects(() => service.invoke('write_file', args()), /not authorized/);
  Object.assign(root, rootPermission('read-only'));
  await assert.rejects(() => service.invoke('write_file', args()), /read-only/);
});

test('direct writes keep path, hardlink, binary and size restrictions', async t => {
  const { service, args, folder, base } = await fixture(t);
  for (const name of ['../outside.txt', '.env', '.git/config', 'file.txt:ads', 'C:/outside.txt']) {
    const result = await service.invoke('write_file', args('bad', null, name)); assert.equal(result.status, 'failed');
  }
  await assert.rejects(() => service.invoke('write_file', args('x\0y')), /binary/);
  await assert.rejects(() => service.invoke('write_file', args('x'.repeat(65537))), /64 KiB/);
  const outside = path.join(base, 'outside.txt'); await fs.writeFile(outside, 'unchanged');
  await fs.link(outside, path.join(folder, 'linked.txt'));
  const blocked = await service.invoke('write_file', args('bad', null, 'linked.txt')); assert.equal(blocked.status, 'failed');
  assert.equal(await fs.readFile(outside, 'utf8'), 'unchanged');
});

test('hash conflicts and concurrent writers never silently overwrite newer text', async t => {
  const { service, args, folder } = await fixture(t);
  const first = await service.invoke('write_file', args('first'));
  const conflict = await service.invoke('write_file', args('wrong', '0'.repeat(64))); assert.equal(conflict.status, 'failed');
  const results = await Promise.all([service.invoke('write_file', args('A', first.sha256)), service.invoke('write_file', args('B', first.sha256))]);
  assert.equal(results.filter(result => result.status === 'written').length, 1);
  assert.equal(results.filter(result => result.status === 'failed').length, 1);
  assert.ok(['A', 'B'].includes(await fs.readFile(path.join(folder, 'example.txt'), 'utf8')));
  const createAgain = await service.invoke('write_file', args('clobber')); assert.equal(createAgain.status, 'failed');
});

test('queued direct write rechecks downgrade and pause before committing', async t => {
  const { service, args, root, policy, folder } = await fixture(t);
  let release; service.commitTail = new Promise(resolve => { release = resolve; });
  const pending = service.invoke('write_file', args()); Object.assign(root, rootPermission('review')); release();
  assert.equal((await pending).status, 'failed'); await assert.rejects(() => fs.access(path.join(folder, 'example.txt')));
  Object.assign(root, rootPermission('direct')); policy.paused = true;
  await assert.rejects(() => service.invoke('write_file', args()), /paused/);
});

test('backup failure blocks replacement; post-commit audit failure does not pretend a write failed', async t => {
  const { service, args, state, folder } = await fixture(t);
  const original = await service.invoke('write_file', args('first'));
  await fs.writeFile(path.join(state, 'backups'), 'not a directory');
  const blocked = await service.invoke('write_file', args('second', original.sha256)); assert.equal(blocked.status, 'failed');
  assert.equal(await fs.readFile(path.join(folder, 'example.txt'), 'utf8'), 'first');
  await fs.unlink(path.join(state, 'backups'));
  const audit = service.audit.bind(service); service.audit = async (action, details) => { if (action === 'written') throw Error('audit unavailable'); return audit(action, details); };
  const result = await service.invoke('write_file', args('second', original.sha256)); assert.equal(result.status, 'written'); assert.match(result.message, /audit/);
});

test('directory mode changes need local consent, invalidate old pending proposals and persist safely', async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-mode-http-')); const folder = path.join(base, 'folder'); await fs.mkdir(folder);
  const stateDir = path.join(base, 'private'); let app = await startController({ stateDir, port: 0 });
  t.after(async () => { await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  const api = (route, body, headers = {}) => fetch(`${app.origin}/api/${route}`, { method: body === undefined ? 'GET' : 'POST', headers: { Origin: app.origin, 'X-Chat2Local-Token': app.token, 'Content-Type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const root = await (await api('root/add', { path: folder, write: true })).json(); assert.equal(root.writeMode, 'review');
  const proposal = await app.files.invoke('propose_write', { rootId: root.id, path: 'old.txt', content: 'do not replay', expectedHash: null });
  const change = { id: root.id, writeMode: 'direct', expectedWriteMode: 'review' };
  assert.equal((await api('root/set-mode', change)).status, 400);
  assert.equal((await api('root/set-mode', { ...change, confirmDirect: true }, { 'X-Chat2Local-Token': '' })).status, 401);
  assert.equal((await api('root/set-mode', { ...change, confirmDirect: true }, { Origin: 'https://untrusted.invalid' })).status, 403);
  assert.equal((await api('root/set-mode', { ...change, confirmDirect: true })).status, 200);
  assert.equal(app.files.status(proposal.operationId).status, 'rejected'); await assert.rejects(() => fs.access(path.join(folder, 'old.txt')));
  assert.equal((await api('root/set-mode', { ...change, confirmDirect: true })).status, 409);
  await app.close(); app = await startController({ stateDir, port: 0 });
  assert.equal((await (await api('status')).json()).roots[0].writeMode, 'direct');
  assert.equal((await new Store(stateDir).load()).config.roots[0].writeMode, 'direct');
  assert.equal((await api('root/set-mode', { id: root.id, writeMode: 'read-only', expectedWriteMode: 'direct' })).status, 200);
  await assert.rejects(() => app.files.invoke('write_file', { rootId: root.id, path: 'denied.txt', content: 'x', expectedHash: null }), /read-only/);
});
