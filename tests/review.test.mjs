import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { FileService, approveRoot } from '../src/agent/files.mjs';
import { checkArguments } from '../src/shared/protocol.mjs';

async function prepared(t) {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'chat2local-review-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const rootPath = path.join(temporary, 'folder'); await fs.mkdir(rootPath);
  const state = path.join(temporary, 'state'); await fs.mkdir(state);
  const root = await approveRoot(rootPath, state, true);
  const service = new FileService(() => ({ roots: [root], paused: false }), state);
  const file = path.join(rootPath, 'test.txt'); await fs.writeFile(file, 'before');
  const args = { rootId: root.id, path: 'test.txt' };
  const original = await service.invoke('read_file', args);
  const proposal = await service.invoke('propose_write', { ...args, content: 'after', expectedHash: original.sha256 });
  return { service, proposal, file };
}

test('non-boolean approval cannot authorize writing', async t => {
  const f = await prepared(t);
  await assert.rejects(f.service.decide(f.proposal.operationId, 'true'));
  assert.equal(await fs.readFile(f.file, 'utf8'), 'before');
  assert.equal(f.service.status(f.proposal.operationId).status, 'pending');
});

test('a successful write remains successful if its audit append fails', async t => {
  const f = await prepared(t);
  f.service.audit = async () => { throw new Error('Simulated storage failure'); };
  const result = await f.service.decide(f.proposal.operationId, true);
  assert.equal(result.status, 'approved');
  assert.match(result.message, /audit log/);
  assert.equal(await fs.readFile(f.file, 'utf8'), 'after');
});

test('concurrent approval clicks commit at most once', async t => {
  const f = await prepared(t);
  const results = await Promise.allSettled([f.service.decide(f.proposal.operationId, true), f.service.decide(f.proposal.operationId, true)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(results.filter(r => r.status === 'rejected').length, 1);
  assert.equal(await fs.readFile(f.file, 'utf8'), 'after');
});

test('schema validation rejects inherited-object property names', () => {
  assert.throws(() => checkArguments('read_file', { rootId: 'x', path: 'x', constructor: 'not-an-argument' }));
  assert.throws(() => checkArguments('read_file', JSON.parse('{"rootId":"x","path":"x","__proto__":"not-an-argument"}')));
});
