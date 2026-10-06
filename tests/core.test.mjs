import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { FileService, approveRoot, relativeParts } from '../src/agent/files.mjs';
import { Bridge } from '../src/agent/bridge.mjs';
import { Store } from '../src/agent/store.mjs';
import { handleMcp, checkArguments, relayOrigin, MAX_FILE_BYTES, PROTOCOL_VERSION, TOOLS } from '../src/shared/protocol.mjs';

async function fixture(t, writable = true) {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'chat2local-test-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const rootPath = path.join(temporary, 'approved');
  const state = path.join(temporary, 'private');
  await fs.mkdir(rootPath); await fs.mkdir(state);
  const root = await approveRoot(rootPath, state, writable);
  const policy = { paused: false, roots: [root] };
  const service = new FileService(() => policy, state);
  await fs.writeFile(path.join(rootPath, 'note.txt'), 'original\n');
  return { temporary, rootPath, state, root, policy, service, args: { rootId: root.id, path: 'note.txt' } };
}

test('paths: traversal, Windows aliases, streams, reserved and sensitive names are rejected', () => {
  for (const input of ['../secret', '..\\secret', '/etc/passwd', 'C:\\test', '\\\\server\\share', 'note.txt:stream', 'a//b', 'a/./b', 'a/../b', 'a.','a ', 'NUL', 'con.txt', '.env', '.env.local', '.git/config', '.ssh/id_rsa', 'x/private.pem', '.dev.vars', 'node_modules/x', 'a\u0000b']) assert.throws(() => relativeParts(input), undefined, input);
  assert.deepEqual(relativeParts('folder\\中文文件.txt'), ['folder', '中文文件.txt']);
  assert.deepEqual(relativeParts('.', true), []);
});

test('root policy refuses a whole drive, home directory and the private state directory', async t => {
  const f = await fixture(t);
  await assert.rejects(approveRoot(path.parse(f.rootPath).root, f.state));
  await assert.rejects(approveRoot(os.homedir(), f.state));
  await assert.rejects(approveRoot(f.state, f.state));
  await assert.rejects(approveRoot(f.temporary, f.state));
});

test('read returns content/hash and directory listing hides sensitive files', async t => {
  const f = await fixture(t);
  await fs.writeFile(path.join(f.rootPath, '.env'), 'not-for-ai');
  const read = await f.service.invoke('read_file', f.args);
  assert.equal(read.content, 'original\n'); assert.match(read.sha256, /^[a-f0-9]{64}$/);
  const list = await f.service.invoke('list_directory', { rootId: f.root.id });
  assert.deepEqual(list.entries.map(e => e.name), ['note.txt']);
  await assert.rejects(f.service.invoke('read_file', { ...f.args, path: '.env' }));
  assert.equal(f.service.events[0].content, undefined);
});

test('proposed writes do not touch a file until local approval, and save a backup', async t => {
  const f = await fixture(t); const read = await f.service.invoke('read_file', f.args);
  const proposal = await f.service.invoke('propose_write', { ...f.args, expectedHash: read.sha256, content: 'approved content\n' });
  assert.equal(proposal.status, 'pending');
  assert.equal(await fs.readFile(path.join(f.rootPath, 'note.txt'), 'utf8'), 'original\n');
  const outcome = await f.service.decide(proposal.operationId, true);
  assert.equal(outcome.status, 'approved');
  assert.equal(await fs.readFile(path.join(f.rootPath, 'note.txt'), 'utf8'), 'approved content\n');
  assert.equal(await fs.readFile(path.join(f.state, 'backups', `${proposal.operationId}.before`), 'utf8'), 'original\n');
  await assert.rejects(f.service.decide(proposal.operationId, true));
});

test('rejecting a proposal never writes', async t => {
  const f = await fixture(t); const read = await f.service.invoke('read_file', f.args);
  const proposal = await f.service.invoke('propose_write', { ...f.args, expectedHash: read.sha256, content: 'must not write' });
  assert.equal((await f.service.decide(proposal.operationId, false)).status, 'rejected');
  assert.equal(await fs.readFile(path.join(f.rootPath, 'note.txt'), 'utf8'), 'original\n');
});

test('file edited after proposal is not overwritten', async t => {
  const f = await fixture(t); const read = await f.service.invoke('read_file', f.args);
  const proposal = await f.service.invoke('propose_write', { ...f.args, expectedHash: read.sha256, content: 'AI content' });
  await fs.writeFile(path.join(f.rootPath, 'note.txt'), 'human edit');
  assert.equal((await f.service.decide(proposal.operationId, true)).status, 'failed');
  assert.equal(await fs.readFile(path.join(f.rootPath, 'note.txt'), 'utf8'), 'human edit');
});

test('new files require an explicit null hash; no clobbering existing files', async t => {
  const f = await fixture(t);
  await assert.rejects(f.service.invoke('propose_write', { ...f.args, expectedHash: null, content: 'no' }));
  const proposal = await f.service.invoke('propose_write', { rootId: f.root.id, path: 'new.txt', expectedHash: null, content: 'created' });
  assert.equal((await f.service.decide(proposal.operationId, true)).status, 'approved');
  assert.equal(await fs.readFile(path.join(f.rootPath, 'new.txt'), 'utf8'), 'created');
  assert.equal((await fs.stat(path.join(f.rootPath, 'new.txt'))).nlink, 1);
});

test('read-only, paused and revoked folders fail locally', async t => {
  const f = await fixture(t, false); const read = await f.service.invoke('read_file', f.args);
  await assert.rejects(f.service.invoke('propose_write', { ...f.args, expectedHash: read.sha256, content: 'no' }));
  f.policy.paused = true; await assert.rejects(f.service.invoke('list_roots'));
  f.policy.paused = false; f.policy.roots = []; await assert.rejects(f.service.invoke('read_file', f.args));
});

test('revocation after a proposal is also enforced during approval', async t => {
  const f = await fixture(t); const read = await f.service.invoke('read_file', f.args);
  const proposal = await f.service.invoke('propose_write', { ...f.args, expectedHash: read.sha256, content: 'no' });
  f.policy.roots = [];
  assert.equal((await f.service.decide(proposal.operationId, true)).status, 'failed');
  assert.equal(await fs.readFile(path.join(f.rootPath, 'note.txt'), 'utf8'), 'original\n');
});

test('junction/symlink escapes are blocked', async t => {
  const f = await fixture(t);
  const outside = path.join(f.temporary, 'outside'); await fs.mkdir(outside);
  await fs.writeFile(path.join(outside, 'secret.txt'), 'outside');
  try { await fs.symlink(outside, path.join(f.rootPath, 'escape'), process.platform === 'win32' ? 'junction' : 'dir'); }
  catch (error) { if (error.code === 'EPERM') return t.skip('Symlink creation is not permitted on this machine.'); throw error; }
  await assert.rejects(f.service.invoke('read_file', { rootId: f.root.id, path: 'escape/secret.txt' }));
  await assert.rejects(f.service.invoke('list_directory', { rootId: f.root.id, path: 'escape' }));
});

test('hard links are blocked', async t => {
  const f = await fixture(t);
  await fs.link(path.join(f.rootPath, 'note.txt'), path.join(f.temporary, 'outside-hardlink.txt'));
  await assert.rejects(f.service.invoke('read_file', f.args));
});

test('binary, oversized and invalid UTF-8 files are rejected', async t => {
  const f = await fixture(t);
  for (const content of [Buffer.from([0, 1, 2]), Buffer.alloc(MAX_FILE_BYTES + 1, 65), Buffer.from([0xc3, 0x28])]) {
    await fs.writeFile(path.join(f.rootPath, 'note.txt'), content);
    await assert.rejects(f.service.invoke('read_file', f.args));
  }
});

test('expired proposals and restarted-agent unknown states cannot be mistaken for success', async t => {
  const f = await fixture(t); const read = await f.service.invoke('read_file', f.args);
  const proposal = await f.service.invoke('propose_write', { ...f.args, expectedHash: read.sha256, content: 'no' });
  f.service.operations.get(proposal.operationId).createdAt -= 11 * 60_000;
  assert.equal(f.service.status(proposal.operationId).status, 'expired');
  await assert.rejects(f.service.decide(proposal.operationId, true));
  const fresh = new FileService(() => f.policy, f.state);
  assert.equal(fresh.status(proposal.operationId).status, 'unknown');
});

test('MCP initialize and tools/list return valid JSON-RPC without SSE dependence', async () => {
  const request = message => new Request('https://example.test/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(message) });
  const init = await (await handleMcp(request({ jsonrpc: '2.0', id: 1, method: 'initialize' }), async () => {})).json();
  assert.equal(init.result.protocolVersion, PROTOCOL_VERSION);
  const tools = await (await handleMcp(request({ jsonrpc: '2.0', id: 2, method: 'tools/list' }), async () => {})).json();
  assert.equal(tools.result.tools.length, TOOLS.length);
  assert.equal(tools.result.tools.some(tool => !tool.name.startsWith('terminal_') && /shell|exec|delete/.test(tool.name)), false);
  assert.ok(tools.result.tools.filter(tool => tool.name.startsWith('terminal_')).every(tool => tool.securitySchemes[0].scopes.includes('terminal:execute')));
});

test('MCP tool calls use the same local permission checks', async t => {
  const f = await fixture(t);
  const call = async args => (await handleMcp(new Request('https://example.test/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: args } }) }), (name, args) => f.service.invoke(name, args))).json();
  assert.equal((await call(f.args)).result.isError, false);
  assert.equal((await call({ ...f.args, path: '../outside' })).result.isError, true);
});

test('MCP malformed requests and notification tool calls are not executed', async () => {
  let called = false;
  const request = body => new Request('https://example.test/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
  assert.equal((await handleMcp(request('{'), () => { called = true; })).status, 400);
  assert.equal((await handleMcp(request(JSON.stringify({ jsonrpc: '2.0', method: 'tools/call', params: {} })), () => { called = true; })).status, 400);
  assert.equal(called, false);
  assert.throws(() => checkArguments('propose_write', { rootId: 'x', path: 'x', content: 'x' }));
  assert.throws(() => checkArguments('read_file', { rootId: 'x', path: 'x', command: 'extra' }));
});

test('relay URL validation requires HTTPS except explicit loopback development', () => {
  assert.equal(relayOrigin('https://relay.example'), 'https://relay.example');
  for (const url of ['http://relay.example', 'https://user:pass@relay.example', 'https://relay.example/path', 'https://relay.example?token=x', 'https://relay.example#x', 'http://127.0.0.1:8000']) assert.throws(() => relayOrigin(url));
  assert.equal(relayOrigin('http://127.0.0.1:8000', true), 'http://127.0.0.1:8000');
});

test('bridge refuses to replay a duplicate request ID', async () => {
  let calls = 0; const responses = [];
  const bridge = new Bridge(async () => { calls++; return { status: 'pending' }; });
  const socket = { readyState: 1, send: data => responses.push(JSON.parse(data)) };
  const message = JSON.stringify({ kind: 'call', id: randomUUID(), tool: 'propose_write', args: {} });
  await bridge.receive(message, socket); await bridge.receive(message, socket);
  assert.equal(calls, 1); assert.match(responses[1].error, /Duplicate/);
  await assert.rejects(bridge.receive(JSON.stringify({ kind: 'bad', id: 'bad' }), socket));
});

test('credentials persist with Windows DPAPI (or POSIX-only development permissions)', async t => {
  const f = await fixture(t); const store = new Store(f.state);
  const example = { identity: { deviceKey: 'TEST-ONLY-NOT-A-REAL-CREDENTIAL' } };
  await store.saveSecrets(example);
  const onDisk = await fs.readFile(path.join(f.state, 'vault.json'), 'utf8');
  assert.equal(onDisk.includes(example.identity.deviceKey), false);
  assert.deepEqual((await store.load()).secrets, example);
  if (process.platform === 'win32') assert.equal(JSON.parse(onDisk).format, 'windows-dpapi-v1');
});
