import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { TerminalService, terminalEnvironment, terminalCwd, terminalShell } from '../src/agent/terminal.mjs';
import { Store } from '../src/agent/store.mjs';
import { approveRoot } from '../src/agent/files.mjs';
import { rootPermission } from '../src/agent/permissions.mjs';
import { TOOLS, checkArguments, requiredScopes } from '../src/shared/protocol.mjs';

async function fixture(t) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-terminal-')); const directory = path.join(base, 'project'); await fs.mkdir(directory);
  const store = new Store(path.join(base, 'state')), root = { ...await approveRoot(directory, store.directory, true), ...rootPermission('direct') };
  const deviceId = 'a'.repeat(32), connectionId = 'b'.repeat(32), resource = 'https://instance.example.test/mcp';
  const config = { roots: [root], paused: false, terminalGrants: [{ rootId: root.id, connectionId, resource, enabled: true }] };
  const access = { version: 1, connectionId, deviceId, resource, roots: [{ rootId: root.id, mode: 'direct' }], scopes: ['files:read','files:write','terminal:execute'] };
  const terminal = new TerminalService({ store, getConfig: () => config, getDevice: () => ({ deviceId }) });
  t.after(async () => { await terminal.close(); await new Promise(r => setTimeout(r, 200)); await fs.rm(base, { recursive: true, force: true }); });
  const args = command => ({ rootId: root.id, requestId: randomUUID(), command });
  const wait = async a => { for (let n = 0; n < 160; n++) { const result = await terminal.invoke('terminal_status', { rootId: root.id, requestId: a.requestId }, access); if (['succeeded','failed','cancelled','timed-out','interrupted'].includes(result.status)) return result; await new Promise(r => setTimeout(r, 50)); } throw Error('Command timed out in test'); };
  return { base, directory, store, root, config, access, terminal, args, wait };
}
test('terminal tools require an independent scope and validate bounded command arguments', () => {
  for (const name of ['terminal_execute','terminal_status','terminal_cancel']) { assert.ok(TOOLS.some(t => t.name === name)); assert.ok(requiredScopes(name).includes('terminal:execute')); }
  assert.throws(() => checkArguments('terminal_execute', { rootId:'r', requestId:randomUUID(), command:'echo ok', timeoutMs:400000 }));
  assert.throws(() => checkArguments('terminal_execute', { rootId:'r', requestId:randomUUID(), command:'echo ok', shell:'bash; bad' }));
  assert.equal(terminalEnvironment({ PATH:'ok', OPENAI_API_KEY:'hidden', CHAT2LOCAL_TOKEN:'hidden', NODE_OPTIONS:'--require evil' }).OPENAI_API_KEY, undefined);
  assert.throws(() => terminalShell('echo ok', 'sh', 'win32'));
});
test('file grants or guessed connections cannot execute terminal commands', async t => {
  const f = await fixture(t), a = f.args('echo allowed');
  await assert.rejects(() => f.terminal.invoke('terminal_execute', a), /scoped/);
  await assert.rejects(() => f.terminal.invoke('terminal_execute', a, { ...f.access, scopes:['files:read','files:write'] }), /requires/);
  await assert.rejects(() => f.terminal.invoke('terminal_execute', a, { ...f.access, connectionId:'c'.repeat(32) }), /requires/);
  f.config.terminalGrants = []; await assert.rejects(() => f.terminal.invoke('terminal_execute', a, f.access), /requires/);
  assert.deepEqual(await fs.readdir(f.directory), []);
});
test('real native command returns output/exit status and duplicate request IDs never replay', async t => {
  const f = await fixture(t);
  const command = process.platform === 'win32' ? "Add-Content -LiteralPath 'once.txt' -Value 'one'; Write-Output 'hello-terminal'; [Console]::Error.WriteLine('stderr-terminal')" : "printf 'one\\n' >> once.txt; printf 'hello-terminal\\n'; printf 'stderr-terminal\\n' >&2";
  const a = f.args(command);
  const results = await Promise.all([f.terminal.invoke('terminal_execute', a, f.access), f.terminal.invoke('terminal_execute', a, f.access)]);
  assert.equal(results[0].requestId, results[1].requestId);
  const done = await f.wait(a); assert.equal(done.status, 'succeeded'); assert.equal(done.exitCode, 0); assert.match(done.stdout, /hello-terminal/); assert.match(done.stderr, /stderr-terminal/);
  await f.terminal.invoke('terminal_execute', a, f.access);
  assert.equal((await fs.readFile(path.join(f.directory,'once.txt'),'utf8')).trim(), 'one');
  await assert.rejects(() => f.terminal.invoke('terminal_execute', { ...a, command:'echo different' }, f.access), /different command/);
  const other = f.args('exit 7'); await f.terminal.invoke('terminal_execute', other, f.access); assert.equal((await f.wait(other)).exitCode, 7);
});
test('timeout and cancellation stop attached native work without claiming rollback', async t => {
  const f = await fixture(t), sleep = process.platform === 'win32' ? 'Start-Sleep -Seconds 30' : 'sleep 30';
  const timeout = { ...f.args(sleep), timeoutMs:250 }; await f.terminal.invoke('terminal_execute', timeout, f.access); assert.equal((await f.wait(timeout)).status, 'timed-out');
  const cancelled = f.args(sleep); await f.terminal.invoke('terminal_execute', cancelled, f.access); await f.terminal.invoke('terminal_cancel', { rootId: f.root.id, requestId: cancelled.requestId }, f.access); assert.equal((await f.wait(cancelled)).status, 'cancelled');
});
test('terminal output is bounded; cwd cannot traverse roots; interrupted journal is not replayed', async t => {
  const f = await fixture(t);
  await assert.rejects(() => terminalCwd(f.directory, '../state'), /relative/);
  const a = f.args(process.platform === 'win32' ? "Write-Output ('x' * 90000)" : "head -c 90000 /dev/zero | tr '\\0' x");
  await f.terminal.invoke('terminal_execute', a, f.access); const done = await f.wait(a); assert.equal(done.truncated, true); assert.ok(Buffer.byteLength(done.stdout + done.stderr) <= 65540);
  const pendingId = randomUUID(); await f.store.savePrivateRecord('terminal-' + pendingId, { requestId:pendingId, rootId:f.root.id, connectionId:f.access.connectionId, resource:f.access.resource, deviceId:f.access.deviceId, status:'running' });
  const unknown = await f.terminal.invoke('terminal_status', { rootId:f.root.id, requestId:pendingId }, f.access); assert.equal(unknown.status,'interrupted'); assert.equal(unknown.outcomeKnown,false);
});
