import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { SerialQueue } from '../src/agent/runtime/serial-queue.mjs';
import { AgentState } from '../src/agent/runtime/agent-state.mjs';
import { createToolDispatcher, FILE_TOOL_NAMES, TERMINAL_TOOL_NAMES } from '../src/agent/runtime/tool-dispatcher.mjs';
import { FileAccessPolicy } from '../src/agent/files/access-policy.mjs';
import { FileService, approveRoot } from '../src/agent/files.mjs';
import { TerminalService } from '../src/agent/terminal.mjs';
import { rootPermission } from '../src/agent/permissions.mjs';
import { TOOLS } from '../src/shared/protocol.mjs';

const deviceId = 'a'.repeat(32);
const connectionId = 'b'.repeat(32);
const resource = 'https://module-fixture.example.test/mcp';
const envelope = (rootId, id = connectionId) => ({
  version: 1, deviceId, connectionId: id, resource,
  roots: [{ rootId, mode: 'direct' }], scopes: ['files:read', 'files:write', 'terminal:execute'],
});

function dispatchFixture() {
  const calls = [];
  const state = {
    secrets: { identity: { origin: 'https://module-fixture.example.test' } },
    config: { roots: [], remoteUseConfirmed: true },
    async saveConfig(next) { this.config = next; },
  };
  const invoke = kind => async (name, args, access) => {
    const result = { kind, name, args, access };
    calls.push(result);
    return result;
  };
  return { calls, state, dispatch: createToolDispatcher({
    state, files: { invoke: invoke('file') }, terminal: { invoke: invoke('terminal') },
    readiness: { observeRemote() {} }, serial: action => action(),
  }) };
}

test('local dispatch registry covers the public tool contract without prefix or prototype dispatch', async () => {
  const names = [...FILE_TOOL_NAMES, ...TERMINAL_TOOL_NAMES];
  assert.deepEqual([...names].sort(), TOOLS.map(tool => tool.name).sort());
  assert.equal(new Set(names).size, names.length);
  const { dispatch, calls } = dispatchFixture();
  for (const name of names) {
    const result = await dispatch(name, {}, undefined, undefined);
    assert.equal(result.kind, TERMINAL_TOOL_NAMES.includes(name) ? 'terminal' : 'file');
  }
  assert.equal(calls.length, names.length);
  for (const name of ['constructor', '__proto__', 'terminal_arbitrary', 'shutdown']) {
    await assert.rejects(() => dispatch(name, {}), /Unknown local tool/);
  }
  assert.equal(calls.length, names.length);
});

test('wrong relay resource is rejected before either execution service runs', async () => {
  const { dispatch, calls } = dispatchFixture();
  await assert.rejects(() => dispatch('write_file', {}, undefined, { resource: 'https://other.example.test/mcp' }), /different relay/);
  assert.equal(calls.length, 0);
});

test('saving remote-use progress cannot turn a completed operation into a failed tool result', async () => {
  const { dispatch, calls, state } = dispatchFixture();
  state.config.remoteUseConfirmed = false;
  state.saveConfig = async () => { throw Error('Synthetic storage failure'); };
  const result = await dispatch('write_file', {});
  assert.equal(result, calls[0]);
  assert.match(state.guideWarning, /未能保存/);
  assert.equal(state.config.remoteUseConfirmed, false);
});

test('bounded queue retains order after rejection and rejects new work while closing', async () => {
  let release, closing = false;
  const queue = new SerialQueue({ capacity: 2, isClosing: () => closing });
  const seen = [];
  const gate = new Promise(resolve => { release = resolve; });
  const first = queue.run(async () => { await gate; seen.push('first'); throw Error('expected'); });
  const rejected = assert.rejects(first, /expected/);
  const second = queue.run(() => { seen.push('second'); });
  await assert.rejects(() => queue.run(() => seen.push('overflow')), { status: 503 });
  closing = true;
  release();
  await rejected;
  await second;
  await queue.drain();
  assert.equal(queue.size, 0);
  assert.deepEqual(seen, ['first', 'second']);
  await assert.rejects(() => queue.run(() => {}), { status: 503 });
});

test('state keeps existing identities and permissions and does not publish failed saves', async () => {
  const saved = { config: { roots: [], paused: false, installationId: 'existing' }, secrets: { identity: { deviceId } } };
  const store = { load: async () => structuredClone(saved), saveConfig: async () => { throw Error('blocked save'); } };
  const state = await AgentState.load(store);
  assert.deepEqual(state.config, saved.config);
  assert.deepEqual(state.secrets, saved.secrets);
  await assert.rejects(() => state.saveConfig({ ...state.config, paused: true }), /blocked save/);
  assert.equal(state.config.paused, false);
});

test('file permission scopes stay isolated across concurrent async connection contexts', async () => {
  const rootA = { id: randomUUID(), connectionId, path: '/fixture/a', ...rootPermission('direct') };
  const other = 'c'.repeat(32);
  const rootB = { id: randomUUID(), connectionId: other, path: '/fixture/b', ...rootPermission('direct') };
  const policy = new FileAccessPolicy(() => ({ roots: [], accountRoots: [rootA, rootB] }), () => ({ deviceId }));
  const check = (root, foreign) => policy.run(envelope(root.id, root.connectionId), async () => {
    await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal(policy.root(root.id, 'direct'), root);
    assert.throws(() => policy.root(foreign.id), /not authorized/);
    return policy.availableRoots().map(item => item.id);
  });
  assert.deepEqual(await Promise.all([check(rootA, rootB), check(rootB, rootA)]), [[rootA.id], [rootB.id]]);
  assert.equal(policy.context.getStore(), undefined);
});

async function terminalFixture(t, save) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-module-terminal-'));
  const directory = path.join(base, 'project');
  await fs.mkdir(directory);
  const root = { ...await approveRoot(directory, path.join(base, 'state'), true), ...rootPermission('direct') };
  const access = envelope(root.id);
  const config = { roots: [root], paused: false, terminalGrants: [{ rootId: root.id, connectionId, resource, enabled: true }] };
  const records = new Map();
  let spawned = 0;
  const store = {
    directory: path.join(base, 'state'),
    readPrivateRecord: async key => records.get(key),
    savePrivateRecord: async (key, record) => {
      await save?.(config, record);
      records.set(key, structuredClone(record));
    },
  };
  const terminal = new TerminalService({
    store, getConfig: () => config, getDevice: () => ({ deviceId }),
    spawnProcess: () => { spawned++; throw Error('No child process expected'); },
  });
  t.after(async () => { await terminal.close(); await fs.rm(base, { recursive: true, force: true }); });
  return { terminal, access, config, records, root, spawned: () => spawned,
    args: { rootId: root.id, requestId: randomUUID(), command: 'echo fixture' } };
}

test('terminal journal reservation failure never launches a native process', async t => {
  const f = await terminalFixture(t, async () => { throw Error('journal unavailable'); });
  await assert.rejects(() => f.terminal.invoke('terminal_execute', f.args, f.access), /journal unavailable/);
  assert.equal(f.spawned(), 0);
  assert.equal(f.terminal.activeCount(), 0);
});

test('terminal rechecks grants after reservation and retains the interrupted request without replay', async t => {
  const f = await terminalFixture(t, async config => { config.paused = true; });
  await assert.rejects(() => f.terminal.invoke('terminal_execute', f.args, f.access), /paused/);
  assert.equal(f.spawned(), 0);
  assert.equal(f.records.size, 1);
  f.config.paused = false;
  const result = await f.terminal.invoke('terminal_execute', f.args, f.access);
  assert.equal(result.status, 'interrupted');
  assert.equal(result.outcomeKnown, false);
  assert.equal(f.spawned(), 0);
});

test('file path validation keeps the asynchronous service contract', async () => {
  const files = new FileService(() => ({ roots: [], paused: false }));
  const result = files.safePath('not-authorized', 'example.txt');
  assert.ok(result instanceof Promise);
  await assert.rejects(result, /not authorized/);
});

test('composition and dispatch no longer inspect file or process implementation state', async () => {
  const main = await fs.readFile('src/agent/main.mjs', 'utf8');
  assert.equal(/terminal\.jobs|files\.operations|switch\s*\(route\)/.test(main), false);
  const dispatch = await fs.readFile('src/agent/runtime/tool-dispatcher.mjs', 'utf8');
  assert.equal(/node:(?:fs|child_process)/.test(dispatch), false);
  for (const file of ['src/agent/files.mjs', 'src/agent/terminal.mjs']) {
    const text = await fs.readFile(file, 'utf8');
    assert.equal(/node:http|from ['"].*relay\//.test(text), false);
  }
});
