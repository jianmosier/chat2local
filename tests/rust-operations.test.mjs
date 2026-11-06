import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { RustOperationCore, configuredOperationsCore } from '../src/agent/files/rust-operations.mjs';
import { FileOperationStore, JavascriptOperationCore } from '../src/agent/files/operation-store.mjs';
import { FileService, approveRoot } from '../src/agent/files.mjs';
import { RustWriterBackend } from '../src/agent/files/rust-writer.mjs';
import { RustReadonlyBackend } from '../src/agent/files/rust-readonly.mjs';
import { assertWriteFenceClear } from '../src/agent/files/write-fence.mjs';
import { startController } from '../src/agent/main.mjs';

const modulePath = process.env.CHAT2LOCAL_OPERATIONS_TEST_MODULE ?? path.resolve('target/wasm32-unknown-unknown/release/chat2local_operation_wasm.wasm');
const writerPath = process.env.CHAT2LOCAL_WRITER_TEST_EXECUTABLE ?? path.resolve('target/debug/chat2local-writer.exe');
const readerPath = process.env.CHAT2LOCAL_READONLY_TEST_EXECUTABLE ?? path.resolve('target/debug/chat2local-readonly.exe');
const unavailable = !existsSync(modulePath) ? 'Build actual operation WASM with npm run test:rust-operations' : false;
const nativeUnavailable = unavailable || (process.platform !== 'win32' || !existsSync(writerPath) || !existsSync(readerPath) ? 'Build required Windows reader/writer' : false);
if (process.env.CHAT2LOCAL_OPERATIONS_TEST_REQUIRED === '1' && nativeUnavailable) throw Error(nativeUnavailable);
const wasm = { skip: unavailable }, native = { skip: nativeUnavailable };
const hash = value => createHash('sha256').update(value).digest('hex');
const input = (extra = {}) => ({ operationId: randomUUID(), rootId: 'r', path: 'note.txt', expectedHash: null, content: 'new', before: 'old', ...extra });
const owner = () => ({ version: 1, connectionId: 'a'.repeat(32), deviceId: 'b'.repeat(32), resource: 'https://relay.example/mcp', roots: [{ rootId: 'r', mode: 'direct' }], scopes: ['files:read', 'files:write', 'files:propose'] });
const core = () => new RustOperationCore({ modulePath });
function store(options = {}) { return new FileOperationStore(undefined, { core: core(), clock: () => 0, ...options }); }
function faultCore() {
  let fault;
  const state = new RustOperationCore({ modulePath, instantiate: module => {
    const instance = new WebAssembly.Instance(module, {}), real = instance.exports;
    return { exports: { ...real, command(length) {
      const command = JSON.parse(Buffer.from(real.memory.buffer, real.input_ptr(), length).toString()).command;
      if (fault?.when(command)) {
        if (fault.kind === 'trap') throw new WebAssembly.RuntimeError('test trap');
        const result = real.command(length);
        if (fault.kind === 'malformed') new Uint8Array(real.memory.buffer, real.output_ptr(), 1)[0] = 0xff;
        if (fault.kind === 'serial') {
          const bytes = Buffer.from(real.memory.buffer, real.output_ptr(), real.output_len());
          const at = bytes.indexOf('"serial":'); assert.notEqual(at, -1); bytes[at + 9] = 57;
        }
        return result;
      }
      return real.command(length);
    } } };
  } });
  return { state, arm(kind, when) { fault = { kind, when }; } };
}
async function fixture(t, { stateCore = core(), nativeIO = false } = {}) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-operations-'));
  t.after(() => fs.rm(base, { recursive: true, force: true }));
  const directory = path.join(base, 'project'), state = path.join(base, 'state');
  await fs.mkdir(directory); await fs.mkdir(state);
  const root = { ...await approveRoot(directory, state, true), writeMode: 'direct' };
  const policy = { paused: false, roots: [root], accountRoots: [] };
  const identity = { deviceId: 'b'.repeat(32), resource: 'https://relay.example/mcp' };
  const service = new FileService(() => policy, state, () => ({ deviceId: identity.deviceId }), { operationsCore: stateCore,
    ...(nativeIO ? { writerBackend: new RustWriterBackend({ executable: writerPath }), readonlyBackend: new RustReadonlyBackend({ executable: readerPath }) } : {}),
    getResource: () => identity.resource });
  return { base, directory, state, root, policy, service, identity,
    write: (name, content, expectedHash = null) => service.invoke('write_file', { rootId: root.id, path: name, content, expectedHash }),
    propose: (name = 'new.txt') => service.invoke('propose_write', { rootId: root.id, path: name, content: 'new', expectedHash: null }) };
}

test('operations selection is explicit and missing WASM fails without fallback', () => {
  assert.equal(configuredOperationsCore({}, {}), undefined);
  assert.equal(configuredOperationsCore({ operationsBackend: 'js' }, { CHAT2LOCAL_OPERATIONS_BACKEND: 'rust' }), undefined);
  assert.throws(() => configuredOperationsCore({ operationsBackend: 'bad' }, {}), /Unsupported/);
  assert.throws(() => configuredOperationsCore({ operationsBackend: 'rust', operationsModulePath: path.resolve('missing-operation.wasm') }, {}), /history is unavailable/);
});

test('actual WASM owns record, original owner and detached approval ticket', wasm, () => {
  const s = store(), grant = owner(), value = input(); s.propose(value, grant);
  value.content = 'changed'; grant.connectionId = 'c'.repeat(32); grant.roots[0].mode = 'read-only';
  const snapshot = s.records.get(value.operationId); snapshot.content = 'snapshot edit'; snapshot.status = 'approved';
  const { ticket } = s.decide(value.operationId, true);
  assert.equal(ticket.operation.content, 'new'); assert.equal(ticket.owner.connectionId, 'a'.repeat(32)); assert.equal(ticket.owner.roots[0].mode, 'direct');
  ticket.operation.path = 'other'; ticket.owner.roots[0].mode = 'read-only';
  const result = s.finish(value.operationId, ticket.attempt, { status: 'approved', sha256: hash('new'), content: 'injected', rootId: 'evil' });
  assert.equal(result.path, 'note.txt'); assert.equal(s.records.get(value.operationId).content, undefined);
  assert.equal(s.records.get(value.operationId).rootId, 'r'); assert.equal(s.records.set, undefined);
  assert.throws(() => s.finish(value.operationId, ticket.attempt, { status: 'failed' }), /active attempt/);
});

test('20 full escaped before/content pairs project per item without exceeding ABI', wasm, () => {
  const s = store(), body = '\x01'.repeat(65536);
  for (let i = 0; i < 20; i++) s.propose(input({ content: body, before: body }));
  assert.equal(s.pending().length, 20);
  assert.equal([...s.records.values()].reduce((sum, value) => sum + value.content.length + value.before.length, 0), 20 * 131072);
  assert.throws(() => s.propose(input()), /Too many pending/); assert.equal(s.core.healthy, true);
});

test('21 concurrent FileService proposals atomically retain exactly 20', wasm, async t => {
  const f = await fixture(t); let count = 0, release;
  const barrier = new Promise(resolve => { release = resolve; });
  f.service.readSnapshot = async () => { if (++count === 21) release(); await barrier; return { sha256: null }; };
  const results = await Promise.allSettled(Array.from({ length: 21 }, (_, n) => f.propose(`${n}.txt`)));
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 20);
  assert.match(results.find(r => r.status === 'rejected').reason.message, /Too many pending/);
  assert.equal(f.service.pendingOperations().length, 20); assert.deepEqual(await fs.readdir(f.directory), []);
});

test('strict approval and attempt checks prevent repeated or swapped finish', wasm, () => {
  const s = store(), value = input(); s.propose(value);
  for (const approved of ['true', 1, null]) assert.throws(() => s.decide(value.operationId, approved), /Invalid/);
  const { ticket } = s.decide(value.operationId, true);
  assert.throws(() => s.decide(value.operationId, true), /no longer pending/);
  assert.throws(() => s.finish(value.operationId, '999', { status: 'failed' }), /active attempt/);
  assert.throws(() => s.finish(value.operationId, ticket.attempt, { status: 'written', sha256: hash('new') }), /Invalid/);
  assert.equal(s.finish(value.operationId, ticket.attempt, { status: 'failed' }).status, 'failed');
  assert.throws(() => s.propose(input({ path: '\ud800' })), /Invalid/);
  assert.equal(s.core.healthy, true);
});

test('strict expiry, cancel and ordered pruning agree with JS baseline', wasm, () => {
  for (const stateCore of [core(), new JavascriptOperationCore()]) {
    let now = 0; const s = store({ core: stateCore, clock: () => now });
    const expiring = input(); s.propose(expiring); now = 600000; s.prune(); assert.equal(s.records.get(expiring.operationId).status, 'pending');
    now++; s.prune(); assert.equal(s.records.get(expiring.operationId).status, 'expired');
    const active = s.beginDirect(input()), pending = input(); s.propose(pending); s.cancelPending('paused');
    assert.equal(s.records.get(active.operation.operationId).status, 'applying'); assert.equal(s.records.get(pending.operationId).status, 'rejected');
    for (let n = 0; n < 197; n++) { const ticket = s.beginDirect(input()); s.finish(ticket.operation.operationId, ticket.attempt, { status: 'failed' }); }
    assert.equal(s.records.size, 200); const ids = [...s.records.keys()]; s.prune();
    assert.equal(s.records.size, 99); assert.equal(s.records.get(active.operation.operationId).status, 'applying');
    assert.deepEqual([...s.records.keys()].filter(id => id !== active.operation.operationId), ids.slice(102));
  }
});

test('bounded content-free event ring supports worst-case paths with one disk append', wasm, async t => {
  const f = await fixture(t), s = store(), name = '\x01'.repeat(4096);
  for (let n = 0; n < 101; n++) await s.audit('read', { rootId: 'r', path: name });
  assert.equal(s.events.length, 100); assert.equal(s.events[0].path, name);
  for (let n = 0; n < 101; n++) await f.service.audit('read', { rootId: 'r', path: `${n}.txt` });
  assert.equal((await fs.readFile(path.join(f.state, 'audit.jsonl'), 'utf8')).trim().split('\n').length, 101);
  await assert.rejects(() => s.audit('read', { rootId: 'r', path: name, content: 'private' }), /Invalid/);
  assert.equal(s.core.healthy, true);
});

test('active records remain bounded at 200 with maximum body storage', wasm, () => {
  const s = store(), body = 'x'.repeat(65536);
  for (let n = 0; n < 200; n++) s.beginDirect(input({ content: body, before: body }));
  assert.equal(s.records.size, 200); assert.equal([...s.records.values()].length, 200);
  assert.throws(() => s.beginDirect(input()), /Too many active/); assert.equal(s.core.healthy, true);
});

test('local account rejection is explicit while remote owner and visibility stay isolated', wasm, async t => {
  const f = await fixture(t), grant = owner(); grant.roots[0].rootId = f.root.id;
  f.policy.roots = []; f.policy.accountRoots = [{ ...f.root, connectionId: grant.connectionId }];
  const args = { rootId: f.root.id, path: 'account.txt', content: 'new', expectedHash: null };
  const proposal = await f.service.invoke('propose_write', args, grant);
  assert.equal((await f.service.decide(proposal.operationId, false)).status, 'rejected');
  assert.equal((await f.service.invoke('operation_status', { operationId: proposal.operationId }, grant)).status, 'rejected');
  const stranger = { ...grant, connectionId: 'c'.repeat(32) };
  assert.equal((await f.service.invoke('operation_status', { operationId: proposal.operationId }, stranger)).status, 'unknown');
  assert.equal(f.service.status(proposal.operationId).status, 'unknown');
  const otherResource = { ...grant, resource: 'https://other.example/mcp' };
  assert.equal((await f.service.invoke('operation_status', { operationId: proposal.operationId }, otherResource)).status, 'unknown');
  f.policy.accountRoots = [];
  assert.equal((await f.service.invoke('operation_status', { operationId: proposal.operationId }, grant)).status, 'unknown');
});

test('history binds original device and resource even when current caller and local identity change together', wasm, async t => {
  for (const stateCore of [core(), new JavascriptOperationCore()]) {
    const f = await fixture(t, { stateCore }), grant = owner(); grant.roots[0].rootId = f.root.id;
    const proposal = await f.service.invoke('propose_write', { rootId: f.root.id, path: 'bound.txt', content: 'new', expectedHash: null }, grant);
    const query = access => f.service.invoke('operation_status', { operationId: proposal.operationId }, access);
    assert.equal((await query(grant)).status, 'pending');
    f.identity.deviceId = 'd'.repeat(32);
    const otherDevice = { ...grant, deviceId: f.identity.deviceId };
    assert.equal((await query(otherDevice)).status, 'unknown');
    f.identity.deviceId = grant.deviceId;
    f.identity.resource = 'https://other.example/mcp';
    const otherResource = { ...grant, resource: f.identity.resource };
    assert.equal((await query(otherResource)).status, 'unknown');
    f.identity.resource = grant.resource;
    assert.equal((await query(grant)).status, 'pending');
  }
});

test('approval re-enters copied owner and rechecks current root revocation', wasm, async t => {
  const f = await fixture(t), grant = owner(); grant.roots[0].rootId = f.root.id;
  const proposal = await f.service.invoke('propose_write', { rootId: f.root.id, path: 'revoked.txt', content: 'new', expectedHash: null }, grant);
  grant.roots.length = 0; f.policy.roots = [];
  assert.equal((await f.service.decide(proposal.operationId, true)).status, 'failed');
  assert.equal(existsSync(path.join(f.directory, 'revoked.txt')), false);
});

test('proposed and rejected audit failures keep transitions; written audit failure keeps success', wasm, async t => {
  const f = await fixture(t);
  await fs.mkdir(path.join(f.state, 'audit.jsonl'));
  await assert.rejects(() => f.propose());
  const pending = f.service.pendingOperations(); assert.equal(pending.length, 1); assert.equal(f.service.events[0].action, 'proposed');
  await assert.rejects(() => f.service.decide(pending[0].operationId, false));
  assert.equal(f.service.status(pending[0].operationId).status, 'rejected'); assert.equal(f.service.events.at(-1).action, 'rejected');
  await fs.rmdir(path.join(f.state, 'audit.jsonl'));
  const audit = f.service.audit.bind(f.service); f.service.audit = async (action, details) => { if (action === 'written') throw Error('test disk failure'); return audit(action, details); };
  const result = await f.write('written.txt', 'bytes'); assert.equal(result.status, 'written'); assert.match(result.message, /audit log/);
  assert.equal(await fs.readFile(path.join(f.directory, 'written.txt'), 'utf8'), 'bytes');
});

test('malformed ABI and traps freeze permanently but status/cancel/prune remain usable', wasm, () => {
  for (const kind of ['trap', 'malformed', 'serial']) {
    const h = faultCore(), s = store({ core: h.state }), value = input(); s.propose(value);
    h.arm(kind, command => command.op === 'snapshotIds'); assert.deepEqual(s.ids(), []); assert.equal(h.state.healthy, false);
    s.cancelPending(); s.prune(); assert.deepEqual(s.pending(), []); assert.deepEqual(s.events, []);
    assert.throws(() => s.propose(input()), /history is unavailable/);
    assert.equal(s.records.get(value.operationId), undefined);
  }
});

test('issued queued tickets cannot start after the Rust state owner traps', wasm, async t => {
  const h = faultCore(), f = await fixture(t, { stateCore: h.state });
  let entered, unblock; const started = new Promise(resolve => { entered = resolve; }); const gate = new Promise(resolve => { unblock = resolve; });
  const commit = f.service.writer.commit.bind(f.service.writer); let calls = 0;
  f.service.writer.commit = async value => { calls++; entered(); await gate; await commit(value); };
  const first = f.write('first.txt', 'one'); await started;
  const second = f.write('second.txt', 'two');
  await new Promise(resolve => setImmediate(resolve));
  h.arm('trap', command => command.op === 'status'); assert.equal(f.service.status(randomUUID()).status, 'unknown');
  unblock(); const receipt = await first; await assert.rejects(second, /history is unavailable/);
  // Direct audit occurs before submit, so this in-flight JS writer fails safely.
  assert.equal(receipt.status, 'failed'); assert.equal(calls, 1); assert.deepEqual(await fs.readdir(f.directory), []);
});

test('actual Rust read/write plus operation state preserves raw backup and lone-surrogate bytes', native, async t => {
  const f = await fixture(t, { nativeIO: true }), before = '\ufefforiginal\r\n', after = '\ufeff\ud800\r\n';
  await fs.writeFile(path.join(f.directory, 'note.txt'), before);
  const read = await f.service.invoke('read_file', { rootId: f.root.id, path: 'note.txt' }); assert.equal(read.sha256, hash(before));
  const proposal = await f.service.invoke('propose_write', { rootId: f.root.id, path: 'note.txt', content: after, expectedHash: read.sha256 });
  const result = await f.service.decide(proposal.operationId, true); assert.equal(result.status, 'approved', JSON.stringify(result));
  assert.equal(result.sha256, hash(Buffer.from(after))); assert.deepEqual(await fs.readFile(path.join(f.directory, 'note.txt')), Buffer.from(after));
  assert.deepEqual(await fs.readFile(path.join(f.state, 'rust-writes', `${result.operationId}.before`)), Buffer.from(before));
  const direct = await f.write('direct.txt', '\ud800'); assert.equal(direct.status, 'written'); assert.equal(direct.sha256, hash('\ufffd'));
  assert.equal(f.service.status(result.operationId).status, 'approved'); await assertWriteFenceClear(f.state);
});

test('trap after real native commit preserves immediate success, freezes history and never replays', native, async t => {
  const h = faultCore(), f = await fixture(t, { stateCore: h.state, nativeIO: true }); h.arm('trap', command => command.op === 'finish');
  const result = await f.write('committed.txt', 'durable');
  assert.equal(result.status, 'written', JSON.stringify(result)); assert.match(result.message, /history is unavailable/);
  assert.equal(await fs.readFile(path.join(f.directory, 'committed.txt'), 'utf8'), 'durable');
  assert.equal(f.service.status(result.operationId).status, 'unknown'); await assert.rejects(() => f.write('blocked.txt', 'x'), /history is unavailable/);
  f.service.cancelPending(); f.service.prune(); await assertWriteFenceClear(f.state);
  const restarted = new FileService(() => f.policy, f.state, undefined, { operationsCore: core() });
  assert.equal(restarted.status(result.operationId).status, 'unknown'); assert.deepEqual(restarted.pendingOperations(), []);
  assert.equal(existsSync(path.join(f.directory, 'blocked.txt')), false);
});

test('ordinary finish rejection after a real write freezes and retains both audit and history warnings', native, async t => {
  const f = await fixture(t, { nativeIO: true });
  const audit = f.service.audit.bind(f.service);
  f.service.audit = async (action, details) => { if (action === 'written') throw Error('disk failure'); return audit(action, details); };
  const finish = f.service.history.finish.bind(f.service.history);
  f.service.history.finish = (id, _attempt, result) => finish(id, '9999', result);
  const result = await f.write('confirmed.txt', 'written');
  assert.equal(result.status, 'written'); assert.match(result.message, /audit log/); assert.match(result.message, /history is unavailable/);
  assert.equal(f.service.history.core.healthy, false); assert.equal(f.service.status(result.operationId).status, 'unknown');
  await assert.rejects(() => f.write('blocked.txt', 'x'), /history is unavailable/);
  assert.equal(await fs.readFile(path.join(f.directory, 'confirmed.txt'), 'utf8'), 'written');
});

test('remote fallback hides actual write receipt after revocation plus trap or attempt failure', native, async t => {
  for (const fault of ['trap', 'attempt']) {
    for (const change of ['root', 'device', 'resource', 'pause']) {
      const h = faultCore(), f = await fixture(t, { stateCore: h.state, nativeIO: true });
      const grant = owner(); grant.roots[0].rootId = f.root.id;
      if (fault === 'trap') h.arm('trap', command => command.op === 'finish');
      else {
        const finish = f.service.history.finish.bind(f.service.history);
        f.service.history.finish = (id, _attempt, result) => finish(id, '9999', result);
      }
      const audit = f.service.audit.bind(f.service);
      f.service.audit = async (action, details) => {
        await audit(action, details);
        if (action !== 'written') return;
        if (change === 'root') f.policy.roots = [];
        if (change === 'device') f.identity.deviceId = 'd'.repeat(32);
        if (change === 'resource') f.identity.resource = null;
        if (change === 'pause') f.policy.paused = true;
      };
      const result = await f.service.invoke('write_file', { rootId: f.root.id, path: 'hidden.txt', expectedHash: null, content: 'written' }, grant);
      assert.equal(result.status, 'unknown', `${fault}/${change}: ${JSON.stringify(result)}`);
      assert.deepEqual(Object.keys(result).sort(), ['message', 'operationId', 'status']);
      assert.match(result.message, /do not retry/);
      assert.equal(await fs.readFile(path.join(f.directory, 'hidden.txt'), 'utf8'), 'written');
      assert.equal(h.state.healthy, false); await assertWriteFenceClear(f.state);
    }
  }
});

test('authenticated local decision retains actual receipt after revocation and history failure', native, async t => {
  for (const fault of ['trap', 'attempt']) {
    const h = faultCore(), f = await fixture(t, { stateCore: h.state, nativeIO: true });
    const grant = owner(); grant.roots[0].rootId = f.root.id;
    const proposal = await f.service.invoke('propose_write', { rootId: f.root.id, path: 'local.txt', expectedHash: null, content: 'written' }, grant);
    if (fault === 'trap') h.arm('trap', command => command.op === 'finish');
    else {
      const finish = f.service.history.finish.bind(f.service.history);
      f.service.history.finish = (id, _attempt, result) => finish(id, '9999', result);
    }
    const audit = f.service.audit.bind(f.service);
    f.service.audit = async (action, details) => { await audit(action, details); if (action === 'written') f.policy.roots = []; };
    const result = await f.service.decide(proposal.operationId, true);
    assert.equal(result.status, 'approved'); assert.equal(result.sha256, hash('written')); assert.match(result.message, /history is unavailable/);
    assert.equal(await fs.readFile(path.join(f.directory, 'local.txt'), 'utf8'), 'written');
  }
});

test('remote normal completion rechecks current root visibility and pause after awaited audit', wasm, async t => {
  for (const change of ['root', 'pause']) {
    const f = await fixture(t), grant = owner(); grant.roots[0].rootId = f.root.id;
    const audit = f.service.audit.bind(f.service);
    f.service.audit = async (action, details) => {
      await audit(action, details);
      if (action === 'written') { if (change === 'root') f.policy.roots = []; else f.policy.paused = true; }
    };
    const result = await f.service.invoke('write_file', { rootId: f.root.id, path: 'hidden.txt', expectedHash: null, content: 'written' }, grant);
    assert.equal(result.status, 'unknown'); assert.equal(await fs.readFile(path.join(f.directory, 'hidden.txt'), 'utf8'), 'written');
    assert.equal(f.service.history.core.healthy, true);
  }
});

test('existing durable unknown fence blocks both Rust-operation JS and native writers after restart', native, async t => {
  const f = await fixture(t), directory = path.join(f.state, 'rust-writes'); await fs.mkdir(directory);
  await fs.writeFile(path.join(directory, `${randomUUID()}.json`), 'corrupt fence');
  for (const writerBackend of [undefined, new RustWriterBackend({ executable: writerPath })]) {
    const service = new FileService(() => f.policy, f.state, undefined, { operationsCore: core(), writerBackend });
    const result = await service.invoke('write_file', { rootId: f.root.id, path: 'blocked.txt', content: 'x', expectedHash: null });
    assert.equal(result.status, 'failed'); assert.match(result.message, /EFENCE/);
  }
  assert.deepEqual(await fs.readdir(f.directory), []);
});

test('actual controller selects Rust operations and authenticates local approval/status and pause', wasm, async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-operations-http-'));
  const app = await startController({ port: 0, stateDir: path.join(base, 'state'), demoDir: path.join(base, 'demo'), operationsBackend: 'rust', operationsModulePath: modulePath });
  t.after(async () => { await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  const api = (route, body) => fetch(`${app.origin}/api/${route}`, { method: body === undefined ? 'GET' : 'POST',
    headers: { 'X-Chat2Local-Token': app.token, Origin: app.origin, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  assert.ok(app.files.history.core instanceof RustOperationCore);
  assert.equal((await fetch(`${app.origin}/api/status`)).status, 401);
  const proposal = await (await api('demo', {})).json(), state = await (await api('status')).json();
  assert.equal(state.pending[0].operationId, proposal.operationId); assert.equal(state.pending[0].owner, undefined); assert.equal(state.pending[0].attempt, undefined);
  assert.equal((await api('approve', { operationId: proposal.operationId, approved: 'true' })).status, 400);
  const response = await api('approve', { operationId: proposal.operationId, approved: true }); assert.equal(response.status, 200); assert.equal((await response.json()).status, 'approved');
  assert.equal((await (await api('status')).json()).pending.length, 0);
  const next = await (await api('demo', {})).json(); assert.equal(next.status, 'pending');
  assert.equal((await api('pause', { paused: true })).status, 200); assert.equal((await (await api('status')).json()).pending.length, 0);
  app.files.history.freeze();
  assert.equal((await api('pause', { paused: false })).status, 200);
  const root = (await (await api('status')).json()).roots[0];
  assert.equal((await api('root/remove', { id: root.id })).status, 200);
  assert.equal((await api('status')).status, 200);
});
