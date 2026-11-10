import { readArtifact } from './relay-runtime.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID, createHash } from 'node:crypto';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { projectRoot } from '../scripts/rust-relay-artifact.mjs';
import { RustDeviceSessionCore } from '../src/relay/rust-device-session.mjs';
import { JsDeviceSessionCore, field, projectLease, validResult } from '../src/relay/device-session-core.mjs';
import { socketIsLive, touchLease, retireSocket } from '../src/relay/socket-lease.mjs';

const directory = process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR ?? process.env.CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR ?? process.env.CHAT2LOCAL_DEVICE_TEST_ARTIFACT_DIR ?? path.join(projectRoot, '.artifacts/rust-relay');
let artifact, unavailable;
try { artifact = await readArtifact(directory); }
catch (error) { if (process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_REQUIRED === '1' || process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR || process.env.CHAT2LOCAL_OAUTH_TEST_REQUIRED === '1' || process.env.CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR || process.env.CHAT2LOCAL_DEVICE_TEST_REQUIRED === '1' || process.env.CHAT2LOCAL_DEVICE_TEST_ARTIFACT_DIR) throw error; unavailable = 'Build the explicit Rust Device artifact'; }
const wasm = { skip: unavailable }, compiled = artifact && new WebAssembly.Module(artifact.bytes);
const core = () => new RustDeviceSessionCore(compiled);
const epoch = 'b'.repeat(64), key = 'c'.repeat(64), idA = 'a'.repeat(32), idB = 'd'.repeat(32);
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(action, timeout = 5000) { const end = Date.now() + timeout; do { const value = await action(); if (value) return value; await pause(10); } while (Date.now() < end); throw Error('Device fixture deadline'); }
const admit = (id = randomUUID(), socket = '1') => ({ op: 'admit', id, socket, epoch, identity: { present: true, revoked: false, epoch }, capability: { required: true, supported: true }, live: true });
function fakeSocket(attachment = { version: 1, connectedAt: Date.now(), lastSeenAt: Date.now(), retired: false, connectionAccess: true, terminal: true }) {
  return { attachment, readyState: 1, sent: [], deserializeAttachment() { return structuredClone(this.attachment); },
    serializeAttachment(value) { this.attachment = structuredClone(value); }, send(value) { this.sent.push(JSON.parse(value)); }, close() { this.readyState = 3; } };
}

test('default worker builds with no generated entry or WASM dependency', async () => {
  const bundle = await build({ entryPoints: ['src/relay/worker.mjs'], bundle: true, write: false, metafile: true, format: 'esm', platform: 'neutral', mainFields: ['module', 'main'], external: ['cloudflare:workers'] });
  assert.equal(Object.keys(bundle.metafile.inputs).some(file => /rust-device-session|\.wasm|\.artifacts/.test(file)), false);
  assert.equal(bundle.outputFiles[0].text.includes('RustDeviceSessionCore'), false);
});

test('real WASM lease decisions match JS exact boundaries and malformed scalar/null distinctions', wasm, () => {
  const rust = core(), js = new JsDeviceSessionCore(), base = { version: 1, connectedAt: 1000, lastSeenAt: 1000, retired: false };
  const values = [null, undefined, false, [], {}, { ...base }, { ...base, version: '1' }, { ...base, retired: 0 }, { ...base, retired: true },
    { ...base, connectedAt: 1001 }, { ...base, lastSeenAt: NaN }, { ...base, lastSeenAt: Infinity }, { ...base, lastSeenAt: null },
    { ...base, connectedAt: -1 }, { ...base, lastSeenAt: 6000 }, { ...base, lastSeenAt: 6001 }];
  for (const value of values) for (const now of [-1, NaN, Infinity, 0, 999, 1000, 75999, 76000, 76001]) for (const open of [true, false]) for (const op of ['leaseObserve', 'leaseTouch']) {
    const command = { op, attachment: projectLease(value), open, now: field(now) };
    assert.deepEqual(rust.execute(command), js.execute(command));
  }
  assert.equal(validResult({ op: 'leaseObserve', attachment: { kind: 'null' }, open: true, now: field(1) }, { live: true, patch: null }), false);
  assert.equal(validResult({ op: 'leaseObserve', attachment: projectLease(base), open: true, now: field(1) }, { live: true, patch: { version: 1, connectedAt: 1, lastSeenAt: 1, retired: false } }), false);
});

test('attachment grace is written once; touch/retire preserve structured-clone root aliases and unknown types', wasm, () => {
  for (const backend of [core(), new JsDeviceSessionCore()]) {
    const empty = fakeSocket(null); let writes = 0; empty.serializeAttachment = value => { writes++; empty.attachment = structuredClone(value); };
    assert.equal(socketIsLive(empty, 1000, backend), true); assert.equal(socketIsLive(empty, 2000, backend), true); assert.equal(writes, 1);
    const inaccessible = fakeSocket(null); inaccessible.serializeAttachment = () => { throw Error('attachment write'); };
    assert.equal(socketIsLive(inaccessible, 1000, backend), false);
    const value = { version: 1, connectedAt: 1000, lastSeenAt: 1000, retired: false, future: { date: new Date(123), bytes: new Uint8Array([1,2]), bigint: 123n } };
    value.self = value; value.map = new Map([['root', value]]); const socket = fakeSocket(value);
    assert.equal(touchLease(socket, 5000, backend), true); assert.equal(touchLease(socket, 4000, backend), true); assert.equal(socket.attachment.lastSeenAt, 5000);
    retireSocket(socket, 'fixture', backend);
    assert.equal(socket.attachment.self, socket.attachment); assert.equal(socket.attachment.map.get('root'), socket.attachment);
    assert.deepEqual(socket.attachment.future, value.future); assert.equal(socket.attachment.retired, true);
  }
});

test('real WASM owns twelve admits, socket ownership, once-only settlement and independent instances', wasm, () => {
  const a = core(), b = core(), commands = Array.from({ length: 12 }, () => admit());
  for (const command of commands) { assert.equal(a.execute(command).admitted, true); assert.equal(b.execute(command).admitted, true); }
  assert.equal(a.execute(admit()).reason, 'busy');
  assert.deepEqual(a.execute({ op: 'settle', id: commands[0].id, socket: '2' }).consumed, []);
  assert.deepEqual(a.execute({ op: 'timeout', id: commands[0].id, socket: '1' }).consumed, [commands[0].id]);
  assert.deepEqual(a.execute({ op: 'settle', id: commands[0].id, socket: '1' }).consumed, []);
  assert.equal(a.execute({ op: 'disconnect', socket: '1' }).consumed.length, 11); assert.equal(b.execute({ op: 'count' }).count, 12);
});

let deviceClass;
async function fixtureDevice(t, { fault } = {}) {
  deviceClass ??= build({ entryPoints: ['src/relay/state.mjs'], bundle: true, write: false, format: 'esm', platform: 'neutral', plugins: [{ name: 'fixture-platform', setup(builder) {
    builder.onResolve({ filter: /^cloudflare:workers$/ }, () => ({ path: 'platform', namespace: 'fixture' }));
    builder.onLoad({ filter: /.*/, namespace: 'fixture' }, () => ({ contents: 'export class DurableObject { constructor(ctx,env) {this.ctx=ctx;this.env=env;} }', loader: 'js' }));
  } }] }).then(result => import('data:text/javascript;base64,' + Buffer.from(result.outputFiles[0].text).toString('base64'))).then(module => module.Device);
  const Device = await deviceClass, socket = fakeSocket(), state = { identity: { epoch, revoked: false }, gets: 0 }, backend = core();
  const ctx = { getWebSockets: () => [socket], storage: { async get() { state.gets++; return structuredClone(state.identity); } } };
  const wrapped = { execute(command) { const value = backend.execute(command); return fault?.(command, value, backend) ?? value; }, freeze() { backend.freeze(); } };
  const device = new Device(ctx, {}, () => wrapped);
  t.after(() => device.failPending());
  const invoke = () => device.fetch(new Request('http://fixture/invoke', { method: 'POST', body: JSON.stringify({ epoch, tool: 'list_roots', args: {} }) }));
  return { device, socket, state, backend, ctx, invoke };
}

test('Device resource adapter rejects thirteenth with zero send and isolates wrong/duplicate/old socket results', wasm, async t => {
  const f = await fixtureDevice(t), requests = Array.from({ length: 12 }, () => f.invoke());
  await until(() => f.socket.sent.length === 12); assert.equal((await f.invoke()).status, 429); assert.equal(f.socket.sent.length, 12);
  const other = fakeSocket(), first = f.socket.sent[0]; f.device.webSocketMessage(other, JSON.stringify({ kind: 'result', id: first.id, result: 0 }));
  assert.equal(f.backend.execute({ op: 'count' }).count, 12); f.device.webSocketClose(other, 1000); assert.equal(f.device.pending.size, 12);
  f.device.webSocketMessage(f.socket, JSON.stringify({ kind: 'result', id: first.id, result: 'done' })); assert.equal((await requests[0]).status, 200);
  f.device.webSocketMessage(f.socket, JSON.stringify({ kind: 'result', id: first.id, result: 'duplicate' })); assert.equal(f.device.pending.size, 11);
  f.device.failPending(f.socket); assert.ok((await Promise.all(requests.slice(1))).every(response => response.status === 503));
  assert.equal(f.backend.execute({ op: 'count' }).count, 0);
});

test('body parsing and last identity read revocation prevent sends; admission through send has no await', wasm, async t => {
  const f = await fixtureDevice(t); let controller;
  const body = new ReadableStream({ start(value) { controller = value; } });
  const pending = f.device.fetch(new Request('http://fixture/invoke', { method: 'POST', body, duplex: 'half' }));
  await until(() => f.state.gets > 0); f.state.identity.revoked = true;
  controller.enqueue(new TextEncoder().encode(JSON.stringify({ epoch, tool: 'list_roots', args: {} }))); controller.close();
  assert.equal((await pending).status, 403); assert.equal(f.socket.sent.length, 0);
  const g = await fixtureDevice(t); g.ctx.storage.get = async () => { g.state.gets++; return { epoch, revoked: g.state.gets > 1 }; };
  assert.equal((await g.invoke()).status, 403); assert.equal(g.socket.sent.length, 0);
  const source = await fs.readFile(path.join(projectRoot, 'src/relay/state.mjs'), 'utf8');
  const dispatch = source.slice(source.indexOf("if (route === '/invoke')"));
  const section = dispatch.slice(dispatch.indexOf("const current = await this.ctx.storage.get('identity');") + "const current = await this.ctx.storage.get('identity');".length, dispatch.indexOf('socket.send('));
  assert.equal(/\bawait\b/.test(section), false);
});

test('trap after admission and invalid consumed IDs poison all resolvers and prevent future sends', wasm, async t => {
  for (const mode of ['trap', 'consumed']) {
    let enabled = false;
    const f = await fixtureDevice(t, { fault(command, value) {
      if (enabled && mode === 'trap' && command.op === 'admit') throw new WebAssembly.RuntimeError('fixture trap after admission');
      if (enabled && mode === 'consumed' && command.op === 'settle') return { consumed: [randomUUID()] };
      return value;
    } });
    const pending = f.invoke(); await until(() => f.socket.sent.length === 1); enabled = true;
    if (mode === 'trap') assert.equal((await f.invoke()).status, 503);
    else f.device.webSocketMessage(f.socket, JSON.stringify({ kind: 'result', id: f.socket.sent[0].id, result: 'must not surface' }));
    assert.equal((await pending).status, 503); assert.equal(f.device.pending.size, 0); assert.equal(f.device.poisoned, true);
    assert.equal((await f.invoke()).status, 503); assert.equal(f.socket.sent.length, 1);
  }
});

test('registration/send failures undo admission; attachment failures settle resources without replay', wasm, async t => {
  for (const mode of ['registration', 'send', 'attachment']) {
    const f = await fixtureDevice(t);
    if (mode === 'registration') f.device.pending.set = () => { throw Error('fixture allocation'); };
    if (mode === 'send') f.socket.send = () => { throw Error('fixture send'); };
    const pending = f.invoke();
    if (mode === 'attachment') { await until(() => f.socket.sent.length === 1); f.socket.serializeAttachment = () => { throw Error('fixture attachment'); }; f.device.webSocketMessage(f.socket, 'ping'); }
    assert.equal((await pending).status, 503); assert.equal(f.device.pending.size, 0); assert.equal(f.backend.execute({ op: 'count' }).count, 0);
  }
});

test('actual WASM ABI trap/malformed output freezes without recreating a state instance', wasm, () => {
  for (const mode of ['trap', 'length']) {
    let calls = 0;
    const broken = new RustDeviceSessionCore(compiled, module => {
      const real = new WebAssembly.Instance(module, {}).exports;
      return { exports: { ...real, command(length) { calls++; if (mode === 'trap') throw new WebAssembly.RuntimeError('fixture'); return real.command(length); }, output_len: () => 16385 } };
    });
    assert.throws(() => broken.execute(admit()), /unavailable/); assert.equal(broken.healthy, false);
    assert.throws(() => broken.execute(admit()), /unavailable/); assert.equal(calls, 1);
  }
});

test('explicit artifacts reject missing or stale binaries and source binding', wasm, async t => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-device-artifact-')); t.after(() => fs.rm(temp, { recursive: true, force: true }));
  await assert.rejects(() => readArtifact(temp));
  await fs.cp(directory, temp, { recursive: true });
  await fs.appendFile(path.join(temp, artifact.manifest.wasm), Buffer.from([0])); await assert.rejects(() => readArtifact(temp), /stale/i);
  await fs.copyFile(artifact.wasmPath, path.join(temp, artifact.manifest.wasm));
  const manifest = structuredClone(artifact.manifest); manifest.sources['src/relay/state.mjs'] = '0'.repeat(64);
  await fs.writeFile(path.join(temp, 'manifest.json'), JSON.stringify(manifest)); await assert.rejects(() => readArtifact(temp), /Stale.*source/);
});

async function runtimeOptions(rust, persist) {
  const entry = rust ? artifact.entry : path.join(projectRoot, 'src/relay/worker.mjs');
  const bundle = await build({ stdin: { resolveDir: projectRoot, sourcefile: 'device-fixture-entry.mjs', contents: `
import { Device as ProductionDevice } from ${JSON.stringify(entry)};
import { sha256 } from './src/shared/protocol.mjs';
export class Device extends ProductionDevice {
  constructor(ctx,env) { super(ctx,env); this.incarnation=crypto.randomUUID(); }
  newRequestId() { return this.fixedId || super.newRequestId(); }
  async fetch(request) {
    const route=new URL(request.url).pathname;
    if (route==='/test/seed') {
      const identity={keyHash:await sha256('${key}'),epoch:'${epoch}',revoked:false,description:{name:'synthetic'},future:{date:new Date(123),bytes:new Uint8Array([1,2]),bigint:123n}};
      identity.self=identity; identity.map=new Map([['root',identity]]);
      await this.ctx.storage.put('identity',identity);
      for(const name of ['pair','browser-handoff','browser-session']) await this.ctx.storage.put(name,{hash:await sha256('e'.repeat(64)),epoch:'${epoch}',expiresAt:9999999999999,future:new Map([['keep',3]])});
      return Response.json({ok:true});
    }
    if(route==='/test/attachment') { for(const socket of this.ctx.getWebSockets('device')) { const value=socket.deserializeAttachment();value.self=value;value.map=new Map([['root',value]]);value.extra={date:new Date(123),bytes:new Uint8Array([1,2]),bigint:123n};socket.serializeAttachment(value); } return Response.json({ok:true}); }
    if(route==='/test/fixed') {this.fixedId='1'.repeat(36);return Response.json({ok:true});}
    if(route==='/test/fault') {this.core.freeze();return Response.json({ok:true});}
    if(route==='/test/state') {
      const record=await this.ctx.storage.get('identity'), lease=this.ctx.getWebSockets('device')[0]?.deserializeAttachment();
      const proofs=[];for(const name of ['pair','browser-handoff','browser-session']) {const value=await this.ctx.storage.get(name);proofs.push([name,value?.hash,value?.epoch,value?.future?.get('keep')]);}
      return Response.json({incarnation:this.incarnation,core:this.core.constructor.name,pending:this.pending.size,poisoned:this.poisoned,
        record:{keyHash:record.keyHash,epoch:record.epoch,revoked:record.revoked,description:record.description,self:record.self===record,map:record.map.get('root')===record,date:record.future.date.getTime(),bytes:[...record.future.bytes],bigint:String(record.future.bigint)},proofs,
        lease:lease&&{version:lease.version,retired:lease.retired,connectedAt:lease.connectedAt,lastSeenAt:lease.lastSeenAt,connectionAccess:lease.connectionAccess,terminal:lease.terminal,self:lease.self===lease,map:lease.map?.get('root')===lease,bigint:String(lease.extra?.bigint)}});
    }
    return super.fetch(request);
  }
}
export default {fetch(request,env){const name=new URL(request.url).searchParams.get('device')||'${idA}';return env.DEVICES.get(env.DEVICES.idFromName(name)).fetch(request);}};
` }, bundle: true, write: false, format: 'esm', platform: 'neutral', mainFields: ['module', 'main'], external: ['cloudflare:workers', '*.wasm'] });
  return convertV4MiniflareOptions({ name: 'chat2local-device-fixture', modulesRoot: directory, modules: [
    { type: 'ESModule', path: path.join(directory, 'fixture-worker.mjs'), contents: bundle.outputFiles[0].text },
    ...(rust ? [{ type: 'CompiledWasm', path: artifact.wasmPath }, { type: 'CompiledWasm', path: artifact.registryWasmPath }, ...(artifact.oauthWasmPath ? [{ type: 'CompiledWasm', path: artifact.oauthWasmPath }] : [])] : []),
  ], compatibilityDate: '2026-09-20', compatibilityFlags: ['nodejs_compat', 'global_fetch_strictly_public'], host: '127.0.0.1', port: 0,
    durableObjectsPersist: persist, durableObjects: { DEVICES: { className: 'Device', useSQLite: true, unsafeUniqueKey: 'chat2local-device-fixture-only', unsafePreventEviction: false } } });
}
const fetchDevice = (mf, route, device = idA, body) => mf.dispatchFetch(`http://fixture${route}?device=${device}`, { method: 'POST', ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
async function data(response, expected = 200) { assert.equal(response.status, expected, await response.clone().text()); return response.json(); }
async function connect(mf, device = idA) {
  const response = await mf.dispatchFetch(`http://fixture/connect?device=${device}`, { headers: { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': `chat2local-v1, device.${key}, connection-access-v1, terminal-jobs-v1` } });
  if (response.status !== 101) assert.fail(await response.text()); response.webSocket.accept(); return response.webSocket;
}
function nextMessage(socket, act) {
  return new Promise((resolve,reject) => { const timer=setTimeout(()=>{socket.removeEventListener('message',message);reject(Error('socket fixture timeout'));},5000);
    const message=event=>{clearTimeout(timer);socket.removeEventListener('message',message);resolve(event.data);};socket.addEventListener('message',message);act?.(); });
}
const invoke = (mf, device = idA) => fetchDevice(mf, '/invoke', device, { epoch, tool: 'list_roots', args: {} });

test('actual Device JS to Rust to JS preserves the original namespace, identity, proofs and structured-clone state', wasm, async t => {
  const persist = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-device-storage-'));
  const mf = new Miniflare(await runtimeOptions(false, persist)); t.after(async () => { await mf.dispose(); await fs.rm(persist, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); }); await mf.ready;
  const objectId = (await mf.getDurableObjectNamespace('DEVICES')).idFromName(idA).toString();
  await data(await fetchDevice(mf, '/test/seed')); const before = await data(await fetchDevice(mf, '/test/state'));
  for (const rust of [true, false]) {
    await mf.setOptions(await runtimeOptions(rust, persist)); await mf.ready;
    assert.equal((await mf.getDurableObjectNamespace('DEVICES')).idFromName(idA).toString(), objectId);
    const state = await data(await fetchDevice(mf, '/test/state')); assert.deepEqual(state.record, before.record); assert.deepEqual(state.proofs, before.proofs);
    assert.match(state.core, rust ? /RustDeviceSessionCore/ : /JsDeviceSessionCore/);
    const socket = await connect(mf), call = nextMessage(socket), pending = invoke(mf); const frame = JSON.parse(await call);
    socket.send(JSON.stringify({ kind: 'result', id: frame.id, result: [rust ? 'rust' : 'js'] })); assert.deepEqual((await data(await pending)).result, [rust ? 'rust' : 'js']);
    socket.close(1000, 'fixture update reconnect');
    await until(async () => !(await data(await fetchDevice(mf, '/describe', idA, { epoch }))).online);
  }
});

test('actual JS and Rust Devices hibernate and resume the same socket with lease, capabilities and unknown graph intact', wasm, async t => {
  for (const rust of [false, true]) await t.test(rust ? 'Rust Device' : 'JS Device', async t => {
  const mf = new Miniflare(await runtimeOptions(rust)); t.after(() => mf.dispose()); await mf.ready;
  await data(await fetchDevice(mf, '/test/seed')); const socket = await connect(mf); t.after(() => socket.close(1000, 'fixture finished'));
  await data(await fetchDevice(mf, '/test/attachment')); assert.equal(await nextMessage(socket, () => socket.send('ping')), 'pong');
  const before = await data(await fetchDevice(mf, '/test/state')); assert.equal(before.pending, 0);
  await mf.unsafeEvictDurableObject('chat2local-device-fixture', 'Device', { name: idA, webSockets: 'hibernate' });
  assert.equal(await nextMessage(socket, () => socket.send('ping')), 'pong'); const after = await data(await fetchDevice(mf, '/test/state'));
  assert.notEqual(after.incarnation, before.incarnation); assert.equal(after.lease.connectedAt, before.lease.connectedAt); assert.ok(after.lease.lastSeenAt >= before.lease.lastSeenAt);
  for (const field of ['version','retired','connectionAccess','terminal','self','map','bigint']) assert.equal(after.lease[field], before.lease[field]);
  assert.equal(after.lease.self, true); assert.equal(after.lease.map, true);
  assert.equal(after.lease.connectionAccess, true); assert.equal(after.lease.terminal, true);
  const call = nextMessage(socket), pending = invoke(mf), frame = JSON.parse(await call); socket.send(JSON.stringify({ kind: 'result', id: frame.id, result: 'same socket' }));
  assert.equal((await data(await pending)).result, 'same socket');
  });
});

test('actual workerd Device admits twelve, rejects thirteenth without send and releases exactly one slot', wasm, async t => {
  const mf = new Miniflare(await runtimeOptions(true)); t.after(() => mf.dispose()); await mf.ready;
  await data(await fetchDevice(mf, '/test/seed')); const socket = await connect(mf); t.after(() => socket.close()); const calls = [];
  socket.addEventListener('message', event => { if (event.data !== 'pong') calls.push(JSON.parse(event.data)); });
  const requests = Array.from({ length: 12 }, () => invoke(mf)); await until(() => calls.length === 12);
  assert.equal((await invoke(mf)).status, 429); await pause(50); assert.equal(calls.length, 12);
  await data(await fetchDevice(mf, '/test/seed', idB)); const other = await connect(mf, idB); t.after(() => other.close());
  const otherMessage = nextMessage(other), otherPending = invoke(mf, idB), otherCall = JSON.parse(await otherMessage);
  other.send(JSON.stringify({ kind: 'result', id: otherCall.id, result: 'independent capacity' }));
  assert.equal((await data(await otherPending)).result, 'independent capacity');
  assert.equal((await data(await fetchDevice(mf, '/test/state'))).pending, 12);
  socket.send(JSON.stringify({ kind: 'result', id: calls[0].id, result: 'one' }));
  await until(async () => (await data(await fetchDevice(mf, '/test/state'))).pending === 11);
  const replacement = invoke(mf); await until(() => calls.length === 13); assert.equal((await invoke(mf)).status, 429); assert.equal(calls.length, 13);
  for (const call of calls.slice(1)) socket.send(JSON.stringify({ kind: 'result', id: call.id, result: 'done' }));
  assert.ok((await Promise.all([...requests, replacement])).every(response => response.status === 200));
  assert.equal((await data(await fetchDevice(mf, '/test/state'))).pending, 0);
});

test('consumed proofs do not revive after JS to Rust and Rust revocation survives return to JS', wasm, async t => {
  const persist = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-device-revoke-'));
  const mf = new Miniflare(await runtimeOptions(false, persist)); t.after(async () => { await mf.dispose(); await fs.rm(persist, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); }); await mf.ready;
  await data(await fetchDevice(mf, '/test/seed')); const original = await connect(mf);
  assert.equal((await data(await fetchDevice(mf, '/consume-pair', idA, { secret: 'e'.repeat(64) }))).epoch, epoch);
  const browserSecret = 'f'.repeat(64), browserHash = createHash('sha256').update(browserSecret).digest('hex');
  await data(await fetchDevice(mf, '/browser/consume', idA, { secret: 'e'.repeat(64), browserHash }));
  original.close(); await until(async () => !(await data(await fetchDevice(mf, '/describe', idA, { epoch }))).online);
  await mf.setOptions(await runtimeOptions(true, persist)); await mf.ready;
  const restored = await connect(mf);
  assert.equal((await fetchDevice(mf, '/consume-pair', idA, { secret: 'e'.repeat(64) })).status, 403);
  assert.equal((await fetchDevice(mf, '/browser/consume', idA, { secret: 'e'.repeat(64), browserHash })).status, 403);
  assert.equal((await data(await fetchDevice(mf, '/browser/verify', idA, { secret: browserSecret }))).epoch, epoch);
  await data(await mf.dispatchFetch('http://fixture/revoke', { method: 'POST', headers: { Authorization: `Bearer ${key}` } }));
  try { restored.close(); } catch {}
  await mf.setOptions(await runtimeOptions(false, persist)); await mf.ready;
  const record = (await data(await fetchDevice(mf, '/test/state'))).record; assert.equal(record.revoked, true); assert.notEqual(record.epoch, epoch);
  assert.equal((await mf.dispatchFetch('http://fixture/connect', { headers: { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': `chat2local-v1, device.${key}` } })).status, 401);
  assert.equal((await invoke(mf)).status, 401);
  assert.equal((await fetchDevice(mf, '/self-initialize', idA, { deviceKey: key })).status, 409);
});

test('two actual Rust Devices isolate identical IDs/socket tokens and faults; real timeout consumes once', { ...wasm, timeout: 40000 }, async t => {
  const mf = new Miniflare(await runtimeOptions(true)); t.after(() => mf.dispose()); await mf.ready;
  for (const device of [idA,idB]) { await data(await fetchDevice(mf, '/test/seed', device)); await data(await fetchDevice(mf, '/test/fixed', device)); }
  const a = await connect(mf,idA), b = await connect(mf,idB); t.after(() => { a.close(); b.close(); });
  const callA = nextMessage(a), callB = nextMessage(b), pendingA = invoke(mf,idA), pendingB = invoke(mf,idB);
  const frameA = JSON.parse(await callA), frameB = JSON.parse(await callB); assert.equal(frameA.id, frameB.id);
  await data(await fetchDevice(mf, '/test/fault', idA)); a.send('ping'); assert.equal((await pendingA).status, 503);
  assert.equal((await data(await fetchDevice(mf, '/test/state', idA))).pending, 0); assert.equal((await data(await fetchDevice(mf, '/test/state', idB))).pending, 1);
  b.send(JSON.stringify({ kind: 'result', id: frameB.id, result: 'B only' })); assert.equal((await data(await pendingB)).result, 'B only');
  const timedMessage = nextMessage(b), timed = invoke(mf,idB); const timedFrame = JSON.parse(await timedMessage);
  assert.equal((await timed).status, 504); b.send(JSON.stringify({ kind: 'result', id: timedFrame.id, result: 'late' }));
  assert.equal((await data(await fetchDevice(mf, '/test/state', idB))).pending, 0);
});
