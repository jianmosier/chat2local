import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { FileService, approveRoot, relativeParts } from '../src/agent/files.mjs';
import { RustReadonlyBackend, configuredReadonlyBackend } from '../src/agent/files/rust-readonly.mjs';
import { SerialQueue } from '../src/agent/runtime/serial-queue.mjs';
import { createToolDispatcher } from '../src/agent/runtime/tool-dispatcher.mjs';
import { rustSourceFiles, buildPublic } from '../scripts/build-public.mjs';
import { auditTree } from '../scripts/audit-public.mjs';

const executable = process.env.CHAT2LOCAL_RUST_TEST_EXECUTABLE ?? path.resolve('target/debug/chat2local-readonly.exe');
const unavailable = process.platform !== 'win32' ? 'Rust readonly currently requires Windows'
  : !existsSync(executable) ? 'Build Rust first with npm run test:rust (native coverage is required there)' : false;
if (process.env.CHAT2LOCAL_RUST_TEST_REQUIRED === '1' && unavailable) throw new Error(unavailable);
const deviceId = 'a'.repeat(32), connectionId = 'b'.repeat(32);
const origin = 'https://readonly-fixture.example.test', resource = `${origin}/mcp`;
const digest = value => createHash('sha256').update(value).digest('hex');
const native = { skip: unavailable };
const grant = id => ({ version: 1, deviceId, connectionId, resource, roots: [{ rootId: id, mode: 'direct' }], scopes: ['files:read', 'files:write', 'files:propose'] });

async function fixture(t, options = {}) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-rust-'));
  const directory = path.join(base, 'project');
  await fs.mkdir(directory);
  const root = { ...await approveRoot(directory, path.join(base, 'state'), true), writeMode: 'direct' };
  const config = { paused: false, roots: [root], accountRoots: [], remoteUseConfirmed: true };
  let device = deviceId, relayResource = resource;
  const backend = options.backend ?? new RustReadonlyBackend({ executable });
  const rust = new FileService(() => config, path.join(base, 'state'), () => ({ deviceId: device }), {
    readonlyBackend: backend, getResource: () => relayResource,
  });
  const js = new FileService(() => config, undefined, () => ({ deviceId: device }));
  const queue = new SerialQueue();
  const state = { config, secrets: { identity: { origin, deviceId } } };
  const dispatch = createToolDispatcher({ files: rust, terminal: { invoke() { throw Error('unexpected terminal'); } },
    readiness: { observeRemote() {} }, state, serial: action => queue.run(action) });
  t.after(async () => { await queue.drain(); await fs.rm(base, { recursive: true, force: true }); });
  return { base, root, directory, config, rust, js, backend, dispatch, queue,
    setDevice: value => { device = value; }, setResource: value => { relayResource = value; },
    args: file => ({ rootId: root.id, path: file }), access: grant(root.id) };
}

test('Rust backend is explicitly selected and fixed to the packaged executable', () => {
  assert.equal(configuredReadonlyBackend({}, {}), undefined);
  assert.equal(configuredReadonlyBackend({ readBackend: 'js' }, { CHAT2LOCAL_READ_BACKEND: 'rust' }), undefined);
  assert.throws(() => configuredReadonlyBackend({}, { CHAT2LOCAL_READ_BACKEND: 'other' }), /must be js or rust/);
  if (process.platform === 'win32') {
    assert.equal(configuredReadonlyBackend({}, { CHAT2LOCAL_READ_BACKEND: 'rust' }).executable, path.resolve('runtime/chat2local-readonly.exe'));
    assert.equal(configuredReadonlyBackend({ readBackend: 'rust', readonlyExecutable: executable }, {}).executable, executable);
  }
});

test('unbuilt native tests explicitly skip by default and fail in the strict runner context', () => {
  const env = { ...process.env, CHAT2LOCAL_RUST_TEST_EXECUTABLE: path.resolve('.artifacts/unbuilt-fixture/chat2local-readonly.exe'), CHAT2LOCAL_RUST_TEST_REQUIRED: '0' };
  // This is a separate CLI harness, not a nested worker in the current test run.
  for (const key of Object.keys(env)) if (key.startsWith('NODE_TEST_')) delete env[key];
  const args = ['--test', '--test-reporter=tap', '--test-name-pattern=real dispatcher reads', 'tests/rust-readonly.test.mjs'];
  const skipped = spawnSync(process.execPath, args, { env, encoding: 'utf8', windowsHide: true, timeout: 15000 });
  assert.equal(skipped.status, 0); assert.match(skipped.stdout, /# SKIP/);
  const required = spawnSync(process.execPath, args, { env: { ...env, CHAT2LOCAL_RUST_TEST_REQUIRED: '1' }, encoding: 'utf8', windowsHide: true, timeout: 15000 });
  assert.equal(required.status, 1); assert.match(required.stdout + required.stderr, /Build Rust first|requires Windows/);
});

test('real dispatcher reads raw-byte hashes, BOM, Unicode, CRLF, empty and 65536-byte files', native, async t => {
  const f = await fixture(t);
  for (const [name, bytes] of [
    ['中文.txt', Buffer.from('\ufeff中文😀\r\nsecond\r\n')], ['empty.txt', Buffer.alloc(0)],
    ['limit.txt', Buffer.alloc(65536, 'x')], ['control.txt', Buffer.alloc(65536, 1)],
  ]) {
    await fs.writeFile(path.join(f.directory, name), bytes);
    const result = await f.dispatch('read_file', f.args(name), undefined, f.access);
    assert.deepEqual(result, await f.js.invoke('read_file', f.args(name), f.access));
    assert.equal(result.sha256, digest(bytes));
  }
  const audit = await fs.readFile(path.join(f.base, 'state', 'audit.jsonl'), 'utf8');
  assert.equal(audit.trim().split('\n').length, 4);
});

test('real Rust denies large, NUL, malformed UTF-8 and missing files without path disclosure', native, async t => {
  const f = await fixture(t);
  for (const [name, bytes] of [['large.txt', Buffer.alloc(65537, 'x')], ['nul.txt', Buffer.from([0])], ['bad.txt', Buffer.from([0xc0, 0xaf])]]) {
    await fs.writeFile(path.join(f.directory, name), bytes);
    await assert.rejects(() => f.js.invoke('read_file', f.args(name)));
    await assert.rejects(() => f.dispatch('read_file', f.args(name)), error => !error.message.includes(f.directory));
  }
  await assert.rejects(() => f.dispatch('read_file', f.args('missing.txt')), /Filesystem operation failed \(ENOENT\)/);
});

test('Rust independently enforces the relative path and sensitive-name policy', native, async t => {
  const f = await fixture(t);
  const authority = f.rust.readonlyAuthority(f.root.id);
  for (const name of ['../x', 'a//b', 'a\\..\\b', '.env', '.env.local', '.dev.vars.test', '.git/config', 'node_modules/x', 'credentials.json', 'auth.json', 'id_rsa.pub', 'x.PEM', 'NUL.txt', 'COM0', 'x:stream', 'x.', 'x ', '/absolute', '\\server', 'x\0', 'x\x1f']) {
    assert.throws(() => relativeParts(name));
    await assert.rejects(() => f.backend.invoke('read_file', f.args(name), authority));
  }
});

test('directory results match actual Windows libuv enumeration and filter before the 500-entry cap', native, async t => {
  const f = await fixture(t);
  for (const name of ['a', 'B', 'é', '中文', '😀', 'Z', '.env', 'auth.json', 'hidden.KEY']) await fs.writeFile(path.join(f.directory, name), 'x');
  await fs.mkdir(path.join(f.directory, 'folder'));
  const read = () => f.dispatch('list_directory', { rootId: f.root.id });
  assert.deepEqual(await read(), await f.js.invoke('list_directory', { rootId: f.root.id }));
  for (let i = 0; i < 493; i++) await fs.writeFile(path.join(f.directory, `item-${String(i).padStart(3, '0')}`), '');
  assert.equal((await read()).entries.length, 500);
  assert.equal((await read()).truncated, false);
  await fs.writeFile(path.join(f.directory, 'item-extra'), '');
  assert.deepEqual(await read(), await f.js.invoke('list_directory', { rootId: f.root.id }));
  assert.equal((await read()).truncated, true);
});

test('real NTFS junctions, root aliases and hardlinks cannot return file contents', native, async t => {
  const f = await fixture(t);
  const outside = path.join(f.base, 'outside'); await fs.mkdir(outside);
  await fs.writeFile(path.join(outside, 'secret.txt'), 'outside');
  await fs.symlink(outside, path.join(f.directory, 'junction'), 'junction');
  await fs.link(path.join(outside, 'secret.txt'), path.join(f.directory, 'hardlink.txt'));
  await assert.rejects(() => f.dispatch('read_file', f.args('junction/secret.txt')), /junctions/);
  await assert.rejects(() => f.dispatch('list_directory', f.args('junction')), /junctions/);
  await assert.rejects(() => f.dispatch('read_file', f.args('hardlink.txt')), /regular text/);
  assert.equal((await f.dispatch('list_directory', f.args('.'))).entries.some(e => e.name === 'junction'), false);
  const alias = path.join(f.base, 'root-alias'); await fs.symlink(f.directory, alias, 'junction');
  f.root.path = alias;
  await assert.rejects(() => f.dispatch('list_directory', f.args('.')), /junctions/);
  f.root.path = path.join(alias, 'subfolder'); await fs.mkdir(path.join(f.directory, 'subfolder'));
  await assert.rejects(() => f.dispatch('list_directory', f.args('.')), /junctions/);
});

test('Rust independently checks paused, device, resource, shares and account ownership', native, async t => {
  const f = await fixture(t);
  await fs.writeFile(path.join(f.directory, 'file.txt'), 'fixture');
  const authority = { ...f.rust.readonlyAuthority(f.root.id), access: f.access };
  assert.equal((await f.backend.invoke('read_file', f.args('file.txt'), authority)).content, 'fixture');
  const changes = [
    a => { a.paused = true; }, a => { a.deviceId = 'c'.repeat(32); }, a => { a.resource = 'https://other.example.test/mcp'; },
    a => { a.access.scopes = ['files:write']; }, a => { a.access.roots[0].rootId = 'other'; },
    a => { a.root.kind = 'account'; a.root.connectionId = 'c'.repeat(32); },
    a => { a.root.kind = 'account'; a.root.connectionId = connectionId; a.access = null; },
    a => { a.access.connectionId = 'invalid'; }, a => { a.access.version = 2; },
    a => { a.access.roots.push(a.access.roots[0]); }, a => { a.root.id = 'other'; },
  ];
  for (const change of changes) {
    const value = structuredClone(authority); change(value);
    await assert.rejects(() => f.backend.invoke('read_file', f.args('file.txt'), value), /not authorized/);
  }
  f.config.roots = []; f.config.accountRoots = [{ ...f.root, connectionId }];
  assert.equal((await f.dispatch('read_file', f.args('file.txt'), undefined, f.access)).content, 'fixture');
  await assert.rejects(() => f.dispatch('read_file', f.args('file.txt')), /not authorized/);
  await assert.rejects(() => f.dispatch('read_file', f.args('file.txt'), undefined, { ...f.access, connectionId: 'c'.repeat(32) }), /not authorized/);
  await assert.rejects(() => f.dispatch('read_file', f.args('file.txt'), undefined, { ...f.access, resource: 'https://other.example.test/mcp' }), /different relay/);
});

test('post-child checks reject local revocation, root changes and changed identity', native, async t => {
  const f = await fixture(t);
  await fs.writeFile(path.join(f.directory, 'file.txt'), 'fixture');
  const original = f.rust.readonlyBackend;
  for (const change of [() => { f.config.paused = true; }, () => { f.root.path += '-changed'; },
    () => { f.config.roots = []; f.config.accountRoots = [{ ...f.root, connectionId }]; },
    () => f.setDevice('c'.repeat(32)), () => f.setResource('https://other.example.test/mcp'), () => { f.config.roots = []; }]) {
    const saved = structuredClone(f.root);
    f.rust.readonlyBackend = { async invoke(...args) { const value = await original.invoke(...args); change(); return value; } };
    await assert.rejects(() => f.dispatch('read_file', f.args('file.txt'), undefined, f.access), /paused|changed|authorized|different relay/);
    Object.assign(f.root, saved); f.config.roots = [f.root]; f.config.accountRoots = []; f.config.paused = false;
    f.setDevice(deviceId); f.setResource(resource);
  }
  await assert.rejects(() => fs.readFile(path.join(f.base, 'state', 'audit.jsonl')), { code: 'ENOENT' });
});

test('write and proposal snapshots remain JS and never invoke readonly backend', async t => {
  let calls = 0;
  const f = await fixture(t, { backend: { invoke() { calls++; throw Error('must not be called'); } } });
  const content = 'before'; await fs.writeFile(path.join(f.directory, 'file.txt'), content);
  const written = await f.dispatch('write_file', { ...f.args('file.txt'), expectedHash: digest(content), content: 'after' });
  assert.equal(written.status, 'written');
  const proposed = await f.dispatch('propose_write', { ...f.args('file.txt'), expectedHash: digest('after'), content: 'proposal' });
  assert.equal(proposed.status, 'pending'); assert.equal(calls, 0);
});

function synthetic(script, timeoutMs = 10000) {
  let launches = 0;
  const backend = new RustReadonlyBackend({ executable: process.execPath, timeoutMs, spawnProcess: (_exe, args, options) => {
    launches++; assert.deepEqual(args, []); assert.equal(options.shell, false); assert.equal(options.windowsHide, true);
    assert.deepEqual(options.stdio, ['pipe', 'pipe', 'ignore']);
    return spawn(process.execPath, ['-e', `let s='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>{const r=JSON.parse(s);${script}});`], options);
  } });
  return { backend, launches: () => launches };
}
const response = "{v:1,id:r.id,ok:true,result:{path:r.args.path,content:'ok',sha256:'a'.repeat(64)}}";

test('IPC rejects malformed/mismatched/oversized responses, failures and timeouts without retry', async () => {
  for (const [script, code, timeoutMs = 10000] of [
    ["process.stdout.write('not-json');", 'EPROTOCOL'],
    ["process.stdout.write(JSON.stringify({v:2,id:r.id,ok:true,result:{}}));", 'EPROTOCOL'],
    [`const value=${response};value.id='other';process.stdout.write(JSON.stringify(value));`, 'EPROTOCOL'],
    [`process.stdout.write(JSON.stringify(${response}));process.exitCode=3;`, 'ECHILD'],
    [`process.stdout.write(JSON.stringify(${response}));setInterval(()=>{},1000);`, 'ETIMEDOUT', 1500],
    ["process.stdout.write('x'.repeat(524289));", 'E2BIG'],
    ["process.stderr.write('private absolute path');process.exitCode=2;", 'ECHILD'],
    ["process.stdout.write(JSON.stringify({v:1,id:r.id,ok:false,error:{code:'unknown',message:'private absolute path'}}));", 'EPROTOCOL'],
    [`const value=${response};value.result.extra='secret';process.stdout.write(JSON.stringify(value));`, 'EPROTOCOL'],
    [`const value=${response};value.result.sha256=['a'.repeat(64)];process.stdout.write(JSON.stringify(value));`, 'EPROTOCOL'],
    [`setTimeout(()=>process.stdout.write(JSON.stringify(${response})),5000);`, 'ETIMEDOUT', 1500],
  ]) {
    const f = synthetic(script, timeoutMs);
    await assert.rejects(() => f.backend.invoke('read_file', { rootId: 'root', path: 'file' }, {}), error => error.code === code && !error.message.includes('private'));
    assert.equal(f.launches(), 1);
  }
});

test('real binary rejects malformed, unknown and oversized request envelopes', native, async t => {
  const f = await fixture(t);
  const request = { v: 1, id: '11111111-1111-1111-1111-111111111111', op: 'list_directory', args: f.args('.'), authority: f.rust.readonlyAuthority(f.root.id) };
  for (const input of ['not-json', 'x'.repeat(524289), JSON.stringify({ ...request, op: 'write_file' }), JSON.stringify({ ...request, extra: 'field' }),
    JSON.stringify({ ...request, v: 2 }), JSON.stringify({ ...request, id: 'wrong' }),
    JSON.stringify({ ...request, args: { ...request.args, access: f.access } }),
    JSON.stringify(request) + JSON.stringify(request)]) {
    const result = await new Promise((resolve, reject) => {
      const child = spawn(executable, [], { windowsHide: true, shell: false, stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '', stderr = ''; child.stdout.on('data', data => { stdout += data; }); child.stderr.on('data', data => { stderr += data; });
      const timeout = setTimeout(() => child.kill(), 10000);
      child.once('error', reject); child.stdin.on('error', () => {});
      child.once('close', (code, signal) => { clearTimeout(timeout); resolve({ code, signal, stdout, stderr }); });
      child.stdin.end(input);
    });
    assert.equal(result.signal, null); assert.equal(result.stderr, '');
    if (result.code === 0) { assert.equal(JSON.parse(result.stdout).ok, false); assert.equal(JSON.parse(result.stdout).error.code, 'EPROTOCOL'); }
    else assert.equal(result.stdout, '');
  }
});

test('IPC limits requests before spawning and rejects unsupported operations', async () => {
  const f = synthetic('throw Error("must not run");');
  await assert.rejects(() => f.backend.invoke('read_file', { path: 'x'.repeat(524289) }, {}), { code: 'E2BIG' });
  await assert.rejects(() => f.backend.invoke('write_file', {}, {}), { code: 'EPROTOCOL' });
  assert.equal(f.launches(), 0);
});

test('IPC success waits for close and owns its FIFO slot through exit', async () => {
  const f = synthetic(`process.stdout.write(JSON.stringify(${response}));setTimeout(()=>{},200);`);
  const queue = new SerialQueue(); const order = [];
  const started = Date.now();
  const first = queue.run(async () => { await f.backend.invoke('read_file', { path: 'file', rootId: 'root' }, {}); order.push('child-closed'); });
  const second = queue.run(() => order.push('policy-change'));
  await Promise.all([first, second]);
  assert.ok(Date.now() - started >= 180); assert.deepEqual(order, ['child-closed', 'policy-change']);
});

test('unconfirmed child termination disables the backend and releases the policy FIFO', async () => {
  let launches = 0;
  const child = new EventEmitter(); child.stdin = new PassThrough(); child.stdout = new PassThrough();
  child.kill = () => { queueMicrotask(() => child.emit('error', Error('synthetic kill failure'))); return false; };
  child.unref = () => {};
  const backend = new RustReadonlyBackend({ executable: process.execPath, timeoutMs: 10, spawnProcess: () => { launches++; return child; } });
  const queue = new SerialQueue(); let revoked = false;
  const pending = queue.run(() => backend.invoke('read_file', { rootId: 'root', path: 'file' }, {}));
  const denied = assert.rejects(pending, { code: 'ECHILD_UNCONFIRMED' });
  const revoke = queue.run(() => { revoked = true; });
  await denied; await revoke;
  assert.equal(revoked, true); assert.equal(child.stdout.destroyed, true); assert.equal(child.stdin.destroyed, true);
  await assert.rejects(() => backend.invoke('read_file', { rootId: 'root', path: 'file' }, {}), { code: 'ECHILD_UNCONFIRMED' });
  assert.equal(launches, 1);
});

test('missing executable and backend errors do not fall back to JS', async t => {
  const f = await fixture(t, { backend: new RustReadonlyBackend({ executable: path.join(os.tmpdir(), 'missing-readonly-fixture.exe') }) });
  await fs.writeFile(path.join(f.directory, 'file.txt'), 'must not return');
  await assert.rejects(() => f.dispatch('read_file', f.args('file.txt')), /Filesystem operation failed/);
});

test('public source export includes only explicit Rust sources and excludes build caches', async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-rust-public-'));
  t.after(() => fs.rm(base, { recursive: true, force: true }));
  const report = await buildPublic(path.join(base, 'export'));
  const manifest = JSON.parse(await fs.readFile(path.join(report.directory, 'SOURCE-SHA256.json'), 'utf8'));
  for (const file of rustSourceFiles) assert.ok(manifest.files[file]);
  assert.equal(Object.keys(manifest.files).some(file => /(^|\/)(target|build|\.cargo)\//.test(file) || /^runtime\//.test(file)), false);
  assert.equal((await auditTree(report.directory)).passed, true);
});
