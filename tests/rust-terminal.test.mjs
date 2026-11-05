import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { TerminalService } from '../src/agent/terminal.mjs';
import { RustTerminalProcessRunner, configuredTerminalRunner } from '../src/agent/terminal/rust-process-runner.mjs';
import { Store } from '../src/agent/store.mjs';
import { approveRoot } from '../src/agent/files.mjs';
import { rootPermission } from '../src/agent/permissions.mjs';
import { startController } from '../src/agent/main.mjs';

const executable = process.env.CHAT2LOCAL_TERMINAL_TEST_EXECUTABLE ?? path.resolve('target/debug/chat2local-terminal-runner.exe');
const unavailable = process.platform !== 'win32' ? 'Windows required' : !existsSync(executable) ? 'Build native terminal helper' : false;
if (process.env.CHAT2LOCAL_TERMINAL_TEST_REQUIRED === '1' && unavailable) throw Error(unavailable);
const native = { skip: unavailable };
const final = value => ['succeeded', 'failed', 'cancelled', 'timed-out', 'interrupted'].includes(value.status);
const ps = value => "'" + value.replaceAll("'", "''") + "'";
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(action, message = 'fixture deadline', timeout = 12000) {
  const end = Date.now() + timeout;
  do { const value = await action(); if (value) return value; await pause(25); } while (Date.now() < end);
  throw Error(message);
}
const alive = pid => { try { process.kill(pid, 0); return true; } catch (error) { if (error.code === 'ESRCH') return false; throw error; } };
async function fixture(t, { disk = false, factory, save } = {}) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-rust-terminal-')), directory = path.join(base, 'project'), records = new Map();
  await fs.mkdir(directory);
  const backing = new Store(path.join(base, 'state'));
  const store = { directory: backing.directory,
    readPrivateRecord: key => disk ? backing.readPrivateRecord(key) : Promise.resolve(records.get(key)),
    async savePrivateRecord(key, value) { await save?.(value); if (disk) await backing.savePrivateRecord(key, value); else records.set(key, structuredClone(value)); } };
  const root = { ...await approveRoot(directory, store.directory, true), ...rootPermission('direct') };
  const deviceId = 'a'.repeat(32), connectionId = 'b'.repeat(32), resource = 'https://terminal.example/mcp';
  const config = { roots: [root], paused: false, terminalGrants: [{ rootId: root.id, connectionId, resource, enabled: true }] };
  const access = { version: 1, deviceId, connectionId, resource, roots: [{ rootId: root.id, mode: 'direct' }], scopes: ['files:read', 'files:write', 'terminal:execute'] };
  const options = { store, getConfig: () => config, getDevice: () => ({ deviceId }) };
  const runnerFactory = factory ? context => factory(context, config) : context => new RustTerminalProcessRunner({ ...context, executable });
  const terminal = new TerminalService({ ...options, runnerFactory });
  t.after(async () => { await terminal.close(); await fs.rm(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); });
  const args = command => ({ rootId: root.id, requestId: randomUUID(), command });
  const status = a => terminal.invoke('terminal_status', { rootId: root.id, requestId: a.requestId }, access);
  const wait = a => until(async () => { const result = await status(a); return final(result) && result; }, 'terminal did not finish');
  return { base, directory, store, backing, records, root, config, access, terminal, options, args, status, wait,
    execute: a => terminal.invoke('terminal_execute', a, access),
    cancel: a => terminal.invoke('terminal_cancel', { rootId: root.id, requestId: a.requestId }, access) };
}
async function script(f, name, code) { const file = path.join(f.directory, name); await fs.writeFile(file, code); return `& ${ps(process.execPath)} ${ps(file)}`; }
async function descendant(f, exitParent = false) {
  const child = path.join(f.directory, 'grandchild.mjs'), pidFile = path.join(f.directory, 'grandchild.pid');
  await fs.writeFile(child, `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(pidFile)},String(process.pid)); setInterval(()=>{},1000);`);
  const command = await script(f, 'parent.mjs', `import {spawn} from 'node:child_process'; import fs from 'node:fs'; const child=spawn(process.execPath,[${JSON.stringify(child)}],{stdio:'ignore',windowsHide:true,detached:${exitParent}}); child.unref(); ${exitParent ? `while(!fs.existsSync(${JSON.stringify(pidFile)})) await new Promise(r=>setTimeout(r,10));` : 'setInterval(()=>{},1000);'}`);
  const pid = () => until(async () => existsSync(pidFile) && Number(await fs.readFile(pidFile, 'utf8')), 'grandchild never started');
  return { command, pid };
}

test('terminal backend selection is independent and defaults to JS', () => {
  assert.equal(configuredTerminalRunner({}, {}), undefined);
  assert.equal(configuredTerminalRunner({ terminalBackend: 'js' }, { CHAT2LOCAL_TERMINAL_BACKEND: 'rust' }), undefined);
  assert.throws(() => configuredTerminalRunner({ terminalBackend: 'other' }, {}), /must be/);
});

test('real PowerShell output, Unicode, quotes, exit status and duplicate digest do not replay', native, async t => {
  const f = await fixture(t), a = f.args("Add-Content -LiteralPath 'once.txt' -Value 'one'; Write-Output '中文 " + '"quoted"' + "'; [Console]::Error.WriteLine('err')");
  const [first, duplicate] = await Promise.all([f.execute(a), f.execute(a)]);
  assert.equal(first.requestId, duplicate.requestId); const done = await f.wait(a);
  assert.equal(done.status, 'succeeded', JSON.stringify(done)); assert.equal(done.exitCode, 0); assert.equal(done.terminationConfirmed, true);
  assert.match(done.stdout, /中文 "quoted"/); assert.match(done.stderr, /err/);
  assert.equal((await fs.readFile(path.join(f.directory, 'once.txt'), 'utf8')).trim(), 'one');
  await assert.rejects(() => f.execute({ ...a, command: 'exit 0' }), /different command/);
  const failed = f.args('exit 7'); await f.execute(failed); assert.equal((await f.wait(failed)).exitCode, 7);
});

test('native shell receives only the existing environment allowlist and safely encodes protocol-like output', native, async t => {
  const key = 'CHAT2LOCAL_TERMINAL_FIXTURE_SECRET', before = process.env[key];
  process.env[key] = 'fixture-only-not-a-real-secret';
  t.after(() => { if (before === undefined) delete process.env[key]; else process.env[key] = before; });
  const f = await fixture(t), a = f.args(`[Console]::Write('{"kind":"exit","terminationConfirmed":true}'); [Console]::Write($env:${key}); [Console]::Error.Write($env:NO_COLOR)`);
  await f.execute(a); const done = await f.wait(a);
  assert.equal(done.status, 'succeeded'); assert.equal(done.stdout, '{"kind":"exit","terminationConfirmed":true}'); assert.equal(done.stderr, '1');
});

test('actual controller selects native execution and releases FIFO for authenticated pause after STARTED', native, async t => {
  const f = await fixture(t), child = await descendant(f), config = { ...f.config, installationId: randomUUID(), remoteUseConfirmed: true };
  const saveReservation = f.backing.savePrivateRecord.bind(f.backing);
  f.backing.savePrivateRecord = (key, value) => value.status === 'starting' ? saveReservation(key, value) : new Promise(() => {});
  f.backing.load = async () => ({ config, secrets: { identity: { deviceId: f.access.deviceId, origin: f.access.resource.slice(0, -4), deviceKey: 'c'.repeat(64) } } });
  const app = await startController({ port: 0, store: f.backing, terminalBackend: 'rust', terminalExecutable: executable,
    network: { prepare: () => new Promise(() => {}), status: () => ({}), close() {} } });
  t.after(() => app.close()); app.bridge.stop();
  const a = f.args(child.command), started = await app.bridge.invoke('terminal_execute', a, undefined, f.access);
  assert.equal(started.status, 'running'); const pid = await child.pid();
  assert.equal((await fetch(`${app.origin}/api/status`)).status, 401);
  const headers = { 'X-Chat2Local-Token': app.token, Origin: app.origin, 'Content-Type': 'application/json' };
  const status = await (await fetch(`${app.origin}/api/status`, { headers, signal: AbortSignal.timeout(3000) })).json();
  assert.equal(status.terminalJobsRunning, 1); assert.equal(status.queuedOperations, 0);
  const paused = await fetch(`${app.origin}/api/pause`, { method: 'POST', headers, body: JSON.stringify({ paused: true }), signal: AbortSignal.timeout(3000) });
  assert.equal(paused.status, 200); await until(() => !alive(pid), 'controller pause left native descendant alive');
  await until(async () => (await (await fetch(`${app.origin}/api/status`, { headers })).json()).terminalJobsRunning === 0);
});

test('reservation and READY authorization failures launch no command', native, async t => {
  let spawned = 0;
  const blocked = await fixture(t, { save: () => { throw Error('reserve failed'); }, factory: context => new RustTerminalProcessRunner({ ...context, executable, spawnHelper: (...args) => { spawned++; return spawn(...args); } }) });
  await assert.rejects(() => blocked.execute(blocked.args("Set-Content 'unexpected.txt' 'x'")), /reserve failed/); assert.equal(spawned, 0);
  const revoked = await fixture(t, { factory: (context, config) => new RustTerminalProcessRunner({ ...context, executable, spawnHelper: (...args) => {
    const child = spawn(...args); child.stdout.on('data', bytes => { if (bytes.includes('"ready"')) config.paused = true; }); return child;
  } }) });
  const result = await revoked.execute(revoked.args("Set-Content 'unexpected.txt' 'x'"));
  assert.equal(result.status, 'failed'); assert.equal(result.outcomeKnown, true); assert.equal(existsSync(path.join(revoked.directory, 'unexpected.txt')), false);
});

test('post-start journal failure supervises termination; final save failure preserves known result', native, async t => {
  const f = await fixture(t, { save: value => { if (value.status === 'running') throw Error('running save failed'); } });
  const a = f.args('Start-Sleep -Seconds 30'); const started = await f.execute(a);
  assert.ok(['running', 'stopping', 'failed'].includes(started.status));
  const done = await f.wait(a); assert.equal(done.status, 'failed'); assert.equal(done.terminationConfirmed, true); assert.match(done.message, /running journal/);
  const g = await fixture(t, { disk: true, save: value => { if (final(value)) throw Error('final save failed'); } });
  const b = g.args("Write-Output 'saved-effect'"); await g.execute(b); const ended = await g.wait(b);
  assert.equal(ended.status, 'succeeded'); assert.equal(ended.outcomeKnown, true); assert.match(ended.message, /final journal/);
  const restarted = new TerminalService({ ...g.options, runnerFactory: context => new RustTerminalProcessRunner({ ...context, executable }) });
  t.after(() => restarted.close());
  const old = await restarted.invoke('terminal_execute', b, g.access); assert.equal(old.status, 'interrupted'); assert.equal(old.outcomeKnown, false);
});

test('DPAPI records are readable in both directions and request digest bytes stay compatible', native, async t => {
  const f = await fixture(t, { disk: true }), a = f.args("Add-Content 'once.txt' 'rust'"); await f.execute(a); await f.wait(a); await f.terminal.jobs.get(a.requestId).persist;
  const js = new TerminalService(f.options); t.after(() => js.close());
  assert.equal((await js.invoke('terminal_execute', a, f.access)).status, 'succeeded');
  const b = f.args("Add-Content 'once.txt' 'js'"); await js.invoke('terminal_execute', b, f.access);
  await until(async () => final(await js.invoke('terminal_status', b, f.access)));
  await js.jobs.get(b.requestId).persist;
  assert.equal((await f.execute(b)).status, 'succeeded');
  assert.deepEqual((await fs.readFile(path.join(f.directory, 'once.txt'), 'utf8')).trim().split(/\r?\n/), ['rust', 'js']);
  const plaintext = await fs.readFile(f.backing.privateRecordPath('terminal-' + a.requestId), 'utf8');
  assert.ok(plaintext.length > 0);
  assert.equal(plaintext.includes('Add-Content'), false);
});

test('two active jobs bound capacity and started returns while children are running', native, async t => {
  const f = await fixture(t), first = f.args('Start-Sleep -Seconds 30'), second = f.args('Start-Sleep -Seconds 30');
  assert.equal((await f.execute(first)).status, 'running'); assert.equal((await f.execute(second)).status, 'running');
  assert.equal(f.terminal.activeCount(), 2); await assert.rejects(() => f.execute(f.args('exit 0')), /Two commands/);
  await f.cancel(first); await f.cancel(second); await f.wait(first); await f.wait(second); assert.equal(f.terminal.activeCount(), 0);
});

test('raw UTF8 capture combines both streams and replacement at cap is preserved', native, async t => {
  const f = await fixture(t);
  const a = f.args(await script(f, 'bytes.mjs', "process.stdout.write(Buffer.from([0xe4]));setTimeout(()=>{process.stdout.write(Buffer.from([0xb8,0xad]));process.stderr.write('err');},20);"));
  await f.execute(a); const done = await f.wait(a); assert.equal(done.stdout, '中'); assert.equal(done.stderr, 'err');
  const b = f.args(await script(f, 'limit.mjs', "process.stdout.write(Buffer.concat([Buffer.alloc(65535,120),Buffer.from([0xe4,0xb8,0xad])]));"));
  await f.execute(b); const capped = await f.wait(b); assert.equal(capped.truncated, true); assert.equal(capped.stdout, 'x'.repeat(65535) + '\ufffd');
  const c = f.args(await script(f, 'flood.mjs', "setInterval(()=>{process.stdout.write(Buffer.alloc(8192,120));process.stderr.write(Buffer.alloc(8192,121));},0);"));
  await f.execute(c); await until(async () => (await f.status(c)).truncated); await f.cancel(c);
  const stopped = await f.wait(c); assert.equal(stopped.status, 'cancelled'); assert.ok(Buffer.byteLength(stopped.stdout + stopped.stderr) <= 65536);
});

test('cancel and timeout confirm attached grandchildren, including surviving descendants after shell exit', native, async t => {
  for (const exitParent of [false, true]) {
    const f = await fixture(t), child = await descendant(f, exitParent), a = f.args(child.command);
    await f.execute(a); const pid = await child.pid(); await pause(150);
    assert.equal(alive(pid), true); assert.equal((await f.status(a)).status, 'running');
    await f.cancel(a); const done = await f.wait(a); assert.equal(done.terminationConfirmed, true); assert.equal(alive(pid), false);
  }
  const f = await fixture(t), child = await descendant(f, true), a = { ...f.args(child.command), timeoutMs: 1500 };
  await f.execute(a); const pid = await child.pid(); assert.equal((await f.wait(a)).status, 'timed-out'); assert.equal(alive(pid), false);
});

test('pause, root revocation and close stop actual attached native work', native, async t => {
  for (const change of ['pause', 'root', 'close']) {
    const f = await fixture(t), child = await descendant(f), a = f.args(child.command);
    await f.execute(a); const pid = await child.pid();
    if (change === 'pause') f.config.paused = true;
    if (change === 'root') f.config.roots = [];
    if (change === 'close') await f.terminal.close();
    await until(() => !alive(pid), 'revoked descendant survived');
    await until(() => f.terminal.activeCount() === 0); assert.equal(f.terminal.jobs.get(a.requestId).record.terminationConfirmed, true);
  }
});

test('helper crash kills the Job but parent honestly retains unknown active ownership', native, async t => {
  const f = await fixture(t), child = await descendant(f), a = f.args(child.command); await f.execute(a); const pid = await child.pid();
  f.terminal.jobs.get(a.requestId).child.kill();
  await until(() => f.terminal.runner.unavailable); await until(() => !alive(pid));
  const record = await f.status(a); assert.equal(record.status, 'stopping'); assert.equal(record.outcomeKnown, false);
  assert.equal(f.terminal.activeCount(), 1); await assert.rejects(() => f.execute(f.args('exit 0')), /supervision is unavailable/);
});

test('parent control EOF terminates the Job and reports confirmed tree cleanup', native, async t => {
  const f = await fixture(t), child = await descendant(f), a = f.args(child.command); await f.execute(a); const pid = await child.pid();
  f.terminal.jobs.get(a.requestId).child.stdin.end(); const done = await f.wait(a);
  assert.equal(done.terminationConfirmed, true); assert.equal(done.status, 'failed'); assert.equal(alive(pid), false);
});

test('native bad control frame kills its attached tree without trusting output as commands', native, async t => {
  const f = await fixture(t), child = await descendant(f), a = f.args(child.command); await f.execute(a); const pid = await child.pid();
  f.terminal.jobs.get(a.requestId).child.stdin.write('malformed\n');
  const done = await f.wait(a); assert.equal(done.status, 'failed'); assert.equal(done.terminationConfirmed, true); assert.equal(alive(pid), false);
});

test('native supervisor exits within its bound when its parent stops reading output', native, async t => {
  const f = await fixture(t), child = await descendant(f, true), binding = { v: 1, session: randomUUID(), requestId: randomUUID(), inputHash: 'a'.repeat(64) };
  const helper = spawn(executable, [], { windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] });
  t.after(() => { if (helper.exitCode === null) helper.kill(); });
  let closed = false; helper.once('exit', () => { closed = true; });
  const command = child.command + '; for ($i=0; $i -lt 200000; $i++) { [Console]::Write("x"); [System.Threading.Thread]::SpinWait(1000) }';
  let input = '';
  await new Promise((resolve, reject) => {
    helper.once('error', reject); helper.stdout.on('data', function ready(bytes) {
      input += bytes;
      if (input.includes('\n')) { assert.equal(JSON.parse(input.trim()).kind, 'ready'); helper.stdout.removeListener('data', ready); helper.stdout._readableState.highWaterMark = 1; helper.stdout.pause(); resolve(); }
    });
    helper.stdin.write(JSON.stringify({ ...binding, kind: 'prepare', command, cwd: f.directory, timeoutMs: 1800 }) + '\n');
  });
  helper.stdin.write(JSON.stringify({ ...binding, kind: 'run' }) + '\n');
  const pid = await child.pid();
  await until(() => closed, 'helper blocked on parent output pipe', 6000);
  assert.equal(alive(pid), false); helper.stdout.resume();
  await new Promise(resolve => { if (helper.stdout.destroyed) resolve(); else helper.once('close', resolve); });
});

test('fixture parent death closes control and terminates descendants without manual process cleanup', native, async t => {
  const f = await fixture(t), child = await descendant(f, true), launcher = path.join(f.directory, 'launcher.mjs');
  const serviceUrl = pathToFileURL(path.resolve('src/agent/terminal.mjs')).href, runnerUrl = pathToFileURL(path.resolve('src/agent/terminal/rust-process-runner.mjs')).href;
  await fs.writeFile(launcher, `import {TerminalService} from ${JSON.stringify(serviceUrl)};import {RustTerminalProcessRunner} from ${JSON.stringify(runnerUrl)};
const records=new Map();const service=new TerminalService({getConfig:()=>(${JSON.stringify(f.config)}),getDevice:()=>({deviceId:${JSON.stringify(f.access.deviceId)}}),store:{directory:${JSON.stringify(f.store.directory)},readPrivateRecord:async k=>records.get(k),savePrivateRecord:async(k,v)=>records.set(k,structuredClone(v))},runnerFactory:c=>new RustTerminalProcessRunner({...c,executable:${JSON.stringify(executable)}})});
await service.invoke('terminal_execute',${JSON.stringify(f.args(child.command))},${JSON.stringify(f.access)});process.send('started');setInterval(()=>{},1000);`);
  const parent = spawn(process.execPath, [launcher], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  t.after(() => { if (parent.exitCode === null) parent.kill(); });
  let errors = ''; parent.stderr.on('data', bytes => { errors += bytes; });
  await new Promise((resolve, reject) => { parent.once('message', resolve); parent.once('exit', () => reject(Error(errors))); });
  const pid = await child.pid(); parent.kill(); await new Promise(resolve => parent.once('close', resolve));
  await until(() => !alive(pid), 'fixture parent death left descendant alive');
});

function fakeHelper(handle) {
  const child = new EventEmitter(); child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.unref = () => {};
  child.kill = () => { queueMicrotask(() => child.emit('close', null, 'SIGTERM')); return true; };
  let buffered = ''; child.stdin.on('data', data => { buffered += data; while (buffered.includes('\n')) { const end = buffered.indexOf('\n'); const frame = JSON.parse(buffered.slice(0, end)); buffered = buffered.slice(end + 1); handle(child, frame); } });
  return child;
}
const reply = (child, frame, details) => child.stdout.write(JSON.stringify({ v: frame.v, session: frame.session, requestId: frame.requestId, inputHash: frame.inputHash, ...details }) + '\n');

test('malformed helper frames and unconfirmed kill never release native active slots or retry', async t => {
  for (const fault of ['malformed', 'nonce', 'close', 'unconfirmed']) {
    let calls = 0;
    const f = await fixture(t, { factory: context => new RustTerminalProcessRunner({ ...context, executable, handshakeMs: 50, cleanupMs: 50,
      spawnHelper: () => { calls++; return fakeHelper((child, frame) => {
        if (frame.kind === 'prepare') reply(child, frame, { kind: 'ready' });
        if (frame.kind === 'run') {
          if (fault === 'unconfirmed') { child.kill = () => false; return; }
          if (fault === 'close') { queueMicrotask(() => child.emit('close', 0, null)); return; }
          if (fault === 'nonce') reply(child, frame, { kind: 'started', pid: 1234, session: randomUUID() });
          else child.stdout.write('not-json\n');
        }
      }); } }) });
    const a = f.args('exit 0'), result = await f.execute(a);
    assert.equal(result.status, 'stopping'); assert.equal(result.outcomeKnown, false); assert.equal(f.terminal.activeCount(), 1);
    await assert.rejects(() => f.execute(f.args('exit 0')), /supervision is unavailable/); assert.equal(calls, 1);
  }
});

test('missing helper fails without JS fallback and retains the request reservation', async t => {
  const f = await fixture(t, { factory: context => new RustTerminalProcessRunner({ ...context, executable: path.resolve('missing-terminal.exe') }) });
  const a = f.args("Set-Content 'unexpected.txt' 'x'"); const result = await f.execute(a);
  assert.equal(result.status, 'failed'); assert.equal((await f.execute(a)).requestId, a.requestId); assert.equal(existsSync(path.join(f.directory, 'unexpected.txt')), false);
});

test('a wedged helper after STARTED is bounded and cannot claim confirmed termination', async t => {
  let calls = 0;
  const f = await fixture(t, { factory: context => new RustTerminalProcessRunner({ ...context, executable, handshakeMs: 50, cleanupMs: 50,
    spawnHelper: () => { calls++; return fakeHelper((child, frame) => {
      if (frame.kind === 'prepare') reply(child, frame, { kind: 'ready' });
      if (frame.kind === 'run') { child.kill = () => false; reply(child, frame, { kind: 'started', pid: 1234 }); }
    }); } }) });
  const a = { ...f.args('exit 0'), timeoutMs: 100 };
  assert.equal((await f.execute(a)).status, 'running');
  await until(() => f.terminal.runner.unavailable, 'wedged helper was not bounded', 4000);
  assert.equal((await f.status(a)).outcomeKnown, false); assert.equal(f.terminal.activeCount(), 1);
  await assert.rejects(() => f.execute(f.args('exit 0')), /unavailable/); assert.equal(calls, 1);
});

test('native STARTED and confirmed close never await a permanently pending post-start journal', async t => {
  const f = await fixture(t, { save: value => value.status === 'starting' ? undefined : new Promise(() => {}),
    factory: context => new RustTerminalProcessRunner({ ...context, executable, handshakeMs: 50, cleanupMs: 50,
      spawnHelper: () => fakeHelper((child, frame) => {
        if (frame.kind === 'prepare') reply(child, frame, { kind: 'ready' });
        if (frame.kind === 'run') reply(child, frame, { kind: 'started', pid: 1234 });
        if (frame.kind === 'cancel') {
          reply(child, frame, { kind: 'exit', exitCode: 1, reason: 'cancelled', terminationConfirmed: true, truncated: false, code: null });
          queueMicrotask(() => child.emit('close', 0, null));
        }
      }) }) });
  const a = f.args('exit 0'); assert.equal((await f.execute(a)).status, 'running');
  await f.cancel(a); await f.terminal.close();
  const record = f.terminal.jobs.get(a.requestId).record;
  assert.equal(record.status, 'cancelled'); assert.equal(record.outcomeKnown, true); assert.equal(record.terminationConfirmed, true);
  assert.match(record.message, /save is pending/); assert.equal(f.terminal.activeCount(), 0);
});
