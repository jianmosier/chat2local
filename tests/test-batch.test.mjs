import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { runTestBatch } from '../scripts/test-batch.mjs';
import { closeBrowserFixture } from './browser-cleanup-fixture.mjs';
import { TEST_GROUPS, testGroupFiles } from '../scripts/test-groups.mjs';

test('release groups cover every test exactly once and isolate the slow UI file', () => {
  const files = ['folders-ui.test.mjs', ...Array.from({ length: 86 }, (_v, index) => `fixture-${index}.test.mjs`)];
  const original = [...files], groups = Array.from({ length: TEST_GROUPS }, (_v, i) => testGroupFiles(files, i + 1));
  assert.deepEqual(groups[0], ['folders-ui.test.mjs']);
  assert.deepEqual(groups.flat().sort(), [...files].sort());
  assert.equal(new Set(groups.flat()).size, files.length);
  assert.deepEqual(files, original);
  for (let group = 1; group <= TEST_GROUPS; group++) assert.deepEqual(testGroupFiles([...files].reverse(), group), groups[group - 1]);
  assert.throws(() => testGroupFiles([...files, files[0]], 1), /duplicate/);
  for (const group of [0, TEST_GROUPS + 1, 1.5]) assert.throws(() => testGroupFiles(files, group), /Invalid/);
});

async function fixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-test-batch-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const metadata = async () => JSON.parse(await fs.readFile(path.join(directory, 'batch-1.json'), 'utf8'));
  return { directory, metadata, group: 1, files: [], output: { write() {} } };
}
test('batch progress and running metadata exist before child completion', async t => {
  const f = await fixture(t); let progress;
  const seen = new Promise(resolve => { progress = resolve; });
  const running = runTestBatch({ ...f, timeoutMs: 5000, args: ['-e', "console.log('fixture-progress');setTimeout(()=>console.log('fixture-complete'),500)"], output: { write: chunk => { if (chunk.toString().includes('fixture-progress')) progress(); } } });
  await seen;
  assert.match(await fs.readFile(path.join(f.directory, 'batch-1.log'), 'utf8'), /fixture-progress/);
  assert.equal((await f.metadata()).phase, 'running');
  const result = await running; assert.equal(result.ok, true); assert.equal(result.pipeCloseObserved, true);
});
test('batch timeout terminates only its current owned test child and records failure durably', { timeout: 10000 }, async t => {
  const f = await fixture(t), started = Date.now();
  const result = await runTestBatch({ ...f, timeoutMs: 1500, drainMs: 1000, args: ['-e', "console.log('owned-child-ready');setInterval(()=>{},1000)"] });
  const saved = await f.metadata();
  assert.equal(result.ok, false); assert.equal(saved.timedOut, true); assert.equal(saved.reason, 'timeout');
  assert.equal(saved.processExitObserved, true); assert.equal(saved.pipeCloseObserved, true);
  assert.match(await fs.readFile(path.join(f.directory, 'batch-1.log'), 'utf8'), /owned-child-ready/);
  assert.ok(Date.now() - started < 8000);
  assert.equal(saved.directTermination, 'requested'); assert.equal(saved.cleanup, 'unknown'); assert.equal(saved.descendantCleanup, 'unknown');
});
test('exited-root pipe stall is bounded and never targets the old PID', async t => {
  const f = await fixture(t), child = new EventEmitter(); let kills = 0, unreferenced = false;
  Object.assign(child, { pid: 999999, exitCode: null, signalCode: null, stdout: new PassThrough(), stderr: new PassThrough(), kill: () => { kills++; }, unref: () => { unreferenced = true; } });
  const running = runTestBatch({ ...f, timeoutMs: 5000, drainMs: 40, spawnProcess: () => { setImmediate(() => { child.stdout.write('fixture-progress\n'); child.exitCode = 0; child.emit('exit', 0, null); }); return child; } });
  const result = await running;
  assert.equal(result.ok, false); assert.equal(result.cleanup, 'unknown'); assert.equal(result.phase, 'drain-unconfirmed');
  assert.equal(result.processExitObserved, true); assert.equal(result.pipeCloseObserved, false);
  assert.equal(kills, 0); assert.equal(unreferenced, true); assert.equal(result.directTermination, undefined);
  assert.equal((await f.metadata()).cleanup, 'unknown');
});
test('exit during stop dispatch stays bound to the owned child handle', async t => {
  const f = await fixture(t), child = new EventEmitter(); let pidReads = 0, kills = 0, raced = false;
  Object.assign(child, { signalCode: null, stdout: new PassThrough(), stderr: new PassThrough(), unref() {}, kill() { assert.equal(this, child); kills++; setImmediate(() => child.emit('close', 0, null)); return false; } });
  Object.defineProperty(child, 'pid', { get() { pidReads++; return pidReads === 1 ? 999999 : 123456; } });
  Object.defineProperty(child, 'exitCode', { get() { if (!raced) { raced = true; child.emit('exit', 0, null); } return null; } });
  const result = await runTestBatch({ ...f, timeoutMs: 20, drainMs: 40, spawnProcess: () => child });
  assert.equal(kills, 1); assert.equal(pidReads, 1); assert.equal(result.processExitObserved, true);
  assert.equal(result.directTermination, 'unconfirmed'); assert.equal(result.cleanup, 'unknown');
});
test('browser server cleanup runs after client failure and requires process/pipe confirmation', async () => {
  const attempts = [], state = { exitObserved: false, closeObserved: false, stdoutEnded: false, stderrEnded: false };
  const browser = { contexts: () => [{ close: async () => { throw Error('synthetic client failure'); } }], close: async () => { throw Error('synthetic disconnect failure'); } };
  const cleanup = async (name, work) => { try { await work(); attempts.push([name, 'confirmed']); } catch { attempts.push([name, 'failed']); } };
  await closeBrowserFixture(browser, { close: async () => {} }, state, cleanup);
  assert.deepEqual(attempts, [['browser-contexts', 'failed'], ['browser-client', 'failed'], ['browser-server', 'confirmed'], ['browser-drain', 'failed']]);
});
test('bounded pending browser client cleanup still attempts server close', async () => {
  const attempts = [], state = { exitObserved: false, closeObserved: false, stdoutEnded: false, stderrEnded: false };
  const browser = { contexts: () => [{ close: () => new Promise(() => {}) }], close: () => new Promise(() => {}) };
  const cleanup = async (name, work) => {
    let timer;
    const result = await Promise.race([Promise.resolve().then(work).then(() => 'confirmed'), new Promise(resolve => { timer = setTimeout(() => resolve('pending'), 10); })]);
    clearTimeout(timer); attempts.push([name, result]);
  };
  await closeBrowserFixture(browser, { close: async () => { Object.keys(state).forEach(key => { state[key] = true; }); } }, state, cleanup);
  assert.deepEqual(attempts, [['browser-contexts', 'pending'], ['browser-client', 'pending'], ['browser-server', 'confirmed'], ['browser-drain', 'confirmed']]);
});
