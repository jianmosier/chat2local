import fs from 'node:fs/promises';
import { openSync, writeSync, fsyncSync, closeSync, renameSync } from 'node:fs';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { VERSION } from '../src/shared/protocol.mjs';
import { TEST_GROUPS, testGroupFiles } from './test-groups.mjs';

/** Termination uses only the owned ChildProcess handle, never a PID dispatch.
 * Direct-child exit does not establish descendant cleanup. */
export async function runTestBatch({ group, groups = TEST_GROUPS, files, directory = path.join('.artifacts', 'verification-' + VERSION), timeoutMs = 600000, drainMs = 5000, args = ['--test', '--test-concurrency=1', '--test-reporter=spec', ...files], output = process.stdout, spawnProcess = spawn } = {}) {
  await fs.mkdir(directory, { recursive: true });
  const log = openSync(path.join(directory, `batch-${group}.log`), 'w');
  const metadata = path.join(directory, `batch-${group}.json`);
  const state = { group, groups, files, phase: 'starting', timedOut: false, outputLimited: false, processExitObserved: false, pipeCloseObserved: false, cleanup: 'not-required', startedAt: new Date().toISOString() };
  let logging = true;
  function checkpoint() {
    if (!logging) return;
    const temporary = metadata + '.tmp';
    const file = openSync(temporary, 'w'); try { writeSync(file, JSON.stringify({ ...state, checkedAt: new Date().toISOString() }, null, 2)); fsyncSync(file); } finally { closeSync(file); }
    renameSync(temporary, metadata); fsyncSync(log);
  }
  checkpoint();
  const child = spawnProcess(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  state.pid = child.pid; state.phase = 'running'; checkpoint();
  let bytes = 0, settled = false, timer, drainTimer, stopping, complete;
  const completion = new Promise(resolve => { complete = resolve; });
  function finish() { if (!settled) { settled = true; complete(); } }
  function abandonPipes() {
    state.cleanup = 'unknown'; state.descendantCleanup = 'unknown'; state.phase = 'drain-unconfirmed';
    checkpoint(); child.stdout.destroy(); child.stderr.destroy(); child.unref(); finish();
  }
  function boundDrain() { if (!settled && !drainTimer) drainTimer = setTimeout(abandonPipes, drainMs); }
  async function stop(reason) {
    if (stopping) return stopping;
    state.phase = 'stopping'; state.reason = reason;
    state.timedOut = reason === 'timeout'; state.outputLimited = reason === 'output-limit';
    // Flush failure metadata and progress BEFORE termination or pipe draining.
    state.cleanup = 'requested'; state.descendantCleanup = 'unknown'; checkpoint();
    stopping = (async () => {
      if (!state.processExitObserved && child.exitCode === null && child.signalCode === null) {
        // Exit can race this check. kill() still uses this ChildProcess's owned
        // handle, so the race cannot redirect termination to a reused PID.
        try { state.directTermination = child.kill() ? 'requested' : 'unconfirmed'; }
        catch { state.directTermination = 'unconfirmed'; }
        checkpoint();
      } else { state.directTermination = 'not-submitted-after-exit'; checkpoint(); }
      boundDrain();
    })();
    return stopping;
  }
  const collect = chunk => {
    if (!logging) return;
    const remaining = Math.max(0, 4 * 1024 * 1024 - bytes), kept = chunk.subarray(0, remaining);
    if (kept.length) { writeSync(log, kept); output.write(kept); }
    bytes += chunk.length;
    if (bytes > 4 * 1024 * 1024) void stop('output-limit');
  };
  child.stdout.on('data', collect); child.stderr.on('data', collect);
  child.once('error', error => { state.spawnError = /^[A-Z0-9_]+$/.test(error.code || '') ? error.code : 'PROCESS_ERROR'; checkpoint(); boundDrain(); });
  child.once('exit', (code, signal) => {
    if (!logging) return;
    state.processExitObserved = true; state.code = code; state.signal = signal;
    if (!stopping) state.phase = 'process-exited';
    clearTimeout(timer); checkpoint(); boundDrain();
  });
  child.once('close', (code, signal) => { state.pipeCloseObserved = true; state.code = code; state.signal = signal; finish(); });
  timer = setTimeout(() => { void stop('timeout'); }, timeoutMs);
  try {
    await completion;
    if (stopping) await stopping;
    state.phase = state.cleanup === 'unknown' ? 'drain-unconfirmed' : 'complete';
    state.outputBytes = bytes;
    if (state.cleanup === 'requested') state.cleanup = 'unknown';
    state.ok = state.code === 0 && !state.timedOut && !state.outputLimited && !state.spawnError && state.cleanup !== 'unknown' && state.pipeCloseObserved;
    checkpoint(); return state;
  } finally { clearTimeout(timer); clearTimeout(drainTimer); logging = false; closeSync(log); }
}

if (import.meta.main) {
  const group = Number(process.argv[2]), groups = TEST_GROUPS;
  if (!Number.isInteger(group) || group < 1 || group > groups) throw Error('Usage: test-batch.mjs GROUP (1 to ' + groups + ')');
  const all = (await fs.readdir('tests')).filter(name => name.endsWith('.test.mjs')).sort();
  const files = testGroupFiles(all, group).map(name => 'tests/' + name);
  console.log(`Test batch ${group}/${groups}: ${files.length} files.`);
  const result = await runTestBatch({ group, groups, files });
  if (!result.ok) { console.error('Test batch did not complete successfully; durable metadata records timeout and cleanup status.'); process.exitCode = 1; }
}
