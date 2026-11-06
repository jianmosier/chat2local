import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { StringDecoder } from 'node:string_decoder';
import { terminalEnvironment } from './shell.mjs';
import { finished } from './job-store.mjs';

const MAX_FRAME = 256 * 1024;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const codes = [null, 'EWIN32', 'EATTRIBUTES', 'EPIPE', 'EJOB', 'ECOMMAND', 'ESPAWN', 'EASSIGN', 'ERESUME', 'EOUTPUT', 'EACCESS', 'EPROTOCOL', 'ENOTSUP'];

/** One supervised Job Object per helper. Journal and current authority stay local. */
export class RustTerminalProcessRunner {
  constructor({ journal, authorize, executable, spawnHelper = spawn, handshakeMs = 10000, cleanupMs = 4000 }) {
    if (typeof executable !== 'string' || !path.isAbsolute(executable)) throw Error('An absolute local terminal helper is required.');
    if (!Number.isInteger(handshakeMs) || handshakeMs < 1 || handshakeMs > 10000 || !Number.isInteger(cleanupMs) || cleanupMs < 1 || cleanupMs > 5000) throw Error('Invalid terminal supervision deadline.');
    Object.assign(this, { journal, authorize, executable, spawnHelper, handshakeMs, cleanupMs });
    this.unavailable = false;
  }

  async start({ record, access, command, cwd, timeoutMs }) {
    this.assertAvailable();
    const binding = { v: 1, session: randomUUID(), requestId: record.requestId, inputHash: record.inputHash };
    const job = { record, access: structuredClone(access), binding, persist: Promise.resolve(), requestedStop: null,
      child: null, phase: 'prepare', runSent: false, bytes: 0, closed: false, timeoutMs, decoders: { stdout: new StringDecoder('utf8'), stderr: new StringDecoder('utf8') } };
    this.journal.jobs.set(record.requestId, job);
    job.done = new Promise(resolve => { job.resolveDone = resolve; });
    const started = new Promise(resolve => { job.resolveStarted = resolve; });
    job.send = kind => {
      if (job.closed || !job.child?.stdin.writable) throw Error('Terminal control pipe is closed.');
      job.child.stdin.write(JSON.stringify({ ...binding, kind }) + '\n');
    };
    let buffer = Buffer.alloc(0);
    try {
      const child = this.spawnHelper(this.executable, [], { shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'], env: terminalEnvironment() });
      job.child = child;
      child.on('error', () => this.abort(job, 'EHELPER'));
      child.stdin.on('error', () => this.abort(job, 'EPIPE'));
      child.stdout.on('error', () => this.abort(job, 'EPIPE'));
      child.stdout.on('data', chunk => {
        if (job.fault) return;
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.includes(10)) {
          const end = buffer.indexOf(10);
          if (end > MAX_FRAME) { this.abort(job, 'EPROTOCOL'); return; }
          const bytes = buffer.subarray(0, end); buffer = buffer.subarray(end + 1);
          try { this.frame(job, JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))); }
          catch { this.abort(job, 'EPROTOCOL'); return; }
        }
        if (buffer.length > MAX_FRAME) this.abort(job, 'EPROTOCOL');
      });
      child.once('close', (code, signal) => {
        job.closed = true; clearTimeout(job.handshake); clearTimeout(job.cleanup); clearTimeout(job.deadline); clearInterval(job.watch);
        if (!job.fault && !buffer.length && code === 0 && !signal && job.exit) {
          void this.confirm(job, job.exit);
        } else if (!job.runSent) {
          void this.confirm(job, { exitCode: null, reason: 'failed', terminationConfirmed: true, code: job.fault || 'EHELPER', truncated: record.truncated });
        } else this.unknown(job);
      });
      job.handshake = setTimeout(() => this.abort(job, 'ETIMEDOUT'), this.handshakeMs);
      job.watch = setInterval(() => {
        try { this.authorize(record.rootId, job.access); }
        catch { void this.stop(job, 'cancelled'); }
      }, 500); job.watch.unref();
      const prepare = Buffer.from(JSON.stringify({ ...binding, kind: 'prepare', command: Buffer.from(command, 'utf8').toString('utf8'), cwd, timeoutMs }) + '\n');
      if (prepare.length > MAX_FRAME) throw Error('Terminal frame exceeds limit.');
      child.stdin.write(prepare);
    } catch { this.abort(job, 'EHELPER'); }
    return started;
  }

  frame(job, value) {
    const base = ['v', 'session', 'requestId', 'inputHash', 'kind'];
    if (!value || Object.entries(job.binding).some(([key, expected]) => value[key] !== expected)) throw Error('Unbound terminal frame.');
    if (value.kind === 'ready') {
      if (!exact(value, base) || job.phase !== 'prepare' || job.requestedStop) throw Error('Unexpected READY.');
      // Synchronous fresh authorization immediately before the one RUN frame.
      this.authorize(job.record.rootId, job.access);
      job.phase = 'run'; job.runSent = true; job.send('run');
    } else if (value.kind === 'started') {
      if (!exact(value, [...base, 'pid']) || job.phase !== 'run' || !Number.isInteger(value.pid) || value.pid < 1) throw Error('Unexpected STARTED.');
      job.phase = 'running'; job.pid = value.pid; clearTimeout(job.handshake);
      // Rust enforces the deadline. This outer bound catches a wedged supervisor
      // without treating helper termination as confirmation of tree cleanup.
      job.deadline = setTimeout(() => this.abort(job, 'EDEADLINE'), job.timeoutMs + this.cleanupMs + 1500);
      job.record.status = job.requestedStop ? 'stopping' : 'running';
      // Output/exit handling is installed before awaiting the running journal.
      void this.journal.save(job).catch(() => {
        job.record.message = [job.record.message, 'Command started, but its running journal save failed. Do not replay it.'].filter(Boolean).join(' ');
        void this.stop(job, 'failed');
      });
      job.resolveStarted(this.journal.view(job.record));
    } else if (value.kind === 'output') {
      if (!exact(value, [...base, 'stream', 'data', 'truncated']) || job.phase !== 'running' || !['stdout', 'stderr'].includes(value.stream)
        || typeof value.data !== 'string' || value.data.length > 8192 || !/^(?:[a-f0-9]{2})*$/.test(value.data) || typeof value.truncated !== 'boolean') throw Error('Invalid terminal output.');
      const bytes = Buffer.from(value.data, 'hex'); job.bytes += bytes.length;
      if (job.bytes > 65536) throw Error('Terminal capture limit exceeded.');
      job.record[value.stream] += job.decoders[value.stream].write(bytes);
      job.record.truncated ||= value.truncated;
    } else if (value.kind === 'exit') {
      if (!exact(value, [...base, 'exitCode', 'reason', 'terminationConfirmed', 'truncated', 'code']) || !['prepare', 'run', 'running'].includes(job.phase)
        || (value.exitCode !== null && (!Number.isInteger(value.exitCode) || value.exitCode < 0 || value.exitCode > 0xffffffff))
        || !['exited', 'failed', 'cancelled', 'timed-out', 'control-lost'].includes(value.reason) || typeof value.terminationConfirmed !== 'boolean'
        || typeof value.truncated !== 'boolean' || !codes.includes(value.code) || (job.phase !== 'running' && value.reason === 'exited')) throw Error('Invalid terminal exit.');
      job.phase = 'exit'; job.exit = value; clearTimeout(job.handshake);
      job.cleanup ??= setTimeout(() => this.abort(job, 'ECLOSE'), this.cleanupMs);
    } else throw Error('Unknown terminal frame.');
  }

  async confirm(job, value) {
    if (!value.terminationConfirmed) { this.unknown(job); return; }
    clearTimeout(job.cleanup); clearTimeout(job.deadline); clearInterval(job.watch);
    job.record.stdout += job.decoders.stdout.end(); job.record.stderr += job.decoders.stderr.end();
    const status = job.requestedStop || (value.reason === 'exited' ? value.exitCode === 0 ? 'succeeded' : 'failed'
      : ['cancelled', 'timed-out'].includes(value.reason) ? value.reason : 'failed');
    Object.assign(job.record, { status, exitCode: value.exitCode, signal: null, endedAt: new Date().toISOString(), outcomeKnown: true,
      terminationConfirmed: true, truncated: job.record.truncated || value.truncated });
    if (value.code) job.record.message = [job.record.message, `Native terminal supervision reported ${value.code}. Do not replay this command.`].filter(Boolean).join(' ');
    const pending = 'Command ended; final journal save is pending. Do not replay it.';
    const saving = this.journal.save(job);
    job.record.message = [job.record.message, pending].filter(Boolean).join(' ');
    void saving.then(() => {
      job.record.message = job.record.message?.replace(pending, '').trim();
    }, () => {
      job.record.message = [job.record.message?.replace(pending, '').trim(), 'Command ended, but final journal save failed. Do not replay it.'].filter(Boolean).join(' ');
    });
    job.resolveStarted(this.journal.view(job.record)); job.resolveDone();
  }

  unknown(job) {
    if (job.unconfirmed) return;
    job.unconfirmed = true;
    this.unavailable = true; clearTimeout(job.handshake); clearTimeout(job.cleanup); clearTimeout(job.deadline); clearInterval(job.watch);
    Object.assign(job.record, { status: 'stopping', outcomeKnown: false, terminationConfirmed: false,
      message: 'Native process-tree termination is unconfirmed. Inspect processes and effects; do not retry.' });
    void this.journal.save(job).catch(() => {});
    job.resolveStarted(this.journal.view(job.record)); job.resolveDone();
    if (!job.closed) { job.child?.unref(); job.child?.stdin.destroy(); job.child?.stdout.destroy(); }
  }

  abort(job, code) {
    if (finished(job.record.status) || job.closed || job.unconfirmed || job.fault) return;
    job.fault ??= code;
    clearTimeout(job.cleanup);
    try { job.child?.kill(); } catch { /* Only close or a valid Job-empty receipt confirms anything. */ }
    if (!job.child) {
      job.closed = true; void this.confirm(job, { exitCode: null, reason: 'failed', terminationConfirmed: true, code, truncated: false }); return;
    }
    job.cleanup = setTimeout(() => this.unknown(job), this.cleanupMs);
  }

  async stop(job, reason) {
    if (finished(job.record.status) || job.requestedStop || job.unconfirmed) return;
    job.requestedStop = reason; job.record.status = 'stopping';
    try { job.send('cancel'); } catch { this.abort(job, 'EPIPE'); }
    job.cleanup ??= setTimeout(() => this.abortThenUnknown(job), this.cleanupMs);
  }
  abortThenUnknown(job) { try { job.child?.kill(); } catch {} this.unknown(job); }
  assertAvailable() {
    if (this.unavailable) throw Error('Native terminal supervision is unavailable. Inspect existing processes; no command was replayed.');
  }
  async close() {
    const jobs = [...this.journal.jobs.values()];
    await Promise.all(jobs.map(job => this.stop(job, 'cancelled')));
    let timer;
    await Promise.race([Promise.all(jobs.map(job => job.done)), new Promise(resolve => { timer = setTimeout(resolve, this.cleanupMs + 250); })]);
    clearTimeout(timer);
  }
}

export function configuredTerminalRunner(options = {}, environment = process.env) {
  const backend = options.terminalBackend ?? environment.CHAT2LOCAL_TERMINAL_BACKEND ?? 'js';
  if (backend === 'js') return undefined;
  if (backend !== 'rust' || process.platform !== 'win32') throw Error('Terminal backend must be js or rust (Windows).');
  const executable = options.terminalExecutable ?? fileURLToPath(new URL('../../../runtime/chat2local-terminal-runner.exe', import.meta.url));
  return context => new RustTerminalProcessRunner({ ...context, executable });
}
