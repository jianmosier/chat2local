import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { StringDecoder } from 'node:string_decoder';
import { checkedAccess } from '../shared/connection-access.mjs';
import { rootWriteMode } from './permissions.mjs';
import { approveRoot } from './files.mjs';

export const TERMINAL_CAPABILITY = 'terminal-jobs-v1';
export const TERMINAL_CONFIRMATION = 'allow-unsandboxed-terminal-v1';
const MAX_OUTPUT = 64 * 1024;
const finished = state => ['succeeded','failed','cancelled','timed-out','interrupted'].includes(state);
const fail = message => new Error(message);
export function terminalEnvironment(env = process.env) {
  const result = {};
  for (const name of ['PATH','Path','PATHEXT','SystemRoot','SYSTEMROOT','WINDIR','COMSPEC','TEMP','TMP','TMPDIR','HOME','USERPROFILE','HOMEDRIVE','HOMEPATH','LANG','LC_ALL','NUMBER_OF_PROCESSORS']) if (typeof env[name] === 'string') result[name] = env[name];
  // No shell profiles, Node preload flags, provider/device tokens or arbitrary
  // parent environment variables are passed to commands. This is NOT a sandbox.
  result.NO_COLOR = '1'; return result;
}
export function terminalShell(command, shell = 'auto', platform = process.platform, env = process.env) {
  const selected = shell === 'auto' ? platform === 'win32' ? 'powershell' : 'sh' : shell;
  if (platform === 'win32' && selected === 'powershell') {
    const file = path.win32.join(env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    return { shell: selected, file, args: ['-NoLogo','-NoProfile','-NonInteractive','-Command', `[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $global:LASTEXITCODE = 0; & { ${command}\n}; if (-not $?) { exit 1 }; exit $LASTEXITCODE`] };
  }
  if (platform !== 'win32' && selected === 'sh') return { shell: selected, file: '/bin/sh', args: ['-c', command] };
  throw fail('Unsupported shell on this computer; use auto, PowerShell on Windows, or sh on macOS/Linux.');
}
export async function terminalCwd(root, relative = '.') {
  if (typeof relative !== 'string' || relative.length > 2048 || path.isAbsolute(relative) || /[\x00-\x1f:]/.test(relative) || relative.split(/[\\/]/).some(p => p === '..')) throw fail('cwd must be a relative directory inside the selected root.');
  const base = await fs.realpath(root);
  let cursor = root;
  for (const item of relative.split(/[\\/]/).filter(p => p && p !== '.')) {
    cursor = path.join(cursor, item); if ((await fs.lstat(cursor)).isSymbolicLink()) throw fail('A linked working directory is not permitted.');
  }
  const current = await fs.realpath(cursor), rel = path.relative(base, current);
  if (rel.startsWith('..' + path.sep) || rel === '..' || path.isAbsolute(rel) || !(await fs.stat(current)).isDirectory()) throw fail('Working directory is not inside the selected root.');
  return current;
}
export class TerminalService {
  constructor({ getConfig, getDevice, store, spawnProcess = spawn }) {
    Object.assign(this, { getConfig, getDevice, store, spawnProcess }); this.jobs = new Map(); this.closed = false; this.launchTail = Promise.resolve();
  }
  authorize(rootId, envelope) {
    if (this.closed || this.getConfig().paused) throw fail('Terminal is paused or stopped.');
    if (!envelope) throw fail('Terminal requires a scoped connection; legacy file authorization cannot execute commands.');
    const access = checkedAccess(envelope, this.getDevice()?.deviceId || '');
    const local = [...this.getConfig().roots, ...(this.getConfig().accountRoots || [])].find(r => r.id === rootId && (!r.connectionId || r.connectionId === access.connectionId));
    const grant = (this.getConfig().terminalGrants || []).find(g => g.rootId === rootId && g.connectionId === access.connectionId && g.resource === access.resource && g.enabled === true);
    if (!access.scopes.includes('terminal:execute') || !local || rootWriteMode(local) !== 'direct' || !access.roots.some(r => r.rootId === rootId && r.mode === 'direct') || !grant) throw fail('Terminal requires terminal:execute AND explicit native terminal permission on a directly writable share.');
    return { access, local };
  }
  async invoke(name, args, envelope) {
    const { access, local } = this.authorize(args.rootId, envelope);
    if (!/^[a-f0-9-]{36}$/.test(args.requestId || '')) throw fail('Use a stable UUID requestId for this command and every status/retry.');
    if (name === 'terminal_execute') {
      const result = this.launchTail.then(() => { this.authorize(args.rootId, envelope); return this.execute(args, access, local); });
      this.launchTail = result.catch(() => {}); return result;
    }
    if (!['terminal_status','terminal_cancel'].includes(name)) throw fail('Unknown terminal operation.');
    const job = this.jobs.get(args.requestId);
    const record = job?.record || await this.store.readPrivateRecord('terminal-' + args.requestId);
    if (!record || record.rootId !== args.rootId || record.connectionId !== access.connectionId || record.resource !== access.resource || record.deviceId !== access.deviceId) throw fail('Command does not belong to this connection, device and root.');
    if (!job && !finished(record.status)) return this.view({ ...record, status: 'interrupted', outcomeKnown: false, message: 'The agent restarted. Do not replay this command; inspect its effects first.' });
    if (name === 'terminal_cancel' && job && !finished(record.status)) await this.stop(job, 'cancelled');
    return this.view(record);
  }
  view(record) {
    const { requestId, rootId, status, exitCode, signal, stdout, stderr, truncated, startedAt, endedAt, outcomeKnown, terminationConfirmed, message } = record;
    return { requestId, rootId, status, exitCode, signal, stdout, stderr, truncated, startedAt, endedAt, outcomeKnown, terminationConfirmed, ...(message ? { message } : {}), sandboxed: false };
  }
  async execute(args, access, root) {
    if (typeof args.command !== 'string' || !args.command.trim() || args.command.includes('\0') || Buffer.byteLength(args.command) > 16384) throw fail('Command must be nonempty UTF-8 text, at most 16 KiB, without NUL.');
    const timeoutMs = args.timeoutMs ?? 120000;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 300000) throw fail('timeoutMs must be 100–300000.');
    const shell = terminalShell(args.command, args.shell || 'auto');
    const inputHash = createHash('sha256').update(JSON.stringify([args.command, args.cwd || '.', timeoutMs, shell.shell, args.rootId, access.connectionId, access.resource, access.deviceId])).digest('hex');
    const previous = this.jobs.get(args.requestId)?.record || await this.store.readPrivateRecord('terminal-' + args.requestId);
    if (previous) {
      if (previous.inputHash !== inputHash) throw fail('requestId already identifies a different command; nothing was executed.');
      return this.invoke('terminal_status', { rootId: args.rootId, requestId: args.requestId }, access);
    }
    if ([...this.jobs.values()].filter(j => !finished(j.record.status)).length >= 2) throw fail('Two commands are already running. Wait or cancel before starting another.');
    if (this.jobs.size >= 128) {
      const victim = [...this.jobs].find(([, j]) => finished(j.record.status));
      if (!victim) throw fail('Command capacity reached.'); this.jobs.delete(victim[0]);
    }
    await approveRoot(root.path, this.store.directory, true);
    const cwd = await terminalCwd(root.path, args.cwd || '.');
    this.authorize(args.rootId, access);
    const record = { requestId: args.requestId, rootId: args.rootId, connectionId: access.connectionId, resource: access.resource, deviceId: access.deviceId, inputHash, status: 'starting', stdout: '', stderr: '', truncated: false, exitCode: null, signal: null, startedAt: new Date().toISOString(), outcomeKnown: false };
    // Durable reservation BEFORE spawn: response loss or restart never replays a
    // command. This is at-most-once launch, not exactly-once external effects.
    await this.store.savePrivateRecord('terminal-' + args.requestId, record);
    this.authorize(args.rootId, access);
    const job = { record, child: null, bytes: 0, requestedStop: null, access, persist: Promise.resolve() };
    this.jobs.set(args.requestId, job);
    try {
      const child = this.spawnProcess(shell.file, shell.args, { cwd, env: terminalEnvironment(), shell: false, detached: process.platform !== 'win32', windowsHide: true, stdio: ['ignore','pipe','pipe'] }); job.child = child;
      record.status = 'running';
      const decoders = { stdout: new StringDecoder('utf8'), stderr: new StringDecoder('utf8') };
      const append = (key, bytes) => {
        const remaining = Math.max(0, MAX_OUTPUT - job.bytes), kept = bytes.subarray(0, remaining);
        job.bytes += kept.length; record[key] += decoders[key].write(kept);
        if (bytes.length > remaining) record.truncated = true;
      };
      child.stdout.on('data', bytes => append('stdout', bytes)); child.stderr.on('data', bytes => append('stderr', bytes));
      child.once('error', error => { record.message = 'Command launch failed: ' + (error.code || 'unknown'); void this.complete(job, null, null, 'failed'); });
      child.once('close', (code, signal) => {
        record.stdout += decoders.stdout.end(); record.stderr += decoders.stderr.end();
        void this.complete(job, code, signal, job.requestedStop || (code === 0 ? 'succeeded' : 'failed'));
      });
      job.timer = setTimeout(() => { void this.stop(job, 'timed-out'); }, timeoutMs);
      job.watch = setInterval(() => { try { this.authorize(record.rootId, job.access); } catch { void this.stop(job, 'cancelled'); } }, 500);
      job.watch.unref();
      await this.save(job); return this.view(record);
    } catch (error) { record.message = 'Command could not start: ' + (error.code || 'unknown'); await this.complete(job, null, null, 'failed'); return this.view(record); }
  }
  save(job) {
    const snapshot = structuredClone(job.record);
    job.persist = job.persist.catch(() => {}).then(() => this.store.savePrivateRecord('terminal-' + snapshot.requestId, snapshot));
    return job.persist;
  }
  async complete(job, code, signal, status) {
    if (finished(job.record.status)) return;
    clearTimeout(job.timer); clearInterval(job.watch);
    job.record.status = status; job.record.exitCode = code; job.record.signal = signal; job.record.endedAt = new Date().toISOString();
    job.record.outcomeKnown = true;
    try { await this.save(job); } catch { job.record.message = 'Command ended, but final journal save failed. Do not replay it.'; }
  }
  async stop(job, reason) {
    if (finished(job.record.status) || job.requestedStop) return;
    job.requestedStop = reason; job.record.status = 'stopping';
    const child = job.child;
    if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
    try {
      if (process.platform === 'win32') {
        const killer = spawn(path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'taskkill.exe'), ['/PID', String(child.pid), '/T', '/F'], { shell: false, windowsHide: true, stdio: 'ignore' });
        killer.once('error', () => { job.record.terminationConfirmed = false; });
        killer.once('close', code => { job.record.terminationConfirmed = code === 0; });
      } else { process.kill(-child.pid, 'SIGKILL'); job.record.terminationConfirmed = true; }
    } catch { job.record.terminationConfirmed = false; }
    // Explicitly report uncertainty if OS termination did not deliver close;
    // killing a shell cannot guarantee descendants that detach are contained.
    setTimeout(() => { if (!finished(job.record.status)) { job.record.outcomeKnown = false; job.record.message = 'Termination is unconfirmed; inspect processes before retrying.'; void this.save(job).catch(() => {}); } }, 3000).unref();
  }
  async close() { this.closed = true; await Promise.all([...this.jobs.values()].map(job => this.stop(job, 'cancelled'))); }
}
