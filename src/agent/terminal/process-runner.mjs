import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { terminalEnvironment, terminateProcessTree } from './shell.mjs';
import { finished } from './job-store.mjs';

const MAX_OUTPUT = 64 * 1024;

/** Owns native child processes, output, deadlines and cancellation. */
export class TerminalProcessRunner {
  constructor({ journal, authorize, spawnProcess = spawn }) {
    Object.assign(this, { journal, authorize, spawnProcess });
  }

  async start({ record, access, shell, cwd, timeoutMs }) {
    const job = { record, child: null, bytes: 0, requestedStop: null, access, persist: Promise.resolve() };
    this.journal.jobs.set(record.requestId, job);
    try {
      const child = this.spawnProcess(shell.file, shell.args, {
        cwd, env: terminalEnvironment(), shell: false, detached: process.platform !== 'win32',
        windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      });
      job.child = child;
      record.status = 'running';
      const decoders = { stdout: new StringDecoder('utf8'), stderr: new StringDecoder('utf8') };
      const append = (key, bytes) => {
        const remaining = Math.max(0, MAX_OUTPUT - job.bytes);
        const kept = bytes.subarray(0, remaining);
        job.bytes += kept.length;
        record[key] += decoders[key].write(kept);
        if (bytes.length > remaining) record.truncated = true;
      };
      child.stdout.on('data', bytes => append('stdout', bytes));
      child.stderr.on('data', bytes => append('stderr', bytes));
      child.once('error', error => {
        record.message = 'Command launch failed: ' + (error.code || 'unknown');
        void this.complete(job, null, null, 'failed');
      });
      child.once('close', (code, signal) => {
        record.stdout += decoders.stdout.end();
        record.stderr += decoders.stderr.end();
        void this.complete(job, code, signal, job.requestedStop || (code === 0 ? 'succeeded' : 'failed'));
      });
      job.timer = setTimeout(() => { void this.stop(job, 'timed-out'); }, timeoutMs);
      job.watch = setInterval(() => {
        try { this.authorize(record.rootId, job.access); }
        catch { void this.stop(job, 'cancelled'); }
      }, 500);
      job.watch.unref();
      await this.journal.save(job);
    } catch (error) {
      record.message = 'Command could not start: ' + (error.code || 'unknown');
      await this.complete(job, null, null, 'failed');
    }
    return this.journal.view(record);
  }

  async complete(job, code, signal, status) {
    if (finished(job.record.status)) return;
    clearTimeout(job.timer);
    clearInterval(job.watch);
    Object.assign(job.record, {
      status, exitCode: code, signal, endedAt: new Date().toISOString(), outcomeKnown: true,
    });
    try { await this.journal.save(job); }
    catch { job.record.message = 'Command ended, but final journal save failed. Do not replay it.'; }
  }

  async stop(job, reason) {
    if (finished(job.record.status) || job.requestedStop) return;
    job.requestedStop = reason;
    job.record.status = 'stopping';
    const child = job.child;
    if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
    terminateProcessTree(child, job.record);
    setTimeout(() => {
      if (!finished(job.record.status)) {
        job.record.outcomeKnown = false;
        job.record.message = 'Termination is unconfirmed; inspect processes before retrying.';
        void this.journal.save(job).catch(() => {});
      }
    }, 3000).unref();
  }
}
