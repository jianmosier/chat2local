import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { terminalEnvironment, terminateProcessTree } from './shell.mjs';
import { finished } from './job-store.mjs';

const MAX_OUTPUT = 64 * 1024;

/** Owns native child processes, output, deadlines and cancellation. */
export class TerminalProcessRunner {
  constructor({ journal, authorize, spawnProcess = spawn, terminate = terminateProcessTree }) {
    Object.assign(this, { journal, authorize, spawnProcess, terminate });
  }

  async start({ record, access, shell, cwd, timeoutMs }) {
    const job = { record, child: null, bytes: 0, requestedStop: null, access, persist: Promise.resolve() };
    job.done = new Promise(resolve => { job.resolveDone = resolve; });
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
        if (!child.pid) void this.complete(job, null, null, 'failed');
        else void this.stop(job, 'failed');
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
      // The durable reservation already exists. Disk completion must not keep
      // the dispatcher from accepting pause/cancel after the process starts.
      void this.journal.save(job).catch(() => {
        record.message = [record.message, 'Command started, but its running journal save failed. Do not replay it.'].filter(Boolean).join(' ');
        void this.stop(job, 'failed');
      });
    } catch (error) {
      if (job.child && !finished(record.status)) {
        record.message = 'Command may have started, but its running journal save failed. Stopping; do not replay it.';
        await this.stop(job, 'failed');
      } else if (!job.child) {
        record.message = 'Command could not start: ' + (error.code || 'unknown');
        await this.complete(job, null, null, 'failed');
      }
    }
    return this.journal.view(record);
  }

  async complete(job, code, signal, status) {
    if (finished(job.record.status) || job.completing) return;
    job.completing = true;
    // Shell close alone does not confirm a requested tree termination. Windows
    // taskkill confirms only the attached targets it found, not escaped work.
    if (job.requestedStop && await job.termination !== true) {
      this.unconfirmed(job); return;
    }
    if (job.requestedStop) job.record.terminationConfirmed = true;
    clearTimeout(job.timer);
    clearInterval(job.watch);
    clearTimeout(job.stopTimer);
    Object.assign(job.record, {
      status, exitCode: code, signal, endedAt: new Date().toISOString(), outcomeKnown: true,
    });
    const pending = 'Command ended; final journal save is pending. Do not replay it.';
    const saving = this.journal.save(job);
    job.record.message = [job.record.message, pending].filter(Boolean).join(' ');
    void saving.then(() => {
      job.record.message = job.record.message?.replace(pending, '').trim();
    }, () => {
      job.record.message = [job.record.message?.replace(pending, '').trim(), 'Command ended, but final journal save failed. Do not replay it.'].filter(Boolean).join(' ');
    });
    job.resolveDone?.();
  }

  async stop(job, reason) {
    if (finished(job.record.status) || job.requestedStop) return;
    job.requestedStop = reason;
    job.record.status = 'stopping';
    const child = job.child;
    if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
    job.termination = this.terminate(child, job.record).catch(() => false);
    job.stopTimer = setTimeout(() => {
      if (!finished(job.record.status)) this.unconfirmed(job);
    }, 3000).unref();
  }

  unconfirmed(job) {
    clearTimeout(job.timer); clearTimeout(job.stopTimer); clearInterval(job.watch);
    Object.assign(job.record, { status: 'stopping', outcomeKnown: false, terminationConfirmed: false });
    job.record.message = [job.record.message, 'Termination is unconfirmed; inspect processes and effects before retrying.'].filter(Boolean).join(' ');
    void this.journal.save(job).catch(() => {});
    job.resolveDone?.();
  }

  async close() {
    const jobs = [...this.journal.jobs.values()];
    await Promise.all(jobs.map(job => this.stop(job, 'cancelled')));
    let timer;
    await Promise.race([Promise.all(jobs.map(job => job.done)), new Promise(resolve => { timer = setTimeout(resolve, 4000); })]);
    clearTimeout(timer);
  }
}
