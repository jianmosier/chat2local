import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { approveRoot } from './files/path-policy.mjs';
import { authorizeTerminal } from './terminal/access-policy.mjs';
import { terminalShell, terminalCwd } from './terminal/shell.mjs';
import { TerminalJobStore, finished } from './terminal/job-store.mjs';
import { TerminalProcessRunner } from './terminal/process-runner.mjs';

export { TERMINAL_CAPABILITY, TERMINAL_CONFIRMATION } from './terminal/access-policy.mjs';
export { terminalEnvironment, terminalShell, terminalCwd } from './terminal/shell.mjs';

/** Terminal use cases: authorize, reserve once, run, query and cancel. */
export class TerminalService {
  constructor({ getConfig, getDevice, store, spawnProcess = spawn }) {
    Object.assign(this, { getConfig, getDevice, store, spawnProcess });
    this.closed = false;
    this.launchTail = Promise.resolve();
    this.journal = new TerminalJobStore(store);
    this.jobs = this.journal.jobs;
    this.runner = new TerminalProcessRunner({
      journal: this.journal,
      authorize: (rootId, access) => this.authorize(rootId, access),
      spawnProcess: (...args) => this.spawnProcess(...args),
    });
  }

  authorize(rootId, envelope) {
    return authorizeTerminal({ config: this.getConfig(), device: this.getDevice(), closed: this.closed }, rootId, envelope);
  }

  async invoke(name, args, envelope) {
    const { access, local } = this.authorize(args.rootId, envelope);
    if (!/^[a-f0-9-]{36}$/.test(args.requestId || '')) {
      throw new Error('Use a stable UUID requestId for this command and every status/retry.');
    }
    if (name === 'terminal_execute') {
      const result = this.launchTail.then(() => {
        this.authorize(args.rootId, envelope);
        return this.execute(args, access, local);
      });
      this.launchTail = result.catch(() => {});
      return result;
    }
    if (!['terminal_status', 'terminal_cancel'].includes(name)) throw new Error('Unknown terminal operation.');
    const job = this.jobs.get(args.requestId);
    const record = await this.journal.read(args.requestId);
    if (!this.journal.owns(record, args, access)) throw new Error('Command does not belong to this connection, device and root.');
    if (!job && !finished(record.status)) {
      return this.view({ ...record, status: 'interrupted', outcomeKnown: false,
        message: 'The agent restarted. Do not replay this command; inspect its effects first.' });
    }
    if (name === 'terminal_cancel' && job && !finished(record.status)) await this.stop(job, 'cancelled');
    return this.view(record);
  }

  async execute(args, access, root) {
    if (typeof args.command !== 'string' || !args.command.trim() || args.command.includes('\0') || Buffer.byteLength(args.command) > 16384) {
      throw new Error('Command must be nonempty UTF-8 text, at most 16 KiB, without NUL.');
    }
    const timeoutMs = args.timeoutMs ?? 120000;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 300000) throw new Error('timeoutMs must be 100–300000.');
    const shell = terminalShell(args.command, args.shell || 'auto');
    const inputHash = createHash('sha256').update(JSON.stringify([
      args.command, args.cwd || '.', timeoutMs, shell.shell, args.rootId,
      access.connectionId, access.resource, access.deviceId,
    ])).digest('hex');
    const previous = await this.journal.read(args.requestId);
    if (previous) {
      if (previous.inputHash !== inputHash) throw new Error('requestId already identifies a different command; nothing was executed.');
      return this.invoke('terminal_status', { rootId: args.rootId, requestId: args.requestId }, access);
    }
    this.journal.ensureCapacity();
    await approveRoot(root.path, this.store.directory, true);
    const cwd = await terminalCwd(root.path, args.cwd || '.');
    this.authorize(args.rootId, access);
    const record = {
      requestId: args.requestId, rootId: args.rootId, connectionId: access.connectionId,
      resource: access.resource, deviceId: access.deviceId, inputHash,
      status: 'starting', stdout: '', stderr: '', truncated: false,
      exitCode: null, signal: null, startedAt: new Date().toISOString(), outcomeKnown: false,
    };
    // Reserve before spawn, then recheck live permission after persistence.
    await this.journal.reserve(record);
    this.authorize(args.rootId, access);
    return this.runner.start({ record, access, shell, cwd, timeoutMs });
  }

  view(record) { return this.journal.view(record); }
  save(job) { return this.journal.save(job); }
  complete(job, code, signal, status) { return this.runner.complete(job, code, signal, status); }
  stop(job, reason) { return this.runner.stop(job, reason); }

  activeCount() {
    return [...this.jobs.values()].filter(job => ['starting', 'running', 'stopping'].includes(job.record.status)).length;
  }

  cancelForRoots(connectionId, rootIds) {
    return Promise.all([...this.jobs.values()]
      .filter(job => job.record.connectionId === connectionId && rootIds.includes(job.record.rootId))
      .map(job => this.stop(job, 'cancelled')));
  }

  async close() {
    this.closed = true;
    await Promise.all([...this.jobs.values()].map(job => this.stop(job, 'cancelled')));
  }
}
