export const finished = state => ['succeeded', 'failed', 'cancelled', 'timed-out', 'interrupted'].includes(state);

/** Stable terminal journal keys and public result shape, independent of processes. */
export class TerminalJobStore {
  constructor(store, records) {
    this.store = store;
    this.records = records;
    this.jobs = new Map();
  }

  async read(requestId) {
    return this.jobs.get(requestId)?.record || await (this.records ? this.records.read(requestId) : this.store.readPrivateRecord('terminal-' + requestId));
  }

  async reserve(record) {
    if (this.records) return this.records.reserve(record);
    await this.store.savePrivateRecord('terminal-' + record.requestId, record);
    return { kind: 'created', record };
  }

  assertAvailable() { this.records?.assertAvailable(); }

  save(job) {
    const snapshot = structuredClone(job.record);
    job.persist = job.persist.catch(() => {}).then(() =>
      this.records ? this.records.save(snapshot) : this.store.savePrivateRecord('terminal-' + snapshot.requestId, snapshot));
    return job.persist;
  }

  ensureCapacity() {
    if ([...this.jobs.values()].filter(job => !finished(job.record.status)).length >= 2) {
      throw new Error('Two commands are already running. Wait or cancel before starting another.');
    }
    if (this.jobs.size >= 128) {
      const victim = [...this.jobs].find(([, job]) => finished(job.record.status));
      if (!victim) throw new Error('Command capacity reached.');
      this.jobs.delete(victim[0]);
    }
  }

  owns(record, args, access) {
    return Boolean(record && record.rootId === args.rootId && record.connectionId === access.connectionId
      && record.resource === access.resource && record.deviceId === access.deviceId);
  }

  view(record) {
    const { requestId, rootId, status, exitCode, signal, stdout, stderr, truncated,
      startedAt, endedAt, outcomeKnown, terminationConfirmed, message } = record;
    return { requestId, rootId, status, exitCode, signal, stdout, stderr, truncated,
      startedAt, endedAt, outcomeKnown, terminationConfirmed,
      ...(message ? { message } : {}), sandboxed: false };
  }
}
