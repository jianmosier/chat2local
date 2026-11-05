import fs from 'node:fs/promises';
import path from 'node:path';
import { fail, registration, outcome, eventDetails, publicView, localView, unknown } from './operation-contract.mjs';

/** Default implementation of the same commands used by the Rust state owner. */
export class JavascriptOperationCore {
  #records = new Map();
  #events = [];
  #attempt = 0;
  #healthy = true;
  get healthy() { return this.#healthy; }
  freeze() { this.#healthy = false; }
  assertHealthy() { if (!this.#healthy) throw fail('EOPERATIONS'); }
  #prune(now) {
    for (const record of this.#records.values()) {
      if (record.status === 'pending' && now - record.createdAt > 600000) {
        record.status = 'expired'; delete record.content; delete record.before;
      }
    }
    if (this.#records.size >= 200) {
      for (const [id, record] of this.#records) {
        if (!['pending', 'applying'].includes(record.status)) this.#records.delete(id);
        if (this.#records.size < 100) break;
      }
    }
  }
  #ticket(record) { return { attempt: record.attempt, operation: localView(record), owner: record.owner }; }
  execute(command) {
    this.assertHealthy();
    const { op, now, id } = command;
    let result = null;
    if (['propose', 'beginDirect', 'decide', 'prune', 'pendingIds', 'status'].includes(op)) this.#prune(now);
    if (op === 'propose' || op === 'beginDirect') {
      const { input } = command;
      const owner = registration(input, command.owner);
      if (this.#records.has(input.operationId)) throw fail('EDUPLICATE');
      if (op === 'propose' && [...this.#records.values()].filter(item => item.status === 'pending').length >= 20) throw fail('EPENDING');
      if (this.#records.size >= 200) throw fail('ECAPACITY');
      const record = structuredClone({ ...input, owner, createdAt: now, status: op === 'propose' ? 'pending' : 'applying' });
      if (op === 'beginDirect') { record.authorization = 'directory-direct'; record.attempt = String(++this.#attempt); }
      this.#records.set(input.operationId, record);
      result = op === 'propose' ? publicView(record) : this.#ticket(record);
    } else if (op === 'decide') {
      if (typeof command.approved !== 'boolean') throw fail('EINPUT');
      const record = this.#records.get(id);
      if (record?.status !== 'pending') throw fail('ENOT_PENDING');
      record.status = command.approved ? 'applying' : 'rejected';
      if (command.approved) {
        record.authorization = 'local-review'; record.attempt = String(++this.#attempt);
        result = { ticket: this.#ticket(record) };
      } else { delete record.content; delete record.before; result = { status: publicView(record) }; }
    } else if (op === 'finish') {
      outcome(command.outcome);
      const record = this.#records.get(id);
      if (record?.status !== 'applying' || record.attempt !== command.attempt) throw fail('EATTEMPT');
      const success = record.authorization === 'local-review' ? 'approved' : 'written';
      if (['written', 'approved'].includes(command.outcome.status) && command.outcome.status !== success) throw fail('EINPUT');
      Object.assign(record, command.outcome); delete record.content; delete record.before; delete record.attempt;
      result = publicView(record);
    } else if (op === 'cancel') {
      if (typeof command.reason !== 'string' || command.reason.length > 4096) throw fail('EINPUT');
      for (const record of this.#records.values()) if (record.status === 'pending') {
        record.status = 'rejected'; record.message = command.reason; delete record.content; delete record.before;
      }
    } else if (op === 'status') {
      const record = this.#records.get(id), viewer = command.viewer;
      const visible = viewer.local || (record && (record.owner?.connectionId ?? null) === viewer.connectionId
        && (record.owner?.deviceId ?? null) === viewer.deviceId && (record.owner?.resource ?? null) === viewer.resource
        && (viewer.connectionId === null || viewer.visibleRoots.includes(record.rootId)));
      result = record && visible ? publicView(record) : unknown(id);
    } else if (op === 'pendingIds') result = [...this.#records.values()].filter(record => record.status === 'pending').map(record => record.operationId);
    else if (op === 'pendingView') { const record = this.#records.get(id); result = record?.status === 'pending' ? localView(record) : null; }
    else if (op === 'snapshotIds') result = [...this.#records.keys()];
    else if (op === 'snapshot') { const record = this.#records.get(id); result = record ? localView(record) : null; }
    else if (op === 'eventCount') result = this.#events.length;
    else if (op === 'event') result = this.#events[command.index] ?? null;
    else if (op === 'audit') {
      eventDetails(command.action, command.details);
      result = { at: command.at, action: command.action, ...command.details };
      this.#events.push(result); this.#events = this.#events.slice(-100);
    } else if (op !== 'prune') throw fail('EINPUT');
    return structuredClone(result);
  }
}

/** Command facade and single disk audit sink. No records are retained here. */
export class FileOperationStore {
  constructor(stateDir, { core = new JavascriptOperationCore(), clock = Date.now } = {}) {
    Object.assign(this, { stateDir, core, clock });
    const store = this;
    // Compatibility diagnostics are detached projections, never a state mutation API.
    this.records = Object.freeze({
      get size() { return store.ids().length; },
      get(id) { return store.safe({ op: 'snapshot', id }, null) ?? undefined; },
      has(id) { return store.ids().includes(id); },
      keys() { return store.ids()[Symbol.iterator](); },
      *values() { for (const id of store.ids()) { const value = this.get(id); if (value) yield value; } },
      *entries() { for (const value of this.values()) yield [value.operationId, value]; },
      [Symbol.iterator]() { return this.entries(); },
    });
  }
  assertHealthy() { this.core.assertHealthy(); }
  freeze() { this.core.freeze(); }
  call(command) { this.assertHealthy(); return this.core.execute(command); }
  safe(command, fallback) {
    if (!this.core.healthy) return fallback;
    try { return this.call(command); } catch (error) { if (!this.core.healthy) return fallback; throw error; }
  }
  now() { const now = this.clock(); if (!Number.isSafeInteger(now) || now < 0) throw fail('EINPUT'); return now; }
  ids() { return this.safe({ op: 'snapshotIds' }, []); }
  prune() { this.safe({ op: 'prune', now: this.now() }, null); }
  cancelPending(reason = 'Access changed locally.') { this.safe({ op: 'cancel', reason }, null); }
  register(op, input, owner = null) {
    input = { ...input, content: Buffer.from(input.content, 'utf8').toString('utf8'),
      ...(input.before === undefined ? {} : { before: Buffer.from(input.before, 'utf8').toString('utf8') }) };
    return this.call({ op, input, owner: owner ?? null, now: this.now() });
  }
  propose(input, owner) { return this.register('propose', input, owner); }
  beginDirect(input, owner) { return this.register('beginDirect', input, owner); }
  decide(id, approved) { return this.call({ op: 'decide', id, approved, now: this.now() }); }
  finish(id, attempt, value) {
    const result = Object.fromEntries(['status', 'message', 'sha256', 'backupSaved'].filter(key => value[key] !== undefined).map(key => [key, value[key]]));
    return this.call({ op: 'finish', id, attempt, outcome: result });
  }
  pending() { return this.safe({ op: 'pendingIds', now: this.now() }, []).map(id => this.safe({ op: 'pendingView', id }, null)).filter(Boolean); }
  view(id, policy) {
    const access = policy.context.getStore();
    const viewer = { local: false, connectionId: access?.connectionId ?? null, deviceId: access?.deviceId ?? null, resource: access?.resource ?? null,
      visibleRoots: policy.availableRoots().filter(root => policy.mode(root) && (!access || access.roots.some(item => item.rootId === root.id))).map(root => root.id) };
    return this.safe({ op: 'status', id, viewer, now: this.now() }, unknown(id));
  }
  get events() {
    const count = this.safe({ op: 'eventCount' }, 0);
    return Array.from({ length: count }, (_, index) => this.safe({ op: 'event', index }, null)).filter(Boolean);
  }
  async audit(action, details) {
    const event = this.call({ op: 'audit', action, details, at: new Date(this.now()).toISOString() });
    if (!this.stateDir) return;
    await fs.mkdir(this.stateDir, { recursive: true });
    const log = path.join(this.stateDir, 'audit.jsonl');
    try { if ((await fs.stat(log)).size > 1024 * 1024) await fs.rename(log, `${log}.previous`); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    await fs.appendFile(log, JSON.stringify(event) + '\n', { mode: 0o600 });
  }
}
