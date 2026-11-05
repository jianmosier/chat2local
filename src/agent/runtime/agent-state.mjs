import { randomUUID } from 'node:crypto';
import { rootWriteMode } from '../permissions.mjs';
import { AgentLifecycle, lifecycleError } from './lifecycle-core.mjs';

function waitForSave(work, signal) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => { if (settled) return; settled = true; signal.removeEventListener('abort', abort); if (error) reject(error); else resolve(value); };
    const abort = () => finish(Object.assign(new Error('Controller stopped waiting for persistence; completion is not confirmed.'), { code: 'EPERSISTENCE', status: 503 }));
    signal.addEventListener('abort', abort, { once: true }); if (signal.aborted) abort();
    Promise.resolve(work).then(value => finish(null, value), error => finish(error));
  });
}

/** Saved identity/policy plus process-local controller state; never a tool result. */
export class AgentState {
  #persistence = Promise.resolve();
  #pendingSaves = 0;
  constructor(store, { config, secrets }, lifecycle = new AgentLifecycle()) {
    Object.assign(this, { store, config, secrets });
    this.lifecycle = lifecycle;
    lifecycle.onFault(() => { this.config = { ...this.config, paused: true }; });
    this.browsing = 0;
    this.lastRemoteCallAt = null;
    this.guideWarning = null;
  }

  get closing() { return ['closing', 'closed', 'faulted'].includes(this.lifecycle.snapshot().phase); }
  get selectionRevision() { return this.lifecycle.snapshot().selectionRevision; }

  static async load(store, lifecycle) {
    const state = new AgentState(store, await store.load(), lifecycle);
    const { config } = state;
    if (config.roots.length > 50 || config.roots.some(root => !root || typeof root.id !== 'string'
      || typeof root.path !== 'string' || typeof root.write !== 'boolean')) {
      throw new Error('Invalid saved directory permissions.');
    }
    if (config.accountRoots !== undefined && (!Array.isArray(config.accountRoots) || config.accountRoots.length > 100)) {
      throw new Error('Invalid account-scoped directory policy.');
    }
    const roots = [...config.roots, ...(config.accountRoots || [])];
    if (new Set(roots.map(root => root?.id)).size !== roots.length) {
      throw new Error('Duplicate directory identity across legacy/account policies.');
    }
    for (const root of roots) {
      if (!root || typeof root.id !== 'string' || typeof root.path !== 'string' || typeof root.write !== 'boolean') {
        throw new Error('Invalid directory permission.');
      }
      rootWriteMode(root);
    }
    if (!config.installationId) await state.saveConfig({ ...config, installationId: randomUUID() });
    return state;
  }

  async drainPersistence() { await this.#persistence; }

  get pendingSaves() { return this.#pendingSaves; }

  #availableSaves(count = 1) {
    if (this.lifecycle.closeSignal.aborted || this.#pendingSaves + count > 24) {
      throw Object.assign(new Error('Persistence is closing or busy; saving this restriction is not confirmed.'), { code: 'EPERSISTENCE', status: 503 });
    }
  }

  #save(work) {
    this.#availableSaves();
    this.#pendingSaves++;
    const result = this.#persistence.then(work).finally(() => { this.#pendingSaves--; });
    // This is an I/O resource tail, not admission or a substitute business queue.
    this.#persistence = result.catch(() => {});
    return result;
  }

  saveConfig(next) {
    if (!this.lifecycle.healthy) return Promise.reject(lifecycleError());
    const value = structuredClone(next);
    return waitForSave(this.#save(async () => {
      if (!this.lifecycle.healthy || this.lifecycle.closeSignal.aborted) throw lifecycleError();
      await this.store.saveConfig(value);
      if (this.lifecycle.healthy && !this.lifecycle.closeSignal.aborted) this.config = value;
    }), this.lifecycle.signal);
  }

  saveSecrets(next) {
    if (!this.lifecycle.healthy) return Promise.reject(lifecycleError());
    const value = structuredClone(next);
    return waitForSave(this.#save(async () => {
      if (!this.lifecycle.healthy || this.lifecycle.closeSignal.aborted) throw lifecycleError();
      await this.store.saveSecrets(value);
      if (this.lifecycle.healthy && !this.lifecycle.closeSignal.aborted) this.secrets = value;
    }), this.lifecycle.signal);
  }

  restrictPolicy(next, files) {
    if (this.lifecycle.healthy) throw lifecycleError('ESTATE');
    // Only remove existing roots and pause. Never accept new grants/metadata.
    this.config = { ...this.config, paused: true, accountPolicyRevision: (this.config.accountPolicyRevision || 0) + 1,
      roots: this.config.roots.filter(root => next.roots.some(item => item.id === root.id)),
      accountRoots: (this.config.accountRoots || []).filter(root => (next.accountRoots || []).some(item => item.id === root.id)) };
    delete this.config.connectionGuide;
    files.cancelPending('Access restricted after lifecycle failure.');
    const value = structuredClone(this.config);
    return waitForSave(this.#save(() => this.store.saveConfig(value)), this.lifecycle.closeSignal);
  }

  persistDisconnect() {
    const config = structuredClone(this.config), secrets = structuredClone(this.secrets);
    this.#availableSaves(2);
    const writes = [this.#save(() => this.store.saveSecrets(secrets)), this.#save(() => this.store.saveConfig(config))];
    return waitForSave(Promise.allSettled(writes).then(results => {
      const errors = results.filter(result => result.status === 'rejected').map(result => result.reason);
      if (errors.length) throw Object.assign(new AggregateError(errors, 'Local restriction is active but persistence failed.'), { code: 'EPERSISTENCE', status: 503 });
    }), this.lifecycle.closeSignal);
  }

  async changePolicy(next, files) {
    next = { ...next, accountPolicyRevision: (this.config.accountPolicyRevision || 0) + 1 };
    files.cancelPending();
    const selected = this.config.connectionGuide?.rootId;
    if (selected) {
      const before = this.config.roots.find(root => root.id === selected);
      const after = next.roots.find(root => root.id === selected);
      if (!after || !before || rootWriteMode(after) !== rootWriteMode(before)) {
        next = { ...next };
        delete next.connectionGuide;
      }
    }
    await this.saveConfig(next);
  }
}
