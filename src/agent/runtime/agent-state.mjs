import { randomUUID } from 'node:crypto';
import { rootWriteMode } from '../permissions.mjs';

/** Saved identity/policy plus process-local controller state; never a tool result. */
export class AgentState {
  constructor(store, { config, secrets }) {
    Object.assign(this, { store, config, secrets });
    this.closing = false;
    this.selectionRevision = 0;
    this.browsing = 0;
    this.lastRemoteCallAt = null;
    this.guideWarning = null;
  }

  static async load(store) {
    const state = new AgentState(store, await store.load());
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

  async saveConfig(next) {
    await this.store.saveConfig(next);
    this.config = next;
  }

  async saveSecrets(next) {
    await this.store.saveSecrets(next);
    this.secrets = next;
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
