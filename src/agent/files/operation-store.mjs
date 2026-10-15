import fs from 'node:fs/promises';
import path from 'node:path';

/** In-memory file operation state and bounded, content-free audit history. */
export class FileOperationStore {
  constructor(stateDir) {
    this.stateDir = stateDir;
    this.records = new Map();
    this.owners = new WeakMap();
    this.events = [];
  }

  prune() {
    for (const operation of this.records.values()) {
      if (operation.status === 'pending' && Date.now() - operation.createdAt > 10 * 60_000) {
        operation.status = 'expired';
        delete operation.content;
        delete operation.before;
      }
    }
    if (this.records.size >= 200) {
      for (const [id, operation] of this.records) {
        if (operation.status !== 'pending' && operation.status !== 'applying') this.records.delete(id);
        if (this.records.size < 100) break;
      }
    }
  }

  cancelPending(reason = 'Access changed locally.') {
    for (const operation of this.records.values()) {
      if (operation.status !== 'pending') continue;
      operation.status = 'rejected';
      operation.message = reason;
      delete operation.content;
      delete operation.before;
    }
  }

  async audit(action, details) {
    const event = { at: new Date().toISOString(), action, ...details };
    this.events.push(event);
    this.events = this.events.slice(-100);
    if (!this.stateDir) return;
    await fs.mkdir(this.stateDir, { recursive: true });
    const log = path.join(this.stateDir, 'audit.jsonl');
    try {
      if ((await fs.stat(log)).size > 1024 * 1024) await fs.rename(log, `${log}.previous`);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await fs.appendFile(log, JSON.stringify(event) + '\n', { mode: 0o600 });
  }

  view(id, policy) {
    this.prune();
    const operation = this.records.get(id);
    const access = policy.context.getStore();
    const owner = operation && this.owners.get(operation);
    const sameConnection = (access?.connectionId || null) === (owner?.connectionId || null);
    const currentRoot = operation && policy.availableRoots().find(root => root.id === operation.rootId);
    const visible = !access || (operation && currentRoot && policy.mode(currentRoot)
      && access.roots.some(root => root.rootId === operation.rootId));
    if (!operation || !sameConnection || !visible) {
      return { operationId: id, status: 'unknown', message: 'Not retained for this connection or agent restarted. Do not assume a write succeeded.' };
    }
    const { status, path, message, sha256, authorization, backupSaved } = operation;
    return { operationId: id, status, path, message, sha256, authorization, backupSaved };
  }
}
