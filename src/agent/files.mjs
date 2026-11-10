import fs from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { checkArguments } from '../shared/protocol.mjs';
import { FileAccessPolicy } from './files/access-policy.mjs';
import { forbiddenName, resolveFilePath } from './files/path-policy.mjs';
import { FileOperationStore } from './files/operation-store.mjs';
import { publicView, unknown } from './files/operation-contract.mjs';
import { FileWriter, readTextSnapshot } from './files/storage.mjs';
import { rootWriteMode } from './permissions.mjs';

// Stable imports for existing controllers, installers and integrations.
export { approveRoot, relativeParts } from './files/path-policy.mjs';

/** File-tool use cases; policy, disk I/O and operation history are separate. */
export class FileService {
  constructor(getPolicy, stateDir, getDeviceInfo = () => undefined, { readonlyBackend, writerBackend, operationsCore, clock, getResource } = {}) {
    Object.assign(this, { getPolicy, stateDir, getDeviceInfo, readonlyBackend, getResource: getResource ?? (() => null), resourceBound: getResource !== undefined });
    this.policy = new FileAccessPolicy(getPolicy, getDeviceInfo);
    this.history = new FileOperationStore(stateDir, { core: operationsCore, clock });
    this.operations = this.history.records;
    this.accessContext = this.policy.context;
    this.commitTail = Promise.resolve();
    this.writer = new FileWriter({
      stateDir,
      writerBackend,
      writeAuthority: (rootId, permission) => {
        this.policyRoot(rootId, permission);
        return this.readonlyAuthority(rootId);
      },
      safePath: (...args) => this.safePath(...args),
      readSnapshot: (...args) => this.readSnapshot(...args),
      policyRoot: (...args) => this.policyRoot(...args),
      audit: (...args) => this.audit(...args),
    });
  }

  get events() { return this.history.events; }
  availableRoots() { return this.policy.availableRoots(); }
  scopedMode(root) { return this.policy.mode(root); }
  policyRoot(id, writing = false) { return this.policy.root(id, writing); }
  prune() { this.history.prune(); }
  cancelPending(reason) { this.history.cancelPending(reason); }
  audit(action, details) { return this.history.audit(action, details); }
  status(id) {
    if (this.getPolicy().paused) return unknown(id);
    const access = this.accessContext.getStore(), resource = this.getResource();
    if (access && (access.deviceId !== this.getDeviceInfo()?.deviceId || (this.resourceBound && access.resource !== resource))) return unknown(id);
    return this.history.view(id, this.policy);
  }

  async safePath(id, relative, options = {}) {
    const root = this.policyRoot(id, options.writing ?? false);
    return resolveFilePath(root, relative, options);
  }

  async readSnapshot(rootId, relative, mayCreate = false) {
    const { target } = await this.safePath(rootId, relative, { mayCreate });
    return readTextSnapshot(target, mayCreate);
  }

  pendingOperations() {
    return this.history.pending();
  }

  async invoke(name, args = {}, access) {
    // The authenticated envelope, not tool input, supplies connection scope.
    return this.policy.run(access, () => this.#invoke(name, args));
  }

  async #invoke(name, args) {
    try {
      checkArguments(name, args);
      this.prune();
      if (this.getPolicy().paused) throw new Error('Local access is paused.');
      const device = this.getDeviceInfo();
      if (args.deviceId !== undefined && args.deviceId !== device?.deviceId) {
        throw new Error('Target device does not match this computer.');
      }
      if (name === 'list_devices') {
        return { devices: device?.deviceId ? [{ ...device, status: 'online' }] : [], selectionRequired: false };
      }
      if (args.deviceId !== undefined) {
        const { deviceId: _target, ...input } = args;
        args = input;
      }
      switch (name) {
        case 'list_roots': return this.listRoots();
        case 'operation_status': return this.status(args.operationId);
        case 'list_directory': return await this.listDirectory(args);
        case 'read_file': return await this.readFile(args);
        case 'write_file': return await this.writeFile(args);
        case 'propose_write': return await this.proposeWrite(args);
        default: throw new Error('Unknown file operation.');
      }
    } catch (error) {
      if (error.code && !['EOPERATIONS', 'EPENDING', 'ECAPACITY', 'ENOT_PENDING'].includes(error.code)) throw new Error(`Filesystem operation failed (${error.code}).`);
      throw error;
    }
  }

  listRoots() {
    return this.availableRoots().filter(root => this.scopedMode(root)).map(root => ({
      id: root.id, label: root.label,
      writeProposalsAllowed: this.scopedMode(root) !== 'read-only',
      writeMode: this.scopedMode(root), directWriteAllowed: this.scopedMode(root) === 'direct',
      ...(this.getDeviceInfo() ? { device: this.getDeviceInfo() } : {}),
    }));
  }

  async listDirectory(args) {
    if (this.readonlyBackend) return this.readonlyInvoke('list_directory', { rootId: args.rootId, path: args.path ?? '.' });
    const { target } = await this.safePath(args.rootId, args.path ?? '.', { directory: true });
    const entries = await fs.readdir(target, { withFileTypes: true });
    const visible = entries.filter(entry => !forbiddenName(entry.name) && !entry.isSymbolicLink()
      && (entry.isDirectory() || entry.isFile()));
    return {
      entries: visible.slice(0, 500).map(entry => ({ name: entry.name, type: entry.isDirectory() ? 'directory' : 'file' })),
      truncated: visible.length > 500,
    };
  }

  async readFile(args) {
    const snapshot = this.readonlyBackend
      ? await this.readonlyInvoke('read_file', { rootId: args.rootId, path: args.path })
      : await this.readSnapshot(args.rootId, args.path);
    await this.audit('read', { rootId: args.rootId, path: args.path });
    return { path: args.path, content: snapshot.content, sha256: snapshot.sha256 };
  }

  readonlyAuthority(rootId) {
    const root = this.policyRoot(rootId);
    const policy = this.getPolicy();
    const legacy = policy.roots.includes(root);
    const access = this.accessContext.getStore() ?? null;
    const resource = this.getResource();
    if (access && access.resource !== resource) throw new Error('Connection access belongs to a different relay.');
    return { paused: policy.paused === true, deviceId: this.getDeviceInfo()?.deviceId ?? null, resource,
      root: { id: root.id, path: root.path, kind: legacy ? 'legacy' : 'account',
        connectionId: legacy ? null : root.connectionId, writeMode: rootWriteMode(root) }, access };
  }

  async readonlyInvoke(op, args) {
    const snapshot = JSON.stringify(this.readonlyAuthority(args.rootId));
    const result = await this.readonlyBackend.invoke(op, args, JSON.parse(snapshot));
    // The dispatcher retains its FIFO slot until the child exits and this latest
    // authorization check completes. Never return data after local revocation.
    if (JSON.stringify(this.readonlyAuthority(args.rootId)) !== snapshot) throw new Error('Folder authorization changed during the read.');
    return result;
  }

  async writeFile(args) {
    this.policyRoot(args.rootId, 'direct');
    if (!this.stateDir) throw new Error('Direct writing requires private backup and audit storage.');
    const ticket = this.history.beginDirect({ ...args, operationId: randomUUID() }, this.accessContext.getStore());
    return this.#commit(ticket);
  }

  async proposeWrite(args) {
    this.policyRoot(args.rootId, true);
    if (this.pendingOperations().length >= 20) throw new Error('Too many pending proposals. Ask the local user to review them.');
    const snapshot = await this.readSnapshot(args.rootId, args.path, true);
    if (snapshot.sha256 !== args.expectedHash) throw new Error('File changed or already exists. Read it again before proposing a write.');
    const operation = this.history.propose({ ...args, operationId: randomUUID(), before: snapshot.content ?? '' }, this.accessContext.getStore());
    await this.audit('proposed', { operationId: operation.operationId, rootId: args.rootId, path: args.path });
    return { operationId: operation.operationId, status: 'pending', message: 'Not written. Await local user approval, then call operation_status.' };
  }

  async decide(id, approved) {
    if (typeof approved !== 'boolean') throw new Error('Local approval must be an explicit boolean.');
    const decision = this.history.decide(id, approved);
    if (!approved) {
      await this.audit('rejected', { operationId: id });
      return decision.status;
    }
    return this.#commit(decision.ticket, true);
  }

  #receiptVisible(rootId, binding) {
    // State may have trapped. Check only the copied submission identity and
    // current policy, never the failed state core or the mutable writer DTO.
    try {
      const access = this.accessContext.getStore() ?? null;
      if ((binding?.connectionId ?? null) !== (access?.connectionId ?? null)
        || (binding?.deviceId ?? null) !== (access?.deviceId ?? null)
        || (binding?.resource ?? null) !== (access?.resource ?? null)) return false;
      if (binding && (binding.deviceId !== this.getDeviceInfo()?.deviceId
        || (this.resourceBound && binding.resource !== this.getResource()))) return false;
      const root = this.availableRoots().find(root => root.id === rootId);
      return !this.getPolicy().paused && Boolean(root && this.scopedMode(root));
    } catch { return false; }
  }

  #commit(ticket, localDecision = false) {
    // Re-enter the original connection scope and check policy inside the queue.
    const { operation, attempt, owner } = ticket;
    const { operationId, rootId, path, authorization } = operation;
    const binding = owner && { connectionId: owner.connectionId, deviceId: owner.deviceId, resource: owner.resource };
    const result = this.commitTail.then(() => this.accessContext.run(owner ?? undefined, async () => {
      // An issued ticket is not permission to start after the state owner traps.
      this.history.assertHealthy();
      await this.writer.commit(operation);
      try {
        const finished = this.history.finish(operationId, attempt, operation);
        const visible = localDecision ? finished : this.status(operationId);
        this.history.assertHealthy();
        return visible;
      }
      catch (error) {
        // Even a valid ABI business error here means our completion ticket and
        // authoritative state disagree. Freeze; never retry or replay a write.
        this.history.freeze();
        if (!localDecision && !this.#receiptVisible(rootId, binding)) {
          return { ...unknown(operationId), message: 'Write outcome is unknown for this connection. Operation history is unavailable; do not retry.' };
        }
        // This transient receipt reflects the writer's actual outcome. It is not
        // retained or replayed; all later history queries return unknown.
        const receipt = publicView({ ...operation, operationId, path, authorization });
        const warning = ['written', 'approved'].includes(operation.status)
          ? 'File was written, but operation history is unavailable. New writes are blocked; inspect local files before proceeding.'
          : 'Operation history is unavailable; do not retry.';
        receipt.message = [operation.message, warning].filter(Boolean).join(' ');
        return receipt;
      }
    }));
    this.commitTail = result.catch(() => {});
    return result;
  }
}
