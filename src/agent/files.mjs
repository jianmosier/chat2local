import fs from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { checkArguments } from '../shared/protocol.mjs';
import { FileAccessPolicy } from './files/access-policy.mjs';
import { forbiddenName, resolveFilePath } from './files/path-policy.mjs';
import { FileOperationStore } from './files/operation-store.mjs';
import { FileWriter, readTextSnapshot } from './files/storage.mjs';

// Stable imports for existing controllers, installers and integrations.
export { approveRoot, relativeParts } from './files/path-policy.mjs';

/** File-tool use cases; policy, disk I/O and operation history are separate. */
export class FileService {
  constructor(getPolicy, stateDir, getDeviceInfo = () => undefined) {
    Object.assign(this, { getPolicy, stateDir, getDeviceInfo });
    this.policy = new FileAccessPolicy(getPolicy, getDeviceInfo);
    this.history = new FileOperationStore(stateDir);
    this.operations = this.history.records;
    this.operationAccess = this.history.owners;
    this.accessContext = this.policy.context;
    this.commitTail = Promise.resolve();
    this.writer = new FileWriter({
      stateDir,
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
  status(id) { return this.history.view(id, this.policy); }

  async safePath(id, relative, options = {}) {
    const root = this.policyRoot(id, options.writing ?? false);
    return resolveFilePath(root, relative, options);
  }

  async readSnapshot(rootId, relative, mayCreate = false) {
    const { target } = await this.safePath(rootId, relative, { mayCreate });
    return readTextSnapshot(target, mayCreate);
  }

  pendingOperations() {
    this.prune();
    return [...this.operations.values()].filter(operation => operation.status === 'pending');
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
      if (error.code) throw new Error(`Filesystem operation failed (${error.code}).`);
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
    const snapshot = await this.readSnapshot(args.rootId, args.path);
    await this.audit('read', { rootId: args.rootId, path: args.path });
    return { path: args.path, content: snapshot.content, sha256: snapshot.sha256 };
  }

  async writeFile(args) {
    this.policyRoot(args.rootId, 'direct');
    if (!this.stateDir) throw new Error('Direct writing requires private backup and audit storage.');
    const operation = this.remember({ ...args, status: 'applying', authorization: 'directory-direct' });
    return this.#commit(operation);
  }

  async proposeWrite(args) {
    this.policyRoot(args.rootId, true);
    if (this.pendingOperations().length >= 20) throw new Error('Too many pending proposals. Ask the local user to review them.');
    const snapshot = await this.readSnapshot(args.rootId, args.path, true);
    if (snapshot.sha256 !== args.expectedHash) throw new Error('File changed or already exists. Read it again before proposing a write.');
    const operation = this.remember({ ...args, before: snapshot.content ?? '', status: 'pending' });
    await this.audit('proposed', { operationId: operation.operationId, rootId: args.rootId, path: args.path });
    return { operationId: operation.operationId, status: 'pending', message: 'Not written. Await local user approval, then call operation_status.' };
  }

  remember(value) {
    const operation = { ...value, operationId: randomUUID(), createdAt: Date.now() };
    this.operations.set(operation.operationId, operation);
    this.operationAccess.set(operation, this.accessContext.getStore());
    return operation;
  }

  async decide(id, approved) {
    if (typeof approved !== 'boolean') throw new Error('Local approval must be an explicit boolean.');
    this.prune();
    const operation = this.operations.get(id);
    if (!operation || operation.status !== 'pending') throw new Error('Proposal is no longer pending.');
    operation.status = approved ? 'applying' : 'rejected';
    if (!approved) {
      delete operation.content;
      delete operation.before;
      await this.audit('rejected', { operationId: id });
      return this.status(id);
    }
    operation.authorization = 'local-review';
    return this.#commit(operation);
  }

  #commit(operation) {
    // Re-enter the original connection scope and check policy inside the queue.
    const access = this.operationAccess.get(operation);
    const result = this.commitTail.then(() => this.accessContext.run(access, async () => {
      await this.writer.commit(operation);
      return this.status(operation.operationId);
    }));
    this.commitTail = result.catch(() => {});
    return result;
  }
}
