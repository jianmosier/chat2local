import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash, randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { checkedAccess, permittedMode } from '../shared/connection-access.mjs';
import { checkArguments, MAX_FILE_BYTES } from '../shared/protocol.mjs';
import { rootWriteMode } from './permissions.mjs';
import { sameDirectory } from './platform.mjs';

const hash = data => createHash('sha256').update(data).digest('hex');
const within = (root, candidate) => { const rel = path.relative(root, candidate); return rel === '' || (!rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel)); };
const forbidden = name => /^(\.env(?:\..*)?|\.dev\.vars(?:\..*)?|\.git|\.ssh|\.aws|\.azure|\.kube|\.gnupg|\.npmrc|\.netrc|\.gitconfig|node_modules|id_rsa.*|id_ed25519.*|credentials(?:\..*)?|auth\.json|\.chat2local-.*)$/i.test(name) || /\.(pem|key|p12|pfx)$/i.test(name);

export function relativeParts(input, allowRoot = false) {
  if (allowRoot && (input === '.' || input === '')) return [];
  if (typeof input !== 'string' || input.length > 1024 || /^[\\/]/.test(input) || /[:\x00-\x1f\x7f]/.test(input)) throw new Error('Only a safe relative path is allowed.');
  const parts = input.replaceAll('\\', '/').split('/');
  if (parts.some(s => !s || s === '.' || s === '..' || /[. ]$/.test(s) || /[<>"|?*]/.test(s) || /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(s) || forbidden(s))) throw new Error('Path traversal, reserved names, and sensitive files are blocked.');
  return parts;
}

export async function approveRoot(input, stateDir, write = false) {
  if (typeof input !== 'string' || !path.isAbsolute(input) || /^\\\\/.test(input)) throw new Error('Choose an absolute local folder.');
  const selected = await fs.lstat(input);
  if (!selected.isDirectory() || selected.isSymbolicLink()) throw new Error('Select a real directory, not a link.');
  const canonical = await fs.realpath(input);
  const home = await fs.realpath(os.homedir());
  if (canonical === path.parse(canonical).root || await sameDirectory(canonical, home)) throw new Error('Do not authorize an entire drive or user profile.');
  // macOS /var and /tmp are aliases. Resolve the state path too, rather than
  // comparing a canonical root against an unresolved private-state path.
  const privateState = stateDir ? await fs.realpath(stateDir).catch(error => { if (error.code === 'ENOENT') return path.resolve(stateDir); throw error; }) : null;
  if (privateState && (within(canonical, privateState) || within(privateState, canonical))) throw new Error('The Chat2Local private state folder cannot be authorized.');
  const systemPaths = process.platform === 'win32'
    ? [process.env.WINDIR, process.env.ProgramFiles, process.env['ProgramFiles(x86)']].filter(Boolean)
    : ['/System', '/Library', '/bin', '/sbin', '/usr', '/etc', '/private/etc', '/boot', '/proc', '/sys', '/dev'];
  for (const protectedPath of systemPaths) {
    if (within(path.resolve(protectedPath), canonical) || within(canonical, path.resolve(protectedPath))) throw new Error('System and application directories are not allowed.');
  }
  return { id: randomUUID(), label: path.basename(canonical), path: canonical, write: write === true };
}

export class FileService {
  constructor(getPolicy, stateDir, getDeviceInfo = () => undefined) {
    this.getPolicy = getPolicy;
    this.stateDir = stateDir;
    this.getDeviceInfo = getDeviceInfo;
    this.operations = new Map();
    this.events = [];
    this.commitTail = Promise.resolve();
    this.accessContext = new AsyncLocalStorage();
    this.operationAccess = new WeakMap();
  }
  availableRoots() {
    const policy = this.getPolicy();
    // Separate storage, not a flag on legacy roots: an older agent cannot
    // accidentally expose new account-only folders after a binary rollback.
    const access = this.accessContext.getStore();
    // Account roots also carry a LOCAL per-connection grant. An authenticated
    // relay envelope cannot widen it just by naming another connection's root.
    return access ? [...policy.roots, ...(policy.accountRoots || []).filter(root => root.connectionId === access.connectionId)] : policy.roots;
  }
  scopedMode(root) {
    const access = this.accessContext.getStore();
    if (!access) return rootWriteMode(root);
    return permittedMode(rootWriteMode(root), access.roots.find(item => item.rootId === root.id), access.scopes);
  }
  policyRoot(id, writing = false) {
    const policy = this.getPolicy();
    if (policy.paused) throw new Error('Local access is paused.');
    const root = this.availableRoots().find(r => r.id === id);
    if (!root) throw new Error('Folder is not authorized.');
    const mode = this.scopedMode(root);
    if (!mode) throw new Error('Folder is not shared with this connection.');
    if (writing && mode === 'read-only') throw new Error('This folder is read-only. Enable write proposals locally first.');
    if (writing === 'direct' && mode !== 'direct') throw new Error('Direct writing is not authorized for this folder. Choose direct read/write once in the local folder permissions, or use propose_write for review.');
    return root;
  }
  async safePath(id, relative, { writing = false, directory = false, mayCreate = false } = {}) {
    const root = this.policyRoot(id, writing);
    const parts = relativeParts(relative, directory);
    const actualRoot = await fs.realpath(root.path);
    if (actualRoot !== root.path) throw new Error('The authorized root changed. Select it again.');
    let current = root.path;
    for (let i = 0; i < parts.length; i++) {
      current = path.join(current, parts[i]);
      let stat;
      try { stat = await fs.lstat(current); }
      catch (error) { if (error.code === 'ENOENT' && mayCreate && i === parts.length - 1) return { root, target: current }; throw error; }
      if (stat.isSymbolicLink()) throw new Error('Symbolic links and junctions are blocked.');
      if (i < parts.length - 1 && !stat.isDirectory()) throw new Error('Parent is not a directory.');
      const real = await fs.realpath(current);
      if (!within(root.path, real)) throw new Error('Path leaves the authorized folder.');
      if (i === parts.length - 1 && !directory && (!stat.isFile() || stat.nlink !== 1)) throw new Error('Only regular, single-link files are allowed.');
    }
    if (directory && !(await fs.stat(current)).isDirectory()) throw new Error('Not a directory.');
    return { root, target: current };
  }
  async readSnapshot(rootId, relative, mayCreate = false) {
    const { target } = await this.safePath(rootId, relative, { mayCreate });
    let handle;
    try { handle = await fs.open(target, 'r'); }
    catch (error) { if (mayCreate && error.code === 'ENOENT') return { target, bytes: null, sha256: null }; throw error; }
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_FILE_BYTES) throw new Error('Only regular text files up to 64 KiB are supported.');
      const buffer = Buffer.alloc(MAX_FILE_BYTES + 1);
      let length = 0;
      while (length < buffer.length) {
        const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
        if (!bytesRead) break;
        length += bytesRead;
      }
      if (length > MAX_FILE_BYTES) throw new Error('File grew beyond the size limit.');
      const bytes = buffer.subarray(0, length);
      if (bytes.includes(0)) throw new Error('Binary files are not supported.');
      const content = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      return { target, bytes, content, sha256: hash(bytes) };
    } finally { await handle.close(); }
  }
  prune() {
    for (const op of this.operations.values()) {
      if (op.status === 'pending' && Date.now() - op.createdAt > 10 * 60_000) { op.status = 'expired'; delete op.content; delete op.before; }
    }
    if (this.operations.size >= 200) {
      for (const [id, op] of this.operations) { if (op.status !== 'pending' && op.status !== 'applying') this.operations.delete(id); if (this.operations.size < 100) break; }
    }
  }
  cancelPending(reason = 'Access changed locally.') {
    for (const op of this.operations.values()) if (op.status === 'pending') { op.status = 'rejected'; op.message = reason; delete op.content; delete op.before; }
  }
  async audit(action, details) {
    const event = { at: new Date().toISOString(), action, ...details };
    this.events.push(event); this.events = this.events.slice(-100);
    if (!this.stateDir) return;
    await fs.mkdir(this.stateDir, { recursive: true });
    const log = path.join(this.stateDir, 'audit.jsonl');
    try { if ((await fs.stat(log)).size > 1024 * 1024) await fs.rename(log, `${log}.previous`); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await fs.appendFile(log, JSON.stringify(event) + '\n', { mode: 0o600 });
  }
  status(id) {
    this.prune();
    const op = this.operations.get(id);
    const access = this.accessContext.getStore();
    const owner = op && this.operationAccess.get(op);
    const sameConnection = (access?.connectionId || null) === (owner?.connectionId || null);
    const currentRoot = op && this.availableRoots().find(root => root.id === op.rootId);
    const visible = !access || (op && currentRoot && this.scopedMode(currentRoot) && access.roots.some(root => root.rootId === op.rootId));
    if (!op || !sameConnection || !visible) return { operationId: id, status: 'unknown', message: 'Not retained for this connection or agent restarted. Do not assume a write succeeded.' };
    return { operationId: id, status: op.status, path: op.path, message: op.message, sha256: op.sha256, authorization: op.authorization, backupSaved: op.backupSaved };
  }
  async invoke(name, args = {}, access) {
    // Access is supplied by the authenticated relay envelope, never tool input.
    // Async-local scope prevents simultaneous connections from sharing policy.
    const fence = access === undefined ? undefined : checkedAccess(access, this.getDeviceInfo()?.deviceId || '');
    return this.accessContext.run(fence, () => this.#invoke(name, args));
  }
  async #invoke(name, args) {
    try {
      checkArguments(name, args); this.prune();
      if (this.getPolicy().paused) throw new Error('Local access is paused.');
      const localDevice = this.getDeviceInfo();
      if (args.deviceId !== undefined && args.deviceId !== localDevice?.deviceId) throw new Error('Target device does not match this computer.');
      if (name === 'list_devices') return { devices: localDevice?.deviceId ? [{ ...localDevice, status: 'online' }] : [], selectionRequired: false };
      if (args.deviceId !== undefined) { const { deviceId: _route, ...input } = args; args = input; }
      if (name === 'list_roots') return this.availableRoots().filter(root => this.scopedMode(root)).map(root => ({ id: root.id, label: root.label, writeProposalsAllowed: this.scopedMode(root) !== 'read-only', writeMode: this.scopedMode(root), directWriteAllowed: this.scopedMode(root) === 'direct', ...(this.getDeviceInfo() ? { device: this.getDeviceInfo() } : {}) }));
      if (name === 'operation_status') return this.status(args.operationId);
      if (name === 'list_directory') {
        const { target } = await this.safePath(args.rootId, args.path ?? '.', { directory: true });
        const entries = await fs.readdir(target, { withFileTypes: true });
        const safe = entries.filter(e => !forbidden(e.name) && !e.isSymbolicLink() && (e.isDirectory() || e.isFile()));
        return { entries: safe.slice(0, 500).map(e => ({ name: e.name, type: e.isDirectory() ? 'directory' : 'file' })), truncated: safe.length > 500 };
      }
      if (name === 'read_file') {
        const snap = await this.readSnapshot(args.rootId, args.path);
        await this.audit('read', { rootId: args.rootId, path: args.path });
        return { path: args.path, content: snap.content, sha256: snap.sha256 };
      }
      if (name === 'write_file') {
        this.policyRoot(args.rootId, 'direct');
        if (!this.stateDir) throw new Error('Direct writing requires private backup and audit storage.');
        const operationId = randomUUID();
        const op = { ...args, operationId, createdAt: Date.now(), status: 'applying', authorization: 'directory-direct' };
        this.operations.set(operationId, op);
        this.operationAccess.set(op, this.accessContext.getStore());
        return await this.#commit(op);
      }
      if (name !== 'propose_write') throw new Error('Unknown file operation.');
      this.policyRoot(args.rootId, true);
      if ([...this.operations.values()].filter(o => o.status === 'pending').length >= 20) throw new Error('Too many pending proposals. Ask the local user to review them.');
      const snap = await this.readSnapshot(args.rootId, args.path, true);
      if (snap.sha256 !== args.expectedHash) throw new Error('File changed or already exists. Read it again before proposing a write.');
      const operationId = randomUUID();
      const op = { ...args, before: snap.content ?? '', operationId, createdAt: Date.now(), status: 'pending' };
      this.operations.set(operationId, op);
      this.operationAccess.set(op, this.accessContext.getStore());
      await this.audit('proposed', { operationId, rootId: args.rootId, path: args.path });
      return { operationId, status: 'pending', message: 'Not written. Await local user approval, then call operation_status.' };
    } catch (error) {
      if (error.code) throw new Error(`Filesystem operation failed (${error.code}).`);
      throw error;
    }
  }
  async decide(id, approved) {
    if (typeof approved !== 'boolean') throw new Error('Local approval must be an explicit boolean.');
    this.prune();
    const op = this.operations.get(id);
    if (!op || op.status !== 'pending') throw new Error('Proposal is no longer pending.');
    op.status = approved === true ? 'applying' : 'rejected';
    if (!approved) { delete op.content; delete op.before; await this.audit('rejected', { operationId: id }); return this.status(id); }
    op.authorization = 'local-review';
    return this.#commit(op);
  }
  #commit(op) {
    // Serialize commits even when FileService is used without the HTTP controller.
    // Re-check the hash and current permission INSIDE the queue, not before it.
    const access = this.operationAccess.get(op);
    const result = this.commitTail.then(() => this.accessContext.run(access, () => this.#commitNow(op)));
    this.commitTail = result.catch(() => {});
    return result;
  }
  async #commitNow(op) {
    const id = op.operationId;
    const requiredPermission = op.authorization === 'directory-direct' ? 'direct' : true;
    let temporary;
    try {
      const { target } = await this.safePath(op.rootId, op.path, { writing: requiredPermission, mayCreate: true });
      const snap = await this.readSnapshot(op.rootId, op.path, true);
      if (snap.sha256 !== op.expectedHash) throw new Error('File changed after proposal; nothing was written.');
      if (requiredPermission === 'direct') await this.audit('direct-write-requested', { operationId: id, rootId: op.rootId, path: op.path });
      op.backupSaved = false;
      if (snap.bytes && this.stateDir) {
        const backupDir = path.join(this.stateDir, 'backups');
        await fs.mkdir(backupDir, { recursive: true });
        await fs.writeFile(path.join(backupDir, `${id}.before`), snap.bytes, { flag: 'wx', mode: 0o600 });
        op.backupSaved = true;
      }
      const bytes = Buffer.from(op.content, 'utf8');
      temporary = path.join(path.dirname(target), `.chat2local-${id}.tmp`);
      await fs.writeFile(temporary, bytes, { flag: 'wx', mode: 0o600 });
      await this.safePath(op.rootId, op.path, { writing: requiredPermission, mayCreate: true });
      const recheck = await this.readSnapshot(op.rootId, op.path, true);
      if (recheck.sha256 !== op.expectedHash) throw new Error('Concurrent file change detected; nothing was written.');
      this.policyRoot(op.rootId, requiredPermission);
      // For creation, link() is exclusive and cannot clobber a file created meanwhile.
      // A temporary-file cleanup failure after a successful commit is not a failed write.
      if (op.expectedHash === null) { await fs.link(temporary, target); }
      else {
        await fs.chmod(temporary, (await fs.stat(target)).mode);
        this.policyRoot(op.rootId, requiredPermission);
        await fs.rename(temporary, target); temporary = undefined;
      }
      op.sha256 = hash(bytes); op.status = requiredPermission === 'direct' ? 'written' : 'approved';
      try { await this.audit('written', { operationId: id, rootId: op.rootId, path: op.path, sha256: op.sha256, authorization: op.authorization }); }
      catch { op.message = 'File was written, but the audit log could not be saved. Check local storage.'; }
    } catch (error) { op.status = 'failed'; op.message = error.code ? `Filesystem operation failed (${error.code}).` : error.message; }
    finally { if (temporary) await fs.unlink(temporary).catch(() => {}); delete op.content; delete op.before; }
    return this.status(id);
  }
}
