import { AsyncLocalStorage } from 'node:async_hooks';
import { checkedAccess, permittedMode } from '../../shared/connection-access.mjs';
import { rootWriteMode } from '../permissions.mjs';

/** File permissions are the intersection of local policy and the relay grant. */
export class FileAccessPolicy {
  constructor(getPolicy, getDeviceInfo) {
    this.getPolicy = getPolicy;
    this.getDeviceInfo = getDeviceInfo;
    this.context = new AsyncLocalStorage();
  }

  run(envelope, action) {
    const access = envelope === undefined
      ? undefined
      : checkedAccess(envelope, this.getDeviceInfo()?.deviceId || '');
    return this.context.run(access, action);
  }

  availableRoots() {
    const policy = this.getPolicy();
    const access = this.context.getStore();
    // Keep legacy and per-connection roots separate, including after rollback.
    return access
      ? [...policy.roots, ...(policy.accountRoots || []).filter(root => root.connectionId === access.connectionId)]
      : policy.roots;
  }

  mode(root) {
    const access = this.context.getStore();
    if (!access) return rootWriteMode(root);
    return permittedMode(rootWriteMode(root), access.roots.find(item => item.rootId === root.id), access.scopes);
  }

  root(id, writing = false) {
    if (this.getPolicy().paused) throw new Error('Local access is paused.');
    const root = this.availableRoots().find(item => item.id === id);
    if (!root) throw new Error('Folder is not authorized.');
    const mode = this.mode(root);
    if (!mode) throw new Error('Folder is not shared with this connection.');
    if (writing && mode === 'read-only') {
      throw new Error('This folder is read-only. Enable write proposals locally first.');
    }
    if (writing === 'direct' && mode !== 'direct') {
      throw new Error('Direct writing is not authorized for this folder. Choose direct read/write once in the local folder permissions, or use propose_write for review.');
    }
    return root;
  }
}
