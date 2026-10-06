import path from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { exactFields, isAccountId } from '../shared/connection-access.mjs';
import { directoryContains } from '../shared/share-tree.mjs';

const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const fail = (message, status = 409) => Object.assign(new Error(message), { status });
export function overlappingPaths(a, b) {
  const inside = (parent, child) => { const rel = path.relative(parent, child); return rel === '' || (rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel)); };
  return inside(a, b) || inside(b, a);
}
/** Revocation, not filesystem deletion. Preview freezes the exact affected
 * sharing entries (target and covering ancestors, NOT independent children). Confirmation removes
 * native access first and journals the same cloud request for retry. No write,
 * deletion, terminal launch, OAuth expansion or other-device mutation occurs.
 */
export class ShareRemoval {
  constructor(options) { Object.assign(this, options); this.previews = new Map(); this.working = new Map(); }
  policy() { const c = this.getConfig(); return hash([this.getIdentity()?.deviceId, c.roots, c.accountRoots || [], c.terminalGrants || [], c.accountPolicyRevision || 0]); }
  async preview(input) {
    exactFields(input, ['connectionId', 'rootId']);
    if (!isAccountId(input.connectionId) || !/^[a-f0-9-]{36}$/.test(input.rootId || '')) throw fail('请选择一个共享文件夹。', 400);
    const before = this.policy();
    const result = await this.management.connections();
    const connection = result.connections.find(c => c.connectionId === input.connectionId);
    const target = connection?.roots.find(r => r.rootId === input.rootId && r.locallyPresent && r.path);
    if (!target || !Number.isSafeInteger(connection.revision)) throw fail('请先更新连接服务，再移除共享。');
    const affected = connection.roots.filter(r => r.locallyPresent && r.path && directoryContains(r.path, target.path, process.platform));
    const retainedChildren = connection.roots.filter(r => r.locallyPresent && r.path && !affected.some(a => a.rootId === r.rootId) && directoryContains(target.path, r.path, process.platform));
    const localRoots = this.getConfig().roots;
    if (affected.some(root => localRoots.some(r => r.id === root.rootId) && result.connections.some(c => c.connectionId !== connection.connectionId && c.roots.some(r => r.rootId === root.rootId)))) throw fail('该目录也用于其他连接；请先核对其他连接，未更改权限。');
    if (before !== this.policy()) throw fail('目录权限刚发生变化，请重新核对。');
    for (const [id, entry] of this.previews) if (entry.until < Date.now()) this.previews.delete(id);
    if (this.previews.size >= 16) throw fail('待确认操作过多，请稍后再试。', 429);
    const requestId = randomBytes(16).toString('hex');
    const preview = { requestId, connectionId: connection.connectionId, expectedRevision: connection.revision, deviceId: this.getIdentity().deviceId, origin: this.getIdentity().origin, target: target.path, folders: affected.map(r => ({ rootId: r.rootId, path: r.path, label: r.label, mode: r.mode })), policy: before, until: Date.now() + 300000 };
    preview.snapshotDigest = hash(preview); this.previews.set(requestId, preview);
    return { requestId, snapshotDigest: preview.snapshotDigest, target: preview.target, folders: preview.folders, includesOverlaps: affected.length > 1, retainedChildren: retainedChildren.map(r => ({ rootId: r.rootId, path: r.path, label: r.label, mode: r.mode })), filesDeleted: false };
  }
  async execute(action, input = {}) {
    if (action === 'remove-prepare') return this.preview(input);
    if (action === 'removals') { exactFields(input, []); return this.flush(); }
    if (action !== 'remove-confirm') throw fail('Unknown removal action.', 404);
    exactFields(input, ['requestId', 'snapshotDigest', 'confirmation']);
    if (!isAccountId(input.requestId) || input.confirmation !== 'remove-shares-keep-files-v1') throw fail('请确认移除共享；磁盘文件保留。', 400);
    const pending = (this.getConfig().shareRemovals || []).find(r => r.requestId === input.requestId);
    if (!pending) {
      const p = this.previews.get(input.requestId);
      if (!p || p.snapshotDigest !== input.snapshotDigest || p.until < Date.now()) throw fail('确认已过期，请重新核对共享范围。');
      // Re-read the actual cloud connection before applying the reviewed native
      // snapshot. If another tab changed the scope, do not remove extra entries.
      const remote = await this.management.connections();
      const current = remote.connections.find(c => c.connectionId === p.connectionId);
      if (!current || current.revision !== p.expectedRevision) throw fail('连接范围已变化，请重新核对。');
      await this.serial(async () => {
        if ((this.getConfig().shareRemovals || []).some(r => r.requestId === p.requestId)) return;
        if (this.policy() !== p.policy || this.getIdentity()?.deviceId !== p.deviceId || this.getIdentity()?.origin !== p.origin) throw fail('本机权限已变化，未执行旧操作。');
        const config = this.getConfig();
        if ((config.shareRemovals || []).length >= 32) throw fail('有撤销待同步，请稍后再试。');
        const rootIds = p.folders.map(r => r.rootId);
        const record = { requestId: p.requestId, snapshotDigest: p.snapshotDigest, connectionId: p.connectionId, rootIds, expectedRevision: p.expectedRevision, origin: p.origin, deviceId: p.deviceId, folders: p.folders };
        await this.changePolicy({ ...config, roots: config.roots.filter(r => !rootIds.includes(r.id)), accountRoots: (config.accountRoots || []).filter(r => !(r.connectionId === p.connectionId && rootIds.includes(r.id))), terminalGrants: (config.terminalGrants || []).filter(g => !(g.connectionId === p.connectionId && rootIds.includes(g.rootId))), shareRemovals: [...(config.shareRemovals || []), record], managedConnections: [...(config.managedConnections || []).filter(c => c.connectionId !== p.connectionId), { connectionId: p.connectionId, deviceId: p.deviceId, origin: p.origin }] });
        await this.stopJobs(p.connectionId, rootIds);
      });
    } else if (pending.snapshotDigest !== input.snapshotDigest) throw fail('撤销请求不匹配。');
    return this.synchronize(input.requestId);
  }
  async synchronize(requestId) {
    if (this.working.has(requestId)) return this.working.get(requestId);
    const work = this.sync(requestId).finally(() => this.working.delete(requestId));
    this.working.set(requestId, work); return work;
  }
  async sync(requestId) {
    const saved = (this.getConfig().shareRemovals || []).find(r => r.requestId === requestId);
    if (!saved) return { requestId, localRevoked: true, cloudSynced: true, filesDeleted: false };
    if (this.getIdentity()?.deviceId !== saved.deviceId || this.getIdentity()?.origin !== saved.origin) return { requestId, localRevoked: true, cloudSynced: false, filesDeleted: false, error: '设备身份已变化，未向其他实例发送撤销。' };
    try {
      const result = await this.management.managementCall('remove', { requestId, connectionId: saved.connectionId, rootIds: saved.rootIds, expectedRevision: saved.expectedRevision });
      if (result.removed !== true || result.connectionId !== saved.connectionId || JSON.stringify(result.rootIds) !== JSON.stringify(saved.rootIds)) throw fail('撤销结果不匹配。');
      await this.serial(async () => { const config = this.getConfig(); await this.saveConfig({ ...config, shareRemovals: (config.shareRemovals || []).filter(r => r.requestId !== requestId) }); });
      return { requestId, localRevoked: true, cloudSynced: true, filesDeleted: false };
    } catch (error) { return { requestId, localRevoked: true, cloudSynced: false, filesDeleted: false, error: error.message }; }
  }
  async flush() {
    const pending = (this.getConfig().shareRemovals || []).slice(0, 4);
    for (const record of pending) await this.synchronize(record.requestId);
    return { pending: (this.getConfig().shareRemovals || []).map(r => ({ requestId: r.requestId, connectionId: r.connectionId, folders: r.folders })), filesDeleted: false };
  }
}
