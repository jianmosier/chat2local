import fs from 'node:fs/promises';
import { randomBytes, createHash } from 'node:crypto';
import { NativeAccountOnboarding } from './account-onboarding.mjs';
import { approveRoot } from './files.mjs';
import { rootPermission, validateWriteMode } from './permissions.mjs';
import { exactFields, isAccountId, checkedScopes } from '../shared/connection-access.mjs';
import { readLimited } from '../shared/protocol.mjs';
import { annotateCoverage } from '../shared/share-tree.mjs';
import { terminalPermission } from '../shared/terminal-permission.mjs';

const fail = (message, status = 409) => Object.assign(new Error(message), { status });
const digest = input => createHash('sha256').update(JSON.stringify(input)).digest('hex');

/** Local-control-only adapter. The HTTP controller checks its secret and Origin
 * before invoking this class. No public MCP file tool can invoke management.
 * Reuses the same persisted one-consent coordinator as initial pairing.
 */
export class FolderManagement extends NativeAccountOnboarding {
  constructor(options) { super({ ...options, profile: 'instance' }); this.managementWork = new Map(); }
  async managementCall(action, input = {}) {
    const identity = this.getIdentity();
    if (!identity || (this.getConfig().paused && !['remove','connections'].includes(action))) throw fail('请先恢复这台电脑的原连接；没有开放新目录。');
    await this.prepareNetwork(identity.origin);
    let response;
    try { response = await this.request(`${identity.origin}/instance/manage/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${identity.deviceKey}` }, body: JSON.stringify({ deviceId: identity.deviceId, input }), redirect: 'error', signal: AbortSignal.timeout(15000) }); }
    catch { throw fail('暂时无法确认目录管理结果。保留原请求，不重复授权。', 503); }
    const value = JSON.parse(await readLimited(response, 32768));
    if (!response.ok) throw fail(value.error || '目录管理暂不可用。', response.status);
    return value;
  }
  async connections() {
    const value = await this.managementCall('connections');
    const config = this.getConfig();
    if (!Array.isArray(value.connections) || value.connections.length > 20) throw fail('连接列表不匹配。');
    // A remote entry alone cannot create a new local trust relationship.
    return { connections: value.connections.filter(c => isAccountId(c.connectionId) && Array.isArray(c.roots) && (c.roots.some(s => [...config.roots, ...(config.accountRoots || []).filter(r => r.connectionId === c.connectionId)].some(r => r.id === s.rootId)) || (config.managedConnections || []).some(m => m.connectionId === c.connectionId && m.deviceId === this.getIdentity()?.deviceId && m.origin === this.getIdentity()?.origin))).map(c => ({ ...c, roots: c.roots.map(s => {
      const local = [...config.roots, ...(config.accountRoots || [])].find(r => r.id === s.rootId);
      return { ...s, path: local?.path || null, label: local?.label || null, locallyPresent: Boolean(local), ...terminalPermission({ grants: config.terminalGrants || [], connectionId: c.connectionId, rootId: s.rootId, resource: this.getIdentity().origin + '/mcp', scopes: c.scopes, mode: s.mode, available: Boolean(local) }) };
    }) })).map(c => ({ ...c, roots: annotateCoverage(c.roots, process.platform) })) };
  }
  async execute(action, input) {
    if (action === 'connections') { exactFields(input, []); return this.connections(); }
    exactFields(input, action === 'prepare' ? ['requestId', 'connectionId', 'folders', 'accessProfile'] : action === 'confirm' ? ['requestId', 'snapshotDigest', 'confirmation'] : ['requestId']);
    if (!['prepare', 'confirm', 'status', 'resume'].includes(action) || !isAccountId(input.requestId)) throw fail('目录管理请求无效。', 400);
    if (action === 'status') return this.inspect(input.requestId);
    const previous = this.managementWork.get(input.requestId);
    const fingerprint = digest([action, input]);
    if (previous) {
      if (previous.fingerprint !== fingerprint) throw fail('同一请求正在处理其他操作，请稍后核对。');
      return previous.promise;
    }
    if (this.managementWork.size >= 8) throw fail('目录管理繁忙，请稍后再试。', 429);
    const promise = this.performManagement(action, input).finally(() => this.managementWork.delete(input.requestId));
    this.managementWork.set(input.requestId, { fingerprint, promise }); return promise;
  }
  async loadManagement(requestId) {
    const local = await this.store.readPrivateRecord('onboarding-flow-' + requestId);
    if (!local?.management || local.profile !== 'instance' || local.until <= Date.now()) throw fail('目录变更请求已过期或不存在。');
    this.current(local); return local;
  }
  async inspect(requestId) {
    const local = await this.loadManagement(requestId);
    const view = await this.view(local);
    return { ...view, finishUrl: null, management: true, connectionId: local.context?.connectionId || null, selection: null, unchangedFoldersRetained: true };
  }
  async performManagement(action, input) {
    if (action !== 'prepare') {
      const local = await this.loadManagement(input.requestId);
      if (action === 'confirm') {
        const expected = local.accessProfile === 'project' ? 'allow-project-files-and-terminal-v1' : 'allow-shared-folders-v1';
        if (input.confirmation !== expected) throw fail('请确认本次显示的共享权限。', 403);
        await this.coordinator(local).confirm(local.flowId, { snapshotDigest: input.snapshotDigest, confirmation: 'allow-shared-folders-v1' });
      }
      else await this.coordinator(local).resume(local.flowId);
      return this.inspect(local.flowId);
    }
    if (!isAccountId(input.connectionId) || !Array.isArray(input.folders) || input.folders.length < 1 || input.folders.length > 20) throw fail('请选择 1–20 个具体文件夹。', 400);
    if (input.accessProfile !== undefined && input.accessProfile !== 'project') throw fail('共享类型无效。', 400);
    if (input.accessProfile === 'project' && input.folders.some(f => f.mode !== 'direct')) throw fail('完整共享需要文件读写权限。', 400);
    for (const folder of input.folders) {
      exactFields(folder, ['path', 'mode']);
      if (typeof folder.path !== 'string' || folder.path.length > 4096) throw fail('文件夹路径无效。', 400);
      validateWriteMode(folder.mode);
    }
    const requestDigest = digest(input);
    let local = await this.store.readPrivateRecord('onboarding-flow-' + input.requestId);
    if (local) {
      if (!local.management || local.managementRequestDigest !== requestDigest) throw fail('同一请求不能更换电脑、目录或权限。');
      this.current(local);
    } else {
      const choices = await this.connections();
      const selected = choices.connections.find(c => c.connectionId === input.connectionId);
      if (!selected) throw fail('请选择这台电脑已经使用的连接。', 403);
      const scopes = checkedScopes(selected.scopes);
      const identity = this.getIdentity();
      local = await this.serial(async () => {
        const config = this.getConfig();
        if (config.paused || this.getIdentity()?.deviceId !== identity.deviceId) throw fail('本机状态发生变化，未继续授权。');
        const selections = [], seen = new Set();
        for (const folder of input.folders) {
          if ((folder.mode === 'direct' && !scopes.includes('files:write')) || (folder.mode === 'review' && !scopes.includes('files:propose'))) throw fail('原连接没有请求的操作权限。', 403);
          const checked = await approveRoot(folder.path, this.store.directory, folder.mode !== 'read-only');
          if (seen.has(checked.path)) continue;
          seen.add(checked.path);
          if (selected.roots.some(r => r.path === checked.path && r.locallyPresent)) throw fail('此文件夹已共享；先从本次新增列表移除它，原权限保持不变。');
          const stat = await fs.stat(checked.path, { bigint: true });
          selections.push({ ...checked, ...rootPermission(folder.mode), dev: String(stat.dev), ino: String(stat.ino) });
        }
        const local = { profile: 'instance', management: true, ...(input.accessProfile === 'project' ? { accessProfile: 'project' } : {}), managementRequestDigest: requestDigest, flowId: input.requestId, origin: identity.origin, deviceId: identity.deviceId, deviceName: this.deviceName(), sessionSecret: randomBytes(32).toString('hex'), revision: this.getRevision(), until: Date.now() + 86400000, selections };
        local.policyDigest = this.policy(local);
        await this.store.savePrivateRecord('onboarding-flow-' + local.flowId, local);
        return local;
      });
    }
    if (!local.context) {
      local.context = await this.managementCall('start', { flowId: local.flowId, connectionId: input.connectionId, sessionSecret: local.sessionSecret });
      if (local.context.management !== true || local.context.flowId !== local.flowId || local.context.deviceId !== local.deviceId || local.context.resource !== local.origin + '/mcp' || local.context.connectionId !== input.connectionId) throw fail('目录管理响应不匹配。', 403);
      await this.store.savePrivateRecord('onboarding-flow-' + local.flowId, local);
    }
    if (!await this.store.readPrivateRecord('onboarding-intent-' + local.flowId)) await this.stageSelection(local);
    return this.inspect(local.flowId);
  }
}
