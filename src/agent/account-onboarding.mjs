import fs from 'node:fs/promises';
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { approveRoot } from './files.mjs';
import { rootPermission, rootWriteMode } from './permissions.mjs';
import { ConsentCoordinator } from './consent-coordinator.mjs';
import { relayOrigin, readLimited } from '../shared/protocol.mjs';
import { exactFields, isAccountId, isDigest, checkedShares, checkedScopes, permittedMode } from '../shared/connection-access.mjs';

const run = promisify(execFile), secret = () => randomBytes(32).toString('hex');
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const fail = (message, status = 400) => Object.assign(new Error(message), { status });
export async function pickAccountFolder(options, windowsPicker) {
  if (process.platform === 'win32') return windowsPicker(options);
  try {
    const result = process.platform === 'darwin'
      ? await run('osascript', ['-e', 'POSIX path of (choose folder with prompt "chat2local: select a folder. Sharing is confirmed on the next screen.")'], { signal: options.signal, timeout: 120000, maxBuffer: 16384 })
      : await run('zenity', ['--file-selection', '--directory', '--title=chat2local: select a folder'], { signal: options.signal, timeout: 120000, maxBuffer: 16384 });
    return result.stdout.trim() || null;
  } catch (error) {
    if ((process.platform === 'darwin' && /\(-128\)/.test(error.stderr || '')) || (process.platform === 'linux' && error.code === 1)) return null;
    throw fail('系统目录选择器未完成；没有授权文件夹。');
  }
}

/** Concrete native adapter: private encrypted journal, actual folder checks,
 * authenticated cloud requests, and atomic accountRoots commit in policy queue.
 * The browser receives no device key, OAuth token or general controller token.
 */
export class NativeAccountOnboarding {
  constructor({ store, getConfig, getIdentity, getRevision, expectedOrigin, prepareRegistration, acceptRegistration, deviceName = () => '这台电脑', saveConfig, serial, prepareNetwork, chooseFolder, request = fetch, allowLocal = false, profile = 'account', invitation = () => undefined }) {
    Object.assign(this, { store, getConfig, getIdentity, getRevision, expectedOrigin, prepareRegistration, acceptRegistration, deviceName, saveConfig, serial, prepareNetwork, chooseFolder, request, allowLocal });
    if (!['account','instance'].includes(profile)) throw new Error('Invalid native onboarding profile.');
    this.profile = profile; this.invitation = invitation; this.cloudPrefix = '/' + profile;
    this.sessions = new Map(); this.work = new Map(); this.ingress = new Map(); this.picking = false;
  }
  pageSession(request) {
    const now = Date.now();
    for (const [id, entry] of this.sessions) if (entry.until <= now) this.sessions.delete(id);
    const old = this.cookie(request.headers.cookie);
    if (old && this.sessions.has(old)) return old;
    if (this.sessions.size >= 32) throw fail('接入页面过多，请稍后再试。', 429);
    const id = secret(); this.sessions.set(id, { until: now + 86400000, flows: new Set() }); return id;
  }
  cookie(value) { const name = 'c2l_' + this.profile + '_local='; const items = String(value || '').split(';').map(x => x.trim()).filter(x => x.startsWith(name)); return items.length === 1 ? items[0].slice(name.length) : null; }
  session(nonce, cookies) {
    const cookie = this.cookie(cookies);
    if (!isDigest(nonce) || !isDigest(cookie) || !timingSafeEqual(Buffer.from(nonce), Buffer.from(cookie))) throw fail('请在发起接入的本机页面操作。', 403);
    const session = this.sessions.get(nonce);
    if (!session || session.until <= Date.now()) throw fail('本机接入页面已过期，请返回原连接入口。', 403);
    return session;
  }
  async call(action, local, input = {}, registrationIdentity) {
    const identity = registrationIdentity || this.getIdentity();
    if (!identity || local.origin !== identity.origin || local.deviceId !== identity.deviceId) throw fail('本机设备身份已变化，没有继续旧授权。', 409);
    await this.prepareNetwork(identity.origin);
    let response;
    try { response = await this.request(`${identity.origin}${this.cloudPrefix}/native/${action}`, { method: 'POST', headers: { Authorization: `Bearer ${identity.deviceKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ flowId: local.flowId, deviceId: identity.deviceId, secret: ['start','enroll'].includes(action) ? local.bootstrap : local.sessionSecret, input, ...(this.profile === 'instance' && ['start','enroll'].includes(action) && local.invitation ? { invitation: local.invitation } : {}) }), redirect: 'error', signal: AbortSignal.timeout(15000) }); }
    catch { throw fail('网络尚未确认当前接入结果；保留同一次请求，不重建设备或目录授权。', 503); }
    const result = JSON.parse(await readLimited(response, 32 * 1024));
    if (!response.ok) throw fail(result.error || '账号服务未完成当前步骤。', response.status);
    return result;
  }
  current(local) {
    const config = this.getConfig(), identity = this.getIdentity();
    if (config.paused || identity?.deviceId !== local.deviceId || identity?.origin !== local.origin || this.getRevision() !== local.revision) throw fail('本机访问已暂停或授权条件已改变，没有继续接入。', 409);
    return config;
  }
  policy(local, config = this.current(local)) {
    return hash({ deviceId: local.deviceId, origin: local.origin, paused: config.paused, roots: config.roots, accountRoots: (config.accountRoots || []).filter(r => r.intentId !== local.flowId), selection: local.reusedRoots || local.selections || local.selection });
  }
  async assertCurrent(local, intent) {
    if (intent.intentId !== local.flowId || intent.policyDigest !== local.policyDigest || this.policy(local) !== local.policyDigest) throw fail('所选目录或权限发生变化，没有沿用旧确认。', 409);
    for (const selection of local.reusedRoots || local.selections || [local.selection]) {
      const root = await approveRoot(selection.path, this.store.directory, selection.write);
      const stat = await fs.stat(root.path, { bigint: true });
      if (root.path !== selection.path || String(stat.dev) !== selection.dev || String(stat.ino) !== selection.ino) throw fail('目录位置已变化，没有沿用旧授权。', 409);
    }
  }
  async stageSelection(local) {
    const roots = checkedShares((local.reusedRoots || local.selections || [local.selection]).map(root => ({ rootId: root.id, mode: root.writeMode })));
    const intent = await this.call('prepare', local, { roots, policyDigest: local.policyDigest });
    if (intent.accountId !== local.context.accountId || intent.clientId !== local.context.clientId || intent.deviceId !== local.deviceId || intent.requestDigest !== local.context.requestDigest || intent.resource !== local.context.resource || intent.deviceEpoch !== local.context.deviceEpoch || intent.policyDigest !== local.policyDigest || (local.context.connectionId && intent.connectionId !== local.context.connectionId) || JSON.stringify(checkedScopes(intent.scopes)) !== JSON.stringify(checkedScopes(local.context.scopes)) || JSON.stringify(checkedShares(intent.roots)) !== JSON.stringify(roots)) throw fail('待确认范围与已有设备、目录或请求应用不一致。', 403);
    await this.coordinator(local).stage(intent);
  }
  async prepareExisting(local) {
    if (this.profile !== 'instance' || local.context.reuseExisting !== true) return;
    if (await this.store.readPrivateRecord('onboarding-intent-' + local.flowId)) return;
    if (!local.reusedRoots) await this.serial(async () => {
      const config = this.current(local);
      const allowed = local.context.recoveryRoots === null ? null : checkedShares(local.context.recoveryRoots);
      const candidates = allowed
        ? [...config.roots, ...(config.accountRoots || []).filter(r => r.connectionId === local.context.connectionId)].filter(r => allowed.some(a => a.rootId === r.id))
        : config.roots;
      if (!candidates.length) throw fail('本机没有可沿用的已授权目录。不会自动添加其他目录。', 409);
      const selected = [];
      for (const existing of candidates) {
        const mode = permittedMode(rootWriteMode(existing), allowed?.find(r => r.rootId === existing.id) || { mode: rootWriteMode(existing) }, local.context.scopes);
        if (!mode) throw fail('原目录权限与此次请求不匹配。', 403);
        const checked = await approveRoot(existing.path, this.store.directory, mode !== 'read-only');
        const stat = await fs.stat(checked.path, { bigint: true });
        selected.push({ id: existing.id, path: existing.path, label: existing.label, ...rootPermission(mode), dev: String(stat.dev), ino: String(stat.ino) });
      }
      local.reusedRoots = selected; local.policyDigest = this.policy(local);
      await this.store.savePrivateRecord('onboarding-flow-' + local.flowId, local);
    });
    await this.stageSelection(local); // Preparation only: never confirms or grants.
  }
  coordinator(local) {
    const journal = { load: id => this.store.readPrivateRecord('onboarding-intent-' + id), save: (id, record) => this.store.savePrivateRecord('onboarding-intent-' + id, record) };
    return new ConsentCoordinator({ journal, cloud: {
      status: () => this.call('status', local),
      confirm: (_id, snapshotDigest) => this.call('confirm', local, { snapshotDigest }),
      activate: (_id, snapshotDigest) => this.call('activate', local, { snapshotDigest }),
    }, local: {
      assertCurrent: intent => this.serial(() => this.assertCurrent(local, intent)),
      consentProof: intent => this.serial(async () => { await this.assertCurrent(local, intent); const journal = await this.store.readPrivateRecord('onboarding-intent-' + local.flowId); if (!journal?.userConfirmed) throw fail('No saved user confirmation.', 403); return 'authenticated-native-flow'; }),
      activate: intent => this.serial(async () => {
        await this.assertCurrent(local, intent);
        const journal = await this.store.readPrivateRecord('onboarding-intent-' + local.flowId);
        if (!journal?.userConfirmed || journal.intent.snapshotDigest !== intent.snapshotDigest) throw fail('本机确认未持久化，没有激活目录。', 403);
        // Recovery keeps the original root IDs, paths and local modes. The exact
        // existing policy and ONE saved consent have just been rechecked above.
        // Do not duplicate roots, move them, or promote their permissions.
        if (local.reusedRoots) return 'retained-local-policy-after-explicit-consent';
        const config = this.current(local);
        const roots = (local.selections || [local.selection]).map(selection => ({ id: selection.id, path: selection.path, label: selection.label, ...rootPermission(selection.writeMode), accountId: intent.accountId, connectionId: intent.connectionId, intentId: local.flowId }));
        const saved = config.accountRoots || [];
        for (const root of roots) {
          const existing = saved.find(r => r.id === root.id);
          if (existing && JSON.stringify(existing) !== JSON.stringify(root)) throw fail('同一目录授权已改变，不会覆盖。', 409);
        }
        const additions = roots.filter(root => !saved.some(r => r.id === root.id));
        if (saved.length + additions.length > 100) throw fail('已达到共享目录数量限制。', 429);
        if (additions.length) await this.saveConfig({ ...config, accountRoots: [...saved, ...additions] });
        // Authenticated activation message is sent only AFTER the durable local save.
        return 'durably-activated-native-flow';
      }),
    } });
  }
  async view(local) {
    const record = await this.store.readPrivateRecord('onboarding-intent-' + local.flowId);
    const status = record ? this.coordinator(local).view(record) : { requiresConsent: false, connected: false, phase: 'choose-folder', confirmationCount: 0 };
    return { terminalRequested: local.context?.scopes.includes('terminal:execute') === true, flowId: local.flowId, displayName: local.context?.displayName, clientName: local.context?.clientName, callbackOrigin: local.context?.callbackOrigin, deviceName: local.deviceName, reuseExisting: Boolean(local.reusedRoots), selections: (local.reusedRoots || local.selections)?.map(r => ({ label: r.label, path: r.path, mode: r.writeMode })), selection: local.selection ? { label: local.selection.label, path: local.selection.path, mode: local.selection.writeMode } : null, snapshotDigest: record?.intent.snapshotDigest || null, ...status, finishUrl: status.connected ? `${local.origin}${this.cloudPrefix}/finish?flow=${local.flowId}` : null };
  }
  async handle(action, input, cookies) {
    if (!['start','choose'].includes(action)) return this.perform(action, input, cookies);
    this.session(input?.nonce, cookies);
    const target = action === 'start' ? input.flow : input.flowId;
    if (typeof target !== 'string' || target.length > 100) throw fail('Invalid onboarding target.');
    // Serialize the same flow across tabs before creating its native secret.
    // A second tab must not overwrite a persisted in-flight session.
    const key = action + ':' + target;
    if (this.ingress.has(key)) {
      const pending = this.ingress.get(key);
      if (pending.nonce !== input.nonce) throw fail('另一个本机页面正在准备此连接，请等待完成后再恢复。', 409);
      return pending.work;
    }
    if (this.ingress.size >= 16) throw fail('接入请求正在处理中，请稍候。', 429);
    const work = this.perform(action, input, cookies).finally(() => this.ingress.delete(key));
    this.ingress.set(key, { nonce: input.nonce, work }); return work;
  }
  async perform(action, input, cookies) {
    exactFields(input, action === 'start' ? ['nonce','origin','flow'] : action === 'confirm' ? ['nonce','flowId','snapshotDigest','confirmation'] : ['nonce','flowId']);
    const session = this.session(input.nonce, cookies);
    if (!['start','choose','status','confirm','resume'].includes(action)) throw fail('Unknown account action.', 404);
    if (action === 'start') {
      let identity = this.getIdentity();
      const origin = relayOrigin(input.origin, this.allowLocal);
      const trusted = identity?.origin || this.expectedOrigin?.();
      if (this.getConfig().paused || origin !== trusted || !/^[a-f0-9]{32}\.[a-f0-9]{64}$/.test(input.flow || '')) throw fail('账号接入链接与本机服务不匹配，或访问已暂停。', 403);
      if (!identity) {
        if (!this.prepareRegistration || !this.acceptRegistration) throw fail('本机未配置账号登记入口。没有使用另一台电脑的身份。', 503);
        identity = await this.serial(() => this.prepareRegistration(origin));
      }
      const [flowId, bootstrap] = input.flow.split('.');
      let local = await this.store.readPrivateRecord('onboarding-flow-' + flowId);
      if (local && ((local.profile || 'account') !== this.profile || local.origin !== origin || local.deviceId !== identity.deviceId || local.bootstrap !== bootstrap || Date.now() > local.until)) throw fail('旧接入请求不能替换账号或设备。', 409);
      if (!local) {
        local = { flowId, bootstrap, origin, profile: this.profile, ...(this.profile === 'instance' && this.invitation() ? { invitation: this.invitation() } : {}), deviceId: identity.deviceId, deviceName: this.deviceName(), sessionSecret: secret(), revision: this.getRevision(), until: Date.now() + 86400000 };
        // Persist before requesting a native session; lost responses reuse this identity.
        await this.store.savePrivateRecord('onboarding-flow-' + flowId, local);
      }
      if (!this.getIdentity()) {
        const provisioned = await this.call('enroll', local, { sessionSecret: local.sessionSecret }, identity);
        if (provisioned.enrolled !== true || provisioned.deviceId !== local.deviceId) throw fail('新设备登记结果不匹配，没有授予文件权限。', 409);
        await this.serial(() => this.acceptRegistration(identity));
      }
      this.current(local);
      if (!local.context) {
        const retained = this.getConfig();
        local.context = await this.call('start', local, { sessionSecret: local.sessionSecret, ...(this.profile === 'instance' && (retained.roots.length || retained.accountRoots?.length) ? { reuseExisting: true } : {}) });
        if (local.context.flowId !== flowId || local.context.deviceId !== local.deviceId || local.context.resource !== origin + '/mcp' || !isAccountId(local.context.accountId) || !isDigest(local.context.deviceEpoch)) throw fail('账号服务响应不匹配。', 403);
        checkedScopes(local.context.scopes);
        await this.store.savePrivateRecord('onboarding-flow-' + flowId, local);
      }
      await this.prepareExisting(local);
      session.flows.add(flowId); return this.view(local);
    }
    if (!isAccountId(input.flowId) || !session.flows.has(input.flowId)) throw fail('当前浏览器未发起此接入。', 403);
    const local = await this.store.readPrivateRecord('onboarding-flow-' + input.flowId);
    if (!local || (local.profile || 'account') !== this.profile || Date.now() > local.until) throw fail('接入请求已过期或不属于此接入方式。', 409);
    this.current(local);
    if (action === 'status') return this.view(local);
    if (this.work.has(local.flowId)) {
      if (action === 'confirm' && input.snapshotDigest !== this.work.get(local.flowId).digest) throw fail('另一个确认正在处理。', 409);
      return this.work.get(local.flowId).promise;
    }
    if (action === 'choose') {
      const previous = await this.store.readPrivateRecord('onboarding-intent-' + local.flowId);
      if (previous) return this.view(local); // Never silently change a staged selection.
      if (this.picking) throw fail('目录选择器已经打开。', 409);
      this.picking = true;
      try {
        if (!local.selection) {
          const selected = await this.chooseFolder(); if (!selected) return this.view(local);
          this.current(local);
          const mode = local.context.scopes.includes('files:write') ? 'direct' : 'read-only';
          const checked = await approveRoot(selected, this.store.directory, mode === 'direct');
          const stat = await fs.stat(checked.path, { bigint: true });
          local.selection = { ...checked, ...rootPermission(mode), dev: String(stat.dev), ino: String(stat.ino) };
          local.policyDigest = this.policy(local);
          await this.store.savePrivateRecord('onboarding-flow-' + local.flowId, local);
        }
        await this.stageSelection(local); return this.view(local);
      } finally { this.picking = false; }
    }
    const coordinator = this.coordinator(local);
    const promise = (async () => {
      if (action === 'confirm') await coordinator.confirm(local.flowId, { snapshotDigest: input.snapshotDigest, confirmation: input.confirmation });
      else await coordinator.resume(local.flowId);
      return this.view(local);
    })().finally(() => this.work.delete(local.flowId));
    this.work.set(local.flowId, { digest: input.snapshotDigest || null, promise }); return promise;
  }
}
