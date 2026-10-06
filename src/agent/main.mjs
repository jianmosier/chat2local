import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { Store, pickFolder, openBrowser, setStartup, startupAvailable } from './store.mjs';
import { platformInfo, sameDirectory } from './platform.mjs';
import { FileService, approveRoot } from './files.mjs';
import { rootWriteMode, rootPermission, validateWriteMode } from './permissions.mjs';
import { Bridge } from './bridge.mjs';
import { SetupManager } from './setup.mjs';
import { FolderPicker } from './folder-picker.mjs';
import { BrowserRecovery, recoveryNavigation, recoveryPage, recoveryScript } from './browser-recovery.mjs';
import { NativeAccountOnboarding, pickAccountFolder } from './account-onboarding.mjs';
import { FolderManagement } from './folder-management.mjs';
import { TerminalService, TERMINAL_CONFIRMATION } from './terminal.mjs';
import { authorizationReturn } from '../shared/authorization-navigation.mjs';
import { parseInstanceInvitation } from '../shared/instance-invitation.mjs';
import { browseFolders } from './folder-browser.mjs';
import { newGuide, guideView, observeGuide } from './connection-guide.mjs';
import { ToolReadiness } from '../shared/tool-capabilities.mjs';
import { NetworkManager, networkSettings, localNetworkOnly } from './network.mjs';
import { VERSION, MAX_WIRE_BYTES, handleMcp, relayOrigin } from '../shared/protocol.mjs';

const entryFile = fileURLToPath(import.meta.url);
const uiDir = path.join(path.dirname(entryFile), 'ui');
export const DEFAULT_PORT = 47631;
const assets = new Map([['/folders', ['folders.html', 'text/html']], ['/folders.js', ['folders.js', 'text/javascript']], ['/folders.css', ['folders.css', 'text/css']], ['/', ['connect.html', 'text/html']], ['/connect.js', ['connect.js', 'text/javascript']], ['/connect.css', ['connect.css', 'text/css']], ['/manage', ['home.html', 'text/html']], ['/developer', ['index.html', 'text/html']], ['/home.js', ['home.js', 'text/javascript']], ['/home.css', ['home.css', 'text/css']], ['/app.js', ['app.js', 'text/javascript']], ['/style.css', ['style.css', 'text/css']], ['/onboarding.js', ['onboarding.js', 'text/javascript']], ['/self-host.html', ['self-host.html', 'text/html']]]);
const securityHeaders = {
  'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
};
function failure(status, message) { return Object.assign(new Error(message), { status }); }
function matchesSecret(candidate, expected) {
  return typeof candidate === 'string' && /^[a-f0-9]{64}$/.test(candidate) && timingSafeEqual(Buffer.from(candidate), Buffer.from(expected));
}
function fields(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !names.includes(key))) throw failure(400, 'Invalid request fields.');
}
function boolean(value) { if (typeof value !== 'boolean') throw failure(400, 'An explicit boolean is required.'); return value; }
function identifier(value) { if (typeof value !== 'string' || !/^[a-f0-9-]{36}$/.test(value)) throw failure(400, 'Invalid identifier.'); return value; }
function selectedPermission(value) {
  if (Object.hasOwn(value, 'writeMode') && Object.hasOwn(value, 'write')) throw failure(400, 'Ambiguous folder permission.');
  const mode = Object.hasOwn(value, 'writeMode') ? validateWriteMode(value.writeMode) : (boolean(value.write) ? 'review' : 'read-only');
  if (value.confirmDirect !== undefined) boolean(value.confirmDirect);
  if (mode === 'direct' && value.confirmDirect !== true) throw failure(400, '请明确确认：此目录允许直接创建和修改文件，不再逐次要求本机审批。');
  return rootPermission(mode);
}
async function bodyJson(request) {
  if (request.headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/json') throw failure(415, 'application/json is required.');
  if (Number(request.headers['content-length']) > MAX_WIRE_BYTES) throw failure(413, 'Request too large.');
  const chunks = []; let size = 0;
  for await (const chunk of request) { size += chunk.length; if (size > MAX_WIRE_BYTES) throw failure(413, 'Request too large.'); chunks.push(chunk); }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
  catch { throw failure(400, 'Invalid JSON.'); }
}

/** Authenticated loopback control plane. No folder is authorized by default. */
export async function startController(options = {}) {
  const store = options.store ?? new Store(options.stateDir);
  const loaded = await store.load();
  let config = loaded.config;
  let secrets = loaded.secrets;
  if (config.roots.length > 50 || config.roots.some(root => !root || typeof root.id !== 'string' || typeof root.path !== 'string' || typeof root.write !== 'boolean')) throw new Error('Invalid saved directory permissions.');
  if (config.accountRoots !== undefined && (!Array.isArray(config.accountRoots) || config.accountRoots.length > 100)) throw new Error('Invalid account-scoped directory policy.');
  const allRoots = [...config.roots, ...(config.accountRoots || [])];
  if (new Set(allRoots.map(root => root?.id)).size !== allRoots.length) throw new Error('Duplicate directory identity across legacy/account policies.');
  for (const root of allRoots) {
    if (!root || typeof root.id !== 'string' || typeof root.path !== 'string' || typeof root.write !== 'boolean') throw new Error('Invalid directory permission.');
    rootWriteMode(root); // Invalid persisted policy fails closed; legacy true remains review.
  }
  if (!config.installationId) { config = { ...config, installationId: randomUUID() }; await store.saveConfig(config); }
  const deviceInfo = () => ({ ...platformInfo(), installationId: config.installationId, deviceId: secrets.identity?.deviceId || null });
  const existingRoot = async candidate => {
    for (const root of config.roots) {
      try { if (await sameDirectory(root.path, candidate)) return root; }
      catch (error) { if (!['ENOENT', 'ENOTDIR'].includes(error.code)) throw error; }
    }
    return undefined;
  };
  const token = randomBytes(32).toString('hex');
  const instanceId = randomUUID();
  let closing = false; let queued = 0; let tail = Promise.resolve();
  let lastRemoteCallAt = null; let closeController; let selectionRevision = 0; let browsing = 0; let guideWarning = null;
  const picker = new FolderPicker(options.pickFolder ?? (args => pickAccountFolder(args, pickFolder)), options.pickerTimeoutMs ?? 120000);
  const recovery = new BrowserRecovery();
  const recoveryBinding = () => JSON.stringify([secrets.identity?.deviceId, secrets.identity?.origin, config.paused, config.roots.map(root => [root.id, root.path, rootWriteMode(root)]), selectionRevision]);
  // Local decisions and bridge operations share a queue: revocation never races a queued approval.
  const serial = action => {
    if (closing || queued >= 24) return Promise.reject(failure(503, 'Local controller is busy or closing.'));
    queued++;
    const result = tail.then(action);
    tail = result.catch(() => {}).finally(() => { queued--; });
    return result;
  };
  const readiness = new ToolReadiness();
  const files = new FileService(() => config, store.directory, deviceInfo);
  const terminal = new TerminalService({ getConfig: () => config, getDevice: deviceInfo, store });
  const network = options.network ?? new NetworkManager(() => config.network, { allowLocal: options.allowLocalRelay === true, ...options.networkOptions });
  const bridge = options.bridge ?? new Bridge((name, args, connectionDiagnostics, connectionAccess) => serial(async () => {
    // Metadata is received only in the authenticated relay envelope, never from
    // file contents, tool arguments, a local test, or a UI success checkbox.
    readiness.observeRemote(connectionDiagnostics, secrets.identity, name);
    if (connectionAccess !== undefined && connectionAccess?.resource !== `${secrets.identity?.origin}/mcp`) throw new Error('Connection access belongs to a different relay.');
    const result = name.startsWith('terminal_') ? await terminal.invoke(name, args, connectionAccess) : await files.invoke(name, args, connectionAccess);
    if (name === 'list_roots' && Array.isArray(result)) for (const root of result) {
      const enabled = Boolean(connectionAccess && connectionAccess.scopes.includes('terminal:execute') && root.writeMode === 'direct' && (config.terminalGrants || []).some(g => g.enabled && g.rootId === root.id && g.connectionId === connectionAccess.connectionId && g.resource === connectionAccess.resource));
      root.terminalAllowed = enabled; root.terminalSandboxed = false;
    }
    lastRemoteCallAt = new Date().toISOString();
    const root = config.roots.find(item => item.id === config.connectionGuide?.rootId);
    const nextGuide = root && rootWriteMode(root) === 'direct'
      ? observeGuide(config.connectionGuide, name, args, result, secrets.identity) : config.connectionGuide;
    if (!config.remoteUseConfirmed || nextGuide !== config.connectionGuide) {
      try {
        await saveConfig({ ...config, remoteUseConfirmed: true, ...(nextGuide ? { connectionGuide: nextGuide } : {}) });
        guideWarning = null;
      } catch {
        // A completed file operation stays successful even if progress cannot be persisted.
        guideWarning = '远端操作已返回，但接入进度未能保存。请读回核对，不要盲目重复写入。';
      }
    }
    return result;
  }), { allowLocal: options.allowLocalRelay === true, prepareNetwork: origin => network.prepare(origin), connectionAccess: true, terminal: true });
  const saveConfig = async next => { await store.saveConfig(next); config = next; };
  const changePolicy = async next => {
    next = { ...next, accountPolicyRevision: (config.accountPolicyRevision || 0) + 1 };
    files.cancelPending();
    const selected = config.connectionGuide?.rootId;
    if (selected) {
      const before = config.roots.find(root => root.id === selected);
      const after = next.roots.find(root => root.id === selected);
      if (!after || !before || rootWriteMode(after) !== rootWriteMode(before)) {
        next = { ...next }; delete next.connectionGuide;
      }
    }
    await saveConfig(next);
  };
  const setup = new SetupManager({
    identity: () => secrets.identity, pending: () => secrets.enrollmentPending,
    defaultRelay: options.defaultRelay, allowLocal: options.allowLocalRelay,
    prepareNetwork: origin => network.prepare(origin), fetch: options.setupFetch,
    bridge, openBrowser: options.openBrowser ?? openBrowser,
    // Network setup runs outside the policy queue; only these short commits join
    // it, checking cancellation after earlier pause/disconnect actions complete.
    savePending: (identity, signal) => serial(async () => { signal.throwIfAborted(); const next = { ...secrets, enrollmentPending: identity }; await store.saveSecrets(next); secrets = next; }),
    acceptIdentity: (identity, signal) => serial(async () => { signal.throwIfAborted(); const next = { ...secrets, identity }; delete next.enrollmentPending; await store.saveSecrets(next); secrets = next; await saveConfig({ ...config, relay: identity.origin }); }),
  });
  const nativeOrigin = profile => secrets.identity?.origin || (profile === 'instance' ? secrets.privateInstanceInvitation?.origin : null) || setup.origin();
  const createNativeOnboarding = profile => new NativeAccountOnboarding({
    profile, invitation: () => secrets.privateInstanceInvitation?.invitation,
    store, getConfig: () => config, getIdentity: () => secrets.identity, getRevision: () => config.accountPolicyRevision || 0,
    expectedOrigin: () => nativeOrigin(profile),
    prepareRegistration: async origin => {
      if (config.paused || origin !== nativeOrigin(profile)) throw failure(409, '设备登记条件已改变。');
      if (secrets.identity) return secrets.identity;
      const pending = secrets.accountEnrollmentPending;
      if (pending && pending.origin !== origin) throw failure(409, '另一个账号登记尚未完成，没有覆盖本机身份。');
      if (pending) return pending;
      const identity = { origin, deviceId: randomUUID().replaceAll('-', ''), deviceKey: randomBytes(32).toString('hex') };
      const next = { ...secrets, accountEnrollmentPending: identity };
      await store.saveSecrets(next); secrets = next; return identity;
    },
    acceptRegistration: async identity => {
      if (config.paused || identity.origin !== nativeOrigin(profile)) throw failure(409, '本机访问已暂停或登记目标改变。');
      const saved = secrets.identity || secrets.accountEnrollmentPending;
      if (!saved || saved.origin !== identity.origin || saved.deviceId !== identity.deviceId || saved.deviceKey !== identity.deviceKey) throw failure(409, '登记期间本机身份已改变。');
      const next = { ...secrets, identity }; delete next.accountEnrollmentPending;
      await store.saveSecrets(next); secrets = next;
      await saveConfig({ ...config, relay: identity.origin });
      bridge.start(identity);
    },
    deviceName: () => deviceInfo().name, allowLocal: options.allowLocalRelay === true, saveConfig, serial, prepareNetwork: origin => network.prepare(origin),
    chooseFolder: async () => { const selection = await picker.run(); return selection.cancelled ? null : selection.path; },
    ...(options.accountFetch ? { request: options.accountFetch } : {}),
  });
  const accountOnboarding = createNativeOnboarding('account');
  const instanceOnboarding = createNativeOnboarding('instance');
  const folderManagement = new FolderManagement({ store, getConfig: () => config, getIdentity: () => secrets.identity, getRevision: () => config.accountPolicyRevision || 0, deviceName: () => deviceInfo().name, saveConfig, serial, prepareNetwork: origin => network.prepare(origin), allowLocal: options.allowLocalRelay === true, ...(options.accountFetch ? { request: options.accountFetch } : {}) });
  const demoDir = options.demoDir ?? path.join(path.dirname(store.directory), 'Chat2LocalDemo');
  const connectionState = () => guideView(config, { device: deviceInfo(), bridge: bridge.state, setup: setup.info, setupActive: Boolean(setup.active), warning: guideWarning, capabilities: readiness.view(secrets.identity, config.connectionGuide?.id) });
  const status = () => {
    files.prune();
    return {
      name: 'chat2local', version: VERSION, instanceId, device: deviceInfo(),
      startupAvailable: Boolean(options.setStartup) || startupAvailable(store.directory),
      paused: config.paused, startup: config.startup === true, roots: config.roots.map(root => ({ ...root, writeMode: rootWriteMode(root) })),
      accountRoots: (config.accountRoots || []).map(root => ({ ...root, writeMode: rootWriteMode(root), accountScoped: true })),
      relay: config.relay || '', bridge: bridge.state, lastRemoteCallAt, hasRemoteUse: config.remoteUseConfirmed === true,
      setup: setup.info, setupOrigin: setup.origin(), setupActive: Boolean(setup.active), queuedOperations: queued, folderPickerActive: picker.busy,
      network: network.status(), networkSettings: networkSettings(config.network),
      mcpUrl: secrets.identity ? `${secrets.identity.origin}/mcp` : '',
      pending: [...files.operations.values()].filter(op => op.status === 'pending').map(op => ({ ...op, rootLabel: config.roots.find(root => root.id === op.rootId)?.label ?? '' })),
      terminalJobsRunning: [...terminal.jobs.values()].filter(j => ['starting','running','stopping'].includes(j.record.status)).length,
      events: files.events,
    };
  };
  async function mutate(route, value) {
    switch (route) {
      case 'instance/import-invitation': {
        fields(value, ['url']);
        const selected = parseInstanceInvitation(value.url, options.allowLocalRelay === true);
        if (config.paused || setup.active || instanceOnboarding.work.size || instanceOnboarding.ingress.size) throw failure(409, '请先完成或停止当前接入；没有覆盖邀请。');
        const assigned = secrets.identity || secrets.accountEnrollmentPending || secrets.enrollmentPending;
        if (assigned && assigned.origin !== selected.origin) throw failure(409, '本机已属于另一个实例；不会替换设备身份。');
        const next = { ...secrets, privateInstanceInvitation: selected };
        await store.saveSecrets(next); secrets = next;
        return { imported: true, origin: selected.origin, mcpUrl: selected.origin + '/mcp', foldersGranted: false };
      }
      case 'guide/session-tools': {
        // Optional operator inspection, not a claim that the agent can inspect
        // the ChatGPT account. Advisory only; never changes a grant or evidence.
        fields(value, ['attemptId', 'tools']); identifier(value.attemptId);
        if (value.attemptId !== config.connectionGuide?.id) throw failure(409, '接入步骤已变化；工具观察未绑定到当前步骤。');
        readiness.reportSession(value.attemptId, value.tools);
        return connectionState();
      }
      case 'guide/authorize': {
        fields(value, ['path', 'expectedRootId', 'expectedWriteMode', 'requestId', 'confirmDirect']);
        identifier(value.requestId);
        if (value.confirmDirect !== true) throw failure(400, '请点击明确标注的“允许读写并继续”完成此次目录授权。');
        if (config.paused) throw failure(409, '访问已暂停。没有更改目录或重新接入。');
        if (setup.active) throw failure(409, '当前连接正在进行，请先等待或取消。');
        const checked = await approveRoot(value.path, store.directory, true);
        const previous = await existingRoot(checked.path);
        if (config.connectionGuide?.id === value.requestId) {
          if (!previous || previous.id !== config.connectionGuide.rootId || rootWriteMode(previous) !== 'direct') throw failure(409, '此次接入已失效，没有重新授权。');
          return connectionState(); // Lost response / double click: reuse, never restart or widen.
        }
        if (previous) {
          if (value.expectedRootId !== previous.id || value.expectedWriteMode !== rootWriteMode(previous)) throw failure(409, '目录授权已变化。请重新选择并查看当前权限，没有自动升级。');
        } else if (value.expectedRootId !== null || value.expectedWriteMode !== null) throw failure(409, '原目录授权已移除，请重新选择。');
        if (!previous && config.roots.length >= 50) throw failure(400, 'At most 50 folders may be authorized.');
        const root = { ...(previous || checked), ...rootPermission('direct') };
        const roots = previous ? config.roots.map(item => item.id === root.id ? root : item) : [...config.roots, root];
        const changed = !previous || rootWriteMode(previous) !== 'direct';
        if (changed) files.cancelPending();
        // One atomic local consent commit: selected folder, permission and resumable intent.
        await saveConfig({ ...config, roots, connectionGuide: newGuide(root.id, value.requestId) });
        guideWarning = null;
        if (changed) {
          try { await files.audit('directory-consent', { rootId: root.id, from: previous ? rootWriteMode(previous) : 'not-authorized', to: 'direct', flow: 'connection-guide' }); }
          catch { guideWarning = '目录授权已保存，但操作日志写入失败。'; }
        }
        return connectionState();
      }
      case 'guide/cancel': {
        fields(value, ['attemptId']); identifier(value.attemptId);
        if (config.connectionGuide?.id !== value.attemptId) throw failure(409, '接入步骤已变化，请刷新后再取消。');
        setup.cancel();
        const next = { ...config }; delete next.connectionGuide; await saveConfig(next);
        return { cancelled: true, permissionsPreserved: true };
      }
      case 'setup/inspect': fields(value, []); return setup.inspect();
      case 'setup/start': {
        fields(value, []);
        if (config.paused) throw failure(409, '请先恢复本机访问，再连接 ChatGPT。');
        if (!config.roots.length) throw failure(409, '请先选择允许访问的文件夹。');
        return setup.start();
      }
      case 'root/add': {
        fields(value, ['path', 'write', 'writeMode', 'confirmDirect']); const permission = selectedPermission(value);
        if (config.paused) throw failure(409, '本机访问已暂停；没有新增目录授权。');
        const root = { ...await approveRoot(value.path, store.directory, permission.write), ...permission };
        const existing = await existingRoot(root.path);
        // Repeating setup preserves the root ID and its saved permission, including read-only/review.
        if (existing) return { ...existing, writeMode: rootWriteMode(existing), alreadyAuthorized: true };
        if (config.roots.length >= 50) throw failure(400, 'At most 50 folders may be authorized.');
        await changePolicy({ ...config, roots: [...config.roots, root] }); return root;
      }
      case 'root/set-mode': {
        fields(value, ['id', 'writeMode', 'expectedWriteMode', 'confirmDirect']); identifier(value.id);
        const permission = selectedPermission(value);
        const previous = config.roots.find(root => root.id === value.id);
        if (!previous) throw failure(404, 'Folder is not authorized.');
        if (rootWriteMode(previous) !== validateWriteMode(value.expectedWriteMode)) throw failure(409, '目录权限已在其他页面改变，请刷新后重试。');
        await approveRoot(previous.path, store.directory, permission.write);
        const root = { ...previous, ...permission };
        await changePolicy({ ...config, roots: config.roots.map(item => item.id === root.id ? root : item) });
        let warning;
        try { await files.audit('permission-changed', { rootId: root.id, from: rootWriteMode(previous), to: root.writeMode }); }
        catch { warning = '权限已保存，但操作日志写入失败，请检查本机存储。'; }
        return { ...root, ...(warning ? { warning } : {}) };
      }
      case 'account-root/remove': {
        fields(value, ['id']); identifier(value.id);
        if (!(config.accountRoots || []).some(root => root.id === value.id)) throw failure(404, 'Account folder is not shared.');
        await changePolicy({ ...config, accountRoots: config.accountRoots.filter(root => root.id !== value.id) });
        return { ok: true, localAccessRevoked: true, cloudMembershipRemoved: false };
      }
      case 'root/remove': {
        fields(value, ['id']); identifier(value.id);
        const remaining = config.roots.filter(root => root.id !== value.id);
        if (!remaining.length) setup.cancel();
        await changePolicy({ ...config, roots: remaining }); return { ok: true };
      }
      case 'pause': {
        fields(value, ['paused']); boolean(value.paused);
        if (value.paused) { selectionRevision++; picker.cancel(); setup.cancel(); }
        await changePolicy({ ...config, paused: value.paused }); return { paused: config.paused };
      }
      case 'approve': fields(value, ['operationId', 'approved']); return files.decide(identifier(value.operationId), boolean(value.approved));
      case 'folder/cancel': fields(value, []); picker.cancel(); return { ok: true };
      case 'demo': {
        fields(value, []);
        if (config.paused) throw failure(409, 'Resume access before running the local demo.');
        await fs.mkdir(demoDir, { recursive: true });
        const checkedRoot = await approveRoot(demoDir, store.directory, true);
        const root = config.roots.find(old => old.path === checkedRoot.path) ?? checkedRoot;
        if (!config.roots.some(old => old.id === root.id)) await saveConfig({ ...config, roots: [...config.roots, root] });
        const target = path.join(root.path, 'hello-chat2local.txt');
        try { await fs.writeFile(target, 'Hello from Chat2Local.\n这是独立示例文件，不是你的业务项目。\n', { flag: 'wx' }); }
        catch (error) { if (error.code !== 'EEXIST') throw error; }
        // Exercise exactly the same JSON-RPC dispatcher used by the relay.
        const call = async (name, args) => {
          const response = await handleMcp(new Request('http://127.0.0.1/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: randomUUID(), method: 'tools/call', params: { name, arguments: args } }) }), (tool, input) => files.invoke(tool, input));
          const result = (await response.json()).result;
          if (result?.isError || !result?.content?.[0]) throw failure(400, result?.content?.[0]?.text ?? 'Demo MCP call failed.');
          return JSON.parse(result.content[0].text);
        };
        const snapshot = await call('read_file', { rootId: root.id, path: 'hello-chat2local.txt' });
        return call('propose_write', { rootId: root.id, path: 'hello-chat2local.txt', expectedHash: snapshot.sha256, content: `${snapshot.content}\n本次修改经由 MCP 提议，只有在本机确认后才会保存。\n` });
      }
      case 'network/set': {
        const selected = networkSettings(value);
        setup.cancel(); bridge.stop(); files.cancelPending('Network settings changed locally.');
        await saveConfig({ ...config, network: selected });
        const relay = secrets.identity?.origin || config.relay;
        if (relay) {
          await network.prepare(relay, true);
          if (secrets.identity) bridge.start(secrets.identity);
        } else { bridge.start(undefined); }
        return { ok: true, settings: selected, network: network.status() };
      }
      case 'network/check': {
        fields(value, ['origin']);
        const relay = relayOrigin(secrets.identity?.origin || config.relay || value.origin, options.allowLocalRelay === true);
        await network.prepare(relay, true);
        try {
          const response = await fetch(`${relay}/healthz`, { redirect: 'error', signal: AbortSignal.timeout(10_000) });
          const healthy = response.ok && (await response.json()).name === 'chat2local-relay';
          return { ok: healthy, network: network.status(), websiteClientVerified: false,
            message: healthy ? '中继网络可达；这不代表已完成 ChatGPT 官网授权。' : '入口响应不匹配，请核对中继地址。' };
        } catch { return { ok: false, network: network.status(), websiteClientVerified: false, message: '无法连接中继，请检查直连／代理设置及代理是否运行。没有自动改用其他网络。' }; }
      }
      case 'enroll': {
        fields(value, ['origin', 'enrollmentToken']);
        if (typeof value.origin !== 'string' || value.origin.length > 2048 || typeof value.enrollmentToken !== 'string' || value.enrollmentToken.length > 512) throw failure(400, 'Invalid relay settings.');
        if (secrets.identity) throw failure(409, 'Disconnect the existing relay before registering a different one.');
        setup.cancel();
        const identity = await bridge.enroll(value.origin, value.enrollmentToken);
        const nextSecrets = { identity };
        await store.saveSecrets(nextSecrets); secrets = nextSecrets;
        await saveConfig({ ...config, relay: identity.origin });
        bridge.start(identity); return { ok: true };
      }
      case 'disconnect': {
        fields(value, []); const identity = secrets.identity;
        selectionRevision++; picker.cancel(); setup.cancel();
        bridge.stop(); bridge.identity = undefined; lastRemoteCallAt = null; files.cancelPending('Disconnected locally.');
        // Stop locally before any network request, even if remote revocation cannot finish.
        config = { ...config, paused: true, relay: '', remoteUseConfirmed: false }; delete config.connectionGuide; secrets = {};
        await store.saveSecrets(secrets); await store.saveConfig(config);
        try { return { ok: true, ...await bridge.revokeIdentity(identity) }; }
        catch { return { ok: true, remoteRevoked: false, warning: '本机访问已停止，但云端撤销未确认。请同时在 AI 客户端移除此连接。' }; }
      }
      case 'pair-code': fields(value, []); return bridge.pairCode();
      case 'shutdown': {
        fields(value, []);
        // Finish the authenticated response before closing this controller only.
        setup.cancel();
        setTimeout(() => { void closeController().catch(() => {}); }, 150).unref();
        return { ok: true };
      }
      case 'startup': {
        fields(value, ['enabled']); boolean(value.enabled);
        await (options.setStartup ?? setStartup)(value.enabled, entryFile, store.directory);
        await saveConfig({ ...config, startup: value.enabled }); return { enabled: config.startup };
      }
      default: throw failure(404, 'Unknown local API route.');
    }
  }
  let origin;
  const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 15_000, headersTimeout: 10_000, keepAliveTimeout: 3000 }, (request, response) => {
    const send = (code, data, type = 'application/json', extraHeaders = {}) => {
      if (response.destroyed || response.writableEnded) return;
      response.writeHead(code, { ...securityHeaders, 'Content-Type': `${type}; charset=utf-8`, ...extraHeaders });
      response.end(type === 'application/json' ? JSON.stringify(data) : data);
    };
    void (async () => {
      if (closing) throw failure(503, 'Controller is closing.');
      if (request.headers.host !== new URL(origin).host) throw failure(403, 'Invalid Host.');
      if (request.headers.origin && request.headers.origin !== origin) throw failure(403, 'Invalid Origin.');
      // A top-level GET may show only the limited recovery page. It never
      // exposes the control token or grants access. All APIs remain same-origin.
      const accountNavigation = request.method === 'GET' && ['/account-connect','/instance-connect'].includes(request.url) && request.headers['sec-fetch-mode'] === 'navigate' && request.headers['sec-fetch-dest'] === 'document';
      if (request.headers['sec-fetch-site'] === 'cross-site' && !recoveryNavigation(request) && !accountNavigation) throw failure(403, 'Cross-site access is not allowed.');
      if (!request.url?.startsWith('/') || request.url.startsWith('//') || request.url.includes('?')) throw failure(400, 'Invalid request target.');
      const route = request.url;
      if (['/account-connect','/instance-connect'].includes(route) && request.method === 'GET') {
        if (request.headers['sec-fetch-dest'] && request.headers['sec-fetch-dest'] !== 'document') throw failure(403, 'Top-level page required.');
        const privateMode = route === '/instance-connect';
        const adapter = privateMode ? instanceOnboarding : accountOnboarding;
        const nonce = adapter.pageSession(request);
        let page = (await fs.readFile(path.join(uiDir, 'account-connect.html'), 'utf8')).replace('{{NONCE}}', nonce);
        if (privateMode) page = page.replace('/account-connect.js', '/instance-connect.js').replace('<dt>账号</dt>', '<dt>私人实例</dt>').replace('登录验证与平台自身的确认不由本程序跳过。', '不需要第三方账号登录；平台自身的确认仍由平台处理。');
        send(200, page, 'text/html', { 'Set-Cookie': `c2l_${adapter.profile}_local=${nonce}; HttpOnly; SameSite=Strict; Path=${route}; Max-Age=86400` }); return;
      }
      if (['/account-connect.js','/instance-connect.js'].includes(route) && request.method === 'GET') { send(200, await fs.readFile(path.join(uiDir, 'account-connect.js'), 'utf8'), 'text/javascript'); return; }
      if (route.startsWith('/account-connect/') || route.startsWith('/instance-connect/')) {
        if (request.method !== 'POST' || request.headers.origin !== origin) throw failure(403, 'Same-origin onboarding operation required.');
        const value = await bodyJson(request);
        const adapter = route.startsWith('/instance-connect/') ? instanceOnboarding : accountOnboarding;
        send(200, await adapter.handle(route.slice(route.indexOf('/', 1) + 1), value, request.headers.cookie)); return;
      }
      if (route === '/connect' && request.method === 'GET') {
        if (request.headers['sec-fetch-dest'] && request.headers['sec-fetch-dest'] !== 'document') throw failure(403, 'Top-level page required.');
        const available = Boolean(secrets.identity && config.roots.length && !config.paused);
        const nonce = recovery.issue(recoveryBinding());
        const reason = config.paused ? '本机访问已暂停。请在原向导恢复访问后再继续。' : '请先启动 chat2local 主向导并选择文件夹；不会自动登记设备或开放目录。';
        send(200, recoveryPage({ token: nonce, name: platformInfo().name, available, reason, relay: setup.origin() }), 'text/html', { 'Set-Cookie': `c2l_recovery=${nonce}; HttpOnly; SameSite=Strict; Path=/connect; Max-Age=300` }); return;
      }
      if (route === '/recovery.js' && request.method === 'GET') { send(200, recoveryScript, 'text/javascript'); return; }
      if (route === '/connect/continue') {
        if (request.method !== 'POST') throw failure(405, 'POST required.');
        if (request.headers.origin !== origin) throw failure(403, 'Same-origin confirmation required.');
        const value = await bodyJson(request); fields(value, ['nonce', 'confirm', 'returnUrl']);
        if (value.confirm !== true || !secrets.identity || !config.roots.length || config.paused) throw failure(409, '请先在本机主向导完成连接；没有修改任何权限。');
        authorizationReturn(value.returnUrl, secrets.identity.origin);
        recovery.consume(value.nonce, request.headers.cookie, recoveryBinding());
        if (setup.active) throw failure(409, '连接正在进行，不重复打开授权页。');
        const binding = recoveryBinding(); let handoff;
        const work = setup.start({ allowEnrollment: false, onHandoff: async url => {
          if (closing || config.paused || recoveryBinding() !== binding) throw failure(409, '本机状态已变化，连接已取消。');
          handoff = url;
        } });
        const attempt = setup.active;
        const onClose = () => { if (!response.writableEnded && setup.active === attempt) setup.cancel(); };
        response.once('close', onClose);
        try {
          const result = await work;
          if (result.ok && (!handoff || closing || config.paused || recoveryBinding() !== binding)) throw failure(409, '连接已取消。');
          send(200, result.ok ? { ok: true, url: handoff } : result);
        } finally { response.removeListener('close', onClose); }
        return;
      }
      if (route.startsWith('/api/')) {
        if (!matchesSecret(request.headers['x-chat2local-token'], token)) throw failure(401, 'Local control token required. Reopen the app using its launcher.');
        if (route === '/api/status' && request.method === 'GET') { send(200, status()); return; }
        if (route === '/api/guide' && request.method === 'GET') { send(200, connectionState()); return; }
        if (request.method !== 'POST') throw failure(405, 'POST required.');
        if (request.headers.origin !== origin) throw failure(403, 'Same-origin confirmation required.');
        const value = await bodyJson(request);
        if (route === '/api/terminal/permissions') {
          fields(value, []);
          const { connections } = await folderManagement.connections();
          send(200, { connections: connections.map(c => ({ ...c, roots: c.roots.map(r => ({ ...r, terminalAllowed: (config.terminalGrants || []).some(g => g.enabled && g.connectionId === c.connectionId && g.rootId === r.rootId) })) })), sandboxed: false }); return;
        }
        if (route === '/api/terminal/set-permission') {
          fields(value, ['connectionId','rootId','enabled','confirmation']); boolean(value.enabled);
          if (value.enabled && value.confirmation !== TERMINAL_CONFIRMATION) throw failure(400, '请明确确认：终端以当前系统用户权限运行，不是目录沙箱；可能修改或删除目录外文件和访问网络。');
          const { connections } = await folderManagement.connections();
          const selected = connections.find(c => c.connectionId === value.connectionId), root = selected?.roots.find(r => r.rootId === value.rootId && r.locallyPresent);
          if (!root || (value.enabled && root.mode !== 'direct')) throw failure(403, '只有原连接内允许直接读写的本机目录可以启用终端。');
          await serial(async () => {
            if (config.paused) throw failure(409, '本机访问已暂停。');
            const local = [...config.roots, ...(config.accountRoots || [])].find(r => r.id === value.rootId);
            if (!local || (value.enabled && rootWriteMode(local) !== 'direct')) throw failure(409, '目录权限已变化。');
            const grants = (config.terminalGrants || []).filter(g => !(g.connectionId === value.connectionId && g.rootId === value.rootId));
            if (value.enabled) grants.push({ connectionId: value.connectionId, rootId: value.rootId, resource: secrets.identity.origin + '/mcp', enabled: true });
            await changePolicy({ ...config, terminalGrants: grants });
          });
          send(200, { saved: true, enabled: value.enabled, oauthScopeGranted: selected.scopes.includes('terminal:execute'), sandboxed: false }); return;
        }
        if (route.startsWith('/api/shares/')) {
          // Network work runs outside the policy queue; each durable local
          // activation rechecks the exact selected paths and current revision.
          send(200, await folderManagement.execute(route.slice('/api/shares/'.length), value)); return;
        }
        if (route === '/api/setup/inspect') {
          fields(value, []); send(200, await setup.inspect()); return;
        }
        if (route === '/api/setup/start') {
          // Human/network waits must not block local revocation or file operations.
          fields(value, []);
          if (setup.active) throw failure(409, '连接正在处理中；不会重复注册或打开配对页。');
          const work = mutate('setup/start', value); const attempt = setup.active;
          const onClose = () => { if (!response.writableEnded && attempt && setup.active === attempt) setup.cancel(); };
          response.once('close', onClose);
          try { send(200, await work); } finally { response.removeListener('close', onClose); }
          return;
        }
        if (route === '/api/folder/browse') {
          fields(value, ['path']);
          if (value.path !== undefined && typeof value.path !== 'string') throw failure(400, '目录路径必须是文字。');
          if (browsing >= 2) throw failure(429, '目录列表正在加载，请稍候。');
          browsing++;
          try {
            const page = await browseFolders(value.path, store.directory);
            const existing = page.selectable ? await existingRoot(page.path) : null;
            send(200, { ...page, existingRoot: existing ? { id: existing.id, writeMode: rootWriteMode(existing), label: existing.label } : null });
          } finally { browsing--; }
          return;
        }
        if (route === '/api/pick-folder' || route === '/api/folder/select') {
          // Waiting for a person must not hold the policy/MCP queue. Only the
          // short final authorization joins that queue, using current state.
          const add = route === '/api/folder/select';
          fields(value, add ? ['write', 'writeMode', 'confirmDirect'] : []);
          if (add) selectedPermission(value);
          if (config.paused) throw failure(409, '本机访问已暂停，请恢复访问后再添加目录。');
          const revision = selectionRevision;
          const abort = new AbortController();
          const onClose = () => { if (!response.writableEnded) abort.abort(); };
          response.once('close', onClose);
          try {
            const selected = await picker.run({ signal: abort.signal });
            if (selected.cancelled || abort.signal.aborted || closing || config.paused || revision !== selectionRevision) {
              send(200, add ? { cancelled: true, expired: selected.expired } : { path: null }); return;
            }
            if (!add) { send(200, { path: selected.path }); return; }
            const root = await serial(async () => {
              if (abort.signal.aborted || closing || config.paused || revision !== selectionRevision) return { cancelled: true };
              const permission = selectedPermission(value);
              const checked = await approveRoot(selected.path, store.directory, permission.write);
              const existing = await existingRoot(checked.path);
              // Picking an existing folder is not a permission change or re-pair.
              if (existing) return { ...existing, writeMode: rootWriteMode(existing), alreadyAuthorized: true };
              if (abort.signal.aborted || closing || config.paused || revision !== selectionRevision) return { cancelled: true };
              return mutate('root/add', { ...value, path: checked.path });
            });
            send(200, root); return;
          } finally { response.removeListener('close', onClose); }
        }
        send(200, await serial(() => mutate(route.slice(5), value))); return;
      }
      if (request.method !== 'GET') throw failure(405, 'GET required.');
      const asset = assets.get(route);
      if (!asset) throw failure(404, 'Not found.');
      send(200, await fs.readFile(path.join(uiDir, asset[0]), 'utf8'), asset[1]);
    })().catch(error => send(error.status ?? 400, { error: error.code ? `Local operation failed (${error.code}).` : error.message }));
  });
  server.maxConnections = 32;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: '127.0.0.1', port: options.port ?? DEFAULT_PORT, exclusive: true }, () => { server.removeListener('error', reject); resolve(); });
  });
  origin = `http://127.0.0.1:${server.address().port}`;
  try {
    await store.saveSession({ origin, token, instanceId, pid: process.pid });
    if (secrets.identity) bridge.start(secrets.identity);
  } catch (error) { await new Promise(resolve => server.close(resolve)); throw error; }
  closeController = async () => {
    if (closing) return;
    closing = true; picker.cancel(); setup.cancel(); bridge.stop(); files.cancelPending('Agent stopped.'); await terminal.close();
    await tail;
    network.close();
    await new Promise(resolve => { server.close(resolve); server.closeIdleConnections(); });
  };
  return { origin, token, instanceId, server, files, bridge, close: closeController };
}

export async function runCli(args = process.argv.slice(2)) {
  if (args.some(arg => arg !== '--background')) throw new Error('Usage: node src/agent/main.mjs [--background]');
  // Local session bootstrap is always direct, even with a inherited global proxy.
  localNetworkOnly();
  const store = new Store();
  try {
    const app = await startController({ store });
    console.log(`Chat2Local ${VERSION} local panel: ${app.origin} (open with the launcher for authorization)`);
    if (!args.includes('--background')) await openBrowser(`${app.origin}/#${app.token}`);
    let stopping = false;
    const stop = async () => { if (stopping) return; stopping = true; await app.close(); process.exitCode = 0; };
    process.once('SIGINT', stop); process.once('SIGTERM', stop);
    return app;
  } catch (error) {
    if (error.code !== 'EADDRINUSE') throw error;
    // Never stop an unknown listener. Reuse only a verified instance and encrypted session.
    const session = await store.readSession().catch(() => null);
    if (!session || session.origin !== `http://127.0.0.1:${DEFAULT_PORT}` || !/^[a-f0-9]{64}$/.test(session.token)) throw new Error('Local port is busy. No process was stopped.');
    const response = await fetch(`${session.origin}/api/status`, { headers: { 'X-Chat2Local-Token': session.token }, signal: AbortSignal.timeout(2500), redirect: 'error' });
    const status = response.ok ? await response.json() : null;
    if (status?.name !== 'chat2local' || status.instanceId !== session.instanceId) throw new Error('Local port belongs to an unverified process.');
    if (!args.includes('--background')) await openBrowser(`${session.origin}/#${session.token}`);
    console.log('Reused the existing verified Chat2Local panel.'); return null;
  }
}
if (import.meta.main) {
  runCli().catch(error => { console.error(`Chat2Local: ${error.message}`); process.exitCode = 1; });
}
