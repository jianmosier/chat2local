import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, randomUUID } from 'node:crypto';
import { Store, pickFolder, openBrowser, startupAvailable } from './store.mjs';
import { ManagementSessions } from './management-session.mjs';
import { platformInfo, sameDirectory } from './platform.mjs';
import { FileService } from './files.mjs';
import { rootWriteMode } from './permissions.mjs';
import { TerminalService } from './terminal.mjs';
import { Bridge } from './bridge.mjs';
import { SetupManager } from './setup.mjs';
import { FolderPicker } from './folder-picker.mjs';
import { BrowserRecovery } from './browser-recovery.mjs';
import { NativeAccountOnboarding, pickAccountFolder } from './account-onboarding.mjs';
import { FolderManagement } from './folder-management.mjs';
import { ShareRemoval } from './share-removal.mjs';
import { guideView } from './connection-guide.mjs';
import { ToolReadiness } from '../shared/tool-capabilities.mjs';
import { NetworkManager, networkSettings, localNetworkOnly } from './network.mjs';
import { VERSION } from '../shared/protocol.mjs';
import { failure } from './controller-http.mjs';
import { AgentState } from './runtime/agent-state.mjs';
import { SerialQueue } from './runtime/serial-queue.mjs';
import { createToolDispatcher } from './runtime/tool-dispatcher.mjs';
import { createControllerActions } from './runtime/controller-actions.mjs';
import { createHttpRouter } from './runtime/http-router.mjs';

const entryFile = fileURLToPath(import.meta.url);
const uiDir = path.join(path.dirname(entryFile), 'ui');
export const DEFAULT_PORT = 47631;

/** Composition root: construct services, bind transports, start and stop the agent. */
export async function startController(options = {}) {
  const store = options.store ?? new Store(options.stateDir);
  const state = await AgentState.load(store);
  const saveConfig = next => state.saveConfig(next);
  const deviceInfo = () => ({ ...platformInfo(), installationId: state.config.installationId,
    deviceId: state.secrets.identity?.deviceId || null });
  const existingRoot = async candidate => {
    for (const root of state.config.roots) {
      try { if (await sameDirectory(root.path, candidate)) return root; }
      catch (error) { if (!['ENOENT', 'ENOTDIR'].includes(error.code)) throw error; }
    }
    return undefined;
  };
  const token = randomBytes(32).toString('hex');
  const instanceId = randomUUID();
  let origin, closeController;
  const queue = new SerialQueue({ isClosing: () => state.closing });
  const serial = action => queue.run(action);
  const picker = new FolderPicker(options.pickFolder ?? (args => pickAccountFolder(args, pickFolder)), options.pickerTimeoutMs ?? 120000);
  const recovery = new BrowserRecovery();
  const recoveryBinding = () => JSON.stringify([
    state.secrets.identity?.deviceId, state.secrets.identity?.origin, state.config.paused,
    state.config.roots.map(root => [root.id, root.path, rootWriteMode(root)]), state.selectionRevision,
  ]);
  const readiness = new ToolReadiness();
  const files = new FileService(() => state.config, store.directory, deviceInfo);
  const terminal = new TerminalService({ getConfig: () => state.config, getDevice: deviceInfo, store });
  const network = options.network ?? new NetworkManager(() => state.config.network, {
    allowLocal: options.allowLocalRelay === true, ...options.networkOptions,
  });
  const dispatch = createToolDispatcher({ files, terminal, readiness, state, serial });
  const bridge = options.bridge ?? new Bridge(dispatch, {
    allowLocal: options.allowLocalRelay === true, prepareNetwork: origin => network.prepare(origin),
    connectionAccess: true, terminal: true,
  });
  const changePolicy = next => state.changePolicy(next, files);
  const setup = new SetupManager({
    identity: () => state.secrets.identity, pending: () => state.secrets.enrollmentPending,
    defaultRelay: options.defaultRelay, allowLocal: options.allowLocalRelay,
    prepareNetwork: origin => network.prepare(origin), fetch: options.setupFetch,
    bridge, openBrowser: options.openBrowser ?? openBrowser,
    // Only short durable commits join the queue; browser/network waits do not.
    savePending: (identity, signal) => serial(async () => {
      signal.throwIfAborted();
      await state.saveSecrets({ ...state.secrets, enrollmentPending: identity });
    }),
    acceptIdentity: (identity, signal) => serial(async () => {
      signal.throwIfAborted();
      const next = { ...state.secrets, identity };
      delete next.enrollmentPending;
      await state.saveSecrets(next);
      await saveConfig({ ...state.config, relay: identity.origin });
    }),
  });
  const nativeOrigin = profile => state.secrets.identity?.origin
    || (profile === 'instance' ? state.secrets.privateInstanceInvitation?.origin : null) || setup.origin();
  const createNativeOnboarding = profile => new NativeAccountOnboarding({
    profile, invitation: () => state.secrets.privateInstanceInvitation?.invitation,
    store, getConfig: () => state.config, getIdentity: () => state.secrets.identity,
    getRevision: () => state.config.accountPolicyRevision || 0,
    expectedOrigin: () => nativeOrigin(profile),
    prepareRegistration: async origin => {
      if (state.config.paused || origin !== nativeOrigin(profile)) throw failure(409, '设备登记条件已改变。');
      if (state.secrets.identity) return state.secrets.identity;
      const pending = state.secrets.accountEnrollmentPending;
      if (pending && pending.origin !== origin) throw failure(409, '另一个账号登记尚未完成，没有覆盖本机身份。');
      if (pending) return pending;
      const identity = { origin, deviceId: randomUUID().replaceAll('-', ''), deviceKey: randomBytes(32).toString('hex') };
      await state.saveSecrets({ ...state.secrets, accountEnrollmentPending: identity });
      return identity;
    },
    acceptRegistration: async identity => {
      if (state.config.paused || identity.origin !== nativeOrigin(profile)) throw failure(409, '本机访问已暂停或登记目标改变。');
      const saved = state.secrets.identity || state.secrets.accountEnrollmentPending;
      if (!saved || saved.origin !== identity.origin || saved.deviceId !== identity.deviceId || saved.deviceKey !== identity.deviceKey) {
        throw failure(409, '登记期间本机身份已改变。');
      }
      const next = { ...state.secrets, identity };
      delete next.accountEnrollmentPending;
      await state.saveSecrets(next);
      await saveConfig({ ...state.config, relay: identity.origin });
      bridge.start(identity);
    },
    deviceName: () => deviceInfo().name, allowLocal: options.allowLocalRelay === true,
    saveConfig, serial, prepareNetwork: origin => network.prepare(origin),
    chooseFolder: async () => { const selection = await picker.run(); return selection.cancelled ? null : selection.path; },
    ...(options.accountFetch ? { request: options.accountFetch } : {}),
  });
  const accountOnboarding = createNativeOnboarding('account');
  const instanceOnboarding = createNativeOnboarding('instance');
  const folderManagement = new FolderManagement({
    store, getConfig: () => state.config, getIdentity: () => state.secrets.identity,
    getRevision: () => state.config.accountPolicyRevision || 0, deviceName: () => deviceInfo().name,
    saveConfig, serial, prepareNetwork: origin => network.prepare(origin), allowLocal: options.allowLocalRelay === true,
    ...(options.accountFetch ? { request: options.accountFetch } : {}),
  });
  const shareRemoval = new ShareRemoval({
    management: folderManagement, getConfig: () => state.config, getIdentity: () => state.secrets.identity,
    serial, changePolicy, saveConfig, stopJobs: (connectionId, rootIds) => terminal.cancelForRoots(connectionId, rootIds),
  });
  const connectionState = () => guideView(state.config, {
    device: deviceInfo(), bridge: bridge.state, setup: setup.info, setupActive: Boolean(setup.active),
    warning: state.guideWarning, capabilities: readiness.view(state.secrets.identity, state.config.connectionGuide?.id),
  });
  const status = () => {
    files.prune();
    const config = state.config;
    return {
      name: 'chat2local', version: VERSION, instanceId, device: deviceInfo(),
      startupAvailable: Boolean(options.setStartup) || startupAvailable(store.directory),
      paused: config.paused, startup: config.startup === true,
      roots: config.roots.map(root => ({ ...root, writeMode: rootWriteMode(root) })),
      accountRoots: (config.accountRoots || []).map(root => ({ ...root, writeMode: rootWriteMode(root), accountScoped: true })),
      relay: config.relay || '', bridge: bridge.state, lastRemoteCallAt: state.lastRemoteCallAt,
      hasRemoteUse: config.remoteUseConfirmed === true,
      setup: setup.info, setupOrigin: setup.origin(), setupActive: Boolean(setup.active),
      queuedOperations: queue.size, folderPickerActive: picker.busy,
      network: network.status(), networkSettings: networkSettings(config.network),
      mcpUrl: state.secrets.identity ? `${state.secrets.identity.origin}/mcp` : '',
      pending: files.pendingOperations().map(operation => ({ ...operation,
        rootLabel: config.roots.find(root => root.id === operation.rootId)?.label ?? '' })),
      terminalJobsRunning: terminal.activeCount(), events: files.events,
    };
  };
  const mutate = createControllerActions({
    state, store, options, entryFile, files, setup, picker, bridge, network, instanceOnboarding,
    readiness, existingRoot, connectionState, changePolicy, closeController: () => closeController(),
    demoDir: options.demoDir ?? path.join(path.dirname(store.directory), 'Chat2LocalDemo'),
  });
  const managementSessions = new ManagementSessions({ store, binding: () => JSON.stringify([
    origin, state.config.installationId, state.secrets.identity?.origin || '',
    state.secrets.identity?.deviceId || '', state.secrets.identity?.deviceKey || '',
  ]) });
  const router = createHttpRouter({
    state, getOrigin: () => origin, token, store, uiDir, setup, picker, recovery, recoveryBinding,
    accountOnboarding, instanceOnboarding, managementSessions, folderManagement, shareRemoval,
    status, connectionState, existingRoot, changePolicy, serial, mutate,
  });
  const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 15_000, headersTimeout: 10_000, keepAliveTimeout: 3000 }, router);
  server.maxConnections = 32;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: '127.0.0.1', port: options.port ?? DEFAULT_PORT, exclusive: true }, () => {
      server.removeListener('error', reject); resolve();
    });
  });
  origin = `http://127.0.0.1:${server.address().port}`;
  try {
    await store.saveSession({ origin, token, instanceId, pid: process.pid });
    if (state.secrets.identity) bridge.start(state.secrets.identity);
  } catch (error) {
    await new Promise(resolve => server.close(resolve));
    throw error;
  }
  let removalSyncBusy = false;
  const removalSyncTimer = setInterval(() => {
    if (state.closing || removalSyncBusy || !(state.config.shareRemovals || []).length) return;
    removalSyncBusy = true;
    void shareRemoval.flush().catch(() => {}).finally(() => { removalSyncBusy = false; });
  }, 10000);
  removalSyncTimer.unref();
  closeController = async () => {
    if (state.closing) return;
    clearInterval(removalSyncTimer);
    state.closing = true;
    picker.cancel(); setup.cancel(); bridge.stop(); files.cancelPending('Agent stopped.');
    await terminal.close();
    await queue.drain();
    network.close();
    await new Promise(resolve => { server.close(resolve); server.closeIdleConnections(); });
  };
  return { origin, token, instanceId, server, files, bridge, close: closeController };
}

export async function runCli(args = process.argv.slice(2)) {
  if (args.some(arg => arg !== '--background')) throw new Error('Usage: node src/agent/main.mjs [--background]');
  localNetworkOnly();
  const store = new Store();
  try {
    const app = await startController({ store });
    console.log(`Chat2Local ${VERSION} local panel: ${app.origin} (open with the launcher for authorization)`);
    if (!args.includes('--background')) await openBrowser(`${app.origin}/folders#${app.token}`);
    let stopping = false;
    const stop = async () => { if (stopping) return; stopping = true; await app.close(); process.exitCode = 0; };
    process.once('SIGINT', stop); process.once('SIGTERM', stop);
    return app;
  } catch (error) {
    if (error.code !== 'EADDRINUSE') throw error;
    const session = await store.readSession().catch(() => null);
    if (!session || session.origin !== `http://127.0.0.1:${DEFAULT_PORT}` || !/^[a-f0-9]{64}$/.test(session.token)) {
      throw new Error('Local port is busy. No process was stopped.');
    }
    const response = await fetch(`${session.origin}/api/status`, {
      headers: { 'X-Chat2Local-Token': session.token }, signal: AbortSignal.timeout(2500), redirect: 'error',
    });
    const status = response.ok ? await response.json() : null;
    if (status?.name !== 'chat2local' || status.instanceId !== session.instanceId) throw new Error('Local port belongs to an unverified process.');
    if (!args.includes('--background')) await openBrowser(`${session.origin}/folders#${session.token}`);
    console.log('Reused the existing verified Chat2Local panel.');
    return null;
  }
}
if (import.meta.main) runCli().catch(error => { console.error(`Chat2Local: ${error.message}`); process.exitCode = 1; });
