import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, randomUUID } from 'node:crypto';
import { Store, pickFolder, openBrowser, startupAvailable } from './store.mjs';
import { ManagementSessions } from './management-session.mjs';
import { platformInfo, sameDirectory } from './platform.mjs';
import { FileService } from './files.mjs';
import { configuredReadonlyBackend } from './files/rust-readonly.mjs';
import { configuredWriterBackend } from './files/rust-writer.mjs';
import { configuredOperationsCore } from './files/rust-operations.mjs';
import { assertWriteFenceClear } from './files/write-fence.mjs';
import { rootWriteMode } from './permissions.mjs';
import { TerminalService } from './terminal.mjs';
import { configuredTerminalRunner } from './terminal/rust-process-runner.mjs';
import { configuredTerminalStore } from './terminal/rust-job-store.mjs';
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
import { claimControllerOwner } from './runtime/controller-owner.mjs';
import { AgentState } from './runtime/agent-state.mjs';
import { SerialQueue } from './runtime/serial-queue.mjs';
import { configuredLifecycle } from './runtime/rust-lifecycle.mjs';
import { createToolDispatcher } from './runtime/tool-dispatcher.mjs';
import { createControllerActions } from './runtime/controller-actions.mjs';
import { createHttpRouter } from './runtime/http-router.mjs';

const entryFile = fileURLToPath(import.meta.url);
const uiDir = path.join(path.dirname(entryFile), 'ui');
export const DEFAULT_PORT = 47631;

/** Composition root: construct services, bind transports, start and stop the agent. */
export async function startController(options = {}) {
  const lifecycle = configuredLifecycle(options);
  const readonlyBackend = configuredReadonlyBackend(options);
  const writerBackend = configuredWriterBackend(options);
  const operationsCore = configuredOperationsCore(options);
  const terminalRunner = options.terminalRunnerFactory ?? configuredTerminalRunner(options);
  const terminalJournal = configuredTerminalStore(options);
  let active = false, router, owner;
  const suppliedStore = options.store ?? new Store(options.stateDir);
  // Old controller callbacks retain their own guard even if a caller reuses a Store.
  const store = new Proxy(suppliedStore, { get(target, key, receiver) {
    if (key === 'publicationGuard') return owner ? () => owner.guard() : undefined;
    return Reflect.get(target, key, receiver);
  } });
  const requests = new Set();
  const server = (options.createServer ?? http.createServer)({ maxHeaderSize: 8192, requestTimeout: 15_000, headersTimeout: 10_000, keepAliveTimeout: 3000 }, (request, response) => {
    if (!active) { response.writeHead(503, { Connection: 'close' }); response.end(); return; }
    const work = router(request, response); requests.add(work);
    Promise.resolve(work).finally(() => requests.delete(work)).catch(() => {});
  });
  server.maxConnections = 32;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: '127.0.0.1', port: options.port ?? DEFAULT_PORT, exclusive: true }, () => { server.removeListener('error', reject); resolve(); });
  });
  let state;
  try {
    owner = await claimControllerOwner(store, options.inspectOwner);
    store.publicationGuard = () => owner.guard();
    await assertWriteFenceClear(store.directory);
    await owner.guard();
    state = await AgentState.load(store, lifecycle);
  } catch (error) { await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }); throw error; }
  try {
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
  const origin = `http://127.0.0.1:${server.address().port}`;
  const queue = new SerialQueue({ lifecycle });
  const serial = action => queue.run(action);
  const picker = new FolderPicker(options.pickFolder ?? (args => pickAccountFolder(args, pickFolder)), options.pickerTimeoutMs ?? 120000);
  const recovery = new BrowserRecovery();
  const recoveryBinding = () => JSON.stringify([
    state.secrets.identity?.deviceId, state.secrets.identity?.origin, state.config.paused,
    state.config.roots.map(root => [root.id, root.path, rootWriteMode(root)]), state.selectionRevision,
  ]);
  const readiness = new ToolReadiness();
  const files = new FileService(() => state.config, store.directory, deviceInfo, {
    readonlyBackend, writerBackend, operationsCore, getResource: () => state.secrets.identity ? `${state.secrets.identity.origin}/mcp` : null,
  });
  const terminal = new TerminalService({ getConfig: () => state.config, getDevice: deviceInfo, store, runnerFactory: terminalRunner, journalFactory: terminalJournal });
  const network = options.network ?? new NetworkManager(() => state.config.network, {
    allowLocal: options.allowLocalRelay === true, ...options.networkOptions,
  });
  const dispatch = createToolDispatcher({ files, terminal, readiness, state, serial });
  const bridge = options.bridge ?? new Bridge(dispatch, {
    allowLocal: options.allowLocalRelay === true, prepareNetwork: origin => network.prepare(origin),
    connectionAccess: true, terminal: true,
    ...options.bridgeOptions,
    lifecycle,
  });
  const prepareNetwork = origin => { lifecycle.permit(); return lifecycle.wait(network.prepare(origin)); };
  const accountRequest = (...args) => { lifecycle.permit(); return lifecycle.wait((options.accountFetch ?? fetch)(...args)); };
  const changePolicy = next => state.changePolicy(next, files);
  const setup = new SetupManager({
    identity: () => state.secrets.identity, pending: () => state.secrets.enrollmentPending,
    defaultRelay: options.defaultRelay, allowLocal: options.allowLocalRelay,
    lifecycle, prepareNetwork, fetch: options.setupFetch,
    bridge, openBrowser: options.openBrowser ?? openBrowser,
    // Only short durable commits join the queue; browser/network waits do not.
    savePending: (identity, signal) => serial(async () => {
      signal.throwIfAborted(); lifecycle.permit();
      await state.saveSecrets({ ...state.secrets, enrollmentPending: identity });
    }),
    acceptIdentity: (identity, signal) => serial(async () => {
      signal.throwIfAborted(); lifecycle.permit();
      const next = { ...state.secrets, identity };
      delete next.enrollmentPending;
      await state.saveSecrets(next);
      signal.throwIfAborted(); lifecycle.permit();
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
      lifecycle.permit();
      if (state.config.paused || origin !== nativeOrigin(profile)) throw failure(409, '设备登记条件已改变。');
      if (state.secrets.identity) return state.secrets.identity;
      const pending = state.secrets.accountEnrollmentPending;
      if (pending && pending.origin !== origin) throw failure(409, '另一个账号登记尚未完成，没有覆盖本机身份。');
      if (pending) return pending;
      const identity = { origin, deviceId: randomUUID().replaceAll('-', ''), deviceKey: randomBytes(32).toString('hex') };
      await state.saveSecrets({ ...state.secrets, accountEnrollmentPending: identity });
      lifecycle.permit();
      return identity;
    },
    acceptRegistration: async identity => {
      lifecycle.permit();
      if (state.config.paused || identity.origin !== nativeOrigin(profile)) throw failure(409, '本机访问已暂停或登记目标改变。');
      const saved = state.secrets.identity || state.secrets.accountEnrollmentPending;
      if (!saved || saved.origin !== identity.origin || saved.deviceId !== identity.deviceId || saved.deviceKey !== identity.deviceKey) {
        throw failure(409, '登记期间本机身份已改变。');
      }
      const next = { ...state.secrets, identity };
      delete next.accountEnrollmentPending;
      await state.saveSecrets(next);
      lifecycle.permit();
      await saveConfig({ ...state.config, relay: identity.origin });
      lifecycle.permit();
      bridge.start(identity);
    },
    deviceName: () => deviceInfo().name, allowLocal: options.allowLocalRelay === true,
    saveConfig, serial, prepareNetwork,
    chooseFolder: async () => { const selection = await picker.run(); return selection.cancelled ? null : selection.path; },
    request: accountRequest,
  });
  const accountOnboarding = createNativeOnboarding('account');
  const instanceOnboarding = createNativeOnboarding('instance');
  const folderManagement = new FolderManagement({
    store, getConfig: () => state.config, getIdentity: () => state.secrets.identity,
    getRevision: () => state.config.accountPolicyRevision || 0, deviceName: () => deviceInfo().name,
    saveConfig, serial, prepareNetwork, allowLocal: options.allowLocalRelay === true,
    request: accountRequest,
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
      pending: files.pendingOperations().map(operation => ({ operationId: operation.operationId, rootId: operation.rootId,
        path: operation.path, status: operation.status, expectedHash: operation.expectedHash,
        content: operation.content, before: operation.before, createdAt: operation.createdAt,
        rootLabel: config.roots.find(root => root.id === operation.rootId)?.label ?? '' })),
      terminalJobsRunning: terminal.activeCount(), events: files.events,
      ...(lifecycle.fault ? { lifecycleWarning: lifecycle.fault.message } : {}),
    };
  };
  const mutate = createControllerActions({
    state, store, options, entryFile, files, setup, picker, bridge, network, lifecycle, instanceOnboarding,
    readiness, existingRoot, connectionState, changePolicy, closeController: () => closeController(),
    demoDir: options.demoDir ?? path.join(path.dirname(store.directory), 'Chat2LocalDemo'),
  });
  const managementSessions = new ManagementSessions({ store, binding: () => JSON.stringify([
    origin, state.config.installationId, state.secrets.identity?.origin || '',
    state.secrets.identity?.deviceId || '', state.secrets.identity?.deviceKey || '',
  ]) });
  router = createHttpRouter({
    state, getOrigin: () => origin, token, store, uiDir, setup, picker, recovery, recoveryBinding,
    accountOnboarding, instanceOnboarding, managementSessions, folderManagement, shareRemoval,
    status, connectionState, existingRoot, changePolicy, serial, mutate, lifecycle,
  });
  let removalSyncTimer, closePromise;
  const cleanupErrors = [];
  const attemptCleanup = async work => { try { await work(); } catch (error) { cleanupErrors.push(error); } };
  lifecycle.onEffect(e => { if (e.type === 'cancelPicker') picker.cancel(); else if (e.type === 'cancelSetup') setup.cancel(); });
  lifecycle.onFault(() => {
    // Restrict in-flight authorizations synchronously, before any late READY.
    state.config = { ...state.config, paused: true };
    for (const work of [() => picker.cancel(), () => setup.cancel(), () => bridge.stop(), () => files.cancelPending('Agent lifecycle failed.'), () => network.close()]) {
      try { Promise.resolve(work()).catch(error => cleanupErrors.push(error)); } catch (error) { cleanupErrors.push(error); }
    }
    void terminal.close().catch(error => cleanupErrors.push(error));
  });
  function closeController() {
    if (closePromise) return closePromise;
    active = false;
    // Cache the promise before invoking any user/platform cleanup callback.
    const actualClose = Promise.resolve().then(async () => {
      await attemptCleanup(() => lifecycle.beginClose());
      clearInterval(removalSyncTimer);
      // Cancel unfinished body readers while preserving the listening reservation.
      const stopReaders = setTimeout(() => server.closeAllConnections(), 100);
      stopReaders.unref();
      server.closeIdleConnections();
      for (const work of [() => picker.cancel(), () => setup.cancel(), () => bridge.stop(), () => files.cancelPending('Agent stopped.'),
        () => terminal.close(), () => queue.drain(), () => network.close(),
        async () => { while (requests.size) await Promise.allSettled([...requests]); clearTimeout(stopReaders); },
        () => state.drainPersistence(), () => managementSessions.tail, () => store.drainPublications?.(),
        () => new Promise((resolve, reject) => {
          if (!server.listening) { resolve(); return; }
          const deadline = setTimeout(() => server.closeAllConnections(), 100);
          server.close(error => { clearTimeout(deadline); if (error) reject(error); else resolve(); }); server.closeIdleConnections();
        }),
        () => { if (lifecycle.healthy) lifecycle.run({ op: 'finishClose' }); }]) await attemptCleanup(work);
      if (!cleanupErrors.length) await owner.release();

      if (state.pendingSaves) cleanupErrors.push(Object.assign(new Error('Persistence is still pending; its completion and durable restriction are not confirmed.'), { code: 'EPERSISTENCE' }));
      if (cleanupErrors.length) throw new AggregateError(cleanupErrors, 'Agent cleanup had failures; termination is not implied.');
    });
    let timeout;
    closePromise = Promise.race([actualClose, new Promise((_, reject) => {
      timeout = setTimeout(() => {
        if (state.pendingSaves || store.publications?.size) {
          server.unref();
          reject(new AggregateError([Object.assign(new Error('Persistence is still pending; ownership remains reserved.'), { code: 'EPERSISTENCE' })], 'Agent cleanup had failures; termination is not implied.'));
        }
      }, options.closeWaitMs ?? 1000);
      timeout.unref();
    })]).finally(() => clearTimeout(timeout));
    // Seal admission immediately, before the cleanup microtask can run.
    try { lifecycle.beginClose(); } catch (error) { cleanupErrors.push(error); }
    return closePromise;
  }
  try {
    await store.saveSession({ origin, token, instanceId, pid: process.pid });
    await owner.published(instanceId);
    lifecycle.run({ op: 'activate' });
    active = true;
    if (state.secrets.identity) bridge.start(state.secrets.identity);
  } catch (error) {
    await closeController().catch(() => {});
    throw error;
  }
  let removalSyncBusy = false;
  removalSyncTimer = setInterval(() => {
    if (state.closing || removalSyncBusy || !(state.config.shareRemovals || []).length) return;
    removalSyncBusy = true;
    void shareRemoval.flush().catch(() => {}).finally(() => { removalSyncBusy = false; });
  }, 10000);
  removalSyncTimer.unref();
  return { origin, token, instanceId, server, files, bridge, lifecycle, close: closeController };
  } catch (error) {
    active = false;
    await state.drainPersistence();
    if (server.listening) await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
    throw error;
  }
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
