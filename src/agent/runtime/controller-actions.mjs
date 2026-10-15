import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { setStartup } from '../store.mjs';
import { approveRoot } from '../files.mjs';
import { rootWriteMode, rootPermission, validateWriteMode } from '../permissions.mjs';
import { newGuide } from '../connection-guide.mjs';
import { networkSettings } from '../network.mjs';
import { fields, identifier, boolean, selectedPermission, failure } from '../controller-http.mjs';
import { parseInstanceInvitation } from '../../shared/instance-invitation.mjs';
import { handleMcp, relayOrigin } from '../../shared/protocol.mjs';

/** Local controller commands. The HTTP layer authenticates and schedules them. */
export function createControllerActions({
  state, store, options, entryFile, demoDir, files, setup, picker, bridge, network,
  instanceOnboarding, readiness, existingRoot, connectionState, changePolicy, closeController,
}) {
  const saveConfig = next => state.saveConfig(next);

  return async function mutate(route, value) {
    switch (route) {
      case 'instance/import-invitation': {
        fields(value, ['url']);
        const selected = parseInstanceInvitation(value.url, options.allowLocalRelay === true);
        if (state.config.paused || setup.active || instanceOnboarding.work.size || instanceOnboarding.ingress.size) {
          throw failure(409, '请先完成或停止当前接入；没有覆盖邀请。');
        }
        const assigned = state.secrets.identity || state.secrets.accountEnrollmentPending || state.secrets.enrollmentPending;
        if (assigned && assigned.origin !== selected.origin) throw failure(409, '本机已属于另一个实例；不会替换设备身份。');
        await state.saveSecrets({ ...state.secrets, privateInstanceInvitation: selected });
        return { imported: true, origin: selected.origin, mcpUrl: selected.origin + '/mcp', foldersGranted: false };
      }
      case 'guide/session-tools': {
        fields(value, ['attemptId', 'tools']);
        identifier(value.attemptId);
        if (value.attemptId !== state.config.connectionGuide?.id) throw failure(409, '接入步骤已变化；工具观察未绑定到当前步骤。');
        readiness.reportSession(value.attemptId, value.tools);
        return connectionState();
      }
      case 'guide/authorize': {
        fields(value, ['path', 'expectedRootId', 'expectedWriteMode', 'requestId', 'confirmDirect']);
        identifier(value.requestId);
        if (value.confirmDirect !== true) throw failure(400, '请点击明确标注的“允许读写并继续”完成此次目录授权。');
        if (state.config.paused) throw failure(409, '访问已暂停。没有更改目录或重新接入。');
        if (setup.active) throw failure(409, '当前连接正在进行，请先等待或取消。');
        const checked = await approveRoot(value.path, store.directory, true);
        const previous = await existingRoot(checked.path);
        if (state.config.connectionGuide?.id === value.requestId) {
          if (!previous || previous.id !== state.config.connectionGuide.rootId || rootWriteMode(previous) !== 'direct') {
            throw failure(409, '此次接入已失效，没有重新授权。');
          }
          return connectionState();
        }
        if (previous) {
          if (value.expectedRootId !== previous.id || value.expectedWriteMode !== rootWriteMode(previous)) {
            throw failure(409, '目录授权已变化。请重新选择并查看当前权限，没有自动升级。');
          }
        } else if (value.expectedRootId !== null || value.expectedWriteMode !== null) {
          throw failure(409, '原目录授权已移除，请重新选择。');
        }
        if (!previous && state.config.roots.length >= 50) throw failure(400, 'At most 50 folders may be authorized.');
        const root = { ...(previous || checked), ...rootPermission('direct') };
        const roots = previous ? state.config.roots.map(item => item.id === root.id ? root : item) : [...state.config.roots, root];
        const changed = !previous || rootWriteMode(previous) !== 'direct';
        if (changed) files.cancelPending();
        await saveConfig({ ...state.config, roots, connectionGuide: newGuide(root.id, value.requestId) });
        state.guideWarning = null;
        if (changed) {
          try {
            await files.audit('directory-consent', {
              rootId: root.id, from: previous ? rootWriteMode(previous) : 'not-authorized',
              to: 'direct', flow: 'connection-guide',
            });
          } catch { state.guideWarning = '目录授权已保存，但操作日志写入失败。'; }
        }
        return connectionState();
      }
      case 'guide/cancel': {
        fields(value, ['attemptId']);
        identifier(value.attemptId);
        if (state.config.connectionGuide?.id !== value.attemptId) throw failure(409, '接入步骤已变化，请刷新后再取消。');
        setup.cancel();
        const next = { ...state.config };
        delete next.connectionGuide;
        await saveConfig(next);
        return { cancelled: true, permissionsPreserved: true };
      }
      case 'setup/inspect': fields(value, []); return setup.inspect();
      case 'setup/start': {
        fields(value, []);
        if (state.config.paused) throw failure(409, '请先恢复本机访问，再连接 ChatGPT。');
        if (!state.config.roots.length) throw failure(409, '请先选择允许访问的文件夹。');
        return setup.start();
      }
      case 'root/add': {
        fields(value, ['path', 'write', 'writeMode', 'confirmDirect']);
        const permission = selectedPermission(value);
        if (state.config.paused) throw failure(409, '本机访问已暂停；没有新增目录授权。');
        const root = { ...await approveRoot(value.path, store.directory, permission.write), ...permission };
        const existing = await existingRoot(root.path);
        if (existing) return { ...existing, writeMode: rootWriteMode(existing), alreadyAuthorized: true };
        if (state.config.roots.length >= 50) throw failure(400, 'At most 50 folders may be authorized.');
        await changePolicy({ ...state.config, roots: [...state.config.roots, root] });
        return root;
      }
      case 'root/set-mode': {
        fields(value, ['id', 'writeMode', 'expectedWriteMode', 'confirmDirect']);
        identifier(value.id);
        const permission = selectedPermission(value);
        const previous = state.config.roots.find(root => root.id === value.id);
        if (!previous) throw failure(404, 'Folder is not authorized.');
        if (rootWriteMode(previous) !== validateWriteMode(value.expectedWriteMode)) throw failure(409, '目录权限已在其他页面改变，请刷新后重试。');
        await approveRoot(previous.path, store.directory, permission.write);
        const root = { ...previous, ...permission };
        await changePolicy({ ...state.config, roots: state.config.roots.map(item => item.id === root.id ? root : item) });
        let warning;
        try { await files.audit('permission-changed', { rootId: root.id, from: rootWriteMode(previous), to: root.writeMode }); }
        catch { warning = '权限已保存，但操作日志写入失败，请检查本机存储。'; }
        return { ...root, ...(warning ? { warning } : {}) };
      }
      case 'account-root/remove': {
        fields(value, ['id']);
        identifier(value.id);
        if (!(state.config.accountRoots || []).some(root => root.id === value.id)) throw failure(404, 'Account folder is not shared.');
        await changePolicy({ ...state.config, accountRoots: state.config.accountRoots.filter(root => root.id !== value.id) });
        return { ok: true, localAccessRevoked: true, cloudMembershipRemoved: false };
      }
      case 'root/remove': {
        fields(value, ['id']);
        identifier(value.id);
        const remaining = state.config.roots.filter(root => root.id !== value.id);
        if (!remaining.length) setup.cancel();
        await changePolicy({ ...state.config, roots: remaining });
        return { ok: true };
      }
      case 'pause': {
        fields(value, ['paused']);
        boolean(value.paused);
        if (value.paused) { state.selectionRevision++; picker.cancel(); setup.cancel(); }
        await changePolicy({ ...state.config, paused: value.paused });
        return { paused: state.config.paused };
      }
      case 'approve':
        fields(value, ['operationId', 'approved']);
        return files.decide(identifier(value.operationId), boolean(value.approved));
      case 'folder/cancel': fields(value, []); picker.cancel(); return { ok: true };
      case 'demo': {
        fields(value, []);
        if (state.config.paused) throw failure(409, 'Resume access before running the local demo.');
        await fs.mkdir(demoDir, { recursive: true });
        const checked = await approveRoot(demoDir, store.directory, true);
        const root = state.config.roots.find(old => old.path === checked.path) ?? checked;
        if (!state.config.roots.some(old => old.id === root.id)) await saveConfig({ ...state.config, roots: [...state.config.roots, root] });
        const target = path.join(root.path, 'hello-chat2local.txt');
        try { await fs.writeFile(target, 'Hello from Chat2Local.\n这是独立示例文件，不是你的业务项目。\n', { flag: 'wx' }); }
        catch (error) { if (error.code !== 'EEXIST') throw error; }
        const call = async (name, args) => {
          const request = new Request('http://127.0.0.1/mcp', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jsonrpc: '2.0', id: randomUUID(), method: 'tools/call', params: { name, arguments: args } }),
          });
          const result = (await (await handleMcp(request, (tool, input) => files.invoke(tool, input))).json()).result;
          if (result?.isError || !result?.content?.[0]) throw failure(400, result?.content?.[0]?.text ?? 'Demo MCP call failed.');
          return JSON.parse(result.content[0].text);
        };
        const snapshot = await call('read_file', { rootId: root.id, path: 'hello-chat2local.txt' });
        return call('propose_write', { rootId: root.id, path: 'hello-chat2local.txt', expectedHash: snapshot.sha256,
          content: `${snapshot.content}\n本次修改经由 MCP 提议，只有在本机确认后才会保存。\n` });
      }
      case 'network/set': {
        const selected = networkSettings(value);
        setup.cancel(); bridge.stop(); files.cancelPending('Network settings changed locally.');
        await saveConfig({ ...state.config, network: selected });
        const relay = state.secrets.identity?.origin || state.config.relay;
        if (relay) {
          await network.prepare(relay, true);
          if (state.secrets.identity) bridge.start(state.secrets.identity);
        } else { bridge.start(undefined); }
        return { ok: true, settings: selected, network: network.status() };
      }
      case 'network/check': {
        fields(value, ['origin']);
        const relay = relayOrigin(state.secrets.identity?.origin || state.config.relay || value.origin, options.allowLocalRelay === true);
        await network.prepare(relay, true);
        try {
          const response = await fetch(`${relay}/healthz`, { redirect: 'error', signal: AbortSignal.timeout(10_000) });
          const healthy = response.ok && (await response.json()).name === 'chat2local-relay';
          return { ok: healthy, network: network.status(), websiteClientVerified: false,
            message: healthy ? '中继网络可达；这不代表已完成 ChatGPT 官网授权。' : '入口响应不匹配，请核对中继地址。' };
        } catch {
          return { ok: false, network: network.status(), websiteClientVerified: false,
            message: '无法连接中继，请检查直连／代理设置及代理是否运行。没有自动改用其他网络。' };
        }
      }
      case 'enroll': {
        fields(value, ['origin', 'enrollmentToken']);
        if (typeof value.origin !== 'string' || value.origin.length > 2048
          || typeof value.enrollmentToken !== 'string' || value.enrollmentToken.length > 512) throw failure(400, 'Invalid relay settings.');
        if (state.secrets.identity) throw failure(409, 'Disconnect the existing relay before registering a different one.');
        setup.cancel();
        const identity = await bridge.enroll(value.origin, value.enrollmentToken);
        await state.saveSecrets({ identity });
        await saveConfig({ ...state.config, relay: identity.origin });
        bridge.start(identity);
        return { ok: true };
      }
      case 'disconnect': {
        fields(value, []);
        const identity = state.secrets.identity;
        state.selectionRevision++; picker.cancel(); setup.cancel();
        bridge.stop(); bridge.identity = undefined; state.lastRemoteCallAt = null; files.cancelPending('Disconnected locally.');
        // Stop in memory before persistence or a possibly unavailable cloud call.
        state.config = { ...state.config, paused: true, relay: '', remoteUseConfirmed: false };
        delete state.config.connectionGuide;
        state.secrets = {};
        await store.saveSecrets(state.secrets);
        await store.saveConfig(state.config);
        try { return { ok: true, ...await bridge.revokeIdentity(identity) }; }
        catch { return { ok: true, remoteRevoked: false, warning: '本机访问已停止，但云端撤销未确认。请同时在 AI 客户端移除此连接。' }; }
      }
      case 'pair-code': fields(value, []); return bridge.pairCode();
      case 'shutdown': {
        fields(value, []);
        setup.cancel();
        setTimeout(() => { void closeController().catch(() => {}); }, 150).unref();
        return { ok: true };
      }
      case 'startup': {
        fields(value, ['enabled']);
        boolean(value.enabled);
        await (options.setStartup ?? setStartup)(value.enabled, entryFile, store.directory);
        await saveConfig({ ...state.config, startup: value.enabled });
        return { enabled: state.config.startup };
      }
      default: throw failure(404, 'Unknown local API route.');
    }
  };
}
