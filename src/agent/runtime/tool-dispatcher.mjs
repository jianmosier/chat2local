import { terminalPermission } from '../../shared/terminal-permission.mjs';
import { rootWriteMode } from '../permissions.mjs';
import { observeGuide } from '../connection-guide.mjs';

export const FILE_TOOL_NAMES = Object.freeze([
  'list_devices', 'list_roots', 'list_directory', 'read_file', 'write_file', 'propose_write', 'operation_status',
]);
export const TERMINAL_TOOL_NAMES = Object.freeze(['terminal_execute', 'terminal_status', 'terminal_cancel']);

/** One remote entry point; transport metadata cannot select arbitrary methods. */
export function createToolDispatcher({ files, terminal, readiness, state, serial }) {
  const routes = Object.create(null);
  for (const name of FILE_TOOL_NAMES) routes[name] = (args, access) => files.invoke(name, args, access);
  for (const name of TERMINAL_TOOL_NAMES) routes[name] = (args, access) => terminal.invoke(name, args, access);
  Object.freeze(routes);

  return (name, args, diagnostics, access) => serial(async () => {
    // Only the authenticated relay envelope supplies diagnostics and scope.
    readiness.observeRemote(diagnostics, state.secrets.identity, name);
    if (access !== undefined && access?.resource !== `${state.secrets.identity?.origin}/mcp`) {
      throw new Error('Connection access belongs to a different relay.');
    }
    if (!Object.hasOwn(routes, name)) throw new Error('Unknown local tool.');
    const result = await routes[name](args, access);
    if (name === 'list_roots' && Array.isArray(result)) {
      for (const root of result) Object.assign(root, terminalPermission({
        grants: state.config.terminalGrants, connectionId: access?.connectionId,
        resource: access?.resource, rootId: root.id, mode: root.writeMode,
        scopes: access?.scopes, available: Boolean(access),
      }));
    }
    state.lastRemoteCallAt = new Date().toISOString();
    const config = state.config;
    const root = config.roots.find(item => item.id === config.connectionGuide?.rootId);
    const nextGuide = root && rootWriteMode(root) === 'direct'
      ? observeGuide(config.connectionGuide, name, args, result, state.secrets.identity) : config.connectionGuide;
    if (!config.remoteUseConfirmed || nextGuide !== config.connectionGuide) {
      try {
        await state.saveConfig({ ...config, remoteUseConfirmed: true, ...(nextGuide ? { connectionGuide: nextGuide } : {}) });
        state.guideWarning = null;
      } catch {
        // Progress persistence must not turn an already completed write into a failure.
        state.guideWarning = '远端操作已返回，但接入进度未能保存。请读回核对，不要盲目重复写入。';
      }
    }
    return result;
  });
}
