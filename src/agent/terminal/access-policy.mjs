import { checkedAccess } from '../../shared/connection-access.mjs';
import { rootWriteMode } from '../permissions.mjs';

export const TERMINAL_CAPABILITY = 'terminal-jobs-v1';
export const TERMINAL_CONFIRMATION = 'allow-unsandboxed-terminal-v1';

/** Terminal permission is separate from file permission; it is not a sandbox. */
export function authorizeTerminal({ config, device, closed }, rootId, envelope) {
  if (closed || config.paused) throw new Error('Terminal is paused or stopped.');
  if (!envelope) throw new Error('Terminal requires a scoped connection; legacy file authorization cannot execute commands.');
  const access = checkedAccess(envelope, device?.deviceId || '');
  const local = [...config.roots, ...(config.accountRoots || [])].find(root =>
    root.id === rootId && (!root.connectionId || root.connectionId === access.connectionId));
  const grant = (config.terminalGrants || []).find(item => item.rootId === rootId
    && item.connectionId === access.connectionId && item.resource === access.resource && item.enabled === true);
  if (!access.scopes.includes('terminal:execute') || !local || rootWriteMode(local) !== 'direct'
    || !access.roots.some(root => root.rootId === rootId && root.mode === 'direct') || !grant) {
    throw new Error('Terminal requires terminal:execute AND explicit native terminal permission on a directly writable share.');
  }
  return { access, local };
}
