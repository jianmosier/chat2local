import { checkedReferenceGrant, checkedAccess, ACCESS_CAPABILITY, permittedMode } from '../shared/connection-access.mjs';
import { requiredScopes, TERMINAL_CAPABILITY } from '../shared/protocol.mjs';
import { selectDevice, deviceDescription } from '../shared/device-grants.mjs';
import { invocationCapabilities } from '../shared/tool-capabilities.mjs';

/** Account-reference grants resolve only current, explicitly confirmed shares.
 * Owning a computer or refreshing an OAuth token never adds a share. A native
 * scope fence is mandatory, including for operation_status and list_roots.
 */
export async function routeAccountTool({ props, tool, args = {}, origin, resolveConnection, describe, invoke }) {
  const grant = checkedReferenceGrant(props);
  if (grant.resource !== `${origin}/mcp`) throw new Error('Grant is for a different MCP resource.');
  if (typeof resolveConnection !== 'function') throw new Error('Account connections are not enabled. Existing device grants are unchanged.');
  const snapshot = await resolveConnection(grant);
  if (!snapshot || snapshot.connectionId !== grant.connectionId || snapshot.accountId !== grant.accountId || snapshot.clientId !== grant.clientId || snapshot.resource !== grant.resource || !Array.isArray(snapshot.devices)) throw new Error('Account connection resolution mismatch.');
  const scopes = grant.scopes.filter(scope => snapshot.scopes.includes(scope));
  const required = requiredScopes(tool);
  if (required.some(scope => !scopes.includes(scope))) throw Object.assign(new Error('This OAuth connection does not allow the requested operation.'), { wwwAuthenticate: `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp", error="insufficient_scope", scope="${required.join(' ')}"` });
  if (tool === 'list_devices') {
    const devices = await Promise.all(snapshot.devices.map(async target => {
      try {
        const state = await describe(target);
        return { deviceId: target.deviceId, ...deviceDescription(state.description), status: !state.online ? 'offline' : !state.capabilities?.includes(ACCESS_CAPABILITY) ? 'update-required' : 'online' };
      } catch (error) { return { deviceId: target.deviceId, status: [401, 403].includes(error.status) ? 'revoked' : 'unavailable' }; }
    }));
    return { devices, selectionRequired: devices.length > 1 };
  }
  if (!snapshot.devices.length) throw new Error('No folders have been shared with this connection.');
  const target = selectDevice(snapshot.devices, args.deviceId);
  // selectDevice deliberately drops non-identity fields for legacy safety.
  // Retrieve this device's root fence ONLY from the same resolved snapshot.
  const roots = snapshot.devices.find(item => item.deviceId === target.deviceId).roots;
  const access = checkedAccess({ version: 1, connectionId: grant.connectionId, deviceId: target.deviceId, resource: grant.resource, roots, scopes }, target.deviceId);
  if (!['list_roots', 'operation_status'].includes(tool)) {
    const root = access.roots.find(item => item.rootId === args.rootId);
    if (!root) throw new Error('Folder is not shared with this connection.');
    if (tool === 'write_file' && root.mode !== 'direct') throw new Error('This share does not allow direct writing.');
    if (tool === 'propose_write' && root.mode === 'read-only') throw new Error('This share is read-only.');
  }
  const state = await describe(target);
  if (!state.online) throw new Error('Computer is offline. No operation was queued or replayed.');
  if (tool.startsWith('terminal_') && !state.capabilities?.includes(TERMINAL_CAPABILITY)) throw new Error('Target agent needs the terminal update; no command was forwarded.');
  if (!state.capabilities?.includes(ACCESS_CAPABILITY)) throw new Error('This agent needs the connection-scope update. No request was sent.');
  const { deviceId: _target, ...localArgs } = args;
  const diagnostics = await invocationCapabilities({ ...props, scopes }, origin, target.deviceId, tool);
  const result = await invoke(target, tool, localArgs, diagnostics, access);
  if (tool === 'list_roots') {
    if (!Array.isArray(result)) throw new Error('Invalid scoped directory response.');
    return result.filter(root => access.roots.some(share => share.rootId === root.id)).map(root => {
      const mode = permittedMode(root.writeMode, access.roots.find(share => share.rootId === root.id), scopes);
      return { ...root, writeMode: mode, writeProposalsAllowed: mode !== 'read-only', directWriteAllowed: mode === 'direct', deviceId: target.deviceId, device: { ...deviceDescription(state.description), deviceId: target.deviceId }, connectionDiagnostics: diagnostics };
    });
  }
  return result && typeof result === 'object' && !Array.isArray(result) ? { ...result, deviceId: target.deviceId } : result;
}
