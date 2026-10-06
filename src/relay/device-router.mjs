import { grantDevices, selectDevice, deviceDescription } from '../shared/device-grants.mjs';
import { requiredScopes } from '../shared/protocol.mjs';
import { invocationCapabilities } from '../shared/tool-capabilities.mjs';
import { routeAccountTool } from './account-router.mjs';

/** Route only from signed OAuth props. No shared active-device switch, host-name
 * matching, offline fallback, or automatic write retry exists in this layer.
 */
export async function routeDeviceTool({ props, tool, args, origin, describe, invoke, resolveConnection }) {
  if (props?.grantVersion === 3) return routeAccountTool({ props, tool, args, origin, describe, invoke, resolveConnection });
  const devices = grantDevices(props);
  const required = requiredScopes(tool);
  if (required.some(scope => !props.scopes.includes(scope))) {
    throw Object.assign(new Error('OAuth scope does not allow this operation. Explicit file permission is required; existing grants are not expanded.'), {
      wwwAuthenticate: `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp", error="insufficient_scope", scope="${required.join(' ')}"`,
    });
  }
  if (tool === 'list_devices') {
    const result = await Promise.all(devices.map(async target => {
      try {
        const status = await describe(target);
        return { deviceId: target.deviceId, ...target.description, ...deviceDescription(status.description), status: status.online ? 'online' : 'offline' };
      } catch (error) {
        return { deviceId: target.deviceId, ...target.description, status: [401, 403].includes(error.status) ? 'revoked' : 'unavailable' };
      }
    }));
    return { devices: result, selectionRequired: devices.length > 1 };
  }
  const target = selectDevice(devices, args.deviceId);
  const { deviceId: _routingOnly, ...localArgs } = args;
  // Epoch and root checks run again at the selected device/agent. The routing
  // selector is not passed as a local-file argument to older agents.
  const connectionDiagnostics = await invocationCapabilities(props, origin, target.deviceId, tool);
  const result = await invoke(target, tool, localArgs, connectionDiagnostics);
  if (tool === 'list_roots' && Array.isArray(result)) {
    // Backward-compatible metadata on an EXISTING read tool; no new tool refresh
    // is needed just to diagnose catalog-versus-client-versus-scope problems.
    return result.map(root => ({ ...root, deviceId: target.deviceId, device: { ...target.description, ...deviceDescription(root.device), deviceId: target.deviceId }, connectionDiagnostics }));
  }
  return result && typeof result === 'object' && !Array.isArray(result) ? { ...result, deviceId: target.deviceId } : result;
}
