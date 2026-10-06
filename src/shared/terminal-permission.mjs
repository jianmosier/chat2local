/** Same meaning on native UI and MCP responses: enabled is a saved local
 * decision; allowed is its intersection with the caller/connection scope. */
export function terminalPermission({ grants = [], connectionId, resource, rootId, mode, scopes = [], available = true }) {
  const local = grants.some(g => g.enabled === true && g.connectionId === connectionId && g.rootId === rootId && g.resource === resource);
  const scope = scopes.includes('terminal:execute');
  return { terminalLocalEnabled: local, terminalScopeGranted: scope, terminalAllowed: Boolean(available && mode === 'direct' && local && scope), terminalStatus: !available || mode !== 'direct' ? 'unavailable' : !local ? 'disabled' : !scope ? 'authorization-required' : 'allowed', terminalSandboxed: false };
}
