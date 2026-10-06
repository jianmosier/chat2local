import { TOOLS, VERSION, sha256 } from './protocol.mjs';

const names = TOOLS.map(tool => tool.name).sort();
const scopeNames = ['files:read', 'files:propose', 'files:write', 'terminal:execute'];
const hex = (value, length) => typeof value === 'string' && new RegExp(`^[a-f0-9]{${length}}$`).test(value);
const keys = ['version', 'origin', 'deviceId', 'serverVersion', 'toolNames', 'schemaSha256', 'grantedScopes', 'invokedTool', 'checkedAt'];
let fingerprint;

/** Same definitions as tools/list, not a claim about what ChatGPT imported or
 * enabled. No token, client secret, file content, or local path is returned.
 */
export async function toolCatalog() {
  fingerprint ||= sha256(JSON.stringify(TOOLS));
  return { serverVersion: VERSION, toolNames: [...names], schemaSha256: await fingerprint };
}
export async function invocationCapabilities(props, origin, deviceId, invokedTool) {
  return { version: 1, origin, deviceId, ...await toolCatalog(), grantedScopes: scopeNames.filter(scope => props.scopes.includes(scope)), invokedTool, checkedAt: new Date().toISOString() };
}
export function checkedCapabilities(value, identity, invokedTool, now = Date.now()) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !keys.includes(key)) || keys.some(key => !Object.hasOwn(value, key))) return null;
  if (value.version !== 1 || !identity || value.origin !== identity.origin || value.deviceId !== identity.deviceId || !hex(value.deviceId, 32) || !hex(value.schemaSha256, 64)) return null;
  if (value.invokedTool !== invokedTool || !names.includes(invokedTool) || !/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?$/.test(value.serverVersion || '')) return null;
  const time = Date.parse(value.checkedAt);
  if (!Number.isFinite(time) || Math.abs(now - time) > 300000) return null;
  if (!Array.isArray(value.toolNames) || value.toolNames.length < 1 || value.toolNames.length > 64 || new Set(value.toolNames).size !== value.toolNames.length || value.toolNames.some(name => typeof name !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(name))) return null;
  if (!Array.isArray(value.grantedScopes) || value.grantedScopes.length > scopeNames.length || new Set(value.grantedScopes).size !== value.grantedScopes.length || value.grantedScopes.some(scope => !scopeNames.includes(scope))) return null;
  return { ...value, toolNames: [...value.toolNames].sort(), grantedScopes: [...value.grantedScopes].sort() };
}

/** Session observations are explicitly reported by an operator, not remotely
 * enumerable by the agent. They are advisory and can NEVER authorize file I/O.
 */
export class ToolReadiness {
  constructor(clock = Date.now) { this.clock = clock; this.remote = null; this.session = null; }
  observeRemote(value, identity, tool) {
    const checked = checkedCapabilities(value, identity, tool, this.clock());
    if (checked) this.remote = checked;
  }
  reportSession(attemptId, tools) {
    if (!/^[a-f0-9-]{36}$/.test(attemptId || '') || !Array.isArray(tools) || tools.length > 64 || new Set(tools).size !== tools.length || tools.some(name => typeof name !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(name))) throw new Error('Invalid session tool observation.');
    this.session = { attemptId, tools: [...tools].sort(), checkedAt: new Date(this.clock()).toISOString(), source: 'operator-observed-session' };
  }
  view(identity, attemptId) {
    const fresh = value => value && this.clock() - Date.parse(value.checkedAt) >= -30000 && this.clock() - Date.parse(value.checkedAt) < 300000;
    const remote = fresh(this.remote) && this.remote.deviceId === identity?.deviceId && this.remote.origin === identity?.origin ? this.remote : null;
    const session = fresh(this.session) && this.session.attemptId === attemptId ? this.session : null;
    const serverNames = remote?.toolNames || [];
    const sessionNames = session?.tools || [];
    const missingTools = session ? ['write_file', 'list_devices'].filter(name => !sessionNames.includes(name)) : null;
    const latestCallWriteScope = remote ? ['files:read', 'files:write'].every(scope => remote.grantedScopes.includes(scope)) : null;
    return {
      expectedTools: [...names],
      server: remote ? { status: 'observed-on-authenticated-call', ...remote } : { status: 'unknown' },
      savedConnection: { status: 'not-observable', message: '本地程序不能读取 ChatGPT 保存或启用的工具清单。' },
      session: session ? { ...session, status: 'reported', missingTools } : { status: 'unknown', missingTools: null },
      latestCallWriteScope,
      mayAttemptWrite: Boolean(remote && serverNames.includes('write_file') && latestCallWriteScope && session && sessionNames.includes('write_file')),
      fileAccessGranted: false,
    };
  }
}
