// V3 is an explicit opt-in contract. Legacy device grants are NEVER upgraded here.
const id = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const rootId = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(value);
export const FILE_SCOPES = Object.freeze(['files:read', 'files:write', 'files:propose']);
export const CONNECTION_SCOPES = Object.freeze([...FILE_SCOPES, 'terminal:execute']);
export const ACCESS_CAPABILITY = 'connection-access-v1';
export function exactFields(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !names.includes(key))) throw new Error('Invalid connection fields.');
}
export function checkedScopes(scopes) {
  if (!Array.isArray(scopes) || !scopes.includes('files:read') || scopes.length > CONNECTION_SCOPES.length || new Set(scopes).size !== scopes.length || scopes.some(scope => !CONNECTION_SCOPES.includes(scope))) throw new Error('Invalid connection scopes.');
  return [...scopes].sort();
}
export function checkedResource(value) {
  if (typeof value !== 'string' || value.length > 2048) throw new Error('Invalid connection resource.');
  const url = new URL(value);
  const loopback = url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  // Matches the existing isolated loopback harness. Production still enforces
  // HTTPS PUBLIC_ORIGIN and exact resource equality before any account routing.
  if ((url.protocol !== 'https:' && !loopback) || url.username || url.password || url.search || url.hash || url.pathname !== '/mcp' || url.href !== value) throw new Error('Connection resource must be a canonical HTTPS MCP endpoint (or isolated loopback).');
  return value;
}
export function checkedClient(value) {
  if (typeof value !== 'string' || !value || value.length > 512 || /[\x00-\x20\x7f]/.test(value)) throw new Error('Invalid client identity.');
  return value;
}
export function checkedReferenceGrant(value) {
  exactFields(value, ['grantVersion', 'accountId', 'connectionId', 'connectionEpoch', 'clientId', 'resource', 'scopes']);
  if (value.grantVersion !== 3 || !id(value.accountId) || !id(value.connectionId) || !hash(value.connectionEpoch)) throw new Error('Invalid account connection grant.');
  return { ...value, clientId: checkedClient(value.clientId), resource: checkedResource(value.resource), scopes: checkedScopes(value.scopes) };
}
export function checkedShares(roots) {
  if (!Array.isArray(roots) || !roots.length || roots.length > 50) throw new Error('Select specific shared folders.');
  const seen = new Set();
  return roots.map(root => {
    exactFields(root, ['rootId', 'mode']);
    if (!rootId(root.rootId) || seen.has(root.rootId) || !['read-only', 'review', 'direct'].includes(root.mode)) throw new Error('Invalid or duplicate shared folder.');
    seen.add(root.rootId); return { ...root };
  }).sort((a, b) => a.rootId.localeCompare(b.rootId));
}
/** Internal authenticated relay envelope, not tool arguments or an authorization token. */
export function checkedAccess(value, expectedDevice) {
  exactFields(value, ['version', 'connectionId', 'deviceId', 'resource', 'roots', 'scopes']);
  if (value.version !== 1 || !id(value.connectionId) || !id(value.deviceId) || (expectedDevice !== undefined && value.deviceId !== expectedDevice)) throw new Error('Connection access targets another device.');
  return { ...value, resource: checkedResource(value.resource), roots: checkedShares(value.roots), scopes: checkedScopes(value.scopes) };
}
export function permittedMode(localMode, share, scopes) {
  if (!share || !scopes.includes('files:read')) return null;
  if (localMode === 'read-only' || share.mode === 'read-only') return 'read-only';
  if (localMode === 'direct' && share.mode === 'direct' && scopes.includes('files:write')) return 'direct';
  return scopes.includes('files:propose') ? 'review' : 'read-only';
}
export const isAccountId = id;
export const isDigest = hash;
