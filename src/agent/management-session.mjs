import { createHash, randomBytes } from 'node:crypto';

const name = 'c2l_management';
const digest = value => createHash('sha256').update(value).digest('hex');
const valid = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const lifetime = 7 * 86400000;
const routes = new Set([
  '/api/management/session', '/api/management/logout', '/api/management/startup', '/api/folder/browse',
  '/api/shares/connections', '/api/shares/prepare', '/api/shares/confirm',
  '/api/shares/status', '/api/shares/resume', '/api/shares/remove-prepare',
  '/api/shares/remove-confirm', '/api/shares/removals',
  '/api/terminal/permissions', '/api/terminal/set-permission',
]);
export function managerRoute(method, route) {
  return method === 'GET' && route === '/api/status' || method === 'POST' && routes.has(route);
}
function proofFrom(cookies) {
  const items = String(cookies || '').split(';').map(x => x.trim()).filter(x => x.startsWith(name + '='));
  const proof = items.length === 1 ? items[0].slice(name.length + 1) : '';
  return valid(proof) ? proof : null;
}

/** Browser-specific local management access, minted only by the authenticated
 * native launcher token. It survives a controller restart, never authenticates
 * MCP, returns no controller/device token, and cannot access general control
 * APIs (shutdown, network, file operations, etc.). A dedicated explicit boolean
 * startup preference is permitted; it cannot choose a program. Host/Origin/fetch
 * metadata validation remains in the HTTP controller. No public localhost GET
 * can mint this capability. Only digests are persisted in private app storage.
 */
export class ManagementSessions {
  constructor({ store, binding, now = Date.now }) {
    Object.assign(this, { store, binding, now }); this.tail = Promise.resolve(); this.records = null;
  }
  async load() {
    if (this.records) return this.records;
    const saved = await this.store.readPrivateRecord('management-sessions');
    if (saved && (saved.version !== 1 || !Array.isArray(saved.sessions) || saved.sessions.length > 16 || saved.sessions.some(s => !valid(s.proofHash) || !valid(s.bindingHash) || !Number.isSafeInteger(s.expiresAt)))) throw new Error('Invalid management sessions; no session was restored.');
    this.records = saved?.sessions || []; return this.records;
  }
  async matching(cookies) {
    const proof = proofFrom(cookies);
    if (!proof) return null;
    const proofHash = digest(proof), bindingHash = digest(this.binding());
    const record = (await this.load()).find(s => s.proofHash === proofHash && s.bindingHash === bindingHash && s.expiresAt > this.now());
    return record ? { record, proof } : null;
  }
  async accepts(request) {
    if (request.headers['x-chat2local-manager'] !== '1' || !managerRoute(request.method, request.url)) return false;
    return Boolean(await this.matching(request.headers.cookie));
  }
  exclusive(action) {
    const work = this.tail.then(action); this.tail = work.catch(() => {}); return work;
  }
  async establish(cookies, launcherAuthenticated) {
    return this.exclusive(async () => {
      const previous = await this.matching(cookies);
      if (previous) return { expiresAt: previous.record.expiresAt, cookie: this.cookie(previous.proof, previous.record.expiresAt) };
      if (!launcherAuthenticated) throw Object.assign(new Error('Open the installed Chat2Local launcher to verify this browser.'), { status: 401 });
      const bindingHash = digest(this.binding()), sessions = (await this.load()).filter(s => s.expiresAt > this.now() && s.bindingHash === bindingHash);
      if (sessions.length >= 16) throw Object.assign(new Error('Too many verified management browsers.'), { status: 429 });
      const proof = randomBytes(32).toString('hex'), expiresAt = this.now() + lifetime;
      const next = [...sessions, { proofHash: digest(proof), bindingHash, expiresAt }];
      await this.store.savePrivateRecord('management-sessions', { version: 1, sessions: next }); this.records = next;
      return { expiresAt, cookie: this.cookie(proof, expiresAt) };
    });
  }
  cookie(proof, expiresAt) {
    // Explicit loopback HTTP service; never set Domain or send this to the relay.
    // Cookie path is not an authorization boundary: managerRoute enforces it.
    return `${name}=${proof}; HttpOnly; SameSite=Strict; Path=/api; Max-Age=${Math.max(0, Math.floor((expiresAt - this.now()) / 1000))}`;
  }
  async logout(cookies) {
    return this.exclusive(async () => {
      const proof = proofFrom(cookies), sessions = await this.load();
      const next = sessions.filter(s => s.expiresAt > this.now() && (!proof || s.proofHash !== digest(proof)));
      await this.store.savePrivateRecord('management-sessions', { version: 1, sessions: next }); this.records = next;
      return `${name}=; HttpOnly; SameSite=Strict; Path=/api; Max-Age=0`;
    });
  }
}
