import { sha256 } from '../shared/protocol.mjs';

const verified = new WeakMap();
const unavailable = () => Object.assign(new Error('Account sign-in provider is not configured. No device or permission was granted.'), { status: 503, code: 'IDENTITY_NOT_CONFIGURED' });

/** Server-owned adapter. verifySession must validate its upstream session/token
 * (signature, issuer, audience, expiry and applicable nonce/CSRF) using that
 * provider's supported library. It is NOT a function supplied by an HTTP caller.
 * No default implementation trusts email, userId headers, Codex or device keys.
 */
export class AccountIdentity {
  constructor({ verifySession, now = Date.now } = {}) { this.verifySession = verifySession; this.now = now; }
  async authenticate(request) {
    if (typeof this.verifySession !== 'function') throw unavailable();
    const claims = await this.verifySession(request);
    if (!claims) throw Object.assign(new Error('Sign in to the account that owns this connection.'), { status: 401, code: 'ACCOUNT_LOGIN_REQUIRED' });
    const { issuer, subject, sessionId, expiresAt } = claims;
    let url;
    try { url = new URL(issuer); } catch { throw new Error('Invalid verified identity issuer.'); }
    if (typeof issuer !== 'string' || issuer.length > 2048 || url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error('Invalid verified identity issuer.');
    if (typeof subject !== 'string' || !/^[\x21-\x7e]{1,255}$/.test(subject) || typeof sessionId !== 'string' || !sessionId || sessionId.length > 1024 || !Number.isSafeInteger(expiresAt) || expiresAt <= this.now()) throw new Error('Invalid or expired verified account session.');
    // Preserve exact issuer/sub spelling. Email/display name cannot merge accounts.
    const identityKey = await sha256(JSON.stringify([issuer, subject]));
    const sessionBinding = await sha256(JSON.stringify([issuer, subject, sessionId]));
    const principal = Object.freeze({ displayName: typeof claims.displayName === 'string' ? claims.displayName.replace(/[\x00-\x1f\x7f]/g, '').slice(0, 120) : '已登录账号' });
    verified.set(principal, { identityKey, sessionBinding, expiresAt, now: this.now });
    return principal;
  }
}
export function accountPrincipal(principal) {
  const claims = verified.get(principal);
  if (!claims || claims.expiresAt <= claims.now()) throw Object.assign(new Error('A current verified account session is required.'), { status: 401 });
  return { identityKey: claims.identityKey, sessionBinding: claims.sessionBinding };
}

/** Narrow adapter to the existing private Registry binding. Neither the identity
 * assertion nor this route is exposed as an MCP tool/public account API.
 */
export class AccountRepository {
  constructor(request) { if (typeof request !== 'function') throw new Error('Private account transport required.'); this.request = request; }
  async act(principal, action, input = {}) {
    const actor = accountPrincipal(principal);
    return this.request({ action, actor, input });
  }
  async resolve(grant) { return this.request({ action: 'resolve', grant }); }
}
