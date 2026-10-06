import { randomSecret, sha256, readLimited } from '../shared/protocol.mjs';
import * as oauth from 'oauth4webapi';
import { identityProviderEnvironment, expectedGoogleTokenIssuer } from '../shared/google-identity.mjs';

const fail = (message, status = 401) => Object.assign(new Error(message), { status });
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
const bytes = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > 32768) throw fail('Malformed identity token.');
  try { return Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0)); } catch { throw fail('Malformed identity token.'); }
};
export function identityCookie(request, name) {
  const matches = (request.headers.get('Cookie') || '').split(';').map(s => s.trim()).filter(s => s.startsWith(name + '='));
  const value = matches.length === 1 ? matches[0].slice(name.length + 1) : null;
  return /^[a-f0-9]{64}$/.test(value || '') ? value : null;
}
export const sessionCookieName = origin => origin.startsWith('https:') ? '__Host-c2l_account' : 'c2l_account';
export function cookieHeader(name, value, origin, maxAge) { return `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${origin.startsWith('https:') ? '; Secure' : ''}`; }
function httpsUrl(value) {
  let url; try { url = new URL(value); } catch { throw fail('Identity provider configuration is incomplete.', 503); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) throw fail('Identity provider must use public HTTPS.', 503);
  return url;
}
export function oidcConfiguration(env, origin) {
  if (env.ACCOUNT_CONNECTIONS !== 'true') throw fail('Account connections are not enabled.', 503);
  env = identityProviderEnvironment(env);
  const issuer = env.OIDC_ISSUER;
  if (httpsUrl(issuer).search) throw fail('Identity issuer must not contain a query.', 503);
  if (typeof env.OIDC_CLIENT_ID !== 'string' || !/^[\x21-\x7e]{1,255}$/.test(env.OIDC_CLIENT_ID)) throw fail('Identity provider client is not configured.', 503);
  const endpoints = ['OIDC_AUTHORIZATION_ENDPOINT', 'OIDC_TOKEN_ENDPOINT', 'OIDC_JWKS_URI'].map(name => httpsUrl(env[name]).href);
  // Explicit, maintainer-configured endpoints; no request-controlled discovery/JKU/redirect fetch.
  const method = env.OIDC_CLIENT_SECRET ? 'client_secret_post' : 'none';
  return { issuer, clientId: env.OIDC_CLIENT_ID, authorizationEndpoint: endpoints[0], tokenEndpoint: endpoints[1], jwksUri: endpoints[2], clientSecret: env.OIDC_CLIENT_SECRET, method, redirectUri: origin + '/account/callback' };
}

/** Narrow OIDC authorization-code/RS256 profile. Cryptography uses WebCrypto;
 * no unsigned, symmetric, implicit, encrypted or token-specified remote keys.
 * Each login validates exact iss/aud/azp, exp/iat/nbf, nonce and PKCE. Upstream
 * access/refresh tokens are never persisted or passed to a desktop/ChatGPT.
 */
export async function verifyIdToken(token, jwks, { issuer, clientId, nonce, now = Date.now(), accessToken } = {}) {
  if (typeof token !== 'string' || token.length > 32768) throw fail('Invalid identity token.');
  const parts = token.split('.'); if (parts.length !== 3) throw fail('Invalid identity token.');
  let header, claims;
  try { header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes(parts[0]))); claims = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes(parts[1]))); } catch { throw fail('Malformed identity token.'); }
  if (!header || header.alg !== 'RS256' || typeof header.kid !== 'string' || header.kid.length > 256 || ['jku','jwk','x5u','crit','b64'].some(k => Object.hasOwn(header, k))) throw fail('Unsupported identity signature.');
  if (!Array.isArray(jwks?.keys) || jwks.keys.length > 32) throw fail('Invalid identity key set.');
  const candidates = jwks.keys.filter(k => k.kid === header.kid && k.kty === 'RSA' && (!k.alg || k.alg === 'RS256') && (!k.use || k.use === 'sig') && (!k.key_ops || (Array.isArray(k.key_ops) && k.key_ops.includes('verify'))) && !k.d);
  if (candidates.length !== 1 || bytes(candidates[0].n).length < 256) throw fail('Unknown or invalid identity signing key.');
  // Delegate ID-token claim and signature processing to the maintained OIDC
  // library. JWKS was fetched from the maintainer-pinned URI; token jku/jwk never
  // controls a network destination. The local adapter below performs no I/O.
  const tokenIssuer = expectedGoogleTokenIssuer(issuer, claims.iss);
  const as = { issuer: tokenIssuer, jwks_uri: new URL('.well-known/jwks.json', issuer).href };
  const client = { client_id: clientId, id_token_signed_response_alg: 'RS256', [oauth.clockTolerance]: 0, [oauth.clockSkew]: Math.floor((now - Date.now()) / 1000) };
  const response = Response.json({ token_type: 'Bearer', access_token: accessToken || 'unused-id-token-validation', id_token: token });
  try {
    const processed = await oauth.processAuthorizationCodeResponse(as, client, response, { expectedNonce: nonce, requireIdToken: true });
    await oauth.validateApplicationLevelSignature(as, response, { [oauth.customFetch]: async url => {
      if (String(url) !== as.jwks_uri) throw fail('Unexpected identity key request.');
      return Response.json(jwks);
    } });
    claims = oauth.getValidatedIdTokenClaims(processed);
  } catch { throw fail('Identity token signature or claims did not verify.'); }
  const seconds = Math.floor(now / 1000), aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== tokenIssuer || aud.length !== 1 || aud[0] !== clientId || (claims.azp !== undefined && claims.azp !== clientId)) throw fail('Identity issuer or audience mismatch.');
  if (!Number.isSafeInteger(claims.exp) || claims.exp <= seconds || !Number.isSafeInteger(claims.iat) || claims.iat > seconds + 30 || claims.iat < seconds - 600 || claims.exp <= claims.iat || (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || claims.nbf > seconds + 30))) throw fail('Identity token is expired or outside this login window.');
  if (claims.nonce !== nonce || !/^[a-f0-9]{64}$/.test(nonce || '') || typeof claims.sub !== 'string' || !/^[\x21-\x7e]{1,255}$/.test(claims.sub)) throw fail('Identity nonce or subject mismatch.');
  if (claims.at_hash !== undefined) {
    if (typeof accessToken !== 'string' || accessToken.length > 16384) throw fail('Invalid identity access-token binding.');
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken));
    if (claims.at_hash !== b64(digest.slice(0, 16))) throw fail('Identity access-token binding mismatch.');
  }
  return { issuer, subject: claims.sub, displayName: typeof claims.name === 'string' ? claims.name.replace(/[\x00-\x1f\x7f]/g, '').slice(0, 120) : '已登录账号' };
}

export class OidcLogin {
  constructor({ env, origin, records, request = fetch, now = Date.now }) { this.config = oidcConfiguration(env, origin); this.origin = origin; this.records = records; this.request = request; this.now = now; }
  async begin(returnPath) {
    const target = typeof returnPath === 'string' ? new URL(returnPath, this.origin) : null;
    const joining = target?.pathname === '/account/add' && [...target.searchParams.keys()].every(k => k === 'connection') && target.searchParams.getAll('connection').length <= 1 && (!target.searchParams.has('connection') || /^[a-f0-9]{32}$/.test(target.searchParams.get('connection')));
    if (!target || returnPath.length > 8192 || !returnPath.startsWith('/') || target.origin !== this.origin || target.hash || !(returnPath.startsWith('/authorize?') || joining)) throw fail('Invalid sign-in continuation.', 400);
    const state = randomSecret(), browser = randomSecret(), nonce = randomSecret(), verifier = randomSecret();
    await this.records('put', 'login', state, { browserHash: await sha256(browser), nonce, verifier, returnPath }, 300);
    const query = new URLSearchParams({ client_id: this.config.clientId, redirect_uri: this.config.redirectUri, response_type: 'code', scope: 'openid profile', state, nonce, code_challenge: await oauth.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256' });
    const authorizationUrl = new URL(this.config.authorizationEndpoint);
    for (const [key, value] of query) authorizationUrl.searchParams.set(key, value);
    return new Response(null, { status: 303, headers: { Location: authorizationUrl.href, 'Set-Cookie': cookieHeader('c2l_oidc_' + state.slice(0, 16), browser, this.origin, 300) } });
  }
  async callback(request) {
    const query = new URL(request.url).searchParams;
    if (['state','code','error','iss'].some(k => query.getAll(k).length > 1)) throw fail('Duplicate identity callback fields.');
    const state = query.get('state'); if (!/^[a-f0-9]{64}$/.test(state || '')) throw fail('Identity callback state is missing.');
    const cookie = identityCookie(request, 'c2l_oidc_' + state.slice(0, 16));
    if (!cookie) throw fail('This sign-in belongs to another browser or has expired.');
    const pending = await this.records('take', 'login', state, { browserHash: await sha256(cookie) });
    if (query.has('error') || !query.get('code') || query.get('code').length > 4096 || (query.has('iss') && query.get('iss') !== this.config.issuer)) throw fail('Identity provider did not complete this sign-in.');
    const body = { grant_type: 'authorization_code', client_id: this.config.clientId, redirect_uri: this.config.redirectUri, code: query.get('code'), code_verifier: pending.verifier, ...(this.config.clientSecret ? { client_secret: this.config.clientSecret } : {}) };
    const response = await this.request(this.config.tokenEndpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body), redirect: 'manual', signal: AbortSignal.timeout(12000) });
    if (!response.ok) throw fail('Identity token exchange failed. Restart sign-in; no connection was authorized.');
    const tokens = JSON.parse(await readLimited(response, 64 * 1024));
    const keyResponse = await this.request(this.config.jwksUri, { redirect: 'manual', signal: AbortSignal.timeout(12000) });
    if (!keyResponse.ok) throw fail('Identity signing keys are unavailable.');
    const jwks = JSON.parse(await readLimited(keyResponse, 64 * 1024));
    const claims = await verifyIdToken(tokens.id_token, jwks, { ...this.config, nonce: pending.nonce, now: this.now(), accessToken: tokens.access_token });
    const secret = randomSecret();
    // A bounded, revocable application session after verified login; NOT a claim
    // that the upstream ID/access token lasts 12h or is refreshed silently.
    await this.records('put', 'session', secret, { ...claims, sessionId: randomSecret(), expiresAt: this.now() + 43200000 }, 43200);
    const headers = new Headers({ Location: this.origin + pending.returnPath });
    headers.append('Set-Cookie', cookieHeader(sessionCookieName(this.origin), secret, this.origin, 43200));
    headers.append('Set-Cookie', cookieHeader('c2l_oidc_' + state.slice(0, 16), '', this.origin, 0));
    return new Response(null, { status: 303, headers });
  }
  async verifySession(request) {
    const secret = identityCookie(request, sessionCookieName(this.origin));
    if (!secret) return null;
    const session = await this.records('get', 'session', secret);
    return session?.expiresAt > this.now() && session.issuer === this.config.issuer ? session : null;
  }
}
