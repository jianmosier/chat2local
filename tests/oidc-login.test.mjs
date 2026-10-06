import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createPrivateKey, sign, randomBytes } from 'node:crypto';
import { verifyIdToken, oidcConfiguration, OidcLogin } from '../src/relay/oidc-login.mjs';
import { OnboardingStore } from '../src/relay/onboarding-store.mjs';

const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...keys.publicKey.export({ format: 'jwk' }), kid: 'test-key', alg: 'RS256', use: 'sig' };
const now = Date.now(), nonce = 'a'.repeat(64), issuer = 'https://identity.example.test', clientId = 'registered-client';
export function signedIdentity(payload, options = {}) {
  const head = Buffer.from(JSON.stringify({ alg: 'RS256', kid: jwk.kid, ...options.header })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${head}.${body}.${sign('RSA-SHA256', Buffer.from(`${head}.${body}`), options.privateKey || keys.privateKey).toString('base64url')}`;
}
const claims = changes => ({ iss: issuer, sub: 'owner-123', aud: clientId, iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 300, nonce, name: 'Owner', ...changes });
const verify = (changes = {}, options = {}) => verifyIdToken(signedIdentity(claims(changes), options), { keys: [jwk] }, { issuer, clientId, nonce, now });

/** Serial transactions with rollback and list, mirroring the private storage API. */
class Records {
  constructor() { this.data = new Map(); this.tail = Promise.resolve(); }
  async get(k) { return structuredClone(this.data.get(k)); }
  transaction(fn) { const work = this.tail.then(async () => { const data = structuredClone(this.data); const tx = { get: async k => structuredClone(data.get(k)), put: async (k,v) => data.set(k, structuredClone(v)), delete: async k => data.delete(k), list: async ({ prefix, limit }) => new Map([...data].filter(([k]) => k.startsWith(prefix)).slice(0, limit)) }; const result = await fn(tx); this.data = data; return result; }); this.tail = work.catch(() => {}); return work; }
}

test('OIDC profile verifies a genuine RS256 signature and stable issuer/sub, not a claimed email or device', async () => {
  assert.equal((await verify()).subject, 'owner-123');
  const result = await verify({ email: 'untrusted@example.test', deviceId: 'same-machine' });
  assert.deepEqual(Object.keys(result).sort(), ['displayName','issuer','subject']);
});
test('OIDC rejects wrong issuer/audience/nonce/time, unsigned tokens, foreign keys and token-controlled remote keys', async () => {
  for (const change of [{ iss: issuer + '/' }, { aud: 'other' }, { aud: [clientId, 'other'] }, { azp: 'other' }, { nonce: 'b'.repeat(64) }, { exp: Math.floor(now / 1000) - 1 }, { iat: Math.floor(now / 1000) + 500 }, { nbf: Math.floor(now / 1000) + 500 }, { sub: '' }, { at_hash: 'bad' }]) await assert.rejects(() => verify(change));
  for (const header of [{ alg: 'none' }, { alg: 'HS256' }, { jku: 'https://attacker.example/keys' }, { jwk }, { crit: ['x'] }]) await assert.rejects(() => verify({}, { header }));
  const foreign = generateKeyPairSync('rsa', { modulusLength: 2048 });
  await assert.rejects(() => verify({}, { privateKey: foreign.privateKey }), /signature/);
  await assert.rejects(() => verifyIdToken(signedIdentity(claims()), { keys: [jwk, jwk] }, { issuer, clientId, nonce, now }), /key/);
});
test('identity provider config is explicit, HTTPS-only and does not normalize an issuer into a different account', () => {
  const env = { ACCOUNT_CONNECTIONS: 'true', OIDC_ISSUER: issuer + '/', OIDC_CLIENT_ID: clientId, OIDC_AUTHORIZATION_ENDPOINT: issuer + '/authorize', OIDC_TOKEN_ENDPOINT: issuer + '/token', OIDC_JWKS_URI: issuer + '/keys' };
  assert.equal(oidcConfiguration(env, 'https://relay.example.test').issuer, issuer + '/');
  assert.throws(() => oidcConfiguration({ ...env, ACCOUNT_CONNECTIONS: 'false' }, 'https://relay.example.test'));
  assert.throws(() => oidcConfiguration({ ...env, OIDC_TOKEN_ENDPOINT: 'http://127.0.0.1/token' }, 'https://relay.example.test'));
});
test('real login implementation binds state to the initiating browser, consumes once and stores no upstream token', async () => {
  const storage = new Records(), store = new OnboardingStore(storage, () => now), origin = 'https://relay.example.test';
  const env = { ACCOUNT_CONNECTIONS: 'true', OIDC_ISSUER: issuer, OIDC_CLIENT_ID: clientId, OIDC_AUTHORIZATION_ENDPOINT: issuer + '/authorize', OIDC_TOKEN_ENDPOINT: issuer + '/token', OIDC_JWKS_URI: issuer + '/keys' };
  let loginNonce, tokenPosts = 0;
  const login = new OidcLogin({ env, origin, now: () => now, records: (action,kind,secret,value,ttl) => store.records({ action,kind,secret,value,ttl }), request: async (url, options) => {
    if (url.endsWith('/keys')) return Response.json({ keys: [jwk] });
    assert.equal(url, issuer + '/token'); assert.equal(options.redirect, 'manual');
    const form = new URLSearchParams(options.body); assert.match(form.get('code_verifier'), /^[a-f0-9]{64}$/); tokenPosts++;
    return Response.json({ id_token: signedIdentity(claims({ nonce: loginNonce })), access_token: 'private-upstream-access-token', refresh_token: 'private-upstream-refresh-token' });
  } });
  const started = await login.begin('/authorize?client_id=original-client');
  const url = new URL(started.headers.get('Location')); loginNonce = url.searchParams.get('nonce');
  const cookie = started.headers.get('Set-Cookie').split(';')[0];
  const callback = origin + '/account/callback?state=' + url.searchParams.get('state') + '&code=auth-code';
  await assert.rejects(() => login.callback(new Request(callback)), /browser/); assert.equal(tokenPosts, 0);
  const completed = await login.callback(new Request(callback, { headers: { Cookie: cookie } }));
  assert.equal(completed.status, 303); assert.equal(completed.headers.get('Location'), origin + '/authorize?client_id=original-client');
  assert.equal(tokenPosts, 1); await assert.rejects(() => login.callback(new Request(callback, { headers: { Cookie: cookie } })));
  const sessionCookie = completed.headers.getSetCookie().find(v => v.startsWith('__Host-c2l_account=')).split(';')[0];
  const session = await login.verifySession(new Request(origin, { headers: { Cookie: sessionCookie } })); assert.equal(session.subject, 'owner-123');
  assert.doesNotMatch(JSON.stringify([...storage.data]), /private-upstream|id_token|code_verifier/);
});
