import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { generateKeyPairSync, sign } from 'node:crypto';
import { GOOGLE_ISSUER, GOOGLE_OIDC, googleCallbackUri } from '../src/shared/google-identity.mjs';
import { oidcConfiguration, verifyIdToken, OidcLogin } from '../src/relay/oidc-login.mjs';
import { checkGoogleClient, inspectGoogleClientFile } from '../scripts/check-google-client.mjs';

const origin = 'https://relay.example.test';
const clientId = '1234567890-fixture.apps.googleusercontent.com';
const clientSecret = 'isolated-test-secret-never-issued-by-Google';
const env = { ACCOUNT_CONNECTIONS: 'true', OIDC_PROVIDER: 'google', OIDC_CLIENT_ID: clientId, OIDC_CLIENT_SECRET: clientSecret };
const exported = () => ({ web: { client_id: clientId, client_secret: clientSecret, redirect_uris: [googleCallbackUri(origin)], auth_uri: 'https://accounts.google.com/o/oauth2/auth', token_uri: 'https://oauth2.googleapis.com/token' } });

test('Google preset pins one backend identity configuration for every desktop platform', () => {
  const config = oidcConfiguration(env, origin);
  assert.equal(config.issuer, GOOGLE_ISSUER);
  assert.equal(config.authorizationEndpoint, GOOGLE_OIDC.OIDC_AUTHORIZATION_ENDPOINT);
  assert.equal(config.tokenEndpoint, GOOGLE_OIDC.OIDC_TOKEN_ENDPOINT);
  assert.equal(config.jwksUri, GOOGLE_OIDC.OIDC_JWKS_URI);
  assert.equal(config.redirectUri, origin + '/account/callback');
  assert.equal(config.method, 'client_secret_post');
  assert.equal(env.OIDC_ISSUER, undefined, 'Preset must not mutate existing settings');
});
test('Google config rejects missing web credentials and endpoint substitutions', () => {
  for (const changes of [{ OIDC_CLIENT_SECRET: undefined }, { OIDC_CLIENT_ID: 'not-a-google-client' }, { OIDC_PROVIDER: 'invented' }, { OIDC_TOKEN_ENDPOINT: 'https://attacker.example/token' }, { OIDC_ISSUER: GOOGLE_ISSUER + '/' }, { ACCOUNT_CONNECTIONS: 'false' }]) assert.throws(() => oidcConfiguration({ ...env, ...changes }, origin));
  assert.throws(() => googleCallbackUri('http://127.0.0.1:47631'));
  assert.throws(() => googleCallbackUri(origin + '/mcp'));
});
test('Google login requests only identity scopes, with PKCE and no forced repeated consent or Google offline token', async () => {
  let count = 0;
  const login = new OidcLogin({ env, origin, records: async (...args) => { assert.equal(args[0], 'put'); count++; }, request: () => { throw new Error('No network expected'); } });
  const response = await login.begin('/account/add');
  const url = new URL(response.headers.get('location'));
  assert.equal(count, 1); assert.equal(url.origin + url.pathname, GOOGLE_OIDC.OIDC_AUTHORIZATION_ENDPOINT);
  assert.equal(url.searchParams.get('scope'), 'openid profile');
  assert.equal(url.searchParams.get('redirect_uri'), origin + '/account/callback');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  for (const key of ['prompt', 'access_type', 'client_secret']) assert.equal(url.searchParams.has(key), false);
  assert.doesNotMatch(url.href, /gmail|drive|isolated-test-secret/);
});
test('both documented Google issuers verify their ORIGINAL signature and map to the same canonical identity', async () => {
  // Genuine RSA signatures using a LOCAL fixture key, NOT Google's production keys.
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...keys.publicKey.export({ format: 'jwk' }), kid: 'google-shaped-test-only', alg: 'RS256', use: 'sig' };
  const now = Date.now(), nonce = 'a'.repeat(64);
  const signToken = (iss, extra = {}) => {
    const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid: jwk.kid })).toString('base64url');
    const p = Buffer.from(JSON.stringify({ iss, aud: clientId, sub: 'fixture-owner', nonce, iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 300, ...extra })).toString('base64url');
    return h + '.' + p + '.' + sign('RSA-SHA256', Buffer.from(h + '.' + p), keys.privateKey).toString('base64url');
  };
  const check = token => verifyIdToken(token, { keys: [jwk] }, { issuer: GOOGLE_ISSUER, clientId, nonce, now });
  const first = await check(signToken(GOOGLE_ISSUER));
  const second = await check(signToken('accounts.google.com'));
  assert.deepEqual(first, second); assert.equal(second.issuer, GOOGLE_ISSUER);
  for (const issuer of [GOOGLE_ISSUER + '/', 'http://accounts.google.com', 'https://accounts.google.com.attacker.example', 'ACCOUNTS.GOOGLE.COM']) await assert.rejects(() => check(signToken(issuer)));
  await assert.rejects(() => check(signToken('accounts.google.com', { aud: 'another-client' })));
  await assert.rejects(() => verifyIdToken(signToken('accounts.google.com'), { keys: [jwk] }, { issuer: 'https://identity.example.test', clientId, nonce, now }));
  const valid = signToken('accounts.google.com'); const parts = valid.split('.');
  parts[1] = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(parts[1], 'base64url')), sub: 'another-owner' })).toString('base64url');
  await assert.rejects(() => check(parts.join('.')), /signature/);
});
test('client export validation returns only public settings, never a secret or activation flag', () => {
  const report = checkGoogleClient(exported(), origin);
  assert.equal(report.redirectUri, origin + '/account/callback');
  assert.deepEqual(report.publicSettings, { OIDC_PROVIDER: 'google', OIDC_CLIENT_ID: clientId });
  assert.equal(report.secretPresent, true); assert.equal(report.googleLoginVerified, false);
  assert.equal(report.accountModeEnabled, false); assert.equal(report.secretsUploaded, false);
  assert.doesNotMatch(JSON.stringify(report), /isolated-test-secret/);
});
test('wrong client type, callback, or export endpoint is rejected before configuration', () => {
  assert.throws(() => checkGoogleClient({ installed: exported().web }, origin));
  assert.throws(() => checkGoogleClient({ type: 'service_account', private_key: 'fixture' }, origin));
  for (const patch of [{ redirect_uris: [origin + '/mcp'] }, { redirect_uris: [origin + '/account/callback/'] }, { redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'] }, { client_secret: undefined }, { token_uri: 'https://attacker.example/token' }]) assert.throws(() => checkGoogleClient({ web: { ...exported().web, ...patch } }, origin));
});
test('file checker uses the selected path, never changes its bytes, and hides malformed credential contents', async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-google-export-')); t.after(() => fs.rm(base, { recursive: true, force: true }));
  const filename = path.join(base, 'client.json');
  const contents = JSON.stringify(exported()); await fs.writeFile(filename, contents);
  assert.equal((await inspectGoogleClientFile(filename, origin)).clientId, clientId);
  assert.equal(await fs.readFile(filename, 'utf8'), contents);
  await fs.writeFile(filename, '{"client_secret":"' + clientSecret + '"');
  await assert.rejects(() => inspectGoogleClientFile(filename, origin), error => !error.message.includes(clientSecret) && error.message.includes('not printed'));
  await assert.rejects(() => inspectGoogleClientFile(path.join(base, 'missing.json'), origin), /could not be found/);
  await assert.rejects(() => inspectGoogleClientFile('relative.json', origin), /absolute path/);
});
