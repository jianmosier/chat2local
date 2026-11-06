import baseTest from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readArtifact, projectRoot } from '../scripts/oidc-artifact.mjs';
import { RustOidcDecisionCore } from '../src/relay/rust-oidc.mjs';
import { OidcLogin } from '../src/relay/oidc-login.mjs';

const directory = process.env.CHAT2LOCAL_OIDC_TEST_ARTIFACT_DIR;
if (process.env.CHAT2LOCAL_OIDC_TEST_REQUIRED === '1' && !directory) throw Error('Strict OIDC tests require an explicit artifact directory.');
const artifact = directory ? await readArtifact(directory) : null, module = artifact && new WebAssembly.Module(artifact.oidcBytes);
const test = (name, fn) => baseTest(name, { skip: directory ? false : 'Build and explicitly select the OIDC artifact.' }, fn);
const origin = 'https://relay.example.test', issuer = 'https://identity.example.test';
const envFor = (value = issuer) => ({ ACCOUNT_CONNECTIONS: 'true', OIDC_ISSUER: value, OIDC_CLIENT_ID: 'client', OIDC_AUTHORIZATION_ENDPOINT: issuer + '/authorize', OIDC_TOKEN_ENDPOINT: issuer + '/token', OIDC_JWKS_URI: issuer + '/keys' });
const factory = () => new RustOidcDecisionCore(module);
baseTest('strict OIDC selection refuses missing, stale and conflicting artifact profiles', () => {
  const clean = { ...process.env };
  for (const key of Object.keys(clean)) if (/^CHAT2LOCAL_(OIDC|OAUTH(?:_PROVIDER)?|DEVICE|REGISTRY)_TEST_/.test(key)) delete clean[key];
  delete clean.NODE_TEST_CONTEXT;
  for (const selection of [{ CHAT2LOCAL_OIDC_TEST_REQUIRED: '1' }, { CHAT2LOCAL_OIDC_TEST_ARTIFACT_DIR: 'missing-oidc-artifact' }, { CHAT2LOCAL_OIDC_TEST_ARTIFACT_DIR: 'one', CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR: 'two' }]) {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', "const runtime = await import('./tests/relay-runtime.mjs'); await runtime.relayEntry();"], { cwd: projectRoot, env: { ...clean, ...selection }, encoding: 'utf8', windowsHide: true });
    assert.equal(result.status, 1); assert.match(result.stderr, /explicit artifact directory|ENOENT|cannot select another Rust relay profile/);
  }
});
function fixture(options = {}) {
  const log = [], data = new Map(); let created = 0;
  const login = new OidcLogin({ origin, env: envFor(options.issuer), decisionFactory: () => { created++; return factory(); },
    records: async (action, kind, secret, value) => {
      log.push(action + ':' + kind);
      const key = kind + ':' + secret;
      if (action === 'put') { data.set(key, value); return {}; }
      const record = data.get(key);
      if (action === 'take') {
        if (!record || record.browserHash !== value.browserHash) throw Object.assign(Error('Sign-in expired.'), { status: 401 });
        data.delete(key);
      }
      return record;
    }, request: options.request || (async () => { log.push('token'); return new Response(null, { status: 400 }); }) });
  return { login, log, data, get created() { return created; } };
}
async function start(f, continuation = '/authorize?client_id=client') {
  const response = await f.login.begin(continuation), url = new URL(response.headers.get('Location'));
  return { state: url.searchParams.get('state'), nonce: url.searchParams.get('nonce'), cookie: response.headers.get('Set-Cookie').split(';')[0] };
}
const callback = (started, query = {}, cookie = started.cookie) => new Request(origin + '/account/callback?' + new URLSearchParams({ state: started.state, code: 'code', ...query }), { headers: cookie ? { Cookie: cookie } : {} });

test('independent artifact selects no-import OIDC ABI v1 and no provider effect runtime', () => {
  assert.equal(artifact.manifest.kind, 'oidc-login-decisions');
  assert.equal(artifact.manifest.profileABI, 1);
  assert.deepEqual(WebAssembly.Module.imports(module), []);
  assert.equal(new WebAssembly.Instance(module).exports.frame_capacity(), 65536);
});

test('begin continuation decision supports authorize and selected joins with bounded projection', async () => {
  const f = fixture();
  for (const continuation of ['/authorize?client_id=x', '/account/add', '/account/add?connection=' + 'a'.repeat(32)]) assert.equal((await f.login.begin(continuation)).status, 303);
  for (const continuation of ['/authorize', '/account/add?connection=x', '/account/add?x=1', '//other.example/authorize?x', '/authorize?x#fragment', '/authorize?' + 'x'.repeat(8192), null]) await assert.rejects(f.login.begin(continuation), { status: 400, message: 'Invalid sign-in continuation.' });
  assert.equal(f.log.filter(v => v === 'put:login').length, 3);
});

test('callback admission rejects duplicates before state, then cookie, before take', async () => {
  const f = fixture(), started = await start(f);
  await assert.rejects(f.login.callback(new Request(origin + '/account/callback?code=a&code=b')), /Duplicate identity callback fields/);
  await assert.rejects(f.login.callback(new Request(origin + '/account/callback?code=a')), /state is missing/);
  await assert.rejects(f.login.callback(callback(started, {}, '')), /another browser/);
  await assert.rejects(f.login.callback(callback(started, {}, started.cookie + '; ' + started.cookie)), /another browser/);
  assert.deepEqual(f.log, ['put:login']);
});

test('post-take error, empty and oversized code, issuer mismatch consume exactly once', async () => {
  for (const query of [{ error: '' }, { code: '' }, { code: 'x'.repeat(4097) }, { iss: issuer + '/' }, { iss: issuer.slice(0, -1) + 'X' }]) {
    const f = fixture(), started = await start(f), request = callback(started, query);
    await assert.rejects(f.login.callback(request), /Identity provider did not complete/);
    await assert.rejects(f.login.callback(request), { status: 401, message: 'Sign-in expired.' });
    assert.deepEqual(f.log, ['put:login', 'take:login', 'take:login']);
    assert.equal(f.created, 3);
  }
});

test('issuer comparison handles long exact UTF16 values in 512-unit frames', async () => {
  const longIssuer = issuer + '/' + 'a'.repeat(20480) + '\ud800';
  const core = factory();
  core.callbackPre(new URLSearchParams({ state: 'a'.repeat(64), code: 'z' })); core.callbackCookie('b'.repeat(64));
  // Direct projection retains the code units used by URLSearchParams, while
  // the configured issuer can contain a lone UTF16 surrogate.
  assert.throws(() => core.callbackAfterTake(new MapQuery({ code: 'z', iss: longIssuer.slice(0, -1) + '\udc00' }), longIssuer), /Identity provider did not complete/);
  const equalCore = factory();
  equalCore.callbackPre(new URLSearchParams({ state: 'a'.repeat(64), code: 'z' })); equalCore.callbackCookie('b'.repeat(64));
  assert.equal(equalCore.callbackAfterTake(new MapQuery({ code: '\ud800z', iss: longIssuer }), longIssuer), '\ud800z');
});
class MapQuery {
  constructor(value) { this.value = value; }
  get(key) { return Object.hasOwn(this.value, key) ? this.value[key] : null; }
  has(key) { return Object.hasOwn(this.value, key); }
}

test('callback code at the 4096 limit reaches original token exchange', async () => {
  const f = fixture(), started = await start(f);
  await assert.rejects(f.login.callback(callback(started, { code: 'x'.repeat(4096), iss: issuer })), /Identity token exchange failed/);
  assert.deepEqual(f.log, ['put:login', 'take:login', 'token']);
});

test('stage failures are permanent 503 and cannot issue a replacement take', () => {
  const core = factory();
  assert.throws(() => core.execute({ kind: 'issuer_finish' }), { status: 503 });
  assert.equal(core.healthy, false);
  assert.throws(() => core.callbackPre(new URLSearchParams({ state: 'a'.repeat(64) })), { status: 503 });
});

test('configured factory cannot silently fall back to JS', async () => {
  for (const decisionFactory of [null, () => null, () => { throw Error('broken'); }]) {
    const login = new OidcLogin({ env: envFor(), origin, decisionFactory, records: () => { throw Error('must not store'); } });
    await assert.rejects(login.begin('/authorize?x'), { status: 503 });
  }
});

test('one OidcLogin supports signed begin/callback/repeat and concurrent operations', async () => {
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...keys.publicKey.export({ format: 'jwk' }), kid: 'fixture', alg: 'RS256', use: 'sig' };
  const nonces = new Map(); let tokenCalls = 0;
  const f = fixture({ request: async (url, options) => {
    if (url.endsWith('/keys')) return Response.json({ keys: [jwk] });
    tokenCalls++; const form = new URLSearchParams(options.body), seconds = Math.floor(Date.now() / 1000);
    const head = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'fixture' })).toString('base64url');
    const body = Buffer.from(JSON.stringify({ iss: issuer, aud: 'client', sub: 'owner', nonce: nonces.get(form.get('code')), iat: seconds, exp: seconds + 300 })).toString('base64url');
    const token = head + '.' + body + '.' + sign('RSA-SHA256', Buffer.from(head + '.' + body), keys.privateKey).toString('base64url');
    return Response.json({ id_token: token, access_token: 'upstream-never-stored' });
  } });
  const first = await start(f), second = await start(f); nonces.set('first', first.nonce); nonces.set('second', second.nonce);
  const responses = await Promise.all([f.login.callback(callback(first, { code: 'first' })), f.login.callback(callback(second, { code: 'second', iss: issuer }))]);
  assert.equal(tokenCalls, 2); assert.equal(f.created, 4);
  for (const response of responses) {
    assert.equal(response.status, 303);
    const cookies = response.headers.getSetCookie(); assert.equal(cookies.length, 2);
    const session = await f.login.verifySession(new Request(origin, { headers: { Cookie: cookies.find(c => c.startsWith('__Host-c2l_account=')).split(';')[0] } }));
    assert.equal(session.subject, 'owner');
  }
  await assert.rejects(f.login.callback(callback(first, { code: 'first' })), { status: 401, message: 'Sign-in expired.' });
  assert.doesNotMatch(JSON.stringify([...f.data]), /upstream-never-stored|id_token|code_verifier/);
});
