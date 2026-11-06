import baseTest from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readArtifact, projectRoot } from '../scripts/oidc-token-artifact.mjs';
import { RustOidcTokenVerifier } from '../src/relay/rust-oidc-token.mjs';
import { verifyIdToken } from '../src/relay/oidc-login.mjs';
const directory = process.env.CHAT2LOCAL_OIDC_TOKEN_TEST_ARTIFACT_DIR;
if (process.env.CHAT2LOCAL_OIDC_TOKEN_TEST_REQUIRED === '1' && !directory) throw Error('Strict OIDC token tests require an explicit artifact directory.');
const artifact = directory ? await readArtifact(directory) : null, module = artifact && new WebAssembly.Module(artifact.oidcTokenBytes);
const test = (name, fn) => baseTest(name, { skip: directory ? false : 'Build and explicitly select the OIDC token artifact.' }, fn);
const key = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...key.publicKey.export({ format: 'jwk' }), alg: 'RS256', use: 'sig', kid: 'fixture' };
const issuer = 'https://identity.example.test', now = Date.now(), nonce = 'a'.repeat(64);
const options = { issuer, clientId: 'client', nonce, now, accessToken: 'access' };
const claims = change => ({ iss: issuer, aud: 'client', sub: 'owner', nonce, iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 300, ...change });
function signed(payload = claims(), header = { alg: 'RS256', kid: 'fixture' }) {
  const input = Buffer.from(JSON.stringify(header)).toString('base64url') + '.' + Buffer.from(JSON.stringify(payload)).toString('base64url');
  return input + '.' + sign('RSA-SHA256', Buffer.from(input), key.privateKey).toString('base64url');
}
const verifier = () => new RustOidcTokenVerifier(module);
const verify = (token = signed(), keys = [jwk], opts = options) => verifier().verify(token, JSON.stringify({ keys }), opts);
baseTest('strict token selector rejects missing and conflicting profiles', () => {
  const clean = { ...process.env };
  for (const key of Object.keys(clean)) if (/^CHAT2LOCAL_(OIDC(?:_TOKEN)?|OAUTH(?:_PROVIDER)?|DEVICE|REGISTRY)_TEST_/.test(key)) delete clean[key];
  delete clean.NODE_TEST_CONTEXT;
  for (const selection of [{ CHAT2LOCAL_OIDC_TOKEN_TEST_REQUIRED: '1' }, { CHAT2LOCAL_OIDC_TOKEN_TEST_ARTIFACT_DIR: 'missing-token-artifact' }, { CHAT2LOCAL_OIDC_TOKEN_TEST_ARTIFACT_DIR: 'one', CHAT2LOCAL_OIDC_TEST_ARTIFACT_DIR: 'two' }]) {
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', "const r=await import('./tests/relay-runtime.mjs');await r.relayEntry();"], { cwd: projectRoot, env: { ...clean, ...selection }, windowsHide: true, encoding: 'utf8' });
    assert.equal(r.status, 1); assert.match(r.stderr, /explicit artifact directory|ENOENT|cannot select another Rust relay profile/);
  }
});
test('token artifact has separate profile, dual WASM and public-only no-import core', async () => {
  assert.equal(artifact.manifest.kind, 'oidc-token-verification');
  assert.deepEqual(WebAssembly.Module.imports(module), []);
  assert.ok(artifact.oidcWasmPath); assert.ok(artifact.oidcTokenWasmPath);
  assert.equal(new WebAssembly.Instance(module).exports.frame_capacity(), 65536);
});
test('Rust standard RS256 produces the original identity including UTF16 display projection', async () => {
  const token = signed(claims({ name: '\0Owner\n\ud800' }));
  assert.deepEqual(await verify(token), await verifyIdToken(token, { keys: [jwk] }, options));
});
test('signature and required claim failures remain generic401 before local checks', async () => {
  for (const change of [{ iss: issuer + '/' }, { aud: 'other' }, { nonce: 'other' }, { nbf: Math.floor(now / 1000) + 1 }, { auth_time: -1 }, { exp: 1 }]) await assert.rejects(verify(signed(claims(change))), { status: 401, message: 'Identity token signature or claims did not verify.' });
  const token = signed(); await assert.rejects(verify(token.slice(0, -20) + 'A'.repeat(20)), /signature or claims/);
});
test('wrapper malformed token, header and first-key errors retain their messages', async () => {
  await assert.rejects(verify('x'), /Invalid identity token/);
  await assert.rejects(verify('!.e30.x'), /Malformed identity token/);
  await assert.rejects(verify(signed(claims(), { alg: 'RS256' })), /Unsupported identity signature/);
  await assert.rejects(verify(signed(), []), /Unknown or invalid identity signing key/);
  await assert.rejects(verify(signed(), [{ ...jwk, n: null }]), /Malformed identity token/);
  await assert.rejects(verify(signed(), [null]), TypeError);
});
test('whole-JWKS normalization retains raw infinity first view and validates unrelated SDK members', async () => {
  const text = JSON.stringify({ keys: [jwk, { kid: 'unrelated', kty: 'RSA', n: 'x', e: 'AQAB' }] }).replace('"unrelated"', '1e400');
  assert.equal((await verifier().verify(signed(), text, options)).subject, 'owner');
  await assert.rejects(verify(signed(), [jwk, []]), /signature or claims/);
});
test('JWK DOMString conversion, private-key presence and optional dictionaries follow Worker profile', async () => {
  for (const extra of [{ e: ['AQAB'] }, { e: [['AQAB']] }, { oth: [null, {}, []] }, { crv: {} }, { key_ops: null }]) assert.equal((await verify(signed(), [{ ...jwk, ...extra }])).subject, 'owner');
  for (const extra of [{ d: null }, { d: false }, { crv: { toString: null } }, { oth: ['x'] }, { use: '' }, { key_ops: false }]) await assert.rejects(verify(signed(), [{ ...jwk, ...extra }]), /signature or claims/);
});
test('original Google signed issuer spelling is preserved before identity projection', async () => {
  const opts = { ...options, issuer: 'https://accounts.google.com' };
  assert.equal((await verify(signed(claims({ iss: 'accounts.google.com' })), [jwk], opts)).issuer, opts.issuer);
});
test('at_hash uses Rust SHA256 and only the hash branch limits long access strings', async () => {
  const at_hash = createHash('sha256').update('access').digest().subarray(0, 16).toString('base64url');
  assert.equal((await verify(signed(claims({ at_hash })))).subject, 'owner');
  await assert.rejects(verify(signed(claims({ at_hash: 'bad' }))), /access-token binding mismatch/);
  const opts = { ...options, accessToken: 'a'.repeat(100000) };
  assert.equal((await verify(signed(), [jwk], opts)).subject, 'owner');
  await assert.rejects(verify(signed(claims({ at_hash })), [jwk], opts), /Invalid identity access-token binding/);
});
test('streaming crosses64KiB and preserves the second signature-independent input view', async () => {
  const jwks = JSON.stringify({ keys: [jwk], ignored: 'a'.repeat(60000) });
  assert.equal((await verifier().verify(signed(), jwks, options)).subject, 'owner');
  await assert.rejects(verify(signed(), [jwk], { ...options, issuer: issuer + 'a'.repeat(100000) }), /signature or claims/);
  const longIssuer = issuer + '/' + 'a'.repeat(22000), token = signed(claims({ iss: longIssuer }));
  assert.ok(token.length < 32768); assert.equal((await verify(token, [jwk], { ...options, issuer: longIssuer })).issuer, longIssuer);
});
test('clock strings and ordinary JSON arrays retain original numeric coercion', async () => {
  const token = signed();
  for (const nowValue of [null, false, true, [], [0], [[0]], '0'.repeat(40000), '\ufeff0x0\ufeff', '0b0', '0o0', [String(now)], ['not-a-number']]) {
    const opts = { ...options, now: nowValue };
    const result = async fn => { try { return { ok: true, value: await fn() }; } catch (e) { return { ok: false, name: e.name, message: e.message, status: e.status }; } };
    assert.deepEqual(await result(() => verify(token, [jwk], opts)), await result(() => verifyIdToken(token, { keys: [jwk] }, opts)));
  }
  await assert.rejects(verify(token, [jwk], { ...options, now: { toString: null } }), TypeError);
});
test('ABI sequence failure and reused verifier refuse503 without fallback', async () => {
  const v = verifier(); assert.throws(() => v.execute({ kind: 'eof' }), { status: 503 });
  await assert.rejects(v.verify(signed(), JSON.stringify({ keys: [jwk] }), options), { status: 503 });
  const used = verifier(); await used.verify(signed(), JSON.stringify({ keys: [jwk] }), options);
  await assert.rejects(used.verify(signed(), JSON.stringify({ keys: [jwk] }), options), { status: 503 });
});
