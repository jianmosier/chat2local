import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeValue, decodeValue } from '../src/relay/rust-oauth-values.mjs';
import { RustOAuthProvider } from '../src/relay/rust-oauth-provider.mjs';
import { readArtifact } from '../scripts/oauth-artifact.mjs';
import { originalProvider, memoryKV, resource } from './oauth-fixture.mjs';

test('sparse array graph preserves holes, own keys, aliases and cycles', () => {
  const value = new Array(10_000), child = { text: '\ud800' };
  value[3] = undefined; value[9999] = child; value['01'] = child;
  value['4294967295'] = 'non-index'; value.self = value;
  const wire = encodeValue(value);
  assert.ok(wire.nodes.length <= 10);
  const result = decodeValue(wire);
  assert.equal(result.length, 10_000);
  assert.deepEqual(Object.keys(result), ['3', '9999', '01', '4294967295', 'self']);
  assert.equal(Object.hasOwn(result, 0), false);
  assert.equal(Object.hasOwn(result, 3), true);
  assert.strictEqual(result[9999], result['01']);
  assert.strictEqual(result.self, result);
  assert.equal(result[9999].text, '\ud800');
  assert.deepEqual(decodeValue({ root: 0, nodes: [['a', [1]], ['n']] }), [null]);
  assert.equal(encodeValue([undefined, 'x']).nodes[0][0], 'a');
  assert.equal(encodeValue([, 'x']).nodes[0][0], 'A');
  const withExtra = ['x']; withExtra.extra = true;
  assert.equal(encodeValue(withExtra).nodes[0][0], 'A');
  assert.deepEqual(decodeValue(encodeValue([undefined, 'x'])), [undefined, 'x']);
});

test('dense repeated undefined stays compact without losing indices or object identity', () => {
  const count = 10_000, wire = encodeValue(Array(count).fill(undefined));
  assert.equal(wire.nodes[0][0], 'a');
  assert.ok(wire.nodes.length <= 3, 'Repeated undefined must not allocate one graph node per item');
  const dense = decodeValue(wire);
  assert.equal(dense.length, count);
  assert.equal(Object.keys(dense).length, count);
  assert.ok(dense.every(value => value === undefined));
  const shared = { missing: undefined }, distinct = { missing: undefined };
  const value = decodeValue(encodeValue([undefined, null, undefined, shared, shared, distinct, -0, 0, NaN]));
  assert.equal(value[0], undefined); assert.equal(value[1], null); assert.equal(value[2], undefined);
  assert.strictEqual(value[3], value[4]); assert.notStrictEqual(value[3], value[5]);
  assert.ok(Object.hasOwn(value[3], 'missing')); assert.equal(value[3].missing, undefined);
  assert.ok(Object.is(value[6], -0)); assert.ok(Object.is(value[7], 0)); assert.ok(Number.isNaN(value[8]));
  assert.equal(decodeValue(encodeValue(undefined)), undefined);
  assert.deepEqual(decodeValue(encodeValue({ another: undefined })), { another: undefined });
});

const directory = process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR;
test('ordinary helper null and missing arguments match pinned provider', { skip: !directory && 'Build an explicit provider artifact' }, async () => {
  const artifact = await readArtifact(directory, { requireProvider: true });
  const { getOAuthApi, AuthorizationError } = await originalProvider();
  const origin = new URL(resource).origin;
  const options = { apiRoute: '/mcp', apiHandler: { fetch() {} }, defaultHandler: { fetch() {} }, authorizeEndpoint: '/authorize', tokenEndpoint: '/oauth/token', clientIdMetadataDocumentEnabled: false, resourceMetadata: { resource } };
  const originalKV = memoryKV(), rustKV = memoryKV();
  const expected = getOAuthApi(options, { OAUTH_KV: originalKV });
  const driver = new RustOAuthProvider(new WebAssembly.Module(artifact.oauthBytes), { authorizationErrorClass: AuthorizationError });
  const actual = driver.helpers({ OAUTH_KV: rustKV }, { origin });
  const capture = async fn => {
    let value, promise = false;
    try { value = fn(); promise = value instanceof Promise; return { promise, value: await value }; }
    catch (error) { return { promise, name: error.name, message: error.message, typeError: error instanceof TypeError, ownName: Object.hasOwn(error, 'name') }; }
  };
  for (const call of [h => h.parseAuthRequest(), h => h.parseAuthRequest(null), h => h.completeAuthorization(), h => h.completeAuthorization(null), h => h.completeAuthorization({}), h => h.completeAuthorization({ request: null }), h => h.listUserGrants('user', null)]) {
    assert.deepEqual(await capture(() => call(actual)), await capture(() => call(expected)));
  }
  const self = []; self.push(self);
  const left = ['x'], right = []; left.push(right); right.push(left, 'x');
  const shared = [left, left];
  for (const id of [self, shared]) {
    assert.deepEqual(await capture(() => actual.listUserGrants(id, null)), await capture(() => expected.listUserGrants(id, null)));
    assert.deepEqual(await capture(() => actual.lookupClient(id)), await capture(() => expected.lookupClient(id)));
  }
  for (const key of ['toString', 'join']) for (const value of [0, null, undefined]) {
    const id = ['x']; id[key] = value;
    for (const input of [id, [id]]) {
      assert.deepEqual(await capture(() => actual.lookupClient(input)), await capture(() => expected.lookupClient(input)));
      assert.deepEqual(await capture(() => actual.listUserGrants(input, null)), await capture(() => expected.listUserGrants(input, null)));
    }
  }
  assert.deepEqual(rustKV.reads, originalKV.reads);
  assert.deepEqual(rustKV.writes, originalKV.writes);
  await Promise.all([...driver.drains]);
});
