import test from 'node:test';
import assert from 'node:assert/strict';
import { compatibleConnect, selectProxyTlsProfile, COMPATIBLE_GROUPS } from '../src/agent/tls-profile.mjs';
import { NetworkManager } from '../src/agent/network.mjs';
const origin = 'https://relay.invalid';

test('TLS compatibility is selected only after default reset and a successful verified alternate probe', async () => {
  const calls = [];
  const profile = await selectProxyTlsProfile(origin, async (url, groups) => {
    calls.push({ url, groups });
    if (!groups) throw Object.assign(new Error('reset'), { code: 'ECONNRESET' });
    return { verified: true, protocol: 'TLSv1.3' };
  });
  assert.equal(profile, 'proxy-compatible');
  assert.deepEqual(calls, [{ url: origin, groups: undefined }, { url: origin, groups: COMPATIBLE_GROUPS }]);
});

test('healthy TLS never uses a compatibility fallback; cert, DNS and proxy errors are not retried', async () => {
  let calls = 0;
  assert.equal(await selectProxyTlsProfile(origin, async () => { calls++; }), 'default');
  assert.equal(calls, 1);
  for (const code of ['DEPTH_ZERO_SELF_SIGNED_CERT', 'ERR_TLS_CERT_ALTNAME_INVALID', 'ENOTFOUND', 'ETIMEDOUT', 'ECONNREFUSED', 'PROXY_AUTH_REQUIRED']) {
    calls = 0;
    await assert.rejects(() => selectProxyTlsProfile(origin, async () => { calls++; throw Object.assign(new Error(code), { code }); }), { code });
    assert.equal(calls, 1);
  }
});

test('relay-scoped TLS option preserves certificate verification, trust, protocol and explicit caller settings', () => {
  const observations = []; const callback = () => {};
  const connect = compatibleConnect((...args) => observations.push(args), 'relay.invalid');
  const options = { servername: 'relay.invalid', host: '127.0.0.1', rejectUnauthorized: true, minVersion: 'TLSv1.2', ca: 'test-ca', socket: {} };
  connect(options, callback);
  assert.deepEqual(observations[0], [{ ...options, ecdhCurve: COMPATIBLE_GROUPS }, callback]);
  assert.equal(Object.hasOwn(options, 'ecdhCurve'), false);
  const explicit = { ...options, ecdhCurve: 'P-384' }; connect(explicit);
  assert.equal(observations[1][0], explicit);
  const other = { ...options, servername: 'other.invalid' }; connect(other);
  assert.equal(observations[2][0], other);
  connect(443, 'relay.invalid', callback); assert.deepEqual(observations[3], [443, 'relay.invalid', callback]);
});

test('TLS compatibility failure does not activate a profile or change the requested network route', async () => {
  let installed = false; let calls = 0;
  const manager = new NetworkManager(() => ({ mode: 'proxy', proxy: 'http://127.0.0.1:9000' }), {
    apply: () => () => {}, selectTls: async () => { calls++; throw new Error('reset'); }, installTls: () => { installed = true; },
  });
  await assert.rejects(() => manager.prepare(origin), /reset/);
  assert.equal(installed, false); assert.equal(calls, 1); assert.equal(manager.status().source, 'error'); manager.close();
});

test('proxy TLS profile is cached for a stable route and removed when switching to direct', async () => {
  let mode = { mode: 'proxy', proxy: 'http://127.0.0.1:9000' }; let probes = 0; let restored = 0;
  const manager = new NetworkManager(() => mode, {
    apply: () => () => {}, selectTls: async () => { probes++; return 'proxy-compatible'; },
    installTls: (url, profile) => { assert.equal(url, origin); return () => { if (profile === 'proxy-compatible') restored++; }; },
  });
  await manager.prepare(origin); await manager.prepare(origin, true);
  assert.equal(probes, 1); assert.equal(manager.status().tlsProfile, 'proxy-compatible');
  mode = { mode: 'direct' }; await manager.prepare(origin);
  assert.equal(probes, 1); assert.equal(restored, 1); assert.equal(manager.status().tlsProfile, 'default'); manager.close();
});

test('late TLS probe cannot install a profile after shutdown', async () => {
  let finish; let installed = false;
  const manager = new NetworkManager(() => ({ mode: 'proxy', proxy: 'http://127.0.0.1:9000' }), {
    apply: () => () => {}, selectTls: () => new Promise(resolve => { finish = resolve; }), installTls: () => { installed = true; },
  });
  const pending = manager.prepare(origin);
  await new Promise(resolve => setImmediate(resolve));
  manager.close(); finish('proxy-compatible');
  await assert.rejects(() => pending, /变化/); assert.equal(installed, false);
});
