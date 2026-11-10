import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { EventEmitter } from 'node:events';
import { readTransportArtifact } from '../scripts/transport-artifact.mjs';
import { executable, native, nativeSession, oracle, mint, listen, waitClosed, addresses, destination, proxy, clientHelloServer, clientFrameReader, serveWebSocketFixture, frame } from './transport-fixture.mjs';

const required = process.env.CHAT2LOCAL_TRANSPORT_TEST_REQUIRED === '1';
if (required && !executable) throw Error('Required native transport artifact is missing.');
if (executable) await readTransportArtifact(executable);
const nativeTest = (name, fn) => test(name, { skip: !executable && 'Build the explicit native transport fixture first.', timeout: 120000 }, fn);
const good = result => { assert.equal(result.ok, true, JSON.stringify(result.error)); return result.result; };
const bad = (result, code, stage) => { assert.equal(result.ok, false); if (code) assert.equal(result.error.code, code); if (stage) assert.equal(result.error.stage, stage); return result.error; };
const direct = { mode: 'direct' };
let root, leaf, outer;
async function certificates() { if (!root) { root = await mint(); leaf = await mint({ issuer_cert: root.cert, issuer_key: root.key, cn: 'relay.example.test', dns: ['relay.example.test'] }); outer = await mint({ issuer_cert: root.cert, issuer_key: root.key, dns: ['proxy.example.test'] }); } return { root, leaf, outer }; }
function input(endpoint, { scheme = 'https', hostname = 'relay.example.test', ...rest } = {}) { return { op: scheme.startsWith('ws') ? 'ws' : 'request', target: `${scheme}://${hostname}:${endpoint.port}/`, settings: direct, ca: root?.cert, addresses: addresses([hostname, endpoint]), ...rest }; }
function through(endpoint, intermediary, options = {}) { const { scheme = 'https', proxyScheme = 'http', credentials = '', ...rest } = options; return input(endpoint, { scheme, settings: { mode: 'auto' }, env: { HTTPS_PROXY: `${proxyScheme}://${credentials}proxy.example.test:${intermediary.port}`, HTTP_PROXY: `${proxyScheme}://${credentials}proxy.example.test:${intermediary.port}` }, addresses: addresses(['relay.example.test', endpoint], ['proxy.example.test', intermediary]), ...rest }); }

function maskedFrame(payload, opcode = 1) {
  const unmasked = frame(payload, opcode), offset = unmasked.length - payload.length;
  const header = Buffer.from(unmasked.subarray(0, offset)), mask = Buffer.from([8, 2, 3, 4]), encoded = Buffer.from(payload);
  header[1] |= 128;
  for (let i = 0; i < encoded.length; i++) encoded[i] ^= mask[i % 4];
  return Buffer.concat([header, mask, encoded]);
}
function fixtureSocket(head = Buffer.alloc(0)) {
  const socket = new EventEmitter(), writes = [], ends = [], state = { payloads: 0 };
  socket.write = bytes => writes.push(bytes); socket.end = bytes => ends.push(bytes); socket.destroy = () => assert.fail('Unexpected fixture parser refusal');
  serveWebSocketFixture(socket, { head, state });
  return { socket, writes, ends, state };
}
test('WebSocket fixture waits for full masked data and split close frames', () => {
  const { socket, writes, ends, state } = fixtureSocket(), data = maskedFrame(Buffer.from('node exchange'));
  socket.emit('data', data.subarray(0, 2)); assert.equal(writes.length, 0); assert.equal(state.payloads, 0);
  socket.emit('data', data.subarray(2)); assert.equal(writes.length, 1); assert.equal(ends.length, 0); assert.equal(state.payloads, 1);
  assert.deepEqual(writes[0], frame(Buffer.from('native echo')));
  const close = maskedFrame(Buffer.from([3, 232]), 8);
  socket.emit('data', close.subarray(0, 1)); assert.equal(ends.length, 0);
  socket.emit('data', close.subarray(1)); assert.deepEqual(ends, [frame(Buffer.from([3, 232]), 8)]);
});
test('WebSocket fixture retains upgrade head and consumes coalesced frames once', () => {
  const data = maskedFrame(Buffer.from('node exchange')), { socket, writes, ends, state } = fixtureSocket(data.subarray(0, 5));
  assert.equal(writes.length, 0);
  socket.emit('data', Buffer.concat([data.subarray(5), maskedFrame(Buffer.from('ping'), 9), maskedFrame(Buffer.alloc(0), 8), data]));
  assert.deepEqual(writes, [frame(Buffer.from('native echo')), frame(Buffer.from('ping'), 10)]);
  assert.deepEqual(ends, [frame(Buffer.alloc(0), 8)]); assert.equal(state.payloads, 1);
});
test('WebSocket fixture handles split extended headers and complete 512KiB payloads', () => {
  for (const size of [126, 512 * 1024]) {
    const payload = Buffer.alloc(size, 97), encoded = maskedFrame(payload), received = [], read = clientFrameReader(value => received.push(value));
    for (let i = 0; i < 15; i++) read(encoded.subarray(i, i + 1));
    assert.equal(received.length, 0); read(encoded.subarray(15, encoded.length - 1)); assert.equal(received.length, 0);
    read(encoded.subarray(-1)); assert.equal(received.length, 1); assert.deepEqual(received[0].payload, payload);
  }
});

nativeTest('native artifact provenance, pinned oracle, fail-closed manifest and input boundary', async () => {
  const version = await native({ op: 'version' }); assert.equal(version.fixtureOnly, true); assert.match(version.openssl, /^OpenSSL 3\.5\.8 /); assert.equal(version.drivers, 'inline-owned');
  assert.equal((await oracle({ op: 'version' })).node, 'v24.21.0');
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'transport-artifact-'));
  try { const original = JSON.parse(await fs.readFile(path.join(path.dirname(executable), 'manifest.json'))); const copied = path.join(temporary, path.basename(executable)); await fs.copyFile(executable, copied);
    await fs.writeFile(path.join(temporary, 'manifest.json'), JSON.stringify({ ...original, sha256: '0'.repeat(64) })); await assert.rejects(readTransportArtifact(copied), /binary mismatch/);
    original.sources['Cargo.lock'] = '0'.repeat(64); await fs.writeFile(path.join(temporary, 'manifest.json'), JSON.stringify(original)); await assert.rejects(readTransportArtifact(copied), /Stale/);
  } finally { await fs.rm(temporary, { recursive: true, force: true }); }
  bad(await native({ op: 'request', target: 'http://relay.example.test/', addresses: { 'relay.example.test': '192.0.2.1:80' } }), 'invalid_input');
});

nativeTest('startup trust is explicit; unsupported/insecure options refuse; extra CA is read once', async () => {
  for (const env of [{ NODE_TLS_REJECT_UNAUTHORIZED: '0' }, { NODE_OPTIONS: '--use-system-ca' }, { NODE_OPTIONS: '--use-openssl-ca' }, { NODE_OPTIONS: '--tls-min-v1.1' }, { SSL_CERT_FILE: 'unsupported.pem' }, { SSL_CERT_FILE: '0' }, { NODE_USE_SYSTEM_CA: '1' }, { OPENSSL_CONF: 'unsupported.cnf' }]) bad(await native({ op: 'policy', env }), 'incompatible_policy');
  good(await native({ op: 'policy', env: { NODE_OPTIONS: '--use-bundled-ca --tls-min-v1.2 --tls-max-v1.3' } }));
  await certificates(); const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'transport-extra-')); const endpoint = await destination({ certificate: leaf });
  try { const pem = path.join(temp, 'extra.pem'); await fs.writeFile(pem, root.cert); good(await native(input(endpoint, { ca: undefined, env: { NODE_EXTRA_CA_CERTS: pem } }))); }
  finally { await endpoint.close(); await fs.rm(temp, { recursive: true, force: true }); }
});

nativeTest('direct HTTP HTTPS WS WSS perform real exchanges; TLS 1.2 and 1.3', async () => {
  await certificates();
  for (const scheme of ['http', 'https', 'ws', 'wss']) { const endpoint = await destination({ certificate: ['https', 'wss'].includes(scheme) ? leaf : undefined });
    try { const request = input(endpoint, { scheme }); const result = good(await native(request)); if (scheme.startsWith('ws')) assert.equal(result.text, 'native echo'); else assert.equal(result.status, 200); assert.equal(result.proxied, false); assert.equal(endpoint.seen.credentialSafe, true); assert.equal(await waitClosed(endpoint), true); const comparison = await oracle(request); if (!comparison.ok) comparison.error.serverEvents = endpoint.seen.events; good(comparison); }
    finally { await endpoint.close(); }
  }
  for (const version of ['TLSv1.2', 'TLSv1.3']) { const endpoint = await destination({ certificate: leaf, minVersion: version, maxVersion: version }); try { assert.equal(good(await native(input(endpoint))).tls_protocol, version); good(await oracle(input(endpoint))); } finally { await endpoint.close(); } }
  const legacy = await destination({ certificate: { ...leaf, ciphers: 'DEFAULT:@SECLEVEL=0' }, minVersion: 'TLSv1.1', maxVersion: 'TLSv1.1' });
  try { bad(await native(input(legacy)), 'tls', 'target_tls'); assert.equal(legacy.state.accepted, 1); assert.equal(legacy.seen.requests, 0); bad(await oracle(input(legacy))); } finally { await legacy.close(); }
});

nativeTest('HTTP proxies tunnel all four protocols; HTTPS proxies use independent outer and inner TLS', async () => {
  await certificates();
  for (const [proxyScheme, scheme] of [['http', 'http'], ['http', 'https'], ['http', 'ws'], ['http', 'wss'], ['https', 'https'], ['https', 'wss']]) {
    const endpoint = await destination({ certificate: ['https', 'wss'].includes(scheme) ? leaf : undefined });
    const intermediary = await proxy({ target: endpoint, certificate: proxyScheme === 'https' ? outer : undefined, expectedBasic: 'Basic ' + Buffer.from('fixture:secret').toString('base64') });
    try { const request = through(endpoint, intermediary, { scheme, proxyScheme, credentials: 'fixture:secret@', headers: [['Authorization', 'Bearer synthetic-origin'], ['Cookie', 'synthetic=cookie'], ...(scheme.startsWith('ws') ? [['Sec-WebSocket-Protocol', 'synthetic-device-protocol']] : [])] });
      assert.equal(good(await native(request)).proxied, true); assert.equal(intermediary.seen.tunnels, 1); assert.equal(intermediary.seen.upstream, 1); assert.equal(intermediary.seen.authMatches, true); assert.equal(intermediary.seen.isolated, true); assert.equal(endpoint.seen.credentialSafe, true); assert.deepEqual(intermediary.seen.authorities, [`relay.example.test:${endpoint.port}`]);
      good(await oracle({ ...request, headers: [] })); assert.equal(intermediary.seen.tunnels, 2);
    } finally { await intermediary.close(); await endpoint.close(); }
  }
});

nativeTest('Business and Probe route decisions match original Node functions, including lowercase presence', async () => {
  const rows = [ ['example.test', 'example.test'], ['a.example.test', 'example.test'], ['example.test', '*.example.test'], ['a.example.test', '*.example.test'], ['example.test', '.example.test'], ['a.example.test', '.example.test'], ['a.example.test', '*,localhost'], ['a.example.test', 'a.example.test:443'], ['a.example.test', 'example.test:443'], ['10.0.0.2', '10.0.0.1-10.0.0.3'], ['127.attacker.invalid', '127.0.0.1'], ['localhost', ''], ['127.0.0.1', ''], ['[::1]', ''] ];
  for (const [host, bypass] of rows) for (const consumer of ['business', 'probe']) { const request = { op: 'route', consumer, target: `https://${host}/`, env: { HTTPS_PROXY: 'http://proxy.example.test:8000', NO_PROXY: bypass } }; const a = good(await native(request)), b = good(await oracle(request)); assert.equal(a.proxied, b.proxied, `${host}/${bypass}/${consumer}`); }
  for (const env of [{ https_proxy: '', HTTPS_PROXY: 'http://ignored.example.test', HTTP_PROXY: 'http://proxy.example.test' }, { HTTPS_PROXY: 'http://proxy.example.test', ALL_PROXY: 'socks5://unused.example.test' }, { https_proxy: '', HTTPS_PROXY: 'http://ignored.example.test' }, { HTTPS_PROXY: 'http://proxy.example.test', no_proxy: '', NO_PROXY: '*' }]) { const request = { op: 'route', target: 'https://relay.example.test/', env }; assert.equal(good(await native(request)).proxied, good(await oracle(request)).proxied); }
  for (const value of ['socks5://proxy.example.test', 'http://proxy.example.test/path', 'http://bad%FF:x@proxy.example.test', 'http://bad%:x@proxy.example.test']) bad(await native({ op: 'route', target: 'https://relay.example.test/', env: { HTTPS_PROXY: value } }), 'invalid_input');
});

nativeTest('actual bypass/proxy counters and consumer-specific Basic behavior', async () => {
  await certificates();
  for (const [credentials, business, probeAuth] of [['user@', null, 'user:'], [':pass@', null, ':pass'], ['u%3Aer:p%C3%A4ss@', 'u:er:päss', 'u:er:päss']]) {
    const endpoint = await destination({ certificate: leaf });
    for (const op of ['request', 'probe']) { const expected = op === 'probe' ? probeAuth : business; const intermediary = await proxy({ target: endpoint, expectedBasic: expected && 'Basic ' + Buffer.from(expected).toString('base64') });
      try { const request = through(endpoint, intermediary, { op, credentials }); good(await native(request)); assert.equal(intermediary.seen.tunnels, 1); assert.equal(intermediary.seen.authMatches, true); good(await oracle(request)); assert.equal(intermediary.seen.authMatches, true); }
      finally { await intermediary.close(); }
    } await endpoint.close();
  }
  const endpoint = await destination({ certificate: leaf }), intermediary = await proxy({ target: endpoint });
  try { for (const [bypass, business, probeCount] of [['example.test', 0, 1], ['*.example.test', 0, 0], ['*,localhost', 1, 0]]) {
    const before = intermediary.seen.tunnels; const request = through(endpoint, intermediary); request.env.NO_PROXY = bypass; good(await native(request)); assert.equal(intermediary.seen.tunnels - before, business); good(await native({ ...request, op: 'probe' })); assert.equal(intermediary.seen.tunnels - before, business + probeCount);
  }} finally { await intermediary.close(); await endpoint.close(); }
});

nativeTest('certificate chain, name, SAN/CN/IP/wildcard/trailing-dot/IDNA differentials send zero business bytes on refusal', async () => {
  await certificates();
  const rows = [
    { host: 'relay.example.test', dns: ['relay.example.test'], pass: true },
    { host: 'relay.example.test', dns: ['wrong.example.test'], cn: 'relay.example.test', pass: false },
    { host: 'relay.example.test', cn: 'relay.example.test', pass: true },
    { host: 'relay.example.test', dns: ['*.example.test'], pass: true },
    { host: 'relay.example.test', dns: ['r*y.example.test'], pass: true },
    { host: 'a.b.example.test', dns: ['*.example.test'], pass: false },
    { host: 'example.test', dns: ['*.test'], pass: false },
    { host: 'relay.example.test.', dns: ['relay.example.test'], pass: true },
    { host: 'bücher.example.test', dns: ['xn--bcher-kva.example.test'], pass: true },
    { host: '127.0.0.1', ips: ['127.0.0.1'], pass: true },
    { host: '127.0.0.1', cn: '127.0.0.1', pass: false },
    { host: 'relay.example.test', cn: 'relay.example.test', ips: ['127.0.0.1'], pass: true },
    { host: 'relay.example.test', dns: ['relay.example.test'], not_before: -86400, not_after: -60, pass: false },
    { host: 'relay.example.test', dns: ['relay.example.test'], not_before: 3600, not_after: 86400, pass: false },
  ];
  for (const row of rows) { const { host, pass, ...fields } = row; const cert = await mint({ issuer_cert: root.cert, issuer_key: root.key, ...fields }); const endpoint = await destination({ certificate: cert });
    try { const normalized = new URL(`https://${host}`).hostname; const request = input(endpoint, { hostname: host, addresses: addresses([normalized, endpoint]) }); const a = await native(request), b = await oracle(request); assert.equal(a.ok, pass, `native ${host}: ${JSON.stringify(a.error)}`); assert.equal(b.ok, pass, `Node ${host}: ${JSON.stringify(b.error)}`); assert.equal(endpoint.seen.requests, pass ? 2 : 0); } finally { await endpoint.close(); }
  }
  const endpoint = await destination({ certificate: leaf }); try { bad(await native(input(endpoint, { ca: undefined })), 'certificate', 'target_tls'); bad(await oracle(input(endpoint, { ca: undefined }))); assert.equal(endpoint.seen.requests, 0); } finally { await endpoint.close(); }
});

nativeTest('outer versus inner TLS CA/name refusal counters; no downgrade to direct', async () => {
  await certificates(); const unknown = await mint(); const unknownOuter = await mint({ issuer_cert: unknown.cert, issuer_key: unknown.key, dns: ['proxy.example.test'] }); const unknownLeaf = await mint({ issuer_cert: unknown.cert, issuer_key: unknown.key, dns: ['relay.example.test'] });
  for (const [proxyCert, targetCert, code, stage, tunnels] of [[unknownOuter, leaf, 'certificate', 'proxy_tls', 0], [leaf, leaf, 'hostname', 'proxy_tls', 0], [outer, unknownLeaf, 'certificate', 'target_tls', 1], [outer, outer, 'hostname', 'target_tls', 1]]) {
    const endpoint = await destination({ certificate: targetCert }), intermediary = await proxy({ target: endpoint, certificate: proxyCert });
    try { bad(await native(through(endpoint, intermediary, { proxyScheme: 'https' })), code, stage); assert.equal(intermediary.seen.tunnels, tunnels); assert.equal(endpoint.seen.requests, 0); assert.equal(endpoint.state.accepted, tunnels); }
    finally { await intermediary.close(); await endpoint.close(); }
  }
});

nativeTest('proxy failures do not retry or fall back; reachable direct positive control; CONNECT parser bounds', async () => {
  await certificates(); const endpoint = await destination({ certificate: leaf });
  try { good(await native(input(endpoint))); const directCount = endpoint.state.accepted;
    for (const options of [{ status: 407 }, { status: 403 }, { status: 502 }, { raw: 'garbage\r\n\r\n' }, { raw: 'HTTP/1.1 200 OK\r\nBad Header: value\r\n\r\n' }, { raw: 'HTTP/1.1 200 OK\r\nHeader: x\u0000y\r\n\r\n' }, { raw: '' }, { raw: 'HTTP/1.1 200 OK\r\nHeader: ' + 'x'.repeat(9000) + '\r\n\r\n' }, { stall: true }]) {
      const intermediary = await proxy({ target: endpoint, ...options }); try { const r = await native(through(endpoint, intermediary, { timeout_ms: 150 })); bad(r); assert.equal(r.error.send_state, 'definitely_not_submitted'); assert.equal(intermediary.seen.tunnels, 1); assert.equal(intermediary.seen.upstream, 0); assert.equal(endpoint.state.accepted, directCount); assert.equal(await waitClosed(intermediary), true); } finally { await intermediary.close(); }
    }
  } finally { await endpoint.close(); }
});

nativeTest('probe resets and TLS EOF get one fresh same-route attempt; observed groups match Node; status 404/500 succeeds', async () => {
  await certificates();
  const policies = [];
  for (const failure of ['eof', 'rst']) for (const runner of [native, oracle]) {
    const endpoint = await destination({ certificate: leaf, handler: (req, res) => { assert.equal(req.method, 'HEAD'); assert.equal(req.url, '/healthz'); assert.equal(req.headers.authorization, undefined); assert.equal(req.headers.cookie, undefined); assert.equal(req.headers.connection, 'close'); res.writeHead(500); res.end(); } });
    const reset = await clientHelloServer({ next: endpoint, failure }), intermediary = await proxy({ target: reset });
    try { assert.equal(good(await runner(through(endpoint, intermediary, { op: 'probe' }))).profile, 'proxy-compatible'); assert.equal(intermediary.seen.tunnels, 2); assert.equal(endpoint.seen.requests, 1); assert.ok(reset.groups[0].includes(4588), 'default hybrid group'); assert.deepEqual(reset.groups[1], [29, 23]); policies.push(reset.hellos); }
    finally { await intermediary.close(); await reset.close(); await endpoint.close(); }
  }
  assert.deepEqual(policies[0], policies[1], 'full native and pinned Node groups/cipher suites/ALPN'); assert.deepEqual(policies[2], policies[3]);
  const endpoint = await destination({ certificate: leaf, handler: (req, res) => { res.writeHead(404); res.end(); } }), intermediary = await proxy({ target: endpoint });
  try { assert.equal(good(await native(through(endpoint, intermediary, { op: 'probe' }))).profile, 'default'); assert.equal(intermediary.seen.tunnels, 1); } finally { await intermediary.close(); await endpoint.close(); }
});

nativeTest('distinct HTTPS proxy keeps default groups while compatible relay uses X25519 P-256', async () => {
  await certificates(); const endpoint = await destination({ certificate: leaf }), targetHello = await clientHelloServer({ next: endpoint, failCount: 0 }), intermediary = await proxy({ target: targetHello, certificate: outer }), outerHello = await clientHelloServer({ next: intermediary, failCount: 0 });
  try { const request = through(endpoint, outerHello, { proxyScheme: 'https', profile: 'proxy-compatible' }); good(await native(request)); assert.ok(outerHello.groups[0].includes(4588)); assert.deepEqual(targetHello.groups[0], [29, 23]); }
  finally { await outerHello.close(); await intermediary.close(); await targetHello.close(); await endpoint.close(); }
});

nativeTest('probe certificate DNS 407 and timeout never trigger compatibility retry', async () => {
  await certificates(); const endpoint = await destination({ certificate: outer });
  for (const options of [{}, { status: 407 }, { stall: true }]) { const intermediary = await proxy({ target: endpoint, ...options });
    try { bad(await native(through(endpoint, intermediary, { op: 'probe' }))); assert.equal(intermediary.seen.tunnels, 1); } finally { await intermediary.close(); }
  }
  const intermediary = await proxy({ target: endpoint }); try { const request = through(endpoint, intermediary, { op: 'probe' }); request.addresses = {}; bad(await native(request), 'dns'); assert.equal(intermediary.state.accepted, 0); } finally { await intermediary.close(); await endpoint.close(); }
});

nativeTest('business POST unknown outcome is not resent; redirects are not followed; response body bounded', async () => {
  let sideEffects = 0; const severed = await destination({ handler: (req, res) => { req.resume(); req.once('end', () => { sideEffects++; res.socket.destroy(); }); } });
  try { const error = bad(await native(input(severed, { scheme: 'http', method: 'POST', body: 'mutation' }))); assert.equal(error.send_state, 'possibly_submitted'); assert.equal(sideEffects, 1); assert.equal(severed.state.accepted, 1); } finally { await severed.close(); }
  const target = await destination(), redirect = await destination({ handler: (req, res) => { res.writeHead(302, { Location: `http://127.0.0.1:${target.port}/` }); res.end(); } });
  try { assert.equal(good(await native(input(redirect, { scheme: 'http' }))).status, 302); assert.equal(target.seen.requests, 0); } finally { await redirect.close(); await target.close(); }
  const large = await destination({ handler: (req, res) => { res.write(Buffer.alloc(300000)); res.end(Buffer.alloc(300000)); } }); try { bad(await native(input(large, { scheme: 'http' })), 'limit', 'http'); assert.equal(await waitClosed(large), true); } finally { await large.close(); }
});

nativeTest('cancel/revise/close/deadline actually release sockets across TLS CONNECT HTTP and WS', async () => {
  await certificates();
  for (const lifecycle of [{ cancel_ms: 50 }, { revise_ms: 50 }, { close_ms: 50 }, { timeout_ms: 50 }]) {
    for (const stage of ['tls', 'connect', 'http', 'ws']) {
      const endpoint = stage === 'tls' ? await listen(net.createServer(socket => socket.on('data', () => {}))) : await destination({ handler: () => {}, ws: 'stall' });
      const intermediary = stage === 'connect' ? await proxy({ target: endpoint, stall: true }) : null;
      const session = nativeSession();
      try { const request = stage === 'connect' ? through(endpoint, intermediary, lifecycle) : input(endpoint, { scheme: stage === 'tls' ? 'https' : stage === 'ws' ? 'ws' : 'http', ...lifecycle }); const error = bad(await session.request(request)); assert.equal(error.code, lifecycle.revise_ms ? 'stale' : lifecycle.timeout_ms ? 'timeout' : 'cancelled'); assert.equal(session.alive, true); assert.equal(await waitClosed(intermediary ?? endpoint), true); assert.equal(session.alive, true); }
      finally { await session.close(); await intermediary?.close(); await endpoint.close(); }
    }
  }
  for (const revise_ms of [50, 150]) { const endpoint = await destination({ certificate: leaf }); const reset = await clientHelloServer({ next: endpoint, failure: 'stall' }), intermediary = await proxy({ target: reset }); try { bad(await native(through(endpoint, intermediary, { op: 'probe', revise_ms })), 'stale'); assert.equal(await waitClosed(intermediary), true); assert.equal(endpoint.seen.requests, 0); } finally { await intermediary.close(); await reset.close(); await endpoint.close(); } }
});

nativeTest('WebSocket fragmented aggregate limit and control-message loop are bounded with real socket close', async () => {
  for (const ws of ['fragments', 'controls']) { const endpoint = await destination({ ws }); try { bad(await native(input(endpoint, { scheme: 'ws' })), 'limit', 'web_socket'); assert.equal(endpoint.seen.payloads, 1); assert.equal(await waitClosed(endpoint), true); } finally { await endpoint.close(); } }
});

nativeTest('numeric NO_PROXY ports preserve Node Number semantics and never bypass on overflow', async () => {
  for (const suffix of ['65536', '999999', '0', '0443', '999999999999999999999999999999']) for (const consumer of ['business', 'probe']) {
    const request = { op: 'route', consumer, target: 'https://relay.example.test/', env: { HTTPS_PROXY: 'http://proxy.example.test:8000', NO_PROXY: `example.test:${suffix}` } };
    assert.equal(good(await native(request)).proxied, good(await oracle(request)).proxied, `${suffix}/${consumer}`);
  }
  await certificates(); const endpoint = await destination({ certificate: leaf }), intermediary = await proxy({ target: endpoint });
  try { for (const suffix of ['65536', '999999', '0']) for (const runner of [native, oracle]) { const before = intermediary.seen.tunnels, request = through(endpoint, intermediary); request.env.NO_PROXY = `example.test:${suffix}`; good(await runner(request)); assert.equal(intermediary.seen.tunnels - before, suffix === '0' ? 0 : 1); } }
  finally { await intermediary.close(); await endpoint.close(); }
});

nativeTest('one immutable relay plan serves HTTPS and WSS through the same route', async () => {
  await certificates(); const endpoint = await destination({ certificate: leaf }), intermediary = await proxy({ target: endpoint, certificate: outer });
  try { const r = good(await native(through(endpoint, intermediary, { op: 'http_ws', proxyScheme: 'https' }))); assert.equal(r.status, 200); assert.equal(r.text, 'native echo'); assert.equal(r.proxied, true); assert.equal(intermediary.seen.tunnels, 2); assert.equal(endpoint.seen.requests, 1); assert.equal(endpoint.seen.upgrades, 1); }
  finally { await intermediary.close(); await endpoint.close(); }
});

nativeTest('malformed DNS SAN cannot fall back to matching CN; fixture CA cannot bypass startup policy', async () => {
  await certificates();
  for (const env of [{ NODE_TLS_REJECT_UNAUTHORIZED: '0' }, { NODE_OPTIONS: '--use-system-ca' }]) bad(await native({ op: 'policy', ca: root.cert, env }), 'incompatible_policy');
  const malformed = await mint({ issuer_cert: root.cert, issuer_key: root.key, cn: 'relay.example.test', malformed_dns: true }), endpoint = await destination({ certificate: malformed });
  try { bad(await native(input(endpoint)), 'hostname', 'target_tls'); bad(await oracle(input(endpoint))); assert.equal(endpoint.seen.requests, 0); }
  finally { await endpoint.close(); }
});

nativeTest('real IPv6 loopback TLS validates IPv6 SAN independently of DNS and CN', async () => {
  await certificates(); const cert = await mint({ issuer_cert: root.cert, issuer_key: root.key, cn: 'wrong.example.test', ips: ['::1'] });
  const endpoint = await destination({ certificate: cert, host: '::1' });
  try { const request = input(endpoint, { hostname: '[::1]', addresses: addresses(['::1', endpoint], ['[::1]', endpoint]) }); good(await native(request)); good(await oracle(request)); assert.equal(endpoint.seen.requests, 2); }
  finally { await endpoint.close(); }
});

nativeTest('raw identity vectors use pinned Node checkServerIdentity, including partial wildcards and IDNA', async () => {
  await certificates();
  const rows = [
    ['relay.example.test', ['relay.example.test']], ['RELAY.EXAMPLE.TEST', ['relay.example.test']], ['relay.example.test.', ['relay.example.test']], ['relay.example.test..', ['relay.example.test']],
    ['relay.example.test', ['*.example.test']], ['example.test', ['*.example.test']], ['relay.example.test', ['r*.example.test']], ['relay.example.test', ['*lay.example.test']], ['relay.example.test', ['r*y.example.test']], ['relay.example.test', ['*x*.example.test']], ['relay.example.test', ['relay.*.test']], ['a.b.example.test', ['*.example.test']], ['example.test', ['*.test']],
    ['xn--bcher-kva.example.test', ['xn--bcher-kva.example.test']], ['bücher.example.test', ['xn--bcher-kva.example.test']], ['xn--bcher-kva.example.test', ['*.example.test']], ['xn--bcher-kva.example.test', ['xn--*.example.test']],
    ['127.0.0.1', [], undefined, ['127.0.0.1']], ['127.0.0.1', ['127.0.0.1']], ['127.0.0.1', [], '127.0.0.1'], ['::1', [], undefined, ['0:0:0:0:0:0:0:1']], ['0:0:0:0:0:0:0:1', [], undefined, ['::1']],
    ['relay.example.test', [], 'relay.example.test'], ['relay.example.test', ['other.example.test'], 'relay.example.test'], ['relay.example.test', [], 'relay.example.test', ['127.0.0.1']], ['relay.example.test', [], 'wrong.example.test'],
    ['relay.example.test', ['relay.example.test.']], ['relay.example.test', ['relay.example.test..']], ['relay.example.test', ['bad..example.test']], ['relay.example.test', ['wrong.example.test', 'relay.example.test']],
  ];
  for (const [host, dns, cn, ips = []] of rows) { const cert = await mint({ issuer_cert: root.cert, issuer_key: root.key, dns, cn, ips }); const certificate = { subject: { CN: cn ?? 'synthetic-leaf.invalid' }, subjectaltname: [...dns.map(s => `DNS:${s}`), ...ips.map(s => `IP Address:${s}`)].join(', ') };
    const a = await native({ op: 'identity', host, cert: cert.cert }), b = await oracle({ op: 'identity', host, certificate }); assert.equal(a.ok, true); assert.equal(a.matches, b.matches, `${host}/${dns}`);
  }
});

nativeTest('declared response limits refuse before a stalled body; exactly 512KiB is accepted', async () => {
  for (const declared of [true, false]) { const endpoint = await destination({ handler: (req, res) => { if (declared) { res.writeHead(200, { 'Content-Length': 512 * 1024 + 1 }); res.flushHeaders(); } else res.end(Buffer.alloc(512 * 1024, 97)); } }); const session = nativeSession();
    try { const started = Date.now(), result = await session.request(input(endpoint, { scheme: 'http', timeout_ms: 2000 })); if (declared) { bad(result, 'limit', 'http'); assert.ok(Date.now() - started < 1500); } else assert.equal(good(result).body.length, 512 * 1024); assert.equal(session.alive, true); assert.equal(await waitClosed(endpoint), true); }
    finally { await session.close(); await endpoint.close(); }
  }
  let sideEffects = 0; const endpoint = await destination({ handler: (req) => { req.resume(); req.once('end', () => sideEffects++); } }); const session = nativeSession();
  try { const error = bad(await session.request(input(endpoint, { scheme: 'http', method: 'POST', body: 'one-effect', timeout_ms: 100 })), 'timeout'); assert.equal(error.send_state, 'possibly_submitted'); assert.equal(sideEffects, 1); assert.equal(endpoint.seen.requests, 1); assert.equal(await waitClosed(endpoint), true); assert.equal(session.alive, true); }
  finally { await session.close(); await endpoint.close(); }
});

nativeTest('WebSocket exact aggregate, binary refusal and write/read backpressure release while native stays alive', async () => {
  for (const ws of ['exact', 'binary', 'backpressure']) { const endpoint = await destination({ ws }), session = nativeSession();
    try { const request = input(endpoint, { scheme: 'ws', ...(ws === 'backpressure' ? { body: 'x'.repeat(512 * 1024), timeout_ms: 100 } : {}) }); const result = await session.request(request); if (ws === 'exact') assert.equal(good(result).text.length, 512 * 1024); else bad(result, ws === 'binary' ? 'protocol' : 'timeout'); assert.equal(session.alive, true); assert.equal(await waitClosed(endpoint), true); assert.equal(session.alive, true); }
    finally { await session.close(); await endpoint.close(); }
  }
});

nativeTest('CONNECT coalesced tunnel bytes survive and refused proxy cannot reach positive-control target', async () => {
  const endpoint = await destination(); const marker = 'coalesced target bytes'; const intermediary = await proxy({ target: endpoint, raw: 'HTTP/1.1 200 Connection Established\r\n\r\n' + marker });
  try { assert.equal(Buffer.from(good(await native(through(endpoint, intermediary, { op: 'tunnel_prefix', scheme: 'http', body_limit: marker.length }))).bytes).toString(), marker); assert.equal(endpoint.seen.requests, 0); good(await native(input(endpoint, { scheme: 'http' }))); const refusedPort = await listen(net.createServer()); const closedPort = refusedPort.port; await refusedPort.close(); const request = through(endpoint, { port: closedPort }, { scheme: 'http' }); bad(await native(request), 'connect', 'tcp'); assert.equal(endpoint.seen.requests, 1); }
  finally { await intermediary.close(); await endpoint.close(); }
});

nativeTest('pre-response HTTP probe EOF matches Node retry; malformed response does not retry', async () => {
  await certificates();
  for (const runner of [native, oracle]) { let first = true; const endpoint = await destination({ certificate: leaf, handler: (req, res) => { if (first) { first = false; res.socket.end(); } else { res.writeHead(500); res.end(); } } }), intermediary = await proxy({ target: endpoint });
    try { assert.equal(good(await runner(through(endpoint, intermediary, { op: 'probe' }))).profile, 'proxy-compatible'); assert.equal(intermediary.seen.tunnels, 2); }
    finally { await intermediary.close(); await endpoint.close(); }
  }
  const endpoint = await destination({ certificate: leaf, handler: (req, res) => { res.socket.end('invalid response\r\n\r\n'); } }), intermediary = await proxy({ target: endpoint });
  try { bad(await native(through(endpoint, intermediary, { op: 'probe' })), 'protocol', 'http'); assert.equal(intermediary.seen.tunnels, 1); }
  finally { await intermediary.close(); await endpoint.close(); }
});

nativeTest('second probe attempt revision and close cancel resources before returning profile', async () => {
  await certificates();
  for (const lifecycle of [{ revise_ms: 100 }, { close_ms: 100 }]) { const endpoint = await destination({ certificate: leaf }), reset = await clientHelloServer({ next: endpoint, stallAfterFailure: true }), intermediary = await proxy({ target: reset }), session = nativeSession();
    try { const result = await session.request(through(endpoint, intermediary, { op: 'probe', ...lifecycle })); bad(result, lifecycle.revise_ms ? 'stale' : 'cancelled'); assert.equal(intermediary.seen.tunnels, 2); assert.equal(session.alive, true); assert.equal(await waitClosed(intermediary), true); assert.equal(endpoint.seen.requests, 0); }
    finally { await session.close(); await intermediary.close(); await reset.close(); await endpoint.close(); }
  }
});

nativeTest('Business HTTP and WSS ClientHello policy matches pinned Undici including ALPN', async () => {
  await certificates();
  for (const scheme of ['https', 'wss']) { const captured = [];
    for (const runner of [native, oracle]) { const endpoint = await destination({ certificate: leaf }), tap = await clientHelloServer({ next: endpoint, failCount: 0 });
      try { good(await runner(input(tap, { scheme }))); captured.push(tap.hellos[0]); }
      finally { await tap.close(); await endpoint.close(); }
    }
    assert.deepEqual(captured[0], captured[1]); assert.deepEqual(captured[0].alpn, ['http/1.1']);
  }
});

nativeTest('actual pre-response TCP RST retries only Probe across direct and nested TLS routes', async () => {
  await certificates();
  for (const route of ['bypass', 'http', 'https']) {
    for (const runner of [native, oracle]) {
      let first = true;
      const endpoint = await destination({ certificate: leaf, handler: (req, res) => {
        assert.equal(req.method, 'HEAD'); assert.equal(req.url, '/healthz'); assert.equal(req.headers.authorization, undefined); assert.equal(req.headers.cookie, undefined);
        if (first) { first = false; res.socket._parent.resetAndDestroy(); } else { res.writeHead(500); res.end(); }
      } });
      const intermediary = route === 'bypass' ? null : await proxy({ target: endpoint, certificate: route === 'https' ? outer : undefined, resetOnUpstreamError: true });
      try {
        const request = intermediary ? through(endpoint, intermediary, { op: 'probe', proxyScheme: route }) : input(endpoint, { op: 'probe', settings: { mode: 'auto' }, env: { HTTPS_PROXY: 'http://proxy.example.test:8000', NO_PROXY: '*' } });
        assert.equal(good(await runner(request)).profile, 'proxy-compatible'); assert.equal(endpoint.seen.requests, 2); assert.equal(endpoint.state.accepted, 2);
        if (intermediary) { assert.equal(intermediary.seen.tunnels, 2); assert.equal(intermediary.seen.resets, 1); assert.equal(intermediary.seen.isolated, true); }
      } finally { await intermediary?.close(); await endpoint.close(); }
    }
    let sideEffects = 0;
    const endpoint = await destination({ certificate: leaf, handler: (req, res) => { req.resume(); req.once('end', () => { sideEffects++; res.socket._parent.resetAndDestroy(); }); } });
    const intermediary = route === 'bypass' ? null : await proxy({ target: endpoint, certificate: route === 'https' ? outer : undefined, resetOnUpstreamError: true });
    try {
      const request = intermediary ? through(endpoint, intermediary, { proxyScheme: route, method: 'POST', body: 'one-side-effect' }) : input(endpoint, { method: 'POST', body: 'one-side-effect' });
      const error = bad(await native(request), 'protocol', 'http'); assert.equal(error.send_state, 'possibly_submitted'); assert.equal(sideEffects, 1); assert.equal(endpoint.seen.requests, 1); if (intermediary) assert.equal(intermediary.seen.tunnels, 1);
    } finally { await intermediary?.close(); await endpoint.close(); }
  }
});
