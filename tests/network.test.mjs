import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { resolveNetwork, networkSettings, proxyUrl, applyNetwork, NetworkManager, windowsProxyFor, childNetworkEnvironment } from '../src/agent/network.mjs';

const origin = 'https://relay.example.invalid';
const directSystem = async () => ({ proxy: '' });

test('automatic mode without a configured proxy uses direct/OS routing, including TUN', async () => {
  const plan = await resolveNetwork({ mode: 'auto' }, origin, { env: {}, systemProxy: directSystem });
  assert.equal(plan.source, 'system-direct'); assert.equal(plan.environment.NO_PROXY, '*');
  assert.equal(plan.environment.HTTPS_PROXY, '');
});
test('explicit direct mode ignores proxy variables and does not query system settings', async () => {
  const plan = await resolveNetwork({ mode: 'direct' }, origin, { env: { HTTPS_PROXY: 'http://bad.invalid:1' }, systemProxy: () => { throw Error('must not query'); } });
  assert.equal(plan.source, 'direct'); assert.equal(plan.environment.https_proxy, '');
});
test('environment selection preserves bypasses, prioritizes lowercase and redacts status', async () => {
  const env = { HTTPS_PROXY: 'http://upper.invalid:9', https_proxy: 'http://user:secret@127.0.0.1:1234', NO_PROXY: 'other.invalid', no_proxy: '*.internal' };
  const before = JSON.stringify(env);
  const plan = await resolveNetwork({ mode: 'auto' }, origin, { env, systemProxy: () => { throw Error('must not query'); } });
  assert.match(plan.environment.https_proxy, /127\.0\.0\.1:1234/); assert.match(plan.environment.no_proxy, /\*\.internal/);
  assert.match(plan.environment.no_proxy, /127\.0\.0\.1/); assert.equal(JSON.stringify(env), before);
  const manager = new NetworkManager(() => ({ mode: 'auto' }), { env, apply: () => () => {}, selectTls: async () => 'default' });
  await manager.prepare(origin);
  assert.equal(JSON.stringify(manager.status()).includes('secret'), false); manager.close();
});
test('HTTP and ALL_PROXY fallbacks are supported but SOCKS-only configuration fails explicitly', async () => {
  for (const env of [{ HTTP_PROXY: 'http://127.0.0.1:1234' }, { ALL_PROXY: 'http://127.0.0.1:1234' }]) {
    const plan = await resolveNetwork({ mode: 'auto' }, origin, { env }); assert.equal(plan.environment.HTTPS_PROXY, 'http://127.0.0.1:1234');
  }
  const mixed = await resolveNetwork({ mode: 'auto' }, origin, { env: { HTTPS_PROXY: 'http://127.0.0.1:1234', ALL_PROXY: 'socks5://127.0.0.1:9' } });
  assert.equal(mixed.environment.HTTPS_PROXY, 'http://127.0.0.1:1234');
  await assert.rejects(() => resolveNetwork({ mode: 'auto' }, origin, { env: { ALL_PROXY: 'socks5://user:secret@127.0.0.1:5' } }), error => /SOCKS/.test(error.message) && !error.message.includes('secret'));
});
test('system proxy selection is per destination; system bypass returns direct', async () => {
  let seen;
  const proxied = await resolveNetwork({ mode: 'auto' }, origin, { env: {}, systemProxy: async url => { seen = url; return { proxy: 'http://127.0.0.1:9999' }; } });
  assert.equal(seen, origin); assert.equal(proxied.source, 'system-proxy');
  const bypassed = await resolveNetwork({ mode: 'auto' }, origin, { env: {}, systemProxy: directSystem });
  assert.equal(bypassed.source, 'system-direct');
});
test('system lookup errors never silently downgrade to direct; helper output is bounded and sanitized', async () => {
  let timeout;
  const value = await windowsProxyFor(origin, { platform: 'win32', execute: async (script, input, limit) => { assert.equal(input, origin); timeout = limit; return '{"proxy":"http://127.0.0.1:1234"}'; } });
  assert.equal(value.source, 'system-proxy'); assert.equal(timeout, 8000);
  await assert.rejects(() => windowsProxyFor(origin, { platform: 'win32', execute: () => { throw Error('credential-secret'); } }), error => /不会静默/.test(error.message) && !error.message.includes('credential-secret'));
});
test('manual mode is explicit, validates URLs, and does not persist inline credentials', () => {
  assert.deepEqual(networkSettings({ mode: 'proxy', proxy: 'http://127.0.0.1:7890' }), { mode: 'proxy', proxy: 'http://127.0.0.1:7890' });
  for (const proxy of ['http://u:secret@localhost:3', 'http://localhost:3/path', 'file:///x', 'http://localhost:3#x']) assert.throws(() => networkSettings({ mode: 'proxy', proxy }));
  assert.throws(() => proxyUrl('http://u:secret@localhost'), error => !error.message.includes('secret'));
  assert.throws(() => networkSettings({ mode: 'auto', unknown: true }));
});
test('local control requests bypass even a forced proxy and preserve environment data', async () => {
  const plan = await resolveNetwork({ mode: 'proxy', proxy: 'http://127.0.0.1:1234' }, 'http://127.0.0.1:47631', { allowLocal: true });
  assert.equal(plan.source, 'loopback'); assert.equal(plan.environment.NO_PROXY, '*');
  const env = { HTTPS_PROXY: 'http://localhost:99', no_proxy: '*.corp' };
  const child = childNetworkEnvironment(env); assert.equal(env.NODE_USE_ENV_PROXY, undefined);
  assert.equal(child.NODE_USE_ENV_PROXY, '0');
  assert.match(child.no_proxy, /\*\.corp/); assert.match(child.NO_PROXY, /localhost/);
});
test('a remote hostname beginning with 127 is not misclassified as loopback', async () => {
  const plan = await resolveNetwork({ mode: 'proxy', proxy: 'http://localhost:1234' }, 'https://127.attacker.invalid');
  assert.equal(plan.source, 'manual-proxy'); assert.equal(plan.environment.HTTPS_PROXY, 'http://localhost:1234');
});
test('network manager caches resolution and refreshes a changed mode without request replay', async () => {
  let settings = { mode: 'auto' }; let queries = 0; let applied = 0;
  const manager = new NetworkManager(() => settings, { env: {}, systemProxy: async () => { queries++; return { proxy: '' }; }, apply: () => { applied++; return () => {}; }, selectTls: async () => 'default' });
  await manager.prepare(origin); await manager.prepare(origin); assert.equal(queries, 1);
  settings = { mode: 'proxy', proxy: 'http://localhost:3456' }; await manager.prepare(origin);
  assert.equal(manager.status().source, 'manual-proxy'); assert.equal(applied, 2); manager.close();
});

async function servers(t) {
  const sockets = new Set(); const observations = { tunnels: 0, proxyHeaders: [], targetHeaders: [], upgrades: 0 };
  const track = socket => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); };
  const target = http.createServer((req, res) => { observations.targetHeaders.push(req.headers); res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('target-ok'); });
  target.on('connection', track);
  target.on('upgrade', (req, socket) => {
    observations.upgrades++;
    const accept = createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.on('data', bytes => { if ((bytes[0] & 15) === 8) socket.end(Buffer.from([0x88, 0])); else socket.write(Buffer.from([0x81, 4, 112, 111, 110, 103])); });
  });
  await new Promise(resolve => target.listen(0, '127.0.0.1', resolve));
  const port = target.address().port;
  const proxy = http.createServer((req, res) => { res.writeHead(502); res.end(); });
  proxy.on('connection', track);
  proxy.on('connect', (req, client, head) => {
    observations.tunnels++; observations.proxyHeaders.push(req.headers);
    // A local fixture, not a general-purpose open proxy. Only one synthetic host is accepted.
    if (req.url !== `relay.invalid:${port}`) { client.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
    const upstream = net.connect(port, '127.0.0.1'); track(upstream);
    upstream.once('connect', () => { client.write('HTTP/1.1 200 Connection Established\r\n\r\n'); if (head.length) upstream.write(head); client.pipe(upstream); upstream.pipe(client); });
    client.once('close', () => upstream.destroy()); upstream.once('error', () => client.destroy());
  });
  await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await Promise.all([new Promise(resolve => target.close(resolve)), new Promise(resolve => proxy.close(resolve))]); });
  return { proxy: `http://127.0.0.1:${proxy.address().port}`, target: `http://127.0.0.1:${port}`, remote: `http://relay.invalid:${port}`, observations };
}
async function websocketPing(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url); const timer = setTimeout(() => { ws.close(); reject(Error('WebSocket timeout')); }, 4000);
    ws.addEventListener('open', () => ws.send('ping'));
    ws.addEventListener('message', event => { clearTimeout(timer); ws.close(); resolve(event.data); });
    ws.addEventListener('error', () => { clearTimeout(timer); reject(Error('WebSocket connection failed')); });
  });
}
test('real native fetch AND WebSocket use proxy; local control tokens never reach proxy', { timeout: 15000 }, async t => {
  const fixture = await servers(t);
  const plan = await resolveNetwork({ mode: 'proxy', proxy: fixture.proxy }, origin);
  const restore = applyNetwork(plan.environment); t.after(restore);
  const response = await fetch(fixture.remote, { signal: AbortSignal.timeout(4000) }); assert.equal(await response.text(), 'target-ok');
  assert.ok(fixture.observations.tunnels > 0); const first = fixture.observations.tunnels;
  assert.equal(await websocketPing(fixture.remote.replace('http:', 'ws:')), 'pong'); assert.ok(fixture.observations.tunnels > first);
  const beforeLocal = fixture.observations.tunnels;
  const local = await fetch(fixture.target, { headers: { 'X-Chat2Local-Token': 'synthetic-local-secret' }, signal: AbortSignal.timeout(4000) }); assert.equal(await local.text(), 'target-ok');
  assert.equal(fixture.observations.tunnels, beforeLocal);
  assert.equal(JSON.stringify(fixture.observations.proxyHeaders).includes('synthetic-local-secret'), false);
});
test('real direct HTTP and WebSocket work without a proxy dependency', { timeout: 10000 }, async t => {
  const fixture = await servers(t); const plan = await resolveNetwork({ mode: 'direct' }, origin);
  const restore = applyNetwork(plan.environment); t.after(restore);
  assert.equal(await (await fetch(fixture.target)).text(), 'target-ok');
  assert.equal(await websocketPing(fixture.target.replace('http:', 'ws:')), 'pong');
  assert.equal(fixture.observations.tunnels, 0);
});
test('a broken explicit proxy fails without attempting a direct fallback', { timeout: 10000 }, async t => {
  const fixture = await servers(t);
  const plan = await resolveNetwork({ mode: 'proxy', proxy: fixture.proxy }, origin); const restore = applyNetwork(plan.environment); t.after(restore);
  // Fixture rejects this host. A successful direct request would be a routing-policy violation.
  await assert.rejects(() => fetch('http://unapproved.invalid', { signal: AbortSignal.timeout(2000) }));
  assert.equal(fixture.observations.targetHeaders.length, 0);
});
