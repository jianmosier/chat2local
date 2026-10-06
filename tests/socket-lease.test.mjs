import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { SOCKET_LEASE_MS, startLease, socketIsLive, touchLease, retireSocket, failSocketPending } from '../src/relay/socket-lease.mjs';

function fakeSocket(saved = null) {
  return { readyState: 1, attachment: saved, closed: [],
    deserializeAttachment() { return this.attachment && structuredClone(this.attachment); },
    serializeAttachment(value) { this.attachment = structuredClone(value); },
    close(code, reason) { this.closed.push({ code, reason }); },
  };
}
test('status polling does not renew a lease; only a received heartbeat or result can renew it', () => {
  const s = fakeSocket(); startLease(s, 1000);
  assert.equal(socketIsLive(s, 30000), true);
  assert.equal(s.attachment.lastSeenAt, 1000);
  assert.equal(touchLease(s, 30000), true);
  assert.equal(socketIsLive(s, 30000 + SOCKET_LEASE_MS - 1), true);
  assert.equal(socketIsLive(s, 30000 + SOCKET_LEASE_MS), false);
  assert.equal(touchLease(s, 30000 + SOCKET_LEASE_MS), false);
});
test('legacy sockets get one persisted grace period, not an infinite lease across hibernation', () => {
  const s = fakeSocket(); assert.equal(socketIsLive(s, 1000), true);
  const restored = fakeSocket(s.attachment);
  assert.equal(socketIsLive(restored, 1000 + SOCKET_LEASE_MS - 1), true);
  assert.equal(socketIsLive(restored, 1000 + SOCKET_LEASE_MS), false);
  assert.equal(restored.attachment.lastSeenAt, 1000);
});
test('retired sockets stay excluded even if the runtime still reports OPEN or a late ping arrives', () => {
  const s = fakeSocket(); startLease(s, 1000); retireSocket(s);
  assert.equal(s.readyState, 1); assert.equal(socketIsLive(s, 1001), false);
  assert.equal(touchLease(s, 1001), false); assert.equal(s.closed.length, 1);
});
test('malformed attachments, impossible clocks and inaccessible attachments fail closed', () => {
  for (const saved of [{ version: 2 }, { version: 1, connectedAt: 1, lastSeenAt: 1e30, retired: false }, { version: 1, connectedAt: 10, lastSeenAt: 1, retired: false }]) assert.equal(socketIsLive(fakeSocket(saved), 1000), false);
  const s = fakeSocket(); s.deserializeAttachment = () => { throw new Error('unavailable'); };
  assert.equal(socketIsLive(s, 1000), false);
});
test('a late old-socket close cancels only its own pending work and never replays it on a new socket', () => {
  const oldSocket = fakeSocket(), newSocket = fakeSocket(); const results = [];
  const pending = new Map([
    ['old', { socket: oldSocket, resolve: value => results.push(['old', value]) }],
    ['new', { socket: newSocket, resolve: value => results.push(['new', value]) }],
  ]);
  failSocketPending(pending, oldSocket, () => ({ status: 503, outcome: 'unknown' }));
  assert.deepEqual([...pending.keys()], ['new']); assert.equal(results.length, 1);
  failSocketPending(pending, oldSocket, () => assert.fail('already settled'));
  assert.equal(results.length, 1);
  failSocketPending(pending, undefined, () => ({ status: 503 }));
  assert.equal(pending.size, 0); assert.equal(results.length, 2);
});

test('actual Durable Object refuses a healthy duplicate but releases an expired authenticated socket', { timeout: 30000 }, async t => {
  // Expiry control exists ONLY in this generated test bundle, never in worker.mjs.
  const bundle = await build({ stdin: { resolveDir: process.cwd(), sourcefile: 'socket-lease-test-entry.mjs', contents: `
    import { Device as ProductionDevice } from './src/relay/state.mjs';
    export class TestDevice extends ProductionDevice {
      async fetch(request) {
        if (new URL(request.url).pathname === '/test-only-expire') {
          for (const socket of this.ctx.getWebSockets('device')) {
            const lease = socket.deserializeAttachment();
            socket.serializeAttachment({ ...lease, connectedAt: Date.now()-100000, lastSeenAt: Date.now()-90000 });
          }
          return Response.json({ expired: true });
        }
        return super.fetch(request);
      }
    }
    export default { fetch(request, env) { return env.DEVICES.get(env.DEVICES.idFromName('isolated-fixture')).fetch(request); } };
  ` }, bundle: true, write: false, format: 'esm', platform: 'neutral', mainFields: ['module', 'main'], external: ['cloudflare:workers'] });
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundle.outputFiles[0].text, compatibilityDate: '2026-09-20', compatibilityFlags: ['nodejs_compat'], host: '127.0.0.1', port: 0, durableObjects: { DEVICES: { className: 'TestDevice', useSQLite: true } } }));
  t.after(() => mf.dispose()); await mf.ready;
  const key = randomBytes(32).toString('hex');
  const init = await mf.dispatchFetch('http://fixture/initialize', { method: 'POST', body: JSON.stringify({ deviceKey: key }) });
  assert.equal(init.status, 200);
  const connect = (value = key) => mf.dispatchFetch('http://fixture/connect', { headers: { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': 'chat2local-v1, device.' + value } });
  const first = await connect(); assert.equal(first.status, 101); first.webSocket.accept();
  assert.equal((await connect()).status, 409);
  const expire = await mf.dispatchFetch('http://fixture/test-only-expire', { method: 'POST' }); assert.equal(expire.status, 200);
  assert.equal((await connect('f'.repeat(64))).status, 401); // Expiry never bypasses authentication.
  const second = await connect(); assert.equal(second.status, 101); second.webSocket.accept();
  // Old close arrives after the replacement connection. New heartbeat still works.
  try { first.webSocket.close(1000, 'fixture old connection'); } catch {}
  const pong = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('new socket heartbeat timed out')), 5000);
    second.webSocket.addEventListener('message', event => { if (event.data === 'pong') { clearTimeout(timer); resolve(); } });
  });
  second.webSocket.send('ping'); await pong;
  assert.equal((await connect()).status, 409);
  second.webSocket.close(1000, 'fixture finished');
});
