import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

// Local synthetic state only; this harness never reads Wrangler/private config.
const directory = path.dirname(fileURLToPath(import.meta.url));
const fixture = {
  keyHash: 'a'.repeat(64), epoch: 'b'.repeat(64), revoked: false,
  description: { name: 'JS 设备 🖥️', platform: 'win32', arch: 'x64', system: 'Windows' },
  futureField: { absent: null, zero: 0, enabled: false, list: ['中文', 1, null] },
};
const legacy = `
import { DurableObject } from 'cloudflare:workers';
export class Probe extends DurableObject {
  async fetch(request) {
    if (new URL(request.url).pathname === '/seed') {
      await this.ctx.storage.put('identity', ${JSON.stringify(fixture)});
      await this.ctx.storage.put('counter', 0);
    }
    const record = await this.ctx.storage.get('identity');
    return Response.json({ record, isMap: record instanceof Map,
      nestedIsMap: record?.description instanceof Map, keys: Object.keys(record || {}) });
  }
}
export default { fetch(request, env) { return env.PROBE.get(env.PROBE.idFromName('compatibility-fixture')).fetch(request); } };`;
const options = rust => convertV4MiniflareOptions({
  name: 'chat2local-rust-probe', modules: true,
  ...(rust ? {
    modulesRoot: path.join(directory, 'build'),
    modules: [
      { type: 'ESModule', path: path.join(directory, 'build/worker/shim.mjs') },
      { type: 'ESModule', path: path.join(directory, 'build/index.js') },
      { type: 'CompiledWasm', path: path.join(directory, 'build/index_bg.wasm') },
    ],
  } : { script: legacy }),
  compatibilityDate: '2026-09-20', host: '127.0.0.1', port: 0,
  durableObjects: { PROBE: { className: 'Probe', useSQLite: true, unsafeUniqueKey: 'chat2local-rust-probe-only', unsafePreventEviction: false } },
});
async function json(mf, route) {
  const response = await mf.dispatchFetch(`http://probe.invalid${route}`);
  assert.equal(response.status, 200, await response.clone().text());
  return response.json();
}
async function request(mf, route) {
  const response = await mf.dispatchFetch(`http://probe.invalid${route}`);
  assert.equal(response.status, 200, await response.text());
}
async function ping(socket) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { cleanup(); reject(new Error('WebSocket response timed out')); }, 5000);
    const cleanup = () => { clearTimeout(timeout); socket.removeEventListener('message', message); socket.removeEventListener('close', closed); };
    const message = event => { cleanup(); try { resolve(JSON.parse(event.data)); } catch (error) { reject(error); } };
    const closed = () => { cleanup(); reject(new Error('Socket closed before response')); };
    socket.addEventListener('message', message);
    socket.addEventListener('close', closed);
    socket.send('ping');
  });
}

test('Rust WASM on workerd: legacy storage, rollback and actual WebSocket hibernation', { timeout: 60000 }, async t => {
  const manifest = JSON.parse(await fs.readFile(path.join(directory, 'build/probe-manifest.json'), 'utf8'));
  assert.equal(manifest.version, '0.8.7');
  for (const file of ['Cargo.toml', 'Cargo.lock', 'src/lib.rs', 'build/index.js', 'build/index_bg.wasm', 'build/worker/shim.mjs']) {
    const actual = createHash('sha256').update(await fs.readFile(path.join(directory, file))).digest('hex');
    assert.equal(actual, manifest.inputs[file] ?? manifest.artifacts[file], `Rebuild stale probe: ${file}`);
  }
  const mf = new Miniflare(options(false));
  t.after(() => mf.dispose());
  await mf.ready;
  const namespace = await mf.getDurableObjectNamespace('PROBE');
  const id = namespace.idFromName('compatibility-fixture').toString();
  await t.test('JS writes the same structured-clone shape as Device identity', async () => {
    assert.deepEqual((await json(mf, '/seed')).record, fixture);
  });
  await mf.setOptions(options(true));
  await mf.ready;
  await t.test('Rust reads existing state under unchanged object ID', async () => {
    assert.equal((await mf.getDurableObjectNamespace('PROBE')).idFromName('compatibility-fixture').toString(), id);
    assert.deepEqual(await json(mf, '/record'), fixture);
    await request(mf, '/update');
  });
  await t.test('concurrent transactions serialize and errors roll back', async () => {
    await Promise.all(Array.from({ length: 12 }, () => request(mf, '/increment')));
    assert.equal(await json(mf, '/counter'), 12);
    assert.deepEqual(await json(mf, '/rollback'), { rolledBack: true });
    assert.equal(await json(mf, '/counter'), 12);
  });
  await mf.setOptions(options(false));
  await mf.ready;
  await t.test('old JS reads Rust updates, unknown fields, null and plain objects', async () => {
    const value = await json(mf, '/record');
    assert.equal(value.isMap, false);
    assert.equal(value.nestedIsMap, false);
    assert.deepEqual(value.keys, Object.keys(fixture));
    assert.deepEqual(value.record, { ...fixture, description: { ...fixture.description, name: 'Rust 更新 🦀' } });
  });
  await mf.setOptions(options(true));
  await mf.ready;
  await t.test('hibernation recreates Rust object and restores tagged socket attachment', async () => {
    const response = await mf.dispatchFetch('http://probe.invalid/connect', { headers: { Upgrade: 'websocket' } });
    assert.equal(response.status, 101);
    const socket = response.webSocket;
    assert.ok(socket);
    socket.accept();
    t.after(() => { try { socket.close(); } catch {} });
    const before = await ping(socket);
    assert.equal(before.lease.messages, 1);
    assert.equal(before.lease.connectionAccess, true);
    assert.equal((await json(mf, '/sockets')).count, 1);
    // Miniflare's local test API preserves the WS while evicting the DO instance.
    await mf.unsafeEvictDurableObject('chat2local-rust-probe', 'Probe', { name: 'compatibility-fixture', webSockets: 'hibernate' });
    const after = await ping(socket);
    assert.notEqual(after.incarnation, before.incarnation, 'Rust constructor ran again');
    assert.equal(after.lease.messages, 2);
    for (const field of ['version', 'retired', 'terminal', 'connectionAccess']) assert.equal(after.lease[field], before.lease[field]);
    assert.equal(after.lease.connectedAt, before.lease.connectedAt);
    assert.ok(after.lease.lastSeenAt >= before.lease.lastSeenAt);
    assert.equal((await json(mf, '/sockets')).count, 1);
    socket.close(1000, 'test complete');
    for (let attempt = 0; attempt < 50; attempt++) {
      if (await json(mf, '/closed') === 1) return;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.fail('Rust WebSocket close handler did not persist its marker');
  });
});
