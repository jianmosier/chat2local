import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createHash, randomUUID } from 'node:crypto';
import { readControllerArtifact } from '../scripts/controller-artifact.mjs';
import { nativeFixture, raw, request, freePort } from './controller-fixture.mjs';
import { ManagementSessions } from '../src/agent/management-session.mjs';
import { assertWriteFenceClear } from '../src/agent/files/write-fence.mjs';
import { Store } from '../src/agent/store.mjs';
import { startController } from '../src/agent/main.mjs';
const executable = process.env.CHAT2LOCAL_CONTROLLER_TEST_EXECUTABLE;
if (process.env.CHAT2LOCAL_CONTROLLER_TEST_REQUIRED === '1' && !executable) throw Error('Required controller fixture missing.');
if (executable) await readControllerArtifact(executable);
const native = { skip: !executable };
const hash = text => createHash('sha256').update(text).digest('hex');
test('native fixture status cannot satisfy full Agent launcher/upgrade identity; scoped routes persist ordered legacy state', native, async t => {
  const root = randomUUID(), account = randomUUID();
  const config = { version: 1, roots: [{ id: root, path: 'C:/synthetic', write: true, extra: { b: 2, a: 1 } }], paused: false, installationId: randomUUID(), accountRoots: [{ id: account, path: 'C:/account', write: false }], connectionGuide: { id: randomUUID(), rootId: root }, unknown: { z: '\ud800', a: 1 }, terminalGrants: [{ opaque: true }], accountPolicyRevision: 7 };
  const secrets = { identity: { origin: 'https://synthetic.invalid', deviceId: 'd'.repeat(32), deviceKey: 'k'.repeat(64) }, unknown: { b: 1, a: 2 } };
  const f = await nativeFixture(t, executable, { before: async store => { await store.saveConfig(config); await store.saveSecrets(secrets); } });
  const status = await (await f.api('/api/status')).json(); assert.equal(status.name, 'chat2local-native-controller-fixture'); assert.equal(status.fullAgent, false); assert.equal(status.fixtureOnly, true); assert.equal(status.upgradeReady, false); assert.equal(status.bridge, 'unavailable'); assert.equal(status.terminalJobsRunning, 0); assert.deepEqual(status.pending, []); assert.equal(status.roots[0].writeMode, 'review');
  assert.equal((await f.api('/api/pause', { paused: 'true' })).status, 400);
  assert.equal((await f.api('/api/pause', { paused: true, extra: 1 })).status, 400);
  assert.deepEqual(await (await f.api('/api/pause', { paused: true })).json(), { paused: true });
  assert.deepEqual(await (await f.api('/api/account-root/remove', { id: account })).json(), { ok: true, localAccessRevoked: true, cloudMembershipRemoved: false });
  assert.equal((await f.api('/api/account-root/remove', { id: account })).status, 404);
  assert.equal((await f.api('/api/root/remove', { id: root })).status, 200);
  assert.equal((await f.api('/api/disconnect', {})).status, 501);
  for (const route of ['setup/start', 'terminal/set-permission']) assert.equal((await f.api('/api/' + route, {})).status, 409);
  assert.equal((await f.api('/api/root/add', {})).status, 400);
  assert.equal((await f.api('/api/network/set', {})).status, 400);
  const loaded = await f.store.load(); assert.equal(loaded.config.accountPolicyRevision, 10); assert.equal(loaded.config.connectionGuide, undefined); assert.deepEqual(loaded.config.terminalGrants, config.terminalGrants); assert.equal(JSON.stringify(loaded.config.unknown), JSON.stringify(config.unknown)); assert.equal(JSON.stringify(loaded.secrets), JSON.stringify(secrets));
});
test('management proof JS -> native -> JS preserves binding, expiry, cookie scope and restricted authority', native, async t => {
  const port = await freePort(), installationId = randomUUID(); let cookie, expiresAt;
  const f = await nativeFixture(t, executable, { port, before: async store => {
    await store.saveConfig({ version: 1, roots: [], paused: false, installationId });
    const manager = new ManagementSessions({ store, binding: () => JSON.stringify([`http://127.0.0.1:${port}`, installationId, '', '', '']) });
    const result = await manager.establish('', true); cookie = result.cookie.split(';')[0]; expiresAt = result.expiresAt;
  } });
  const headers = { 'X-Chat2Local-Token': '', 'X-Chat2Local-Manager': '1', Cookie: cookie };
  assert.equal((await f.api('/api/status', undefined, headers)).status, 200);
  for (const route of ['pause', 'shutdown', 'root/remove']) assert.equal((await f.api('/api/' + route, {}, headers)).status, 401);
  const established = await f.api('/api/management/session', {}, headers); assert.equal(established.status, 200); assert.equal((await established.json()).expiresAt, expiresAt); assert.match(established.headers.get('set-cookie'), /HttpOnly; SameSite=Strict; Path=\/api; Max-Age=/);
  assert.equal((await f.api('/api/status', undefined, { ...headers, Cookie: cookie + '; ' + cookie })).status, 401);
  const nativeCookie = (await f.api('/api/management/session', {})).headers.get('set-cookie').split(';')[0];
  const manager = new ManagementSessions({ store: new Store(f.directory), binding: () => JSON.stringify([f.ready.origin, installationId, '', '', '']) });
  assert.ok(await manager.matching(nativeCookie));
  assert.equal((await f.api('/api/management/logout', {}, headers)).status, 200);
  assert.equal((await f.api('/api/status', undefined, headers)).status, 401);
  const saved = await f.store.readPrivateRecord('management-sessions'); assert.equal(saved.sessions.some(s => s.proofHash === hash(cookie.split('=')[1])), false);
});
test('native raw HTTP preserves header accounting, fragments, pipeline, chunk trailers, Expect and security hardening', native, async t => {
  const f = await nativeFixture(t, executable);
  const base = request(f, '/api/status', { headers: 'X-Pad: \r\n' });
  const lines = base.split('\r\n'); const accounted = '/api/status'.length + lines.slice(1).filter(Boolean).reduce((n, line) => { const at = line.indexOf(':'); return n + at + line.slice(at + 1).trimStart().length; }, 0);
  assert.match(await raw(f.port, base.replace('X-Pad: ', 'X-Pad: ' + 'x'.repeat(8191 - accounted))), /^HTTP\/1.1 200/);
  assert.match(await raw(f.port, base.replace('X-Pad: ', 'X-Pad: ' + 'x'.repeat(8192 - accounted))), /^HTTP\/1.1 431/);
  assert.match(await raw(f.port, base.replace('X-Pad: ', 'X-Pad:' + ' '.repeat(20000)), { fragments: true }), /^HTTP\/1.1 200/);
  assert.equal((await raw(f.port, request(f, '/api/status', { close: false }) + request(f))).match(/HTTP\/1.1 200/g).length, 2);
  const body = '{"paused":true}', chunked = `${body.length.toString(16)};ext=yes\r\n${body}\r\n0\r\nX-Trailer: yes\r\n\r\n`;
  assert.match(await raw(f.port, request(f, '/api/pause', { method: 'POST', headers: 'Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n', body: chunked }), { fragments: true }), /^HTTP\/1.1 200/);
  for (const headers of ['Content-Length: 0\r\nContent-Length: 0\r\n', 'Content-Length: 0\r\nTransfer-Encoding: chunked\r\n', 'Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n', `Host: 127.0.0.1:${f.port}\r\n`, 'Sec-Fetch-Site: cross-site\r\nSec-Fetch-Site: same-origin\r\n', `Origin: ${f.ready.origin}\r\n`, 'X-Chat2Local-Manager: 1\r\nX-Chat2Local-Manager: 1\r\n']) assert.match(await raw(f.port, request(f, '/api/pause', { method: 'POST', headers })), /^HTTP\/1.1 400/);
  assert.match(await raw(f.port, request(f, '/api/pause', { method: 'POST', headers: 'Expect: unsupported\r\nContent-Length: 0\r\n' })), /^HTTP\/1.1 417/);
  const continued = await raw(f.port, request(f, '/api/pause', { method: 'POST', headers: `Content-Type: application/json\r\nExpect: 100-continue\r\nContent-Length: ${body.length}\r\n`, body })); assert.match(continued, /^HTTP\/1.1 100 Continue/); assert.match(continued, /HTTP\/1.1 200/);
  for (const target of ['http://127.0.0.1/api/pause', '//api/pause', '/api/pause?x', '127.0.0.1:80']) assert.match(await raw(f.port, request(f, target)), /^HTTP\/1.1 (400|403)/);
  assert.equal((await (await f.api('/api/status')).json()).paused, true);
});
test('native strict JSON, declared and streamed body bounds never mutate invalid requests', native, async t => {
  const f = await nativeFixture(t, executable);
  const post = body => request(f, '/api/pause', { method: 'POST', headers: `Content-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n`, body });
  for (const body of ['{bad', 'null', '[]', '{"paused":true,"extra":1}']) assert.match(await raw(f.port, post(body)), /^HTTP\/1.1 400/);
  const invalid = Buffer.concat([Buffer.from(post('x').slice(0, -1)), Buffer.from([0xff])]); assert.match(await raw(f.port, invalid), /^HTTP\/1.1 400/);
  const valid = '{"paused":false}' + ' '.repeat(524288 - 16); assert.equal(valid.length, 524288); assert.match(await raw(f.port, post(valid)), /^HTTP\/1.1 200/);
  assert.match(await raw(f.port, request(f, '/api/pause', { method: 'POST', headers: 'Content-Type: application/json\r\nContent-Length: 524289\r\n' })), /^HTTP\/1.1 413/);
  assert.match(await raw(f.port, request(f, '/api/pause', { method: 'POST', headers: 'Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n', body: '80001\r\n' })), /^HTTP\/1.1 413/);
  assert.equal((await (await f.api('/api/status')).json()).paused, false);
});
test('native ownership rejects busy listener and free-port live owner before any state mutation', native, async t => {
  const f = await nativeFixture(t, executable); const files = ['settings.json', 'session.json'];
  const before = await Promise.all(files.map(name => fs.readFile(path.join(f.directory, name))));
  for (const port of [f.port, await freePort()]) {
    const child = spawn(executable, ['--synthetic-state', f.directory, '--port', String(port), '--fixture-only'], { windowsHide: true, stdio: 'ignore' }); const [code] = await once(child, 'exit'); assert.notEqual(code, 0);
    for (let i = 0; i < files.length; i++) assert.deepEqual(await fs.readFile(path.join(f.directory, files[i])), before[i]);
  }
  // A successor process can use the exact same port and state after confirmed exit.
  await f.close(); const next = await nativeFixture(t, executable, { directory: f.directory, port: f.port }); assert.notEqual(next.session.instanceId, f.session.instanceId); await next.close();
});
test('native slow header and body deadlines release connections without changing policy', native, async t => {
  const f = await nativeFixture(t, executable);
  const header = raw(f.port, 'POST /api/pause HTTP/1.1\r\nHost:');
  const body = raw(f.port, request(f, '/api/pause', { method: 'POST', headers: 'Content-Type: application/json\r\nContent-Length: 16\r\n', body: '{' }));
  assert.match(await header, /^HTTP\/1.1 408/); assert.match(await body, /^HTTP\/1.1 408/); assert.equal((await (await f.api('/api/status')).json()).paused, false);
});
test('native and JS each refuse the other live owner and native rejects stale publication', native, async t => {
  const f = await nativeFixture(t, executable);
  await assert.rejects(startController({ stateDir: f.directory, port: f.port }), { code: 'EADDRINUSE' });
  await assert.rejects(startController({ stateDir: f.directory, port: 0 }), { code: 'EOWNER' });
  const original = await fs.readFile(path.join(f.directory, 'settings.json'));
  await f.store.saveSession({ ...f.session, instanceId: 'replaced-generation' });
  assert.equal((await f.api('/api/pause', { paused: true })).status, 503);
  assert.deepEqual(await fs.readFile(path.join(f.directory, 'settings.json')), original);
  // Restore only this owned synthetic fixture's session to permit its normal close.
  await f.store.saveSession(f.session); await f.close();
  const js = await startController({ stateDir: f.directory, port: f.port });
  const before = await fs.readFile(path.join(f.directory, 'session.json'));
  for (const port of [f.port, await freePort()]) { const child = spawn(executable, ['--synthetic-state', f.directory, '--port', String(port), '--fixture-only'], { windowsHide: true, stdio: 'ignore' }); assert.notEqual((await once(child, 'exit'))[0], 0); }
  assert.deepEqual(await fs.readFile(path.join(f.directory, 'session.json')), before); await js.close();
});
test('native bounds connections and preserves reservation while a body is incomplete during shutdown', native, async t => {
  const f = await nativeFixture(t, executable), sockets = [];
  for (let i = 0; i < 32; i++) { const s = net.connect(f.port, '127.0.0.1'); await once(s, 'connect'); s.on('error', () => {}); sockets.push(s); }
  const extra = net.connect(f.port, '127.0.0.1'); extra.on('error', () => {}); await once(extra, 'close');
  for (const s of sockets) s.destroy(); await new Promise(resolve => setTimeout(resolve, 50));
  const body = net.connect(f.port, '127.0.0.1'); body.on('error', () => {}); await once(body, 'connect'); body.write(request(f, '/api/pause', { method: 'POST', headers: 'Content-Type: application/json\r\nContent-Length: 16\r\n', body: '{' }));
  assert.equal((await f.api('/api/shutdown', {})).status, 200);
  const probe = net.createServer(); const refused = once(probe, 'error'); probe.listen(f.port, '127.0.0.1'); assert.equal((await refused)[0].code, 'EADDRINUSE');
  body.destroy(); await f.exited; assert.equal((await f.store.load()).config.paused, false);
});
test('native Reserved admission rejects a valid previous manager proof during stalled publication', native, async t => {
  const port = await freePort(), installationId = randomUUID(); let cookie, before;
  const f = await nativeFixture(t, executable, { port, publicationDelay: 1800,
    before: async store => {
      await store.saveConfig({ version: 1, roots: [], paused: false, installationId });
      const manager = new ManagementSessions({ store, binding: () => JSON.stringify([`http://127.0.0.1:${port}`, installationId, '', '', '']) });
      cookie = (await manager.establish('', true)).cookie.split(';')[0];
      before = await fs.readFile(store.privateRecordPath('management-sessions'));
    },
    whileStarting: async ({ store }) => {
      const pending = { port, ready: { origin: `http://127.0.0.1:${port}` }, session: { token: '' } };
      let response;
      for (let n = 0; n < 50; n++) { try { response = await raw(port, request(pending, '/api/management/logout', { method: 'POST', headers: `X-Chat2Local-Manager: 1\r\nCookie: ${cookie}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n`, body: '{}' })); break; } catch (e) { if (e.code !== 'ECONNREFUSED') throw e; await new Promise(resolve => setTimeout(resolve, 10)); } }
      assert.match(response, /^HTTP\/1.1 503/);
      assert.deepEqual(await fs.readFile(store.privateRecordPath('management-sessions')), before);
      await assert.rejects(fs.stat(path.join(store.directory, 'session.json')), { code: 'ENOENT' });
    },
  });
  assert.equal((await f.api('/api/status', undefined, { 'X-Chat2Local-Token': '', 'X-Chat2Local-Manager': '1', Cookie: cookie })).status, 200);
  assert.deepEqual(await fs.readFile(f.store.privateRecordPath('management-sessions')), before);
});
test('native startup refuses present non-string saved writeMode without publishing state or session', native, async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-malformed-mode-')); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.writeFile(path.join(directory, '.chat2local-synthetic-fixture'), 'synthetic-only\n');
  const store = new Store(directory);
  for (const mode of [false, 0, {}, []]) {
    await store.saveConfig({ version: 1, roots: [{ id: randomUUID(), path: 'C:/synthetic', write: false, writeMode: mode }], paused: false });
    const before = await fs.readFile(path.join(directory, 'settings.json'));
    const child = spawn(executable, ['--synthetic-state', directory, '--port', String(await freePort()), '--fixture-only'], { windowsHide: true, stdio: 'ignore' }); assert.notEqual((await once(child, 'exit'))[0], 0);
    assert.deepEqual(await fs.readFile(path.join(directory, 'settings.json')), before); await assert.rejects(fs.stat(path.join(directory, 'session.json')), { code: 'ENOENT' });
  }
});


test('native startup accepts completed and aborted write history and refuses unresolved or unsafe fences without writes', native, async t => {
  const operationId = randomUUID();
  const completed = { v: 1, operationId, intent: 'a'.repeat(64), sha256: 'b'.repeat(64), phase: 'complete', binding: { rootId: 'root_1', rootPath: 'C:/synthetic', path: 'safe.txt', beforeHash: null, deviceId: null, resource: '\ud800', connectionId: null, fileId: [0, 1, 4294967295] } };
  const snapshot = async directory => { const out = {}; for (const name of (await fs.readdir(directory, { recursive: true })).sort()) { const stat = await fs.lstat(path.join(directory, name)); out[name] = stat.isDirectory() ? 'directory' : hash(await fs.readFile(path.join(directory, name))); } return out; };
  const writeHistory = async (directory, value = completed, name = operationId + '.json') => { const writes = path.join(directory, 'rust-writes'); await fs.mkdir(writes); await fs.writeFile(path.join(writes, name), typeof value === 'string' ? value : JSON.stringify(value)); return writes; };
  const f = await nativeFixture(t, executable, { before: async store => {
    const writes = await writeHistory(store.directory);
    const abortedId = randomUUID();
    // JSON numeric spellings and duplicate keys follow JSON.parse, including last-key wins.
    await fs.writeFile(path.join(writes, abortedId + '.json'), JSON.stringify({ ...completed, operationId: abortedId, phase: 'aborted' }).replace('"v":1', '"v":0,"v":1.0').replace('[0,1,4294967295]', '[0.0,1e0,4294967295.0]'));
    await fs.writeFile(path.join(writes, operationId + '.before'), 'prior'); await fs.writeFile(path.join(writes, 'writer.lock'), '');
    await assertWriteFenceClear(store.directory);
  } });
  assert.equal((await f.api('/api/status')).status, 200); await f.close();
  const scenarios = [
    ['gate', directory => fs.mkdir(path.join(directory, 'write-gate'))],
    ['pending', directory => writeHistory(directory, { ...completed, phase: 'prepared' })],
    ['malformed JSON', directory => writeHistory(directory, '{')],
    ['unknown field', directory => writeHistory(directory, { ...completed, unknown: 1 })],
    ['uppercase digest', directory => writeHistory(directory, { ...completed, intent: 'A'.repeat(64) })],
    ['unsafe binding', directory => writeHistory(directory, { ...completed, binding: { ...completed.binding, path: '../unsafe.txt' } })],
    ['relative root', directory => writeHistory(directory, { ...completed, binding: { ...completed.binding, rootPath: 'relative' } })],
    ['invalid history name', directory => writeHistory(directory, '', 'invalid.before')],
    ['directory record', async directory => { await fs.mkdir(path.join(directory, 'rust-writes', operationId + '.json'), { recursive: true }); }],
    ['multiple links', async directory => { const writes = await writeHistory(directory); await fs.link(path.join(writes, operationId + '.json'), path.join(directory, 'linked-record')); }],
    ['non-directory fence', directory => fs.writeFile(path.join(directory, 'rust-writes'), 'unsafe')],
  ];
  for (const [label, arrange] of scenarios) {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-write-fence-'));
    try {
      await fs.writeFile(path.join(directory, '.chat2local-synthetic-fixture'), 'synthetic-only\n');
      await new Store(directory).saveConfig({ version: 1, roots: [], paused: false }); await arrange(directory);
      await assert.rejects(assertWriteFenceClear(directory), { code: 'EFENCE' }, label);
      const before = await snapshot(directory);
      await assert.rejects(nativeFixture(t, executable, { directory }), /EFENCE/, label);
      assert.deepEqual(await snapshot(directory), before, label + ' preserves all evidence and publishes nothing');
    } finally { await fs.rm(directory, { recursive: true, force: true }); }
  }
});
