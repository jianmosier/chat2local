import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { TOOLS, handleMcp, sha256 } from '../src/shared/protocol.mjs';
import { toolCatalog, invocationCapabilities, checkedCapabilities, ToolReadiness } from '../src/shared/tool-capabilities.mjs';
import { routeDeviceTool } from '../src/relay/device-router.mjs';
import { newGuide, guideView } from '../src/agent/connection-guide.mjs';
import { startController } from '../src/agent/main.mjs';

const identity = { deviceId: '1'.repeat(32), origin: 'https://relay.example.test' };
const props = { deviceId: identity.deviceId, epoch: '2'.repeat(64), scopes: ['files:read', 'files:propose'] };
const names = TOOLS.map(tool => tool.name).sort();
const oldNames = names.filter(name => !name.startsWith('terminal_') && !['write_file', 'list_devices'].includes(name));

test('advertised catalog matches actual tools/list, including writes not granted to a read-only client', async () => {
  const response = await handleMcp(new Request(identity.origin + '/mcp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) }), () => assert.fail('metadata must not invoke files'));
  const tools = (await response.json()).result.tools;
  const catalog = await toolCatalog();
  assert.deepEqual(catalog.toolNames, tools.map(tool => tool.name).sort());
  assert.equal(catalog.schemaSha256, await sha256(JSON.stringify(tools)));
  const value = await invocationCapabilities(props, identity.origin, identity.deviceId, 'list_roots');
  assert.equal(value.toolNames.includes('write_file'), true);
  assert.equal(value.grantedScopes.includes('files:write'), false);
  assert.equal(JSON.stringify(value).includes(props.epoch), false);
});
test('old list_roots carries diagnostics without changing its arguments or granting a new operation', async () => {
  let envelope;
  const result = await routeDeviceTool({ props, tool: 'list_roots', args: {}, origin: identity.origin, invoke: async (_target, tool, args, diagnostic) => { assert.equal(tool, 'list_roots'); assert.deepEqual(args, {}); envelope = diagnostic; return [{ id: 'root', label: 'sample', writeMode: 'direct' }]; } });
  assert.equal(Array.isArray(result), true); assert.equal(result[0].id, 'root');
  assert.deepEqual(result[0].connectionDiagnostics, envelope);
  assert.equal(envelope.grantedScopes.includes('files:write'), false);
  await assert.rejects(() => routeDeviceTool({ props, tool: 'write_file', args: {}, origin: identity.origin, invoke: () => assert.fail('must not write') }), /permission/);
});
test('missing, stale, forged-target and secret-containing envelopes never count as capability evidence', async () => {
  const valid = await invocationCapabilities(props, identity.origin, identity.deviceId, 'list_roots');
  assert.ok(checkedCapabilities(valid, identity, 'list_roots'));
  for (const value of [null, {}, { ...valid, deviceId: '3'.repeat(32) }, { ...valid, origin: 'https://wrong.test' }, { ...valid, checkedAt: new Date(0).toISOString() }, { ...valid, token: 'secret' }, { ...valid, grantedScopes: ['admin'] }, { ...valid, toolNames: ['write_file', 'write_file'] }]) assert.equal(checkedCapabilities(value, identity, 'list_roots'), null);
  assert.equal(checkedCapabilities(valid, identity, 'read_file'), null);
});
test('five-tool session, server catalog and saved ChatGPT connection remain separate facts', async () => {
  const attempt = randomUUID(); const tracker = new ToolReadiness();
  tracker.reportSession(attempt, oldNames);
  let view = tracker.view(identity, attempt);
  assert.equal(view.server.status, 'unknown'); assert.deepEqual(view.session.missingTools, ['write_file', 'list_devices']);
  tracker.observeRemote(await invocationCapabilities(props, identity.origin, identity.deviceId, 'list_roots'), identity, 'list_roots');
  view = tracker.view(identity, attempt);
  assert.equal(view.server.toolNames.length, TOOLS.length); assert.equal(view.session.tools.length, 5);
  assert.equal(view.savedConnection.status, 'not-observable'); assert.equal(view.latestCallWriteScope, false);
  assert.equal(view.mayAttemptWrite, false); assert.equal(view.fileAccessGranted, false);
  assert.equal(tracker.view({ ...identity, deviceId: '4'.repeat(32) }, attempt).server.status, 'unknown');
});
test('advisory reports expire, cannot grant writing, and cannot complete actual guide evidence', async () => {
  let now = Date.now(); const attempt = randomUUID(); const tracker = new ToolReadiness(() => now);
  tracker.reportSession(attempt, names);
  const diagnostic = await invocationCapabilities({ ...props, scopes: ['files:read', 'files:write'] }, identity.origin, identity.deviceId, 'list_roots');
  tracker.observeRemote(diagnostic, identity, 'list_roots');
  const cap = tracker.view(identity, attempt); assert.equal(cap.mayAttemptWrite, true); assert.equal(cap.fileAccessGranted, false);
  const rootId = randomUUID(); const config = { paused: false, relay: identity.origin, roots: [{ id: rootId, label: 'sample', path: '/sample', write: true, writeMode: 'direct' }], connectionGuide: newGuide(rootId, attempt), remoteUseConfirmed: true };
  assert.equal(guideView(config, { device: identity, bridge: 'connected', capabilities: cap }).complete, false);
  now += 300001;
  const expired = tracker.view(identity, attempt); assert.equal(expired.server.status, 'unknown'); assert.equal(expired.session.status, 'unknown'); assert.equal(expired.mayAttemptWrite, false);
  assert.equal(guideView(config, { device: identity, bridge: 'connected', capabilities: expired }).stage, 'check-tools');
  assert.equal(guideView(config, { device: identity, bridge: 'disconnected', capabilities: expired }).stage, 'reconnecting');
});
test('local session observation endpoint cannot change roots, grant scopes, or mark a probe complete', async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-capability-')); const folder = path.join(base, 'folder'); await fs.mkdir(folder);
  const app = await startController({ port: 0, stateDir: path.join(base, 'private') });
  t.after(async () => { await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  const request = (route, value, extra = {}) => fetch(app.origin + '/api/' + route, { method: value === undefined ? 'GET' : 'POST', headers: { Origin: app.origin, 'Content-Type': 'application/json', 'X-Chat2Local-Token': app.token, ...extra }, ...(value === undefined ? {} : { body: JSON.stringify(value) }) });
  const attemptId = randomUUID();
  assert.equal((await request('guide/authorize', { path: folder, expectedRootId: null, expectedWriteMode: null, requestId: attemptId, confirmDirect: true })).status, 200);
  const before = await (await request('status')).json();
  assert.equal((await request('guide/session-tools', { attemptId, tools: names }, { 'X-Chat2Local-Token': '0'.repeat(64) })).status, 401);
  assert.equal((await request('guide/session-tools', { attemptId, tools: names }, { Origin: 'https://wrong.test' })).status, 403);
  assert.equal((await request('guide/session-tools', { attemptId: randomUUID(), tools: names })).status, 409);
  assert.equal((await request('guide/session-tools', { attemptId, tools: names, complete: true })).status, 400);
  const result = await (await request('guide/session-tools', { attemptId, tools: oldNames })).json();
  assert.equal(result.complete, false); assert.equal(result.capabilities.server.status, 'unknown');
  assert.deepEqual(result.capabilities.session.missingTools, ['write_file', 'list_devices']);
  const after = await (await request('status')).json();
  assert.deepEqual(after.roots, before.roots); assert.equal(after.mcpUrl, before.mcpUrl); assert.equal(after.pending.length, 0);
  assert.deepEqual(await fs.readdir(folder), []);
});
