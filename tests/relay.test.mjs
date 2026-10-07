import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { startController } from '../src/agent/main.mjs';
import { guideProbe } from '../src/agent/connection-guide.mjs';

const secret = () => randomBytes(32).toString('hex');
async function unpack(response, expected = 200) { assert.equal(response.status, expected, await response.clone().text()); return response.json(); }
async function until(check) { const end = Date.now() + 8000; while (Date.now() < end) { if (await check()) return; await new Promise(resolve => setTimeout(resolve, 40)); } throw new Error('Condition timed out.'); }

test('Cloudflare runtime: OAuth, device bridge and locally approved write end-to-end', { timeout: 90000 }, async t => {
  const bundle = await build({ entryPoints: ['src/relay/worker.mjs'], bundle: true, write: false, format: 'esm', platform: 'neutral', mainFields: ['module', 'main'], external: ['cloudflare:workers'] });
  const enrollmentKey = secret();
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundle.outputFiles[0].text, compatibilityDate: '2026-09-20', compatibilityFlags: ['nodejs_compat', 'global_fetch_strictly_public'],
    host: '127.0.0.1', port: 0, kvNamespaces: ['OAUTH_KV'],
    durableObjects: { DEVICES: { className: 'Device', useSQLite: true }, REGISTRY: { className: 'Registry', useSQLite: true } },
    bindings: { ALLOW_LOOPBACK: 'true', ENROLLMENT_KEY: enrollmentKey },
  }));
  t.after(() => mf.dispose());
  const origin = (await mf.ready).origin;
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'chat2local-relay-test-'));
  const root = path.join(base, 'project'); await fs.mkdir(root);
  await fs.writeFile(path.join(root, 'example.txt'), 'Before approval.\n');
  const app = await startController({ port: 0, stateDir: path.join(base, 'private'), demoDir: path.join(base, 'demo'), allowLocalRelay: true });
  t.after(async () => { await app.close(); await fs.rm(base, { recursive: true, force: true }); });
  const local = (route, value) => fetch(`${app.origin}/api/${route}`, { method: value === undefined ? 'GET' : 'POST', headers: { 'X-Chat2Local-Token': app.token, Origin: app.origin, 'Content-Type': 'application/json' }, ...(value === undefined ? {} : { body: JSON.stringify(value) }) });
  const permission = await unpack(await local('root/add', { path: root, write: true }));
  const formPost = (url, value, extra = {}) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...extra }, body: new URLSearchParams(value), redirect: 'manual' });
  const client = async () => unpack(await fetch(`${origin}/oauth/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client_name: 'Test <untrusted>', redirect_uris: ['http://127.0.0.1:54321/callback'], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] }) }), 201);
  const begin = async (scope = 'files:read files:propose') => {
    const registration = await client(); const verifier = secret();
    const query = new URLSearchParams({ response_type: 'code', client_id: registration.client_id, redirect_uri: registration.redirect_uris[0], scope, state: secret(), code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url'), resource: `${origin}/mcp` });
    const response = await fetch(`${origin}/authorize?${query}`, { redirect: 'manual' });
    assert.equal(response.status, 200, await response.clone().text());
    const page = await response.text();
    assert.equal(page.includes('Test <untrusted>'), false); assert.ok(page.includes('Test &lt;untrusted&gt;'));
    const ticket = /name="ticket" value="([a-f0-9]{64})"/.exec(page)?.[1]; assert.ok(ticket);
    return { registration, verifier, query, ticket, cookie: response.headers.get('set-cookie').split(';')[0] };
  };
  const consent = async (flow, pair, write = true, overrides = {}) => formPost(`${origin}/authorize`, { ticket: flow.ticket, pair, ...(write ? { propose: 'yes' } : {}) }, { Origin: origin, Cookie: flow.cookie, ...overrides });
  const exchange = (flow, code, extra = {}) => formPost(`${origin}/oauth/token`, { grant_type: 'authorization_code', client_id: flow.registration.client_id, redirect_uri: flow.registration.redirect_uris[0], code, code_verifier: flow.verifier, resource: `${origin}/mcp`, ...extra });
  const authorize = async (scope = 'files:read files:propose', write = true, getPair = async () => unpack(await local('pair-code', {}))) => {
    const flow = await begin(scope); const { code: pair } = await getPair();
    const accepted = await consent(flow, pair, write); assert.equal(accepted.status, 303, await accepted.clone().text());
    const redirect = new URL(accepted.headers.get('location')); assert.equal(redirect.searchParams.get('state'), flow.query.get('state'));
    const tokens = await unpack(await exchange(flow, redirect.searchParams.get('code')));
    return { flow, pair, tokens, code: redirect.searchParams.get('code') };
  };
  const call = async (token, tool, args = {}) => {
    const response = await fetch(`${origin}/mcp`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'MCP-Protocol-Version': '2025-11-25', Accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: secret(), method: 'tools/call', params: { name: tool, arguments: args } }) });
    const value = await unpack(response); return value.result;
  };

  await t.test('health and OAuth discovery; unauthorized MCP and bad enrollment are rejected', async () => {
    const health = await unpack(await fetch(`${origin}/healthz`));
    assert.equal(health.name, 'chat2local-relay');
    assert.equal(health.requestBudgetVersion, 2, 'The relay-only hotfix is observable without a client version change.');
    const response = await fetch(`${origin}/mcp`); assert.equal(response.status, 401); assert.match(response.headers.get('www-authenticate'), /resource_metadata/);
    const metadata = await unpack(await fetch(`${origin}/.well-known/oauth-protected-resource/mcp`)); assert.equal(metadata.resource, `${origin}/mcp`);
    assert.equal((await fetch(`${origin}/enroll`, { method: 'POST', body: '{}' })).status, 401);
    assert.equal((await fetch(`${origin}/mcp`, { headers: { Origin: 'https://attacker.invalid' } })).status, 403);
  });
  await t.test('device enrolls once and establishes an actual outbound WebSocket', async () => {
    await unpack(await local('enroll', { origin, enrollmentToken: enrollmentKey }));
    await until(() => app.bridge.state === 'connected');
    assert.equal((await unpack(await local('status'))).mcpUrl, `${origin}/mcp`);
  });
  await t.test('PKCE, registered redirects, form origin and CSRF cookie are enforced', async () => {
    const flow = await begin();
    const query = new URLSearchParams(flow.query); query.delete('code_challenge'); query.delete('code_challenge_method');
    assert.equal((await fetch(`${origin}/authorize?${query}`)).status, 400);
    query.set('redirect_uri', 'https://attacker.invalid/callback');
    const invalid = await fetch(`${origin}/authorize?${query}`, { redirect: 'manual' }); assert.equal(invalid.status, 400); assert.equal(invalid.headers.has('location'), false);
    const { code } = await unpack(await local('pair-code', {}));
    assert.equal((await consent(flow, code, true, { Cookie: '' })).status, 403);
    assert.equal((await consent(flow, code, true, { Origin: 'https://attacker.invalid' })).status, 403);
  });
  let full;
  await t.test('OAuth consent and token exchange succeed; pairing codes are single-use', async () => {
    full = await authorize(); assert.ok(full.tokens.access_token);
    const another = await begin(); assert.equal((await consent(another, full.pair)).status, 403);
    assert.equal((await consent(full.flow, full.pair)).status, 403);
    // The provider revokes a grant when its authorization code is replayed.
    // Use a separate grant so the security test does not revoke the main test's token.
    const replay = await authorize();
    assert.equal((await exchange(replay.flow, replay.code)).status, 400);
  });
  await t.test('MCP read -> write proposal -> local approval -> operation status crosses the relay', async () => {
    const roots = await call(full.tokens.access_token, 'list_roots'); assert.equal(roots.isError, false);
    const rootData = JSON.parse(roots.content[0].text)[0];
    assert.equal(rootData.id, permission.id);
    assert.equal(rootData.connectionDiagnostics.toolNames.includes('write_file'), true);
    assert.equal(rootData.connectionDiagnostics.toolNames.includes('list_devices'), true);
    assert.equal(rootData.connectionDiagnostics.grantedScopes.includes('files:write'), false);
    const guide = await unpack(await local('guide'));
    assert.equal(guide.capabilities.server.status, 'observed-on-authenticated-call');
    assert.equal(guide.capabilities.latestCallWriteScope, false);
    assert.equal(guide.capabilities.savedConnection.status, 'not-observable');
    assert.equal(guide.capabilities.session.status, 'unknown');
    assert.equal(guide.complete, false);
    const read = await call(full.tokens.access_token, 'read_file', { rootId: permission.id, path: 'example.txt' });
    assert.equal(read.isError, false); const snapshot = JSON.parse(read.content[0].text);
    const proposed = await call(full.tokens.access_token, 'propose_write', { rootId: permission.id, path: 'example.txt', expectedHash: snapshot.sha256, content: 'After local approval.\n' });
    assert.equal(proposed.isError, false); const op = JSON.parse(proposed.content[0].text);
    assert.equal(op.status, 'pending'); assert.equal(await fs.readFile(path.join(root, 'example.txt'), 'utf8'), 'Before approval.\n');
    assert.equal((await unpack(await local('approve', { operationId: op.operationId, approved: true }))).status, 'approved');
    assert.equal(await fs.readFile(path.join(root, 'example.txt'), 'utf8'), 'After local approval.\n');
    assert.equal(JSON.parse((await call(full.tokens.access_token, 'operation_status', { operationId: op.operationId })).content[0].text).status, 'approved');
  });
  await t.test('OAuth read-only grants cannot propose writes; local pause still overrides cloud grants', async () => {
    const readonly = await authorize('files:read', false);
    const denied = await call(readonly.tokens.access_token, 'propose_write', { rootId: permission.id, path: 'new.txt', expectedHash: null, content: 'bad' }); assert.equal(denied.isError, true); assert.match(denied.content[0].text, /scope/);
    await unpack(await local('pause', { paused: true }));
    assert.equal((await call(full.tokens.access_token, 'list_roots')).isError, true);
    await unpack(await local('pause', { paused: false }));
  });
  await t.test('offline access is advertised and refresh never grants declined write permission', async () => {
    const metadata = await unpack(await fetch(`${origin}/.well-known/oauth-authorization-server`));
    assert.ok(metadata.scopes_supported.includes('offline_access'));
    const readOnly = await authorize('files:read files:propose offline_access', false);
    assert.ok(readOnly.tokens.refresh_token);
    assert.ok(readOnly.tokens.scope.split(' ').includes('offline_access'));
    assert.equal(readOnly.tokens.scope.split(' ').includes('files:propose'), false);
    const refreshed = await unpack(await formPost(`${origin}/oauth/token`, { grant_type: 'refresh_token', client_id: readOnly.flow.registration.client_id, refresh_token: readOnly.tokens.refresh_token, resource: `${origin}/mcp` }));
    assert.equal((await call(refreshed.access_token, 'list_roots')).isError, false);
    assert.equal((await call(refreshed.access_token, 'propose_write', { rootId: permission.id, path: 'no.txt', expectedHash: null, content: 'not approved' })).isError, true);
  });
  await t.test('refreshing to narrower scopes does not retain write permission in application props', async () => {
    const tokens = await unpack(await formPost(`${origin}/oauth/token`, { grant_type: 'refresh_token', client_id: full.flow.registration.client_id, refresh_token: full.tokens.refresh_token, scope: 'files:read', resource: `${origin}/mcp` }));
    assert.equal((await call(tokens.access_token, 'list_roots')).isError, false);
    assert.equal((await call(tokens.access_token, 'propose_write', { rootId: permission.id, path: 'new.txt', expectedHash: null, content: 'bad' })).isError, true);
  });
  let directGrant;
  const issueDirect = async (approve = true) => {
    const flow = await begin('files:read files:write offline_access');
    const { code: pair } = await unpack(await local('pair-code', {}));
    const accepted = await formPost(`${origin}/authorize`, { ticket: flow.ticket, pair, ...(approve ? { directWrite: 'yes' } : {}) }, { Origin: origin, Cookie: flow.cookie });
    assert.equal(accepted.status, 303);
    const code = new URL(accepted.headers.get('location')).searchParams.get('code');
    return { flow, tokens: await unpack(await exchange(flow, code)) };
  };
  await t.test('direct tool requires BOTH explicit OAuth scope and explicit directory mode', async () => {
    const args = { rootId: permission.id, path: 'direct.txt', expectedHash: null, content: 'direct result' };
    const oldGrant = await call(full.tokens.access_token, 'write_file', args);
    assert.equal(oldGrant.isError, true); assert.match(oldGrant._meta['mcp/www_authenticate'][0], /files:write/);
    directGrant = await issueDirect();
    assert.ok(directGrant.tokens.scope.split(' ').includes('files:write'));
    assert.equal((await call(directGrant.tokens.access_token, 'write_file', args)).isError, true); // Still review mode.
    await unpack(await local('root/set-mode', { id: permission.id, writeMode: 'direct', expectedWriteMode: 'review', confirmDirect: true }));
    assert.equal((await call(full.tokens.access_token, 'write_file', args)).isError, true); // Directory consent cannot upgrade old OAuth.
    const response = await call(directGrant.tokens.access_token, 'write_file', args);
    assert.equal(response.isError, false); const op = JSON.parse(response.content[0].text); assert.equal(op.status, 'written');
    assert.equal((await unpack(await local('status'))).pending.length, 0);
    assert.equal(JSON.parse((await call(directGrant.tokens.access_token, 'read_file', { rootId: permission.id, path: 'direct.txt' })).content[0].text).content, 'direct result');
    assert.equal(await fs.readFile(path.join(root, 'direct.txt'), 'utf8'), 'direct result');
    await unpack(await local('root/set-mode', { id: permission.id, writeMode: 'review', expectedWriteMode: 'direct' }));
    assert.equal((await call(directGrant.tokens.access_token, 'write_file', { ...args, expectedHash: op.sha256 })).isError, true);
  });
  await t.test('unified guide completes only after authenticated remote create, backed-up modify and matching readback', async () => {
    const intent = crypto.randomUUID();
    const guided = await unpack(await local('guide/authorize', { path: root, expectedRootId: permission.id, expectedWriteMode: 'review', requestId: intent, confirmDirect: true }));
    assert.equal(guided.directoryGranted, true); assert.equal(guided.complete, false);
    const probe = guideProbe({ version: 1, rootId: permission.id, id: intent, startedAt: guided.startedAt });
    const args = { rootId: permission.id, path: probe.path, expectedHash: null, content: probe.created };
    assert.equal((await call(full.tokens.access_token, 'write_file', args)).isError, true);
    assert.equal((await unpack(await local('guide'))).evidence.createdAt, null);
    assert.equal((await call(directGrant.tokens.access_token, 'write_file', args)).isError, false);
    assert.ok((await unpack(await local('guide'))).evidence.createdAt);
    await call(directGrant.tokens.access_token, 'read_file', { rootId: permission.id, path: probe.path });
    assert.equal((await unpack(await local('guide'))).complete, false);
    assert.equal((await call(directGrant.tokens.access_token, 'write_file', { ...args, expectedHash: probe.createdHash, content: probe.updated })).isError, false);
    assert.equal((await unpack(await local('guide'))).complete, false);
    await call(directGrant.tokens.access_token, 'read_file', { rootId: permission.id, path: probe.path });
    const finished = await unpack(await local('guide')); assert.equal(finished.stage, 'ready'); assert.equal(finished.complete, true);
    assert.equal(await fs.readFile(path.join(root, probe.path), 'utf8'), probe.updated);
    await unpack(await local('root/set-mode', { id: permission.id, expectedWriteMode: 'direct', writeMode: 'review' }));
    assert.equal((await unpack(await local('guide'))).complete, false);
  });
  await t.test('declined or narrowed direct scope is never restored by refresh', async () => {
    const declined = await issueDirect(false); assert.equal(declined.tokens.scope.split(' ').includes('files:write'), false);
    const declinedRefresh = await unpack(await formPost(`${origin}/oauth/token`, { grant_type: 'refresh_token', client_id: declined.flow.registration.client_id, refresh_token: declined.tokens.refresh_token, resource: `${origin}/mcp` }));
    const narrowed = await unpack(await formPost(`${origin}/oauth/token`, { grant_type: 'refresh_token', client_id: directGrant.flow.registration.client_id, refresh_token: directGrant.tokens.refresh_token, resource: `${origin}/mcp`, scope: 'files:read' }));
    for (const tokens of [declined.tokens, declinedRefresh, narrowed]) {
      const result = await call(tokens.access_token, 'write_file', { rootId: permission.id, path: 'never.txt', content: 'denied', expectedHash: null });
      assert.equal(result.isError, true); assert.match(result._meta['mcp/www_authenticate'][0], /insufficient_scope/);
    }
    const flow = await begin('files:read files:propose'); const { code: pair } = await unpack(await local('pair-code', {}));
    const forged = await formPost(`${origin}/authorize`, { ticket: flow.ticket, pair, directWrite: 'yes' }, { Origin: origin, Cookie: flow.cookie });
    assert.equal(forged.status, 400); await assert.rejects(() => fs.access(path.join(root, 'never.txt')));
  });
  await t.test('disconnect/reconnect does not replay a tool request', async () => {
    const saved = app.bridge.identity; const count = app.files.operations.size;
    app.bridge.stop(); await new Promise(resolve => setTimeout(resolve, 100));
    const offline = await call(full.tokens.access_token, 'list_roots'); assert.equal(offline.isError, true);
    app.bridge.start(saved); await until(() => app.bridge.state === 'connected');
    assert.equal((await call(full.tokens.access_token, 'list_roots')).isError, false);
    assert.equal(app.files.operations.size, count);
  });
  let otherToken; let otherRoot;
  await t.test('two computers remain isolated even under the same relay operator', async () => {
    const secondFolder = path.join(base, 'second-project'); await fs.mkdir(secondFolder);
    const second = await startController({ port: 0, stateDir: path.join(base, 'second-private'), allowLocalRelay: true });
    t.after(() => second.close());
    const secondLocal = (route, value) => fetch(`${second.origin}/api/${route}`, { method: 'POST', headers: { 'X-Chat2Local-Token': second.token, Origin: second.origin, 'Content-Type': 'application/json' }, body: JSON.stringify(value) });
    otherRoot = await unpack(await secondLocal('root/add', { path: secondFolder, write: false }));
    await unpack(await secondLocal('enroll', { origin, enrollmentToken: enrollmentKey }));
    await until(() => second.bridge.state === 'connected');
    const auth = await authorize('files:read', false, async () => unpack(await secondLocal('pair-code', {}))); otherToken = auth.tokens.access_token;
    const roots = JSON.parse((await call(otherToken, 'list_roots')).content[0].text);
    assert.deepEqual(roots.map(item => item.id), [otherRoot.id]);
    const foreign = await call(otherToken, 'read_file', { rootId: permission.id, path: 'example.txt' });
    assert.equal(foreign.isError, true); assert.match(foreign.content[0].text, /not authorized/);
  });
  await t.test('device revocation invalidates existing OAuth grants before further file access', async () => {
    const resultLocal = await unpack(await local('disconnect', {})); assert.equal(resultLocal.remoteRevoked, true);
    const result = await call(full.tokens.access_token, 'list_roots'); assert.equal(result.isError, true); assert.match(result.content[0].text, /revoked/);
    const secondRoots = JSON.parse((await call(otherToken, 'list_roots')).content[0].text); assert.equal(secondRoots[0].id, otherRoot.id);
  });
});
