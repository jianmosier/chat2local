import path from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { loadDeployment, canonicalOrigin, verifiedLocalSession } from './cloud-setup.mjs';
import { defaultStateDir } from '../src/agent/store.mjs';
import { localNetworkOnly, NetworkManager } from '../src/agent/network.mjs';
import { readLimited, TOOLS } from '../src/shared/protocol.mjs';

// Explicit live diagnostic. Creates its OWN public OAuth client and read-only
// grant; never uses/replaces ChatGPT tokens. Only initialize/ping/tools/list are
// sent to MCP. No file tool is called. Revoke diagnostic tokens in finally.
if (process.argv[2] !== '--live') throw new Error('Use --live to authorize a metadata-only OAuth diagnostic.');
const report = { client: 'official-mcp-sdk-diagnostic', websiteClientVerified: false, fileToolsCalled: false, stages: [] };
const network = new NetworkManager(() => ({ mode: 'auto' }));
let tokens; let registration; let metadata; let origin; let client;
const secret = () => randomBytes(32).toString('hex');
const safeRoute = value => { const url = new URL(value); if (url.origin !== origin || url.username || url.password || url.hash) throw new Error('Diagnostic refused an external credential destination.'); return url.href; };
const request = async (route, options = {}) => fetch(safeRoute(new URL(route, origin)), { redirect: 'manual', ...options, signal: AbortSignal.timeout(15_000) });
async function decode(response, stage, expected = 200) {
  let data;
  try { data = JSON.parse(await readLimited(response, 64 * 1024)); } catch { throw new Error(`${stage}: non-JSON HTTP ${response.status}`); }
  report.stages.push({ stage, status: response.status, ...(typeof data.error === 'string' && /^[a-z_]{1,60}$/.test(data.error) ? { oauthError: data.error } : {}) });
  if (response.status !== expected) throw new Error(`${stage}: HTTP ${response.status}`);
  return data;
}
const form = (route, body, headers = {}) => request(route, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(body) });
try {
  localNetworkOnly();
  const { session, state } = await verifiedLocalSession();
  report.desktop = { version: state.version, bridge: state.bridge, paused: state.paused, rootCount: state.roots.length, pendingCount: state.pending.length };
  if (state.bridge !== 'connected') throw new Error('DESKTOP_OFFLINE: existing device transport must recover before this metadata-only OAuth diagnostic. No directory or OAuth change is required by this check.');
  const demo = path.resolve(path.dirname(defaultStateDir()), 'Chat2LocalDemo').toLowerCase();
  if (state.roots.some(root => path.resolve(root.path).toLowerCase() !== demo) || state.pending.length || state.paused || state.bridge !== 'connected') throw new Error('Diagnostic requires an idle, connected, sample-only desktop. No policy changed.');
  origin = canonicalOrigin(await loadDeployment());
  if (state.relay !== origin) throw new Error('Desktop and deployment origins do not match.');
  await network.prepare(origin);
  metadata = await decode(await request('/.well-known/oauth-authorization-server'), 'discovery');
  for (const field of ['registration_endpoint', 'authorization_endpoint', 'token_endpoint', 'revocation_endpoint']) safeRoute(metadata[field]);
  const redirect = 'http://127.0.0.1:54321/chat2local-metadata-diagnostic';
  registration = await decode(await request(metadata.registration_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client_name: 'Chat2Local metadata diagnostic (not ChatGPT)', redirect_uris: [redirect], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] }) }), 'diagnostic-client', 201);
  const verifier = secret(); const stateValue = secret();
  const params = new URLSearchParams({ response_type: 'code', client_id: registration.client_id, redirect_uri: redirect, scope: 'files:read', state: stateValue, code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url'), resource: `${origin}/mcp` });
  const response = await request(`${metadata.authorization_endpoint}?${params}`);
  if (response.status !== 200) throw new Error(`Diagnostic consent request: HTTP ${response.status}`);
  const page = await readLimited(response, 64 * 1024);
  const ticket = /name="ticket" value="([a-f0-9]{64})"/.exec(page)?.[1];
  const cookie = response.headers.get('set-cookie')?.split(';')[0];
  if (!ticket || !cookie?.startsWith('c2l_csrf=')) throw new Error('Diagnostic consent proof unavailable.');
  const pairResponse = await fetch(`${session.origin}/api/pair-code`, { method: 'POST', headers: { Origin: session.origin, 'X-Chat2Local-Token': session.token, 'Content-Type': 'application/json' }, body: '{}', redirect: 'error', signal: AbortSignal.timeout(15_000) });
  const pair = await decode(pairResponse, 'diagnostic-pair');
  const consent = await form(metadata.authorization_endpoint, { ticket, pair: pair.code }, { Origin: origin, Cookie: cookie });
  if (consent.status !== 303) throw new Error(`Diagnostic consent: HTTP ${consent.status}`);
  const callback = new URL(consent.headers.get('location'));
  if (callback.origin + callback.pathname !== redirect || callback.searchParams.get('state') !== stateValue) throw new Error('Diagnostic callback mismatch.');
  tokens = await decode(await form(metadata.token_endpoint, { grant_type: 'authorization_code', client_id: registration.client_id, redirect_uri: redirect, code: callback.searchParams.get('code'), code_verifier: verifier, resource: `${origin}/mcp` }), 'diagnostic-token');
  client = new Client({ name: 'chat2local-official-sdk-diagnostic', version: '1.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(`${origin}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${tokens.access_token}` } }, fetch: async (url, options) => {
    safeRoute(url);
    const headers = new Headers(options?.headers); const message = typeof options?.body === 'string' ? JSON.parse(options.body) : undefined;
    if (message && !['initialize', 'notifications/initialized', 'ping', 'tools/list'].includes(message.method)) throw new Error('Diagnostic blocks file tool execution.');
    const out = await fetch(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(15_000) });
    report.stages.push({ stage: message?.method || options?.method || 'GET', status: out.status, protocol: headers.get('MCP-Protocol-Version'), contentType: out.headers.get('content-type') });
    if (!out.ok && out.status !== 405) {
      const raw = await readLimited(out.clone(), 8192); let data; try { data = JSON.parse(raw); } catch {}
      report.failure = { httpStatus: out.status, ...(typeof data?.error === 'string' && data.error.length < 120 ? { serverError: data.error } : {}), ...(Array.isArray(data?.supported) ? { supported: data.supported } : {}) };
    }
    return out;
  } });
  await client.connect(transport, { timeout: 15_000 });
  report.server = client.getServerVersion();
  const listed = await client.listTools({}, { timeout: 15_000 });
  report.tools = listed.tools.map(tool => ({ name: tool.name, hasSchema: tool.inputSchema?.type === 'object', routingParameter: Object.hasOwn(tool.inputSchema?.properties || {}, 'deviceId'), scopes: tool.securitySchemes?.flatMap(item => item.scopes || []) || [] }));
  report.catalog = { source: 'actual-authenticated-tools/list', names: listed.tools.map(tool => tool.name).sort(), schemaSha256: createHash('sha256').update(JSON.stringify(listed.tools)).digest('hex') };
  report.chatgptSavedConnection = 'not-inspected';
  report.chatgptSessionTools = 'not-inspected';
  report.ok = JSON.stringify(report.catalog.names) === JSON.stringify(TOOLS.map(tool => tool.name).sort());
} catch (error) {
  report.ok = false;
  // Never echo transport error bodies or authorization URLs into the transcript.
  report.errorClass = error.name;
  report.error = report.failure ? 'Authenticated discovery failed; see failure/status metadata.' : String(error.message).replace(/https?:\/\/\S+/g, '[url]').replace(/[a-f0-9]{32,}/gi, '[redacted]').slice(0, 220);
  process.exitCode = 1;
} finally {
  await client?.close().catch(() => {});
  if (tokens && metadata && registration) {
    report.revoked = [];
    for (const [key, hint] of [['refresh_token', 'refresh_token'], ['access_token', 'access_token']]) {
      if (!tokens[key]) continue;
      try { const response = await form(metadata.revocation_endpoint, { token: tokens[key], token_type_hint: hint, client_id: registration.client_id }); report.revoked.push({ kind: hint, status: response.status }); }
      catch { report.revoked.push({ kind: hint, status: 'unconfirmed' }); }
    }
  }
  network.close();
  console.log(JSON.stringify(report, null, 2));
}
