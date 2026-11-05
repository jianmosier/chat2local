import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { fileURLToPath } from 'node:url';

export const executable = process.env.CHAT2LOCAL_TRANSPORT_TEST_EXECUTABLE;
export const oracleExecutable = process.env.CHAT2LOCAL_TRANSPORT_NODE_ORACLE || process.execPath;
export const cleanEnv = () => ({ SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, TEMP: process.env.TEMP, TMP: process.env.TMP, PATH: process.platform === 'win32' ? path.join(process.env.SystemRoot, 'System32') : '/usr/bin:/bin' });
export function childJson(file, args, input, timeout = 15000) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { env: cleanEnv(), stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    let output = '', stderr = '', timer = setTimeout(() => child.kill(), timeout), overflow = false;
    child.stdout.on('data', b => { output += b; if (output.length > 4 * 1024 * 1024) { overflow = true; child.kill(); } });
    child.stderr.on('data', b => { stderr += b; if (stderr.length > 65536) child.kill(); });
    child.once('error', reject); child.stdin.on('error', () => {});
    child.once('close', code => { clearTimeout(timer); if (code || overflow) return reject(Error(`Fixture child failed or exceeded bounds: ${code}; ${stderr.slice(-8192)}`)); try { const result = JSON.parse(output); if (!result.ok && result.error && stderr) result.error.stderr = stderr.slice(-8192); resolve(result); } catch { reject(Error(`Invalid fixture JSON output; ${stderr.slice(-8192)}`)); } });
    child.stdin.end(JSON.stringify(input) + '\n');
  });
}
export const native = input => childJson(executable, [], input);
export function nativeSession() {
  const child = spawn(executable, [], { env: cleanEnv(), stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  let output = '', pending, alive = true;
  child.stdout.on('data', data => { output += data; if (output.length > 4 * 1024 * 1024) child.kill(); const index = output.indexOf('\n'); if (index >= 0 && pending) { const line = output.slice(0, index); output = output.slice(index + 1); const next = pending; pending = null; clearTimeout(next.timer); try { next.resolve(JSON.parse(line)); } catch { next.reject(Error('Fixture JSON invalid')); } } });
  child.stderr.resume(); child.stdin.on('error', () => {});
  const closed = new Promise(resolve => child.once('close', code => { alive = false; if (pending) { clearTimeout(pending.timer); pending.reject(Error('Fixture exited during operation')); } resolve(code); }));
  child.on('error', () => { if (pending) pending.reject(Error('Fixture process error')); });
  return { get alive() { return alive; }, request(input) { if (pending) throw Error('Fixture requests are serial'); return new Promise((resolve, reject) => { const timer = setTimeout(() => { child.kill(); reject(Error('Fixture operation timeout')); }, 15000); pending = { resolve, reject, timer }; child.stdin.write(JSON.stringify(input) + '\n'); }); }, async close() { child.stdin.end(); const timer = setTimeout(() => child.kill(), 2000); await closed; clearTimeout(timer); } };
}
export const oracle = input => childJson(oracleExecutable, ['--expose-internals', fileURLToPath(import.meta.url)], input);
export async function mint(input = {}) { const result = await native({ op: 'mint', ...input }); if (!result.ok) throw Error('Synthetic certificate creation failed.'); return result.result; }
export async function listen(server, host = '127.0.0.1') {
  const sockets = new Set(); const state = { accepted: 0, closed: 0, active: 0 };
  server.on('connection', socket => { state.accepted++; state.active++; sockets.add(socket); socket.on('error', () => {}); socket.on('end', () => socket.end()); socket.on('close', () => { state.closed++; state.active--; sockets.delete(socket); }); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, host, resolve); });
  return { server, host, port: server.address().port, state, async close() { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); } };
}
export async function waitClosed(endpoint, before = 0) { for (let i = 0; i < 100; i++) { if (endpoint.state.active === 0 && endpoint.state.closed > before) return true; await new Promise(r => setTimeout(r, 10)); } return false; }
export function addresses(...entries) { return Object.fromEntries(entries.map(([name, endpoint]) => [name, `${endpoint.host === '::1' ? '[::1]' : '127.0.0.1'}:${endpoint.port}`])); }
// TCP data events and HTTP upgrade head are arbitrary pieces of a frame stream.
export function clientFrameReader(onFrame) {
  let buffered = Buffer.alloc(0);
  return chunk => {
    buffered = Buffer.concat([buffered, chunk]);
    while (buffered.length >= 2) {
      const opcode = buffered[0] & 15, fin = Boolean(buffered[0] & 128);
      if (!(buffered[1] & 128) || (buffered[0] & 112)) throw Error('Invalid fixture client frame');
      let length = buffered[1] & 127, offset = 2;
      if (length === 126) { if (buffered.length < 4) return; length = buffered.readUInt16BE(2); offset = 4; }
      else if (length === 127) { if (buffered.length < 10) return; const size = buffered.readBigUInt64BE(2); if (size > 1024n * 1024n) throw Error('Fixture frame limit'); length = Number(size); offset = 10; }
      if (opcode >= 8 && (!fin || length > 125)) throw Error('Invalid fixture control frame');
      if (buffered.length < offset + 4 + length) return;
      const mask = buffered.subarray(offset, offset + 4), payload = Buffer.from(buffered.subarray(offset + 4, offset + 4 + length));
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
      buffered = buffered.subarray(offset + 4 + length);
      onFrame({ opcode, fin, payload });
    }
  };
}
export function serveWebSocketFixture(socket, { state, ws = 'echo', head = Buffer.alloc(0), trace = () => {} }) {
  let handled = false, closing = false;
  const receive = clientFrameReader(({ opcode, payload }) => {
    trace('frame', { opcode, bytes: payload.length });
    if (closing) return;
    if (opcode === 8) { closing = true; trace('close-reply'); socket.end(frame(payload, 8)); return; }
    if (opcode === 9) { socket.write(frame(payload, 10)); return; }
    if (handled || ![1, 2].includes(opcode)) return;
    handled = true; state.payloads++;
    if (ws === 'stall') return;
    trace('reply', { mode: ws });
    if (ws === 'fragments') { socket.write(frame(Buffer.alloc(300000, 97), 1, false)); socket.write(frame(Buffer.alloc(300000, 97), 0, true)); }
    else if (ws === 'exact') { socket.write(frame(Buffer.alloc(256 * 1024, 97), 1, false)); socket.write(frame(Buffer.alloc(256 * 1024, 97), 0, true)); }
    else if (ws === 'binary') socket.write(frame(Buffer.from('binary refusal'), 2));
    else if (ws === 'controls') { for (let i = 0; i < 130; i++) socket.write(frame(Buffer.from('p'), 9)); }
    else socket.write(frame(Buffer.from('native echo'), 1));
  });
  const consume = data => { trace('chunk', { bytes: data.length }); try { receive(data); } catch (error) { trace('parser-error', { message: error.message }); socket.destroy(); } };
  socket.on('data', consume);
  if (head.length) consume(head);
}
export async function destination({ certificate, handler, minVersion, maxVersion, ws = 'echo', host } = {}) {
  const state = { requests: 0, upgrades: 0, credentialSafe: true, payloads: 0, events: [] };
  const request = (req, res) => { state.requests++; state.credentialSafe &&= !req.headers['proxy-authorization']; handler ? handler(req, res, state) : res.end('native response'); };
  const server = certificate ? https.createServer({ ...certificate, minVersion, maxVersion }, request) : http.createServer(request);
  server.on('tlsClientError', () => {});
  server.on('upgrade', (req, socket, head) => {
    state.upgrades++; state.credentialSafe &&= !req.headers['proxy-authorization'];
    const connection = state.upgrades, start = Date.now();
    const trace = (event, details = {}) => { if (state.events.length < 256) state.events.push({ connection, event, ms: Date.now() - start, ...details }); };
    trace('upgrade', { headBytes: head.length });
    socket.on('error', error => trace('error', { code: error.code, message: error.message }));
    socket.on('end', () => trace('end')); socket.on('close', () => trace('close'));
    const accept = createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    let response = `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n`;
    if (req.headers['sec-websocket-protocol']) response += `Sec-WebSocket-Protocol: ${req.headers['sec-websocket-protocol']}\r\n`;
    socket.write(response + '\r\n');
    if (ws === 'backpressure') { socket.pause(); setTimeout(() => socket.resume(), 250).unref(); }
    serveWebSocketFixture(socket, { state, ws, head, trace });
  });
  const endpoint = await listen(server, host); return { ...endpoint, seen: state };
}
export function frame(payload, opcode = 1, fin = true) { const header = Buffer.alloc(payload.length < 126 ? 2 : payload.length < 65536 ? 4 : 10); header[0] = opcode | (fin ? 128 : 0); if (header.length === 2) header[1] = payload.length; else if (header.length === 4) { header[1] = 126; header.writeUInt16BE(payload.length, 2); } else { header[1] = 127; header.writeBigUInt64BE(BigInt(payload.length), 2); } return Buffer.concat([header, payload]); }
export async function proxy({ certificate, target, status = 200, raw, holdRaw = false, stall, expectedBasic = null, resetOnUpstreamError = false } = {}) {
  const seen = { tunnels: 0, upstream: 0, authMatches: true, isolated: true, authorities: [], resets: 0 };
  const server = certificate ? https.createServer(certificate) : http.createServer(); server.on('tlsClientError', () => {});
  const upstreams = new Set();
  server.on('connect', (req, socket, head) => {
    seen.tunnels++; seen.authMatches &&= (req.headers['proxy-authorization'] ?? null) === expectedBasic;
    seen.isolated &&= !req.headers.authorization && !req.headers.cookie && !req.headers['sec-websocket-protocol']; seen.authorities.push(req.url);
    if (stall) { socket.resume(); return; }
    if (raw !== undefined) { if (holdRaw) { socket.write(raw); socket.once('data', () => socket.end()); socket.resume(); } else socket.end(raw); return; }
    if (status !== 200) { socket.end(`HTTP/1.1 ${status} Denied\r\nContent-Length: 0\r\n\r\n`); return; }
    seen.upstream++; const upstream = net.connect(target.port, '127.0.0.1'); upstreams.add(upstream); upstream.on('error', error => { if (resetOnUpstreamError && error.code === 'ECONNRESET') { seen.resets++; (socket._parent ?? socket).resetAndDestroy(); } else socket.destroy(); }); socket.on('error', () => upstream.destroy()); socket.on('close', () => upstream.destroy()); upstream.on('close', () => { upstreams.delete(upstream); socket.destroy(); });
    upstream.once('connect', () => { socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); if (head.length) upstream.write(head); socket.pipe(upstream); upstream.pipe(socket); });
  });
  const endpoint = await listen(server); return { ...endpoint, seen, async close() { for (const s of upstreams) s.destroy(); await endpoint.close(); } };
}
export async function clientHelloServer({ next, failure = 'eof', failCount = 1, stallAfterFailure = false } = {}) {
  const groups = [], hellos = [], peers = new Set(); let attempts = 0;
  const server = net.createServer(socket => { let data = Buffer.alloc(0); const capture = chunk => { data = Buffer.concat([data, chunk]); if (data.length < 5 || data.length < data.readUInt16BE(3) + 5) return; socket.off('data', capture); groups.push(clientGroups(data)); hellos.push(clientHelloPolicy(data)); attempts++;
      if (attempts <= failCount) { if (failure === 'rst') socket.resetAndDestroy(); else if (failure === 'stall') {} else socket.end(); return; }
      if (stallAfterFailure) return;
      const peer = net.connect(next.port, '127.0.0.1'); peers.add(peer); peer.on('error', () => socket.destroy()); peer.on('close', () => { peers.delete(peer); socket.destroy(); }); socket.on('close', () => peer.destroy()); peer.once('connect', () => { peer.write(data); socket.pipe(peer); peer.pipe(socket); });
    }; socket.on('data', capture); });
  const endpoint = await listen(server); return { ...endpoint, groups, hellos, async close() { for (const p of peers) p.destroy(); await endpoint.close(); } };
}
export function clientHelloPolicy(buffer) { const result = { groups: clientGroups(buffer), ciphers: [], alpn: [] }; try { let i = 5 + 4 + 2 + 32; i += 1 + buffer[i]; const cipherEnd = i + 2 + buffer.readUInt16BE(i); for (let p = i + 2; p < cipherEnd; p += 2) result.ciphers.push(buffer.readUInt16BE(p)); i = cipherEnd; i += 1 + buffer[i]; const end = i + 2 + buffer.readUInt16BE(i); i += 2; while (i < end) { const type = buffer.readUInt16BE(i), length = buffer.readUInt16BE(i + 2); i += 4; if (type === 16) for (let p = i + 2; p < i + length;) { const n = buffer[p++]; result.alpn.push(buffer.subarray(p, p + n).toString()); p += n; } i += length; } } catch {} return result; }
export function clientGroups(buffer) { try { let i = 5 + 4 + 2 + 32; i += 1 + buffer[i]; i += 2 + buffer.readUInt16BE(i); i += 1 + buffer[i]; const end = i + 2 + buffer.readUInt16BE(i); i += 2; while (i < end) { const type = buffer.readUInt16BE(i), length = buffer.readUInt16BE(i + 2); i += 4; if (type === 10) { const groups = []; for (let j = i + 2; j < i + length; j += 2) groups.push(buffer.readUInt16BE(j)); return groups; } i += length; } } catch {} return []; }

async function oracleMain(input) {
  if (process.version !== 'v24.21.0' || process.versions.openssl !== '3.5.8') throw Error('Pinned Node oracle required.');
  if (input.op === 'version') return { node: process.version, openssl: process.versions.openssl };
  if (input.op === 'identity') return { matches: !tls.checkServerIdentity(input.host, input.certificate) };
  const require = createRequire(import.meta.url), dns = require('node:dns');
  dns.lookup = (hostname, options, callback) => { if (typeof options === 'function') { callback = options; options = {}; } const address = input.addresses?.[hostname]; queueMicrotask(() => address ? callback(null, ...(options?.all ? [[{ address: '127.0.0.1', family: 4 }]] : ['127.0.0.1', 4])) : callback(Object.assign(Error('Fixture DNS missing'), { code: 'ENOTFOUND' }))); }; syncBuiltinESMExports();
  if (input.ca) tls.setDefaultCACertificates([...tls.rootCertificates, input.ca]);
  const { resolveNetwork, applyNetwork } = await import('../src/agent/network.mjs');
  const { probeHandshake, selectProxyTlsProfile } = await import('../src/agent/tls-profile.mjs');
  const target = new URL(input.target); const origin = new URL(target.origin); origin.protocol = 'https:';
  const plan = await resolveNetwork(input.settings ?? { mode: 'auto' }, origin.href, { env: input.env ?? {}, systemProxy: async () => ({ proxy: input.system ?? '' }), allowLocal: true });
  const restore = applyNetwork(plan.environment);
  try {
    if (input.op === 'route') {
      const { parseProxyConfigFromEnv } = require('internal/http');
      const { EnvHttpProxyAgent } = require('internal/deps/undici/undici');
      if (input.consumer === 'probe') { const p = parseProxyConfigFromEnv(plan.environment, 'https:', false); return { ok: true, result: { proxied: Boolean(p && p.shouldUseProxy(target.hostname, target.port || 443)), source: plan.source } }; }
      const agent = new EnvHttpProxyAgent({ httpProxy: plan.environment.HTTP_PROXY, httpsProxy: plan.environment.HTTPS_PROXY, noProxy: plan.environment.NO_PROXY }); let proxied;
      const directAgent = agent[Object.getOwnPropertySymbols(agent).find(symbol => symbol.description === 'no proxy agent')];
      for (const symbol of Object.getOwnPropertySymbols(agent)) if (['no proxy agent', 'http proxy agent', 'https proxy agent'].includes(symbol.description)) { const child = agent[symbol]; child.dispatch = () => { proxied = child !== directAgent; return true; }; }
      agent.dispatch({ origin: origin.origin, path: '/', method: 'GET' }, {}); await agent.destroy(); return { ok: true, result: { proxied, source: plan.source } };
    }
    if (input.op === 'probe') { const profile = await selectProxyTlsProfile(target.origin); return { ok: true, result: { profile } }; }
    if (input.op === 'probe_once') { return { ok: true, result: await probeHandshake(target.origin, input.profile === 'proxy-compatible' ? 'X25519:P-256' : undefined, input.timeout_ms ?? 3500) }; }
    if (input.op === 'ws') { return await new Promise(resolve => {
      const ws = new WebSocket(input.target), events = [], start = Date.now();
      const trace = (event, details = {}) => { if (events.length < 32) events.push({ event, ms: Date.now() - start, ...details }); };
      const fail = (code, error) => { clearTimeout(timer); resolve({ ok: false, error: { code, scheme: target.protocol, readyState: ws.readyState, detail: error ? { name: error.name, message: String(error.message).slice(0, 512), code: error.code, cause: error.cause ? { name: error.cause.name, message: String(error.cause.message).slice(0, 512), code: error.cause.code } : undefined } : undefined, events } }); };
      const timer = setTimeout(() => { trace('timeout'); ws.close(); fail('TIMEOUT'); }, 5000);
      ws.onopen = () => { trace('open'); ws.send('node exchange'); trace('send'); };
      ws.onmessage = e => { trace('message'); clearTimeout(timer); ws.close(); resolve({ ok: true, result: { text: e.data } }); };
      ws.onerror = event => { trace('error', { message: event.message }); fail('WS', event.error); };
      ws.onclose = event => trace('close', { code: event.code, reason: event.reason });
    }); }
    const response = await fetch(input.target, { method: input.method ?? 'GET', redirect: 'manual', body: input.body, signal: AbortSignal.timeout(input.timeout_ms ?? 5000) }); await response.arrayBuffer(); return { ok: true, result: { status: response.status } };
  } catch (error) { return { ok: false, error: { code: error.cause?.code ?? error.code ?? 'ERROR' } }; } finally { restore(); }
}
if (import.meta.main) { try { let data = ''; for await (const chunk of process.stdin) { data += chunk; if (data.length > 2 * 1024 * 1024) throw Error('Input limit'); } const result = await oracleMain(JSON.parse(data)); process.stdout.write(JSON.stringify(result) + '\n'); } catch { process.stdout.write('{"ok":false,"error":{"code":"ORACLE_SETUP"}}\n'); } }
