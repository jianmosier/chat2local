import { randomUUID } from 'node:crypto';
import { randomSecret, relayOrigin, MAX_WIRE_BYTES, TERMINAL_CAPABILITY } from '../shared/protocol.mjs';
import { deviceDescription } from '../shared/device-grants.mjs';
import { platformInfo } from './platform.mjs';
import { ACCESS_CAPABILITY } from '../shared/connection-access.mjs';

export class Bridge {
  constructor(invoke, options = {}) {
    this.invoke = invoke;
    this.WebSocket = options.WebSocket ?? globalThis.WebSocket;
    this.fetch = options.fetch ?? globalThis.fetch;
    this.allowLocal = options.allowLocal ?? false;
    this.prepareNetwork = options.prepareNetwork ?? (async () => {});
    this.description = options.description ?? (() => platformInfo());
    this.connectionAccess = options.connectionAccess === true;
    this.terminal = options.terminal === true;
    this.state = 'not-configured';
    this.generation = 0; this.attempt = 0; this.seen = new Map();
  }
  async enroll(origin, enrollmentToken) {
    origin = relayOrigin(origin, this.allowLocal);
    if (typeof enrollmentToken !== 'string' || enrollmentToken.length < 32) throw new Error('An enrollment key from your relay operator is required.');
    await this.prepareNetwork(origin);
    const identity = { deviceId: randomUUID().replaceAll('-', ''), deviceKey: randomSecret() };
    const response = await this.fetch(`${origin}/enroll`, { method: 'POST', headers: { Authorization: `Bearer ${enrollmentToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify(identity), signal: AbortSignal.timeout(15_000), redirect: 'error' });
    if (!response.ok) throw new Error(`Relay enrollment failed (${response.status}). Check the relay address and enrollment key.`);
    return { origin, ...identity };
  }
  start(identity) {
    this.stop();
    if (!identity) { this.state = 'not-configured'; return; }
    relayOrigin(identity.origin, this.allowLocal);
    this.identity = identity; this.stopped = false; this.attempt = 0;
    this.connect(this.generation);
  }
  stop() {
    this.stopped = true; this.generation++;
    clearTimeout(this.retry); clearTimeout(this.connectTimer); clearInterval(this.heartbeat);
    this.metadataAbort?.abort();
    try { this.socket?.close(1000, 'Local connection stopped'); } catch {}
    this.socket = undefined; this.state = 'disconnected';
  }
  async connect(generation) {
    if (this.stopped || generation !== this.generation) return;
    const { origin, deviceId, deviceKey } = this.identity;
    const url = `${origin.replace(/^http/, 'ws')}/device/${deviceId}/connect`;
    this.state = 'connecting';
    let socket;
    try {
      await this.prepareNetwork(origin);
      if (this.stopped || generation !== this.generation) return;
      socket = new this.WebSocket(url, ['chat2local-v1', `device.${deviceKey}`, ...(this.connectionAccess ? [ACCESS_CAPABILITY] : []), ...(this.terminal ? [TERMINAL_CAPABILITY] : [])]);
    } catch { this.scheduleReconnect(generation); return; }
    this.socket = socket;
    let opened = false;
    this.connectTimer = setTimeout(() => { if (!opened) { try { socket.close(); } catch {} } }, 15_000);
    this.connectTimer.unref?.();
    socket.addEventListener('open', () => {
      if (generation !== this.generation) { socket.close(); return; }
      opened = true; clearTimeout(this.connectTimer); this.state = 'connected'; this.attempt = 0; this.lastPong = Date.now();
      // Optional descriptive data only. Old relays may return 404; connectivity
      // and file operations do not depend on metadata or trigger retries here.
      void this.publishDescription(generation);
      this.heartbeat = setInterval(() => {
        if (Date.now() - this.lastPong > 65_000) { socket.close(1000, 'Heartbeat expired'); return; }
        if (socket.readyState === 1) socket.send('ping');
      }, 25_000);
      this.heartbeat.unref?.();
    });
    socket.addEventListener('message', event => {
      if (generation !== this.generation) return;
      if (event.data === 'pong') { this.lastPong = Date.now(); return; }
      void this.receive(event.data, socket).catch(() => { try { socket.close(1008, 'Invalid request'); } catch {} });
    });
    socket.addEventListener('error', () => { if (generation === this.generation) this.state = 'reconnecting'; });
    socket.addEventListener('close', () => {
      if (generation !== this.generation || this.stopped) return;
      clearTimeout(this.connectTimer); clearInterval(this.heartbeat);
      this.scheduleReconnect(generation);
    });
  }
  async publishDescription(generation) {
    if (this.stopped || generation !== this.generation || !this.identity) return;
    const abort = new AbortController(); this.metadataAbort = abort;
    const { origin, deviceId, deviceKey } = this.identity;
    try {
      await this.fetch(`${origin}/device/${deviceId}/metadata`, { method: 'POST', headers: { Authorization: `Bearer ${deviceKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(deviceDescription(this.description())), redirect: 'error', signal: AbortSignal.any([abort.signal, AbortSignal.timeout(5000)]) });
    } catch { /* Metadata failure is not file-operation failure or success. */ }
    finally { if (this.metadataAbort === abort) this.metadataAbort = null; }
  }
  scheduleReconnect(generation) {
    if (this.stopped || generation !== this.generation) return;
    this.state = 'reconnecting'; clearTimeout(this.retry);
    const delay = Math.min(30_000, 1000 * 2 ** Math.min(this.attempt++, 5)) + Math.floor(Math.random() * 500);
    this.retry = setTimeout(() => { void this.connect(generation); }, delay); this.retry.unref?.();
  }
  async receive(raw, socket) {
    if (typeof raw !== 'string' || new TextEncoder().encode(raw).length > MAX_WIRE_BYTES) throw new Error('Invalid bridge frame.');
    const message = JSON.parse(raw);
    if (message.kind !== 'call' || !/^[a-f0-9-]{36}$/.test(message.id)) throw new Error('Invalid bridge envelope.');
    if (this.seen.has(message.id)) { socket.send(JSON.stringify({ kind: 'result', id: message.id, error: 'Duplicate request refused; no replay performed.' })); return; }
    this.seen.set(message.id, Date.now());
    if (this.seen.size > 1000) this.seen.delete(this.seen.keys().next().value);
    let response;
    try {
      if (message.connectionAccess !== undefined && !this.connectionAccess) throw new Error('This agent does not support connection-scoped access.');
      response = { kind: 'result', id: message.id, result: await this.invoke(message.tool, message.args, message.connectionDiagnostics, message.connectionAccess) };
    }
    catch (error) { response = { kind: 'result', id: message.id, error: error.message || 'Local operation failed.' }; }
    if (socket.readyState === 1) socket.send(JSON.stringify(response));
  }
  async revokeIdentity(identity = this.identity) {
    if (!identity) return { remoteRevoked: true };
    await this.prepareNetwork(identity.origin);
    const response = await this.fetch(`${identity.origin}/device/${identity.deviceId}/revoke`, { method: 'POST', headers: { Authorization: `Bearer ${identity.deviceKey}` }, signal: AbortSignal.timeout(8000), redirect: 'error' });
    if (!response.ok) throw new Error('Local access stopped, but remote revocation was not confirmed. Remove the AI client connection as well.');
    return { remoteRevoked: true };
  }
  async pairCode() {
    if (!this.identity || this.state !== 'connected') throw new Error('Connect the computer to the relay first.');
    const { origin, deviceId, deviceKey } = this.identity;
    await this.prepareNetwork(origin);
    const response = await this.fetch(`${origin}/device/${deviceId}/pair-code`, { method: 'POST', headers: { Authorization: `Bearer ${deviceKey}` }, signal: AbortSignal.timeout(10_000), redirect: 'error' });
    if (!response.ok) throw new Error(`Could not create pairing code (${response.status}).`);
    return response.json();
  }
}
