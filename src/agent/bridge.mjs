import { randomUUID } from 'node:crypto';
import { randomSecret, relayOrigin, MAX_WIRE_BYTES, TERMINAL_CAPABILITY } from '../shared/protocol.mjs';
import { deviceDescription } from '../shared/device-grants.mjs';
import { platformInfo } from './platform.mjs';
import { ACCESS_CAPABILITY } from '../shared/connection-access.mjs';
import { AgentLifecycle } from './runtime/lifecycle-core.mjs';

function waitForRevocation(work, signal) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => { if (settled) return; settled = true; signal.removeEventListener('abort', abort); if (error) reject(error); else resolve(value); };
    const abort = () => finish(signal.reason);
    signal.addEventListener('abort', abort, { once: true }); if (signal.aborted) abort();
    Promise.resolve(work).then(value => finish(null, value), error => finish(error));
  });
}

/** Socket/timer executor. Lifecycle state, retries and dedup live in the core. */
export class Bridge {
  #resources = new Map();
  constructor(invoke, options = {}) {
    this.invoke = invoke;
    this.WebSocket = options.WebSocket ?? globalThis.WebSocket;
    this.fetch = options.fetch ?? globalThis.fetch;
    this.allowLocal = options.allowLocal ?? false;
    this.prepareNetwork = options.prepareNetwork ?? (async () => {});
    this.description = options.description ?? (() => platformInfo());
    this.connectionAccess = options.connectionAccess === true; this.terminal = options.terminal === true;
    this.now = options.now ?? Date.now; this.random = options.random ?? Math.random;
    this.setTimer = options.setTimeout ?? setTimeout; this.clearTimer = options.clearTimeout ?? clearTimeout;
    this.lifecycle = options.lifecycle ?? new AgentLifecycle();
    if (!options.lifecycle) this.lifecycle.run({ op: 'activate' });
    this.lifecycle.onEffect(effect => this.#effect(effect));
    this.lifecycle.onFault(() => this.cleanup());
  }
  get state() { return this.lifecycle.snapshot().bridge.state; }
  get resourceCount() { return this.#resources.size; }
  get socket() { const b = this.lifecycle.snapshot().bridge; return this.#resources.get(`${b.generation}:${b.attempt}`)?.socket; }
  #key(t) { return `${t.generation}:${t.attempt}`; }
  #event(t, event) {
    if (!this.lifecycle.healthy) return;
    try { this.lifecycle.run({ op: 'bridgeEvent', generation: t.generation, attempt: t.attempt, event, now: this.now(), jitter: Math.floor(this.random() * 500) }); }
    catch (error) { this.lifecycle.poison(error); }
  }
  #retire(key) {
    const r = this.#resources.get(key); if (!r) return; this.#resources.delete(key);
    const errors = []; const attempt = fn => { try { fn(); } catch (error) { errors.push(error); } };
    attempt(() => r.abort.abort()); for (const timer of r.timers.values()) attempt(() => this.clearTimer(timer)); r.timers.clear();
    attempt(() => r.socket?.close(1000, 'Local connection stopped'));
    if (errors.length) throw new AggregateError(errors, 'Bridge resource cleanup failed.');
  }
  cleanup() { const errors = []; for (const key of this.#resources.keys()) { try { this.#retire(key); } catch (error) { errors.push(error); } } if (errors.length) throw new AggregateError(errors, 'Bridge cleanup failed.'); }
  #effect(e) {
    if (e.type === 'clearBridge') { this.cleanup(); return; }
    if (!['armTimer', 'retireAttempt', 'cancelTimers', 'prepareNetwork', 'openSocket', 'publishMetadata', 'sendPing'].includes(e.type)) return;
    const key = this.#key(e);
    if (e.type === 'retireAttempt') { this.#retire(key); return; }
    let r = this.#resources.get(key);
    if (!r) { r = { abort: new AbortController(), timers: new Map(), identity: this.identity, token: { generation: e.generation, attempt: e.attempt } }; this.#resources.set(key, r); }
    if (e.type === 'armTimer') {
      this.clearTimer(r.timers.get(e.timer));
      const timer = this.setTimer(() => { r.timers.delete(e.timer); this.#event(e, e.timer); }, Math.max(0, e.at - this.now()));
      timer.unref?.(); r.timers.set(e.timer, timer); return;
    }
    if (e.type === 'cancelTimers') { for (const timer of r.timers.values()) this.clearTimer(timer); r.timers.clear(); return; }
    if (e.type === 'prepareNetwork') {
      void (async () => {
        this.lifecycle.permit();
        await this.lifecycle.wait(this.prepareNetwork(r.identity.origin), r.abort.signal);
        if (!r.abort.signal.aborted) this.#event(e, 'prepared');
      })().catch(() => { if (!r.abort.signal.aborted) this.#event(e, 'failed'); }); return;
    }
    if (e.type === 'openSocket') {
      try {
        this.lifecycle.permit(); const { origin, deviceId, deviceKey } = r.identity;
        const socket = new this.WebSocket(`${origin.replace(/^http/, 'ws')}/device/${deviceId}/connect`, ['chat2local-v1', `device.${deviceKey}`, ...(this.connectionAccess ? [ACCESS_CAPABILITY] : []), ...(this.terminal ? [TERMINAL_CAPABILITY] : [])]);
        r.socket = socket;
        socket.addEventListener('open', () => this.#event(e, 'open'));
        socket.addEventListener('message', event => {
          if (event.data === 'pong') { this.#event(e, 'pong'); return; }
          void this.receive(event.data, socket, r.token).catch(() => { this.#event(e, 'failed'); });
        });
        socket.addEventListener('error', () => this.#event(e, 'failed'));
        socket.addEventListener('close', () => this.#event(e, 'close'));
      } catch { this.#event(e, 'failed'); }
    } else if (e.type === 'sendPing') {
      try { if (this.#reply(r.token, r.socket)) r.socket.send('ping'); else this.#event(e, 'failed'); } catch { this.#event(e, 'failed'); }
    } else if (e.type === 'publishMetadata') {
      void this.publishDescription(r).catch(() => {});
    }
  }
  start(identity) {
    this.lifecycle.permit(); if (identity) relayOrigin(identity.origin, this.allowLocal);
    this.identity = identity; this.lifecycle.run({ op: 'bridgeStart', hasIdentity: Boolean(identity), now: this.now() });
  }
  stop() { if (this.lifecycle.healthy) this.lifecycle.run({ op: 'bridgeStop' }); else this.cleanup(); }
  async publishDescription(r) {
    if (!this.#reply(r.token, r.socket)) return;
    const { origin, deviceId, deviceKey } = r.identity;
    try { await this.lifecycle.wait(this.fetch(`${origin}/device/${deviceId}/metadata`, { method: 'POST', headers: { Authorization: `Bearer ${deviceKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(deviceDescription(this.description())), redirect: 'error', signal: AbortSignal.any([r.abort.signal, this.lifecycle.signal, AbortSignal.timeout(5000)]) }), r.abort.signal); } catch { /* Optional metadata never confirms business work. */ }
  }
  #reply(token, socket) {
    return this.lifecycle.healthy && this.#resources.get(this.#key(token))?.socket === socket
      && this.lifecycle.run({ op: 'replyPermit', ...token, open: socket?.readyState === 1 });
  }
  async receive(raw, socket, token) {
    if (typeof raw !== 'string' || Buffer.byteLength(raw) > MAX_WIRE_BYTES) throw new Error('Invalid bridge frame.');
    const message = JSON.parse(raw);
    if (message.kind !== 'call' || !/^[a-f0-9-]{36}$/.test(message.id)) throw new Error('Invalid bridge envelope.');
    if (!token || !this.#reply(token, socket)) return;
    const decision = this.lifecycle.run({ op: 'bridgeCall', ...token, id: message.id });
    if (decision === 'drop') return;
    if (decision === 'duplicate') { if (this.#reply(token, socket)) socket.send(JSON.stringify({ kind: 'result', id: message.id, error: 'Duplicate request refused; no replay performed.' })); return; }
    let response;
    try {
      if (message.connectionAccess !== undefined && !this.connectionAccess) throw new Error('This agent does not support connection-scoped access.');
      response = { kind: 'result', id: message.id, result: await this.invoke(message.tool, message.args, message.connectionDiagnostics, message.connectionAccess) };
    } catch (error) { response = { kind: 'result', id: message.id, error: error.message || 'Local operation failed.' }; }
    if (this.#reply(token, socket)) socket.send(JSON.stringify(response));
  }
  async enroll(origin, enrollmentToken) {
    this.lifecycle.permit(); origin = relayOrigin(origin, this.allowLocal);
    if (typeof enrollmentToken !== 'string' || enrollmentToken.length < 32) throw new Error('An enrollment key from your relay operator is required.');
    await this.lifecycle.wait(this.prepareNetwork(origin));
    const identity = { deviceId: randomUUID().replaceAll('-', ''), deviceKey: randomSecret() };
    const response = await this.lifecycle.wait(this.fetch(`${origin}/enroll`, { method: 'POST', headers: { Authorization: `Bearer ${enrollmentToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify(identity), signal: AbortSignal.any([this.lifecycle.signal, AbortSignal.timeout(15000)]), redirect: 'error' }));
    if (!response.ok) throw new Error(`Relay enrollment failed (${response.status}). Check the relay address and enrollment key.`);
    return { origin, ...identity };
  }
  async revokeIdentity(identity = this.identity) {
    // Restriction/revocation remains available independently of a healthy core.
    if (!identity) return { remoteRevoked: true };
    const signal = AbortSignal.any([this.lifecycle.closeSignal, AbortSignal.timeout(8000)]);
    signal.throwIfAborted();
    await waitForRevocation(this.prepareNetwork(identity.origin), signal);
    signal.throwIfAborted();
    const response = await waitForRevocation(this.fetch(`${identity.origin}/device/${identity.deviceId}/revoke`, { method: 'POST', headers: { Authorization: `Bearer ${identity.deviceKey}` }, signal, redirect: 'error' }), signal);
    if (!response.ok) throw new Error('Local access stopped, but remote revocation was not confirmed. Remove the AI client connection as well.');
    return { remoteRevoked: true };
  }
  async pairCode() {
    this.lifecycle.permit(); if (!this.identity || this.state !== 'connected') throw new Error('Connect the computer to the relay first.');
    const { origin, deviceId, deviceKey } = this.identity;
    await this.lifecycle.wait(this.prepareNetwork(origin));
    const response = await this.lifecycle.wait(this.fetch(`${origin}/device/${deviceId}/pair-code`, { method: 'POST', headers: { Authorization: `Bearer ${deviceKey}` }, signal: AbortSignal.any([this.lifecycle.signal, AbortSignal.timeout(10000)]), redirect: 'error' }));
    if (!response.ok) throw new Error(`Could not create pairing code (${response.status}).`); return this.lifecycle.wait(response.json());
  }
}
