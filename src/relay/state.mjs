import { DurableObject } from 'cloudflare:workers';
import { json, readLimited, randomSecret, sha256, checkArguments, MAX_WIRE_BYTES } from '../shared/protocol.mjs';
import { deviceDescription } from '../shared/device-grants.mjs';
import { rosterStorageRoute } from './device-roster.mjs';
import { startLease, readLease, socketIsLive, touchLease, retireSocket, failSocketPending } from './socket-lease.mjs';
import { ACCESS_CAPABILITY, checkedAccess } from '../shared/connection-access.mjs';
import { TERMINAL_CAPABILITY } from '../shared/protocol.mjs';
import { AccountDirectory } from './account-directory.mjs';
import { OnboardingStore } from './onboarding-store.mjs';
import { PrivateInstance } from './private-instance.mjs';
import { InstallPortal } from './install-portal.mjs';

export const validDevice = id => typeof id === 'string' && /^[a-f0-9]{32}$/.test(id);
export const validSecret = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export async function equalSecret(value, digest) { return validSecret(value) && typeof digest === 'string' && await sha256(value) === digest; }

/** One durable object per computer. No file content is persisted in relay storage. */
export class Device extends DurableObject {
  constructor(ctx, env) { super(ctx, env); this.pending = new Map(); }
  sockets() {
    return this.ctx.getWebSockets('device').filter(socket => {
      if (socketIsLive(socket)) return true;
      retireSocket(socket);
      this.failPending(socket);
      return false;
    });
  }
  async fetch(request) {
    const route = new URL(request.url).pathname;
    const record = await this.ctx.storage.get('identity');
    if (route === '/self-initialize') {
      const value = JSON.parse(await readLimited(request, 2048));
      if (!validSecret(value.deviceKey)) return json({ error: 'Invalid device identity.' }, 400);
      const keyHash = await sha256(value.deviceKey);
      return this.ctx.storage.transaction(async storage => {
        const old = await storage.get('identity');
        if (old && (old.revoked || old.keyHash !== keyHash)) return json({ error: 'Device identity cannot be replaced.' }, 409);
        if (!old) await storage.put('identity', { keyHash, epoch: randomSecret(), revoked: false });
        return json({ ok: true });
      });
    }
    if (route === '/initialize') {
      const value = JSON.parse(await readLimited(request, 2048));
      if (record || !validSecret(value.deviceKey)) return json({ error: 'Device already exists or is invalid.' }, 409);
      await this.ctx.storage.put('identity', { keyHash: await sha256(value.deviceKey), epoch: randomSecret(), revoked: false });
      return json({ ok: true });
    }
    if (!record || record.revoked) return json({ error: 'Unknown or revoked device.' }, 401);
    if (route === '/account-auth') {
      if (this.env.ACCOUNT_CONNECTIONS !== 'true' && this.env.PRIVATE_INSTANCE !== 'true') return json({ error: 'Scoped connections are disabled.' }, 403);
      const key = request.headers.get('Authorization')?.replace(/^Bearer /, '');
      if (!await equalSecret(key, record.keyHash)) return json({ error: 'Native device authentication required.' }, 401);
      const current = await this.ctx.storage.get('identity');
      if (!current || current.revoked || current.epoch !== record.epoch) return json({ error: 'Device was revoked.' }, 403);
      return json({ epoch: current.epoch });
    }
    if (route === '/metadata') {
      const key = request.headers.get('Authorization')?.replace(/^Bearer /, '');
      if (!await equalSecret(key, record.keyHash)) return json({ error: 'Invalid device authentication.' }, 401);
      const value = JSON.parse(await readLimited(request, 2048));
      const description = deviceDescription(value);
      if (!value || Object.keys(value).some(key => !['name', 'platform', 'arch', 'system'].includes(key)) || Object.keys(value).length !== Object.keys(description).length) return json({ error: 'Invalid device metadata.' }, 400);
      return this.ctx.storage.transaction(async storage => {
        const current = await storage.get('identity');
        if (!current || current.revoked || current.epoch !== record.epoch) return json({ error: 'Device revoked.' }, 401);
        await storage.put('identity', { ...current, description });
        return json({ ok: true });
      });
    }
    if (route === '/describe') {
      const value = JSON.parse(await readLimited(request, 2048));
      if (value.epoch !== record.epoch) return json({ error: 'Device grant revoked.' }, 403);
      const active = this.sockets()[0];
      return json({ online: Boolean(active), description: deviceDescription(record.description), capabilities: active && readLease(active)?.connectionAccess === true ? [ACCESS_CAPABILITY, ...(readLease(active)?.terminal === true ? [TERMINAL_CAPABILITY] : [])] : [] });
    }
    if (route === '/connect') {
      const protocols = (request.headers.get('Sec-WebSocket-Protocol') || '').split(',').map(item => item.trim());
      const key = protocols.find(item => item.startsWith('device.'))?.slice(7);
      if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket' || !protocols.includes('chat2local-v1') || !await equalSecret(key, record.keyHash)) return json({ error: 'Invalid device authentication.' }, 401);
      const current = await this.ctx.storage.get('identity');
      if (!current || current.revoked || current.epoch !== record.epoch || current.keyHash !== record.keyHash) return json({ error: 'Device grant revoked.' }, 403);
      // A genuinely live authenticated connection retains its exclusive slot.
      // An expired heartbeat must not hold that slot forever after network loss.
      if (this.sockets().length) return json({ error: 'Device is already connected.' }, 409);
      const pair = new WebSocketPair();
      this.ctx.acceptWebSocket(pair[1], ['device']);
      const lease = startLease(pair[1]);
      pair[1].serializeAttachment({ ...lease, connectionAccess: protocols.includes(ACCESS_CAPABILITY), terminal: protocols.includes(TERMINAL_CAPABILITY) });
      return new Response(null, { status: 101, webSocket: pair[0], headers: { 'Sec-WebSocket-Protocol': 'chat2local-v1' } });
    }
    if (route === '/browser-handoff') {
      const key = request.headers.get('Authorization')?.replace(/^Bearer /, '');
      if (!await equalSecret(key, record.keyHash)) return json({ error: 'Invalid device authentication.' }, 401);
      if (!this.sockets().length) return json({ error: 'Computer is offline.' }, 409);
      const secret = randomSecret(); const expiresAt = Date.now() + 300_000;
      const hash = await sha256(secret);
      return this.ctx.storage.transaction(async storage => {
        const current = await storage.get('identity');
        if (current?.revoked || current?.epoch !== record.epoch) return json({ error: 'Device revoked.' }, 401);
        await storage.put('browser-handoff', { hash, expiresAt });
        return json({ secret, expiresAt });
      });
    }
    if (['/browser/inspect', '/browser/consume', '/browser/verify'].includes(route)) {
      const value = JSON.parse(await readLimited(request, 2048));
      if (!validSecret(value.secret)) return json({ error: 'Invalid browser proof.' }, 403);
      const hash = await sha256(value.secret);
      return this.ctx.storage.transaction(async storage => {
        const current = await storage.get('identity');
        const verification = route === '/browser/verify';
        const proof = await storage.get(verification ? 'browser-session' : 'browser-handoff');
        if (current?.revoked || !this.sockets().length || !proof || proof.expiresAt <= Date.now() || proof.hash !== hash || (verification && proof.epoch !== current.epoch)) return json({ error: 'Browser connection expired, offline, or revoked.' }, 403);
        if (route === '/browser/consume') {
          if (!validSecret(value.browserHash)) return json({ error: 'Invalid browser session.' }, 400);
          await storage.delete('browser-handoff');
          await storage.put('browser-session', { hash: value.browserHash, epoch: current.epoch, expiresAt: Date.now() + 900_000 });
        }
        return json({ epoch: current.epoch, description: deviceDescription(current.description) });
      });
    }
    if (route === '/pair-code' || route === '/revoke') {
      const key = request.headers.get('Authorization')?.replace(/^Bearer /, '');
      if (!await equalSecret(key, record.keyHash)) return json({ error: 'Invalid device authentication.' }, 401);
      if (route === '/revoke') {
        await this.ctx.storage.put('identity', { ...record, revoked: true, epoch: randomSecret() });
        await this.ctx.storage.delete(['pair', 'browser-handoff', 'browser-session']);
        for (const socket of this.ctx.getWebSockets('device')) retireSocket(socket, 'Device revoked');
        this.failPending(); return json({ ok: true });
      }
      if (!this.sockets().length) return json({ error: 'Computer is offline.' }, 409);
      const code = randomSecret(); const expiresAt = Date.now() + 5 * 60_000;
      await this.ctx.storage.put('pair', { hash: await sha256(code), expiresAt });
      return json({ secret: code, expiresAt });
    }
    if (route === '/consume-pair') {
      const value = JSON.parse(await readLimited(request, 2048));
      const accepted = await this.ctx.storage.transaction(async storage => {
        const pair = await storage.get('pair');
        if (!pair || pair.expiresAt <= Date.now() || !await equalSecret(value.secret, pair.hash)) return false;
        await storage.delete('pair'); return true;
      });
      return accepted ? json({ epoch: record.epoch }) : json({ error: 'Pairing code invalid, expired, or already used.' }, 403);
    }
    if (route === '/invoke') {
      const value = JSON.parse(await readLimited(request));
      if (value.epoch !== record.epoch) return json({ error: 'Device grant revoked.' }, 403);
      try { checkArguments(value.tool, value.args); } catch { return json({ error: 'Invalid tool request.' }, 400); }
      // Parsing the request may yield. Recheck the epoch immediately before
      // dispatch; there is no intervening async I/O before the socket send.
      const current = await this.ctx.storage.get('identity');
      if (!current || current.revoked || value.epoch !== current.epoch) return json({ error: 'Device grant revoked.' }, 403);
      const socket = this.sockets()[0];
      if (!socket) return json({ error: 'Computer is offline. No operation was queued or replayed.' }, 503);
      if (value.connectionAccess !== undefined) {
        try { checkedAccess(value.connectionAccess); } catch { return json({ error: 'Invalid connection access envelope.' }, 400); }
        if (readLease(socket)?.connectionAccess !== true) return json({ error: 'Current agent cannot enforce connection-scoped access.' }, 409);
      }
      if (this.pending.size >= 12) return json({ error: 'Computer is busy. Retry only after checking operation status.' }, 429);
      const id = crypto.randomUUID();
      return new Promise(resolve => {
        const timer = setTimeout(() => {
          this.pending.delete(id);
          resolve(json({ error: 'Response timed out. Outcome unknown; do not replay a write proposal blindly.' }, 504));
        }, 20_000);
        this.pending.set(id, { resolve, timer, socket });
        try { socket.send(JSON.stringify({ kind: 'call', id, tool: value.tool, args: value.args, ...(value.connectionDiagnostics ? { connectionDiagnostics: value.connectionDiagnostics } : {}), ...(value.connectionAccess !== undefined ? { connectionAccess: value.connectionAccess } : {}) })); }
        catch { clearTimeout(timer); this.pending.delete(id); resolve(json({ error: 'Connection lost. Outcome unknown; request was not replayed.' }, 503)); }
      });
    }
    return json({ error: 'Unknown internal route.' }, 404);
  }
  webSocketMessage(socket, message) {
    if (!socketIsLive(socket)) { retireSocket(socket); this.failPending(socket); return; }
    if (message === 'ping') { touchLease(socket); socket.send('pong'); return; }
    try {
      if (typeof message !== 'string' || new TextEncoder().encode(message).length > MAX_WIRE_BYTES) throw new Error('Frame too large.');
      const value = JSON.parse(message);
      if (value.kind !== 'result' || typeof value.id !== 'string') throw new Error('Invalid frame.');
      touchLease(socket);
      const pending = this.pending.get(value.id);
      if (!pending || pending.socket !== socket) return;
      this.pending.delete(value.id); clearTimeout(pending.timer);
      pending.resolve(typeof value.error === 'string' ? json({ error: value.error }, 422) : json({ result: value.result }));
    } catch { retireSocket(socket, 'Invalid device response'); this.failPending(socket); }
  }
  failPending(socket) {
    failSocketPending(this.pending, socket, () => json({ error: 'Computer disconnected. Outcome unknown; no request was replayed.' }, 503));
  }
  webSocketClose(socket, code) { try { socket.close(code === 1005 ? 1000 : code); } catch {} this.failPending(socket); }
  webSocketError(socket) { retireSocket(socket, 'Device connection error'); this.failPending(socket); }
}

/** Bounded operator enrollment, short-lived consent tickets, and global abuse budgets. */
export class Registry extends DurableObject {
  async fetch(request) {
    const route = new URL(request.url).pathname;
    const value = JSON.parse(await readLimited(request, 16 * 1024));
    if (route.startsWith('/roster/') || route.startsWith('/link-ticket/')) return rosterStorageRoute(this.ctx.storage, route, value);
    if (route.startsWith('/onboarding/')) {
      if (this.env.ACCOUNT_CONNECTIONS !== 'true') return json({ error: 'Account onboarding disabled.' }, 403);
      const action = route.slice('/onboarding/'.length);
      if (!['records','connections','reuse','start','provision','native','finish'].includes(action)) return json({ error: 'Unknown onboarding command.' }, 404);
      try { return json(await new OnboardingStore(this.ctx.storage)[action](value)); }
      catch (error) { return json({ error: error.status ? error.message : 'Account request rejected.' }, error.status || 400); }
    }
    if (route.startsWith('/install/')) {
      if (this.env.PRIVATE_INSTANCE !== 'true' || this.env.ACCOUNT_CONNECTIONS === 'true') return json({ error: 'Private installation is disabled.' }, 403);
      const action = route.slice('/install/'.length);
      if (!['configured','configure','login','logout','start','context','authorize','claim','ready'].includes(action)) return json({ error: 'Unknown installer action.' }, 404);
      try { return json(await new InstallPortal(this.ctx.storage, value.resource, this.env.ENROLLMENT_KEY)[action](value.input)); }
      catch (error) { return json({ error: error.status ? error.message : 'Installer request rejected.' }, error.status || 400); }
    }
    if (route.startsWith('/instance/')) {
      if (this.env.PRIVATE_INSTANCE !== 'true' || this.env.ACCOUNT_CONNECTIONS === 'true') return json({ error: 'Private instance mode is disabled or ambiguous.' }, 403);
      const action = route.slice('/instance/'.length);
      if (!['connections','createInvitation','revokeInvitation','makeFlow','claim','native','finish','remembered','manage'].includes(action)) return json({ error: 'Unknown private-instance command.' }, 404);
      try { return json(await new PrivateInstance(this.ctx.storage, value.resource)[action](value.input)); }
      catch (error) { return json({ error: error.status ? error.message : 'Private-instance request rejected.' }, error.status || 400); }
    }
    if (route === '/accounts/resolve') {
      if (this.env.ACCOUNT_CONNECTIONS !== 'true' && this.env.PRIVATE_INSTANCE !== 'true') return json({ error: 'Scoped connections are not enabled.' }, 403);
      return json(await new AccountDirectory(this.ctx.storage).execute({ action: 'resolve', grant: value }));
    }
    if (route === '/budget') {
      const limits = { register: 100, authorize: 1000, token: 6000, enroll: 200, setup: 200 };
      if (!Object.hasOwn(limits, value.bucket)) return json({ error: 'Invalid budget.' }, 400);
      const key = `budget:${value.bucket}`; const now = Date.now();
      return this.ctx.storage.transaction(async storage => {
        let record = await storage.get(key);
        if (!record || record.until <= now) record = { count: 0, until: now + 3_600_000 };
        if (record.count >= limits[value.bucket]) return json({ error: 'Relay request budget exceeded; retry later.' }, 429);
        record.count++; await storage.put(key, record); return json({ ok: true });
      });
    }
    if (route === '/self-enroll') {
      if (!validDevice(value.deviceId) || !validSecret(value.keyHash) || !validSecret(value.ipHash)) return json({ error: 'Invalid registration.' }, 400);
      const limit = Number(this.env.SELF_SERVICE_DEVICE_LIMIT ?? 10);
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) return json({ error: 'Registration is unavailable.' }, 503);
      return this.ctx.storage.transaction(async storage => {
        const previous = await storage.get(`device:${value.deviceId}`);
        if (previous) return previous.kind === 'self' && previous.keyHash === value.keyHash ? json({ ok: true }) : json({ error: 'Identity already exists.' }, 409);
        const count = await storage.get('deviceCount') ?? 0;
        const selfCount = await storage.get('selfDeviceCount') ?? 0;
        if (count >= 100 || selfCount >= limit) return json({ error: 'New device registration is full.' }, 429);
        const now = Date.now();
        const rates = (await storage.get('selfRates') ?? []).filter(rate => rate.until > now);
        let rate = rates.find(item => item.ipHash === value.ipHash);
        if (!rate) { if (rates.length >= 100) return json({ error: 'Registration is busy.' }, 429); rate = { ipHash: value.ipHash, count: 0, until: now + 3_600_000 }; rates.push(rate); }
        if (rate.count >= 3) return json({ error: 'Registration limit reached for this network.' }, 429);
        rate.count++;
        await storage.put({ selfRates: rates, deviceCount: count + 1, selfDeviceCount: selfCount + 1, [`device:${value.deviceId}`]: { kind: 'self', keyHash: value.keyHash } });
        return json({ ok: true });
      });
    }
    if (route === '/enroll') {
      if (!validDevice(value.deviceId)) return json({ error: 'Invalid device ID.' }, 400);
      return this.ctx.storage.transaction(async storage => {
        const count = await storage.get('deviceCount') ?? 0;
        if (count >= 100 || await storage.get(`device:${value.deviceId}`)) return json({ error: 'Device quota exceeded or identity already enrolled.' }, 409);
        await storage.put({ deviceCount: count + 1, [`device:${value.deviceId}`]: true }); return json({ ok: true });
      });
    }
    if (route === '/ticket/new') {
      const existing = await this.ctx.storage.list({ prefix: 'ticket:', limit: 257 });
      const expired = [...existing].filter(([, ticket]) => ticket.expiresAt <= Date.now()).map(([key]) => key);
      if (expired.length) await this.ctx.storage.delete(expired);
      if (existing.size - expired.length >= 200) return json({ error: 'Too many pending consent requests.' }, 429);
      const ticket = randomSecret();
      await this.ctx.storage.put(`ticket:${await sha256(ticket)}`, { authRequest: value.authRequest, csrfHash: value.csrfHash, browserBinding: value.browserBinding ?? null, browserBindings: value.browserBindings ?? null, expiresAt: Date.now() + 5 * 60_000 });
      return json({ ticket });
    }
    if (route === '/ticket/peek' || route === '/ticket/consume') {
      if (!validSecret(value.ticket) || !validSecret(value.csrf)) return json({ error: 'Invalid consent proof.' }, 403);
      const key = `ticket:${await sha256(value.ticket)}`;
      return this.ctx.storage.transaction(async storage => {
        const ticket = await storage.get(key);
        if (!ticket || ticket.expiresAt <= Date.now() || !await equalSecret(value.csrf, ticket.csrfHash)) return json({ error: 'Consent expired or invalid.' }, 403);
        if (route.endsWith('/consume')) await storage.delete(key);
        return json(ticket);
      });
    }
    return json({ error: 'Unknown internal route.' }, 404);
  }
}
