import { randomSecret, sha256 } from '../shared/protocol.mjs';
import { exactFields, isAccountId, isDigest, checkedResource } from '../shared/connection-access.mjs';
import { PrivateInstance } from './private-instance.mjs';

const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const prefix = 'install:v1:';
const equal = (a, b) => { if (!isDigest(a) || !isDigest(b)) return false; let diff = 0; for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i); return diff === 0; };
const validPassword = value => typeof value === 'string' && value.length >= 16 && new TextEncoder().encode(value).length <= 256;

/** One private instance's restricted installer login, NOT a user-account service.
 * Password setup requires the existing operator at the HTTP boundary. This
 * credential can only issue a short-lived JOIN to a retained connection; it is
 * never a file token, device key, operator key or permission to change folders.
 */
export class InstallPortal {
  constructor(storage, resource, pepper, now = Date.now) {
    this.storage = storage; this.resource = checkedResource(resource); this.pepper = pepper; this.now = now;
    if (!isDigest(pepper)) throw fail('Instance operator credential is unavailable.', 503);
  }
  async keyed(value) {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(this.pepper), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return Array.from(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(JSON.stringify([this.resource, value])))), b => b.toString(16).padStart(2, '0')).join('');
  }
  async verifier(password, salt) {
    if (!validPassword(password)) throw fail('安装密码至少 16 个字符，最多 256 字节。');
    // Server-only pepper prevents a copied Registry database being a standalone
    // password oracle. PBKDF2 uses workerd's supported WebCrypto limit.
    const material = await this.keyed(['install-password', password]);
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(material), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: new TextEncoder().encode(salt), iterations: 100000, hash: 'SHA-256' }, key, 256);
    return Array.from(new Uint8Array(bits), b => b.toString(16).padStart(2, '0')).join('');
  }
  async configured() { return { configured: Boolean(await this.storage.get(prefix + 'password')) }; }
  async configure(input) {
    exactFields(input, ['password']);
    if (await this.storage.get(prefix + 'password')) throw fail('安装密码已经设置；此入口不会覆盖。', 409);
    const salt = randomSecret(), digest = await this.verifier(input.password, salt);
    return this.storage.transaction(async tx => {
      if (await tx.get(prefix + 'password')) throw fail('安装密码已经设置；没有覆盖。', 409);
      await tx.put(prefix + 'password', { salt, digest, epoch: randomSecret() });
      return { configured: true, fileAccessGranted: false };
    });
  }
  async limited(bucket, limit, windowMs) {
    return this.storage.transaction(async tx => {
      const key = prefix + 'rate:' + bucket;
      let rate = await tx.get(key);
      const entries = await tx.list({ prefix: prefix + 'rate:', limit: 129 });
      for (const [id, value] of entries) if (value.until <= this.now()) await tx.delete(id);
      if (!rate && [...entries.values()].filter(v => v.until > this.now()).length >= 128) throw fail('Installer login is busy.', 429);
      if (!rate || rate.until <= this.now()) rate = { count: 0, until: this.now() + windowMs };
      if (rate.count >= limit) throw fail('尝试过多，请稍后再试；没有更改现有连接。', 429);
      rate.count++; await tx.put(key, rate);
    });
  }
  async login({ password, network }) {
    if (!isDigest(network)) throw fail('Login network identity unavailable.', 503);
    await this.limited('login-global', 30, 3600000);
    await this.limited('login-' + network, 5, 900000);
    const config = await this.storage.get(prefix + 'password');
    if (!config) throw fail('实例尚未设置安装密码。现有文件连接不受影响。', 503);
    if (!validPassword(password) || !equal(await this.verifier(password, config.salt), config.digest)) throw fail('安装密码不正确。', 401);
    const secret = randomSecret(), sessionHash = await sha256(secret);
    await this.storage.transaction(async tx => {
      const current = await tx.get(prefix + 'password');
      if (current?.epoch !== config.epoch) throw fail('Installer login changed.', 401);
      const entries = await tx.list({ prefix: prefix + 'session:', limit: 65 });
      for (const [id, value] of entries) if (value.until <= this.now()) await tx.delete(id);
      if ([...entries.values()].filter(v => v.until > this.now()).length >= 64) throw fail('Too many installer sessions.', 429);
      await tx.put(prefix + 'session:' + sessionHash, { epoch: config.epoch, until: this.now() + 1800000 });
    });
    return { session: secret };
  }
  async session(tx, secret) {
    if (!isDigest(secret)) throw fail('请输入你自己的实例安装密码。', 401);
    const session = await tx.get(prefix + 'session:' + await sha256(secret));
    const config = await tx.get(prefix + 'password');
    if (!session || session.until <= this.now() || session.epoch !== config?.epoch) throw fail('安装登录已过期，请重新登录。', 401);
    return session;
  }
  async logout({ session }) { if (isDigest(session)) await this.storage.delete(prefix + 'session:' + await sha256(session)); return { loggedOut: true }; }
  async start(input) {
    exactFields(input, ['id','claimHash','browserHash','name']);
    if (!isAccountId(input.id) || !isDigest(input.claimHash) || !isDigest(input.browserHash) || typeof input.name !== 'string' || input.name.length > 128 || /[\x00-\x1f\x7f]/.test(input.name)) throw fail('Invalid installer request.');
    return this.storage.transaction(async tx => {
      const key = prefix + 'ticket:' + input.id, previous = await tx.get(key);
      if (previous) {
        if (previous.claimHash !== input.claimHash || previous.browserHash !== input.browserHash || previous.name !== input.name || previous.until <= this.now()) throw fail('Installer request changed or expired.', 409);
        return { id: previous.id, until: previous.until };
      }
      const entries = await tx.list({ prefix: prefix + 'ticket:', limit: 65 });
      for (const [id, value] of entries) if (value.until <= this.now()) await tx.delete(id);
      if ([...entries.values()].filter(v => v.until > this.now()).length >= 64) throw fail('Too many pending installers.', 429);
      const value = { ...input, until: this.now() + 600000, phase: 'pending', connectionId: null };
      await tx.put(key, value); return { id: value.id, until: value.until };
    });
  }
  async ticket(tx, id, secret, type) {
    if (!isAccountId(id) || !isDigest(secret)) throw fail('Invalid installer proof.', 401);
    const value = await tx.get(prefix + 'ticket:' + id);
    if (!value || value.until <= this.now() || !equal(value[type], await sha256(secret))) throw fail('Installer request expired or belongs to another computer.', 401);
    return value;
  }
  async invitation(value) {
    const instance = new PrivateInstance(this.storage, this.resource, this.now);
    const secret = await this.keyed(['install-invitation', value.id, value.connectionId]);
    return instance.createInvitation({ purpose: 'join', connectionId: value.connectionId, ttlSeconds: 600 }, { invitationId: value.id, secret });
  }
  async context({ id, browser, session }) {
    const ticket = await this.storage.transaction(tx => this.ticket(tx, id, browser, 'browserHash'));
    let authenticated = false;
    try { await this.storage.transaction(tx => this.session(tx, session)); authenticated = true; } catch (error) { if (error.status !== 401) throw error; }
    const configured = await this.configured();
    const connections = authenticated ? (await new PrivateInstance(this.storage, this.resource, this.now).connections()).connections.map(c => ({ connectionId: c.connectionId, name: c.clientName || 'MCP client', callbackOrigin: new URL(c.redirectUri).origin })) : [];
    // Only the initiating browser sees the continuation, and only after the
    // native runner has imported it. No copy/paste pairing code is exposed.
    const invitation = ticket.phase === 'ready' && authenticated ? await this.invitation(ticket) : null;
    return { ...configured, authenticated, name: ticket.name, phase: ticket.phase, connections, ...(invitation ? { nextUrl: new URL(this.resource).origin + '/instance/invite#' + invitation.invitation } : {}) };
  }
  async authorize({ id, browser, session, connectionId }) {
    const ticket = await this.storage.transaction(async tx => { await this.session(tx, session); return this.ticket(tx, id, browser, 'browserHash'); });
    const connections = (await new PrivateInstance(this.storage, this.resource, this.now).connections()).connections;
    const selected = connectionId === null && connections.length === 1 ? connections[0] : connections.find(c => c.connectionId === connectionId);
    if (!selected) throw fail('请选择原插件连接；不会新建或猜测另一个连接。', 409);
    await this.storage.transaction(async tx => {
      await this.session(tx, session); const current = await this.ticket(tx, id, browser, 'browserHash');
      if (current.connectionId && current.connectionId !== selected.connectionId) throw fail('Installer target is already pinned.', 409);
      current.connectionId = selected.connectionId; await tx.put(prefix + 'ticket:' + id, current);
    });
    // Idempotent create with a server-derived capability survives response loss.
    await this.invitation({ ...ticket, connectionId: selected.connectionId });
    await this.storage.transaction(async tx => {
      await this.session(tx, session); const current = await this.ticket(tx, id, browser, 'browserHash');
      if (current.connectionId !== selected.connectionId) throw fail('Installer connection changed.', 409);
      if (current.phase === 'pending') current.phase = 'authorized';
      await tx.put(prefix + 'ticket:' + id, current);
    });
    return { authorized: true, foldersGranted: false };
  }
  async claim({ id, secret }) {
    const ticket = await this.storage.transaction(tx => this.ticket(tx, id, secret, 'claimHash'));
    if (!['authorized','ready'].includes(ticket.phase)) return { waiting: true };
    const invite = await this.invitation(ticket);
    return { waiting: false, version: 1, purpose: 'join', inviteUrl: new URL(this.resource).origin + '/instance/invite#' + invite.invitation, expiresAt: invite.expiresAt };
  }
  async ready({ id, secret }) {
    return this.storage.transaction(async tx => {
      const ticket = await this.ticket(tx, id, secret, 'claimHash');
      if (!['authorized','ready'].includes(ticket.phase)) throw fail('Installer has no approved connection.', 403);
      ticket.phase = 'ready'; await tx.put(prefix + 'ticket:' + id, ticket); return { ready: true, foldersGranted: false };
    });
  }
}
