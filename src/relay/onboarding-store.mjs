import { randomSecret, sha256 } from '../shared/protocol.mjs';
import { AccountDirectory } from './account-directory.mjs';
import { exactFields, isAccountId, isDigest } from '../shared/connection-access.mjs';

const fail = (message, status = 409) => Object.assign(new Error(message), { status });
const flowKey = id => 'onboarding:v1:flow:' + id;
const validActor = actor => { exactFields(actor, ['identityKey','sessionBinding']); if (!isDigest(actor.identityKey) || !isDigest(actor.sessionBinding)) throw fail('Verified account required.', 401); };

/** Called only via the private Registry binding. The public worker authenticates
 * an OIDC session OR the exact native device and a flow-scoped credential first.
 * No public API can supply actor, authRequest, deviceEpoch or a native proof flag.
 */
export class OnboardingStore {
  constructor(storage, now = Date.now) { this.storage = storage; this.now = now; }
  directory(options = {}) { return new AccountDirectory(this.storage, { now: this.now, assertActorCurrent: (tx, actor) => this.activeSession(actor, tx), ...options }); }
  async activeSession(actor, tx = this.storage) {
    validActor(actor);
    const bound = await tx.get('onboarding:v1:session-binding:' + actor.sessionBinding);
    if (!bound || bound.identityKey !== actor.identityKey || bound.until <= this.now()) throw fail('Account sign-in expired or was signed out. No pending share was activated.', 401);
  }
  async records({ action, kind, secret, value, ttl }) {
    if (!['login','session'].includes(kind) || !isDigest(secret) || !['put','get','take','delete'].includes(action)) throw fail('Invalid private identity record.', 400);
    const key = `onboarding:v1:${kind}:${await sha256(secret)}`;
    let binding;
    if (kind === 'session' && action === 'put') {
      if (typeof value?.issuer !== 'string' || typeof value.subject !== 'string' || !isDigest(value.sessionId) || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= this.now()) throw fail('Invalid verified session record.', 400);
      binding = { id: await sha256(JSON.stringify([value.issuer, value.subject, value.sessionId])), identityKey: await sha256(JSON.stringify([value.issuer, value.subject])) };
    }
    return this.storage.transaction(async tx => {
      const current = await tx.get(key);
      if (action === 'get') return current?.until > this.now() ? current.value : null;
      if (action === 'take') {
        if (!current || current.until <= this.now() || !isDigest(value?.browserHash) || value.browserHash !== current.value.browserHash) throw fail('Identity callback expired or belongs to another browser.', 401);
        await tx.delete(key); return current.value;
      }
      if (action === 'delete') { if (current?.bindingId) await tx.delete('onboarding:v1:session-binding:' + current.bindingId); await tx.delete(key); return { deleted: true }; }
      if (!Number.isInteger(ttl) || ttl < 1 || ttl > 43200 || JSON.stringify(value).length > 16000 || current) throw fail('Invalid or duplicate identity record.', 400);
      const entries = await tx.list({ prefix: `onboarding:v1:${kind}:`, limit: 1025 });
      for (const [id, item] of entries) if (item.until <= this.now()) { if (item.bindingId) await tx.delete('onboarding:v1:session-binding:' + item.bindingId); await tx.delete(id); }
      if ([...entries.values()].filter(item => item.until > this.now()).length >= 1000) throw fail('Too many active account sessions; try later.', 429);
      const until = this.now() + ttl * 1000;
      await tx.put(key, { value, until, ...(binding ? { bindingId: binding.id } : {}) });
      if (binding) await tx.put('onboarding:v1:session-binding:' + binding.id, { identityKey: binding.identityKey, until: Math.min(until, value.expiresAt) });
      return { saved: true };
    });
  }
  async connections({ actor, resource }) {
    await this.activeSession(actor);
    const directory = this.directory();
    await directory.execute({ action: 'account', actor, input: {} });
    return directory.execute({ action: 'connections', actor, input: { resource } });
  }
  async reuse({ actor, authRequest, resource }) {
    await this.activeSession(actor);
    const directory = this.directory();
    await directory.execute({ action: 'account', actor, input: {} });
    const { connections } = await directory.execute({ action: 'connections', actor, input: { clientId: authRequest.clientId, resource } });
    const scopes = authRequest.scope.filter(scope => ['files:read','files:write','files:propose'].includes(scope));
    if (!scopes.includes('files:read') || connections.length !== 1 || scopes.some(scope => !connections[0].scopes.includes(scope))) return { reusable: false };
    const stored = await this.storage.get('accounts:v3:connection:' + connections[0].connectionId);
    const grant = directory.grant(stored, scopes);
    const resolved = await directory.execute({ action: 'resolve', grant });
    if (!resolved.devices.length) return { reusable: false };
    return { reusable: true, accountId: grant.accountId, grant };
  }
  async start({ actor, displayName, clientName, authRequest, resource, mode = 'oauth', connectionId = null }) {
    await this.activeSession(actor);
    const directory = this.directory();
    const { accountId } = await directory.execute({ action: 'account', actor, input: {} });
    const { connections } = await directory.execute({ action: 'connections', actor, input: { clientId: authRequest.clientId, resource } });
    if (!['oauth','join'].includes(mode)) throw fail('Invalid account entry.', 400);
    if (connections.length > 1) throw fail('More than one matching account connection; explicit management is required.');
    if (mode === 'join' && (!connections[0] || connections[0].connectionId !== connectionId)) throw fail('Choose an existing connection owned by this account.', 403);
    const id = crypto.randomUUID().replaceAll('-', ''), bootstrap = randomSecret(), browser = randomSecret();
    const scopes = authRequest.scope.filter(s => ['files:read','files:write','files:propose'].includes(s));
    if (!scopes.includes('files:read')) throw fail('Client must request file read permission.', 400);
    const scopeUpgrade = Boolean(connections[0] && scopes.some(s => !connections[0].scopes.includes(s)));
    if (scopeUpgrade && mode !== 'oauth') throw fail('Adding a device cannot expand the original OAuth scopes.', 403);
    const value = { id, mode, scopeUpgrade, actor, accountId, displayName: String(displayName).slice(0, 120), clientName: String(clientName).slice(0, 120), authRequest, resource, scopes, connectionId: connections[0]?.connectionId || null, bootstrapHash: await sha256(bootstrap), browserHash: await sha256(browser), createdAt: this.now(), until: this.now() + 86400000, finishTaken: false };
    await this.storage.transaction(async tx => {
      await this.activeSession(actor, tx);
      const entries = await tx.list({ prefix: 'onboarding:v1:flow:', limit: 201 });
      for (const [key, record] of entries) if (record.until <= this.now()) await tx.delete(key);
      if ([...entries.values()].filter(record => record.until > this.now()).length >= 200) throw fail('Connection setup is busy.', 429);
      await tx.put(flowKey(id), value);
    });
    return { flowId: id, bootstrap, browser };
  }
  async provision({ flowId, bootstrap, deviceId, keyHash, sessionHash }) {
    if (!isAccountId(flowId) || !isAccountId(deviceId) || !isDigest(bootstrap) || !isDigest(keyHash) || !isDigest(sessionHash)) throw fail('Invalid new-device proof.', 400);
    const proofHash = await sha256(bootstrap);
    const candidate = await this.storage.get(flowKey(flowId));
    if (!candidate) throw fail('Account setup not found.', 401);
    await this.activeSession(candidate.actor);
    return this.storage.transaction(async tx => {
      const flow = await tx.get(flowKey(flowId));
      if (flow) await this.activeSession(flow.actor, tx);
      if (!flow || flow.bootstrapHash !== proofHash || this.now() > flow.createdAt + 300000) throw fail('Sign in before registering a computer.', 401);
      if (flow.device && (!flow.provision || flow.device.deviceId !== deviceId || flow.nativeHash !== sessionHash)) throw fail('This setup is already bound to another native identity.', 403);
      if (flow.provision && (flow.provision.deviceId !== deviceId || flow.provision.keyHash !== keyHash || flow.provision.sessionHash !== sessionHash)) throw fail('This setup is already bound to another native identity.', 403);
      const registration = await tx.get('device:' + deviceId);
      if (registration) {
        if (registration.kind !== 'account' || registration.accountId !== flow.accountId || registration.keyHash !== keyHash) throw fail('Existing device identity cannot be replaced.', 409);
      } else {
        const count = await tx.get('deviceCount') || 0;
        const indexKey = 'onboarding:v1:registered:' + flow.accountId;
        const owned = await tx.get(indexKey) || [];
        if (count >= 100 || owned.length >= 20) throw fail('Account or service device limit reached.', 429);
        await tx.put('device:' + deviceId, { kind: 'account', accountId: flow.accountId, keyHash });
        await tx.put('deviceCount', count + 1); await tx.put(indexKey, [...owned, deviceId]);
      }
      flow.provision = { deviceId, keyHash, sessionHash }; await tx.put(flowKey(flowId), flow);
      return { reserved: true }; // Registering a device grants NO file access.
    });
  }
  async native({ action, flowId, secret, device, input = {} }) {
    if (!isAccountId(flowId) || !isDigest(secret) || !isAccountId(device?.deviceId) || !isDigest(device?.epoch)) throw fail('Authenticated native flow required.', 401);
    if (!['start','prepare','status','confirm','activate','cancel'].includes(action)) throw fail('Unknown native step.', 404);
    const credentialHash = await sha256(secret);
    const candidate = await this.storage.get(flowKey(flowId));
    if (!candidate) throw fail('Account setup not found.', 401);
    await this.activeSession(candidate.actor);
    let flow;
    if (action === 'start') {
      exactFields(input, ['sessionSecret']); if (!isDigest(input.sessionSecret)) throw fail('Invalid native session.', 400);
      const nativeHash = await sha256(input.sessionSecret);
      flow = await this.storage.transaction(async tx => {
        const item = await tx.get(flowKey(flowId));
        if (item) await this.activeSession(item.actor, tx);
        if (!item || item.until <= this.now() || item.bootstrapHash !== credentialHash || this.now() > item.createdAt + 300000) throw fail('This account setup link expired.', 401);
        if (item.provision && (item.provision.deviceId !== device.deviceId || item.provision.sessionHash !== nativeHash)) throw fail('Native enrollment receipt does not match.', 403);
        if (item.device && (item.device.deviceId !== device.deviceId || item.device.epoch !== device.epoch || item.nativeHash !== nativeHash)) throw fail('Setup link already belongs to another native session.', 403);
        item.device = { deviceId: device.deviceId, epoch: device.epoch }; item.nativeHash = nativeHash;
        await tx.put(flowKey(flowId), item); return item;
      });
      return { flowId, accountId: flow.accountId, displayName: flow.displayName, clientId: flow.authRequest.clientId, clientName: flow.clientName, resource: flow.resource, deviceId: device.deviceId, deviceEpoch: device.epoch, scopes: flow.scopes, requestDigest: await sha256(JSON.stringify(flow.authRequest)), connectionId: flow.connectionId, callbackOrigin: new URL(flow.authRequest.redirectUri).origin };
    }
    flow = await this.storage.get(flowKey(flowId));
    if (!flow || flow.until <= this.now() || flow.nativeHash !== credentialHash || flow.device?.deviceId !== device.deviceId || flow.device?.epoch !== device.epoch) throw fail('Native session expired or does not match this device.', 401);
    // The proof is an authenticated device message over the existing device-key
    // channel, bound to a flow-specific native secret and exact snapshot. It is
    // not a browser-provided boolean or an accountId supplied by an MCP tool.
    const directory = this.directory({ verifyDeviceConsent: async ({ action: step, proof, intent }) => {
      if (step !== action || proof !== secret || input.snapshotDigest !== intent.snapshotDigest || intent.id !== flowId || intent.deviceId !== device.deviceId || intent.deviceEpoch !== device.epoch) return null;
      return { intentId: intent.id, deviceId: device.deviceId, deviceEpoch: device.epoch, snapshotDigest: intent.snapshotDigest, phase: action === 'confirm' ? 'consented' : 'activated' };
    } });
    let args;
    if (action === 'prepare') {
      if (this.now() > flow.createdAt + 300000 && !await this.storage.get('accounts:v3:intent:' + flowId)) throw fail('This sign-in setup window expired before folder preparation.', 401);
      exactFields(input, ['roots','policyDigest']);
      args = { intentId: flowId, connectionId: flow.connectionId, clientId: flow.authRequest.clientId, resource: flow.resource, deviceId: device.deviceId, deviceEpoch: device.epoch, roots: input.roots, scopes: flow.scopes, policyDigest: input.policyDigest, requestDigest: await sha256(JSON.stringify(flow.authRequest)), ...(flow.mode === 'oauth' && flow.scopeUpgrade ? { allowScopeUpgrade: true } : {}) };
    } else if (['confirm','activate'].includes(action)) {
      exactFields(input, ['snapshotDigest']); args = { intentId: flowId, snapshotDigest: input.snapshotDigest, proof: secret };
    } else { exactFields(input, []); args = { intentId: flowId }; }
    return directory.execute({ action, actor: flow.actor, input: args });
  }
  async finish({ flowId, browser, actor }) {
    await this.activeSession(actor);
    if (!isAccountId(flowId) || !isDigest(browser)) throw fail('Browser continuation required.', 401);
    const flow = await this.storage.get(flowKey(flowId));
    if (!flow || flow.until <= this.now() || flow.browserHash !== await sha256(browser) || flow.actor.identityKey !== actor.identityKey || flow.actor.sessionBinding !== actor.sessionBinding || flow.finishTaken) throw fail('The original sign-in browser is required to finish this request.', 401);
    const directory = this.directory();
    const intent = await directory.execute({ action: 'status', actor, input: { intentId: flowId } });
    if (intent.phase !== 'active') throw fail('Folder sharing has not been activated.');
    const connection = await this.storage.get('accounts:v3:connection:' + intent.connectionId);
    const grant = directory.grant(connection, flow.scopes);
    await directory.execute({ action: 'resolve', grant });
    if (flow.mode === 'join') return { joined: true, accountId: flow.accountId, connectionId: intent.connectionId };
    // Single issuance. An uncertain completeAuthorization result cannot blindly
    // issue a second code. A new OAuth request can retain activated folder grants.
    await this.storage.transaction(async tx => {
      await this.activeSession(actor, tx);
      const latest = await tx.get(flowKey(flowId));
      if (!latest || latest.finishTaken || latest.browserHash !== flow.browserHash) throw fail('Authorization continuation was already used.');
      latest.finishTaken = true; await tx.put(flowKey(flowId), latest);
    });
    return { authRequest: flow.authRequest, accountId: flow.accountId, grant };
  }
}
