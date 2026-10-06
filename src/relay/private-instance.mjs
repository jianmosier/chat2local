import { randomSecret, sha256 } from '../shared/protocol.mjs';
import { AccountDirectory } from './account-directory.mjs';
import { exactFields, checkedResource, checkedScopes, checkedClient, isAccountId, isDigest } from '../shared/connection-access.mjs';

const fail = (message, status = 409) => Object.assign(new Error(message), { status });
const key = (kind, id = '') => `instance:v1:${kind}:${id}`;
const id = () => crypto.randomUUID().replaceAll('-', '');
export function invitationParts(proof) {
  if (typeof proof !== 'string' || !/^[a-f0-9]{32}\.[a-f0-9]{64}$/.test(proof)) throw fail('A valid private-instance invitation is required.', 401);
  return proof.split('.');
}

/** Private Registry aggregate. Owner commands require operator authentication in
 * the HTTP adapter. Native commands require BOTH a scoped invitation/flow secret
 * and the device's independent credential. No Google session, public actor/user
 * field, or bearer MCP file token is an instance-management credential.
 * Reuses the connection/share repository; its accountId is an internal single
 * instance-owner namespace, NOT a third-party account or browser identity.
 */
export class PrivateInstance {
  constructor(storage, resource, now = Date.now) { this.storage = storage; this.resource = checkedResource(resource); this.now = now; }
  async owner() {
    const saved = await this.storage.transaction(async tx => {
      let value = await tx.get(key('owner'));
      if (value && value.resource !== this.resource) throw fail('Private instance origin changed; explicit migration required.', 403);
      if (!value) { value = { resource: this.resource, identityKey: randomSecret(), sessionBinding: randomSecret() }; await tx.put(key('owner'), value); }
      return value;
    });
    const actor = { identityKey: saved.identityKey, sessionBinding: saved.sessionBinding };
    const { accountId } = await new AccountDirectory(this.storage).execute({ action: 'account', actor, input: {} });
    return { actor, accountId };
  }
  async connections() {
    const owner = await this.owner();
    const result = await new AccountDirectory(this.storage).execute({ action: 'connections', actor: owner.actor, input: { resource: this.resource } });
    return { connections: await Promise.all(result.connections.map(async item => ({ ...item, ...(await this.storage.get(key('client', item.connectionId)) || {}) }))) };
  }
  /** Authenticated native management, limited to connections this exact device
   * already belongs to. It never enrolls a device, issues an OAuth token, or
   * authorizes a folder before the existing native consent/activation protocol.
   */
  async manage({ action, device, input = {} }) {
    if (!isAccountId(device?.deviceId) || !isDigest(device?.epoch) || !isDigest(device?.keyHash)) throw fail('Authenticated device required.', 401);
    if (action === 'remove') return this.removeShares({ device, input });
    if (!['connections', 'start'].includes(action)) throw fail('Unknown folder-management action.', 404);
    exactFields(input, action === 'connections' ? [] : ['flowId', 'connectionId', 'sessionSecret']);
    if (action === 'start' && (!isAccountId(input.flowId) || !isAccountId(input.connectionId) || !isDigest(input.sessionSecret))) throw fail('Invalid folder-management intent.', 400);
    const owner = await this.owner();
    const sessionHash = action === 'start' ? await sha256(input.sessionSecret) : null;
    return this.storage.transaction(async tx => {
      const registration = await tx.get('device:' + device.deviceId);
      if (registration !== true && !(registration?.kind === 'private-instance' && registration.keyHash === device.keyHash)) throw fail('Device registration is unavailable.', 403);
      const connections = [];
      for (const connectionId of await tx.get('accounts:v3:connection-index:' + owner.accountId) || []) {
        const connection = await tx.get('accounts:v3:connection:' + connectionId);
        if (!connection || connection.revoked || connection.accountId !== owner.accountId || connection.resource !== this.resource) continue;
        const roots = connection.shares.filter(s => s.deviceId === device.deviceId && s.deviceEpoch === device.epoch).map(s => ({ rootId: s.rootId, mode: s.mode }));
        const membership = await tx.get(key('device-link', device.deviceId + ':' + connectionId));
        if (!roots.length && !(membership?.deviceEpoch === device.epoch && membership.connectionEpoch === connection.epoch)) continue;
        const descriptor = await tx.get(key('client', connectionId));
        if (!descriptor?.redirectUri) continue;
        connections.push({ connection, roots, descriptor });
      }
      if (action === 'connections') return { connections: connections.map(({ connection: c, roots, descriptor: d }) => ({ connectionId: c.id, revision: c.revision, clientId: c.clientId, clientName: d.clientName, callbackOrigin: new URL(d.redirectUri).origin, scopes: c.scopes, roots })) };
      const matched = connections.find(c => c.connection.id === input.connectionId);
      if (!matched) throw fail('This computer is not shared with the selected connection.', 403);
      const { connection: c, descriptor: d } = matched;
      let flow = await tx.get(key('flow', input.flowId));
      if (flow) {
        if (!flow.manageExisting || flow.connectionId !== c.id || flow.device.deviceId !== device.deviceId || flow.device.epoch !== device.epoch || flow.device.keyHash !== device.keyHash || flow.device.sessionHash !== sessionHash) throw fail('Folder-management intent changed.', 409);
        await this.assertFlow(tx, flow);
      } else {
        const entries = await tx.list({ prefix: key('flow'), limit: 201 });
        for (const [k, value] of entries) if (value.until <= this.now()) await tx.delete(k);
        if ([...entries.values()].filter(value => value.until > this.now()).length >= 200) throw fail('Too many pending management requests.', 429);
        flow = { id: input.flowId, mode: 'manage', manageExisting: true, resource: this.resource, accountId: owner.accountId, actor: { ...owner.actor, sessionBinding: sessionHash }, authRequest: { clientId: c.clientId, scope: c.scopes, redirectUri: d.redirectUri }, clientName: d.clientName, scopes: c.scopes, connectionId: c.id, recoveryEpoch: c.epoch, recoveryRevision: c.revision, device: { ...device, sessionHash }, createdAt: this.now(), until: this.now() + 86400000, finishTaken: false };
        await tx.put(key('flow', flow.id), flow);
      }
      return { flowId: flow.id, management: true, accountId: flow.accountId, displayName: new URL(this.resource).host, clientId: c.clientId, clientName: d.clientName, resource: this.resource, deviceId: device.deviceId, deviceEpoch: device.epoch, scopes: flow.scopes, requestDigest: await sha256(JSON.stringify(flow.authRequest)), connectionId: c.id, callbackOrigin: new URL(d.redirectUri).origin };
    });
  }
  async removeShares({ device, input }) {
    exactFields(input, ['requestId', 'connectionId', 'rootIds', 'expectedRevision']);
    if (!isAccountId(input.requestId) || !isAccountId(input.connectionId) || !Number.isSafeInteger(input.expectedRevision) || !Array.isArray(input.rootIds) || !input.rootIds.length || input.rootIds.length > 100 || new Set(input.rootIds).size !== input.rootIds.length || input.rootIds.some(r => !/^[a-f0-9-]{36}$/.test(r))) throw fail('Invalid removal snapshot.', 400);
    const owner = await this.owner();
    const fingerprint = await sha256(JSON.stringify({ ...input, device }));
    return this.storage.transaction(async tx => {
      const registration = await tx.get('device:' + device.deviceId);
      if (registration !== true && !(registration?.kind === 'private-instance' && registration.keyHash === device.keyHash)) throw fail('Device is no longer registered.', 403);
      const c = await tx.get('accounts:v3:connection:' + input.connectionId);
      const deviceOwner = await tx.get('accounts:v3:device-owner:' + device.deviceId);
      if (!c || c.accountId !== owner.accountId || c.resource !== this.resource || !deviceOwner || deviceOwner.accountId !== owner.accountId || deviceOwner.epoch !== device.epoch) throw fail('Removal does not belong to this device and connection.', 403);
      const saved = await tx.get(key('removal', input.requestId));
      if (saved) {
        if (saved.fingerprint !== fingerprint) throw fail('Removal request changed.', 409);
        return saved.result;
      }
      const targets = c.shares.filter(s => s.deviceId === device.deviceId && s.deviceEpoch === device.epoch && input.rootIds.includes(s.rootId));
      if (!c.revoked && targets.length && c.revision !== input.expectedRevision) throw fail('Shared scope changed after review; local access remains revoked.', 409);
      const retained = await tx.list({ prefix: key('removal'), limit: 513 });
      if (retained.size >= 512) throw fail('Removal receipt capacity reached.', 429);
      if (targets.length) {
        c.shares = c.shares.filter(s => !targets.includes(s)); c.revision++;
        await tx.put('accounts:v3:connection:' + c.id, c);
        // Keep this already proven device's management link, not file access.
        // A zero-folder device can later add a folder with fresh local consent.
        await tx.put(key('device-link', device.deviceId + ':' + c.id), { deviceEpoch: device.epoch, connectionEpoch: c.epoch });
      }
      const result = { requestId: input.requestId, connectionId: c.id, rootIds: input.rootIds, removed: true, revision: c.revision, filesDeleted: false };
      await tx.put(key('removal', input.requestId), { fingerprint, result });
      return result;
    });
  }
  async createInvitation(input, stable = null) {
    exactFields(input, ['purpose', 'connectionId', 'scopes', 'ttlSeconds', 'clientId']);
    // Only an internal caller can supply a stable capability. Public owner input
    // never accepts these fields. Retries reuse a ticket, never rotate a secret.
    if (stable && (!isAccountId(stable.invitationId) || !isDigest(stable.secret))) throw fail('Invalid installer reservation.');
    if (!['connect','join'].includes(input.purpose)) throw fail('Choose connect or join invitation.', 400);
    const ttl = input.ttlSeconds ?? 600;
    if (!Number.isInteger(ttl) || ttl < 60 || ttl > 900) throw fail('Invitation lifetime must be 60–900 seconds.', 400);
    const { accountId } = await this.owner();
    let connection = null, descriptor = null;
    if (input.purpose === 'join') {
      if (!isAccountId(input.connectionId)) throw fail('Choose the exact existing connection.', 400);
      connection = await this.storage.get('accounts:v3:connection:' + input.connectionId);
      descriptor = await this.storage.get(key('client', input.connectionId));
      if (!connection || connection.revoked || connection.accountId !== accountId || connection.resource !== this.resource || !descriptor) throw fail('This private connection is unavailable.', 403);
    } else if (input.connectionId !== undefined) throw fail('A connect invitation cannot attach an existing connection.', 400);
    const scopes = checkedScopes(input.scopes || connection?.scopes || ['files:read','files:write']);
    if (connection && scopes.some(scope => !connection.scopes.includes(scope))) throw fail('A join invitation cannot expand OAuth permissions.', 403);
    const clientId = input.clientId === undefined ? connection?.clientId || null : checkedClient(input.clientId);
    if (connection && clientId !== connection.clientId) throw fail('Invitation client does not match the connection.', 403);
    const invitationId = stable?.invitationId || id(), secret = stable?.secret || randomSecret();
    const value = { id: invitationId, secretHash: await sha256(secret), purpose: input.purpose, resource: this.resource, accountId, connectionId: connection?.id || null, connectionEpoch: connection?.epoch || null, clientId, descriptor, scopes, expiresAt: this.now() + ttl * 1000, revoked: false, claim: null };
    const saved = await this.storage.transaction(async tx => {
      const previous = await tx.get(key('invite', invitationId));
      if (previous) {
        if (!stable || previous.revoked || previous.expiresAt <= this.now() || previous.secretHash !== value.secretHash || previous.resource !== value.resource || previous.purpose !== value.purpose || previous.connectionId !== value.connectionId || previous.connectionEpoch !== value.connectionEpoch || previous.clientId !== value.clientId || JSON.stringify(previous.scopes) !== JSON.stringify(value.scopes)) throw fail('Installer invitation changed, expired or revoked.', 409);
        return previous;
      }
      const entries = await tx.list({ prefix: key('invite'), limit: 65 });
      for (const [k, item] of entries) if ((item.claim ? item.resumeUntil : item.expiresAt) <= this.now()) await tx.delete(k);
      if ([...entries.values()].filter(item => (item.claim ? item.resumeUntil : item.expiresAt) > this.now()).length >= 64) throw fail('Too many current invitations.', 429);
      await tx.put(key('invite', invitationId), value); return value;
    });
    return { invitationId, invitation: invitationId + '.' + secret, purpose: saved.purpose, connectionId: saved.connectionId, expiresAt: saved.expiresAt };
  }
  async revokeInvitation({ invitationId }) {
    if (!isAccountId(invitationId)) throw fail('Invalid invitation identifier.', 400);
    return this.storage.transaction(async tx => {
      const item = await tx.get(key('invite', invitationId));
      if (!item) throw fail('Invitation not found.', 404);
      item.revoked = true; await tx.put(key('invite', invitationId), item);
      return { revoked: true, activeSharesChanged: false };
    });
  }
  async checkInvite(tx, invitationId, secretHash, flowId) {
    const item = await tx.get(key('invite', invitationId));
    if (!item || item.resource !== this.resource || item.secretHash !== secretHash || item.revoked) throw fail('Invitation invalid or revoked.', 403);
    if (item.claim) {
      if (item.claim.flowId !== flowId || item.resumeUntil <= this.now()) throw fail('Invitation already used by another setup or expired.', 403);
    } else if (item.expiresAt <= this.now()) throw fail('Invitation expired.', 403);
    if (item.connectionId) {
      const connection = await tx.get('accounts:v3:connection:' + item.connectionId);
      if (!connection || connection.revoked || connection.epoch !== item.connectionEpoch || connection.accountId !== item.accountId || connection.resource !== this.resource || connection.clientId !== item.clientId || item.scopes.some(scope => !connection.scopes.includes(scope))) throw fail('Invited connection was revoked or changed.', 403);
    }
    return item;
  }
  async makeFlow({ authRequest, clientName, invitation }) {
    let pinned = null;
    if (invitation !== undefined) {
      const [invitationId, secret] = invitationParts(invitation), digest = await sha256(secret);
      pinned = await this.storage.transaction(tx => this.checkInvite(tx, invitationId, digest, null));
      if (pinned.purpose !== 'join') throw fail('Use the supplied installer configuration for a first connection.', 400);
      authRequest = { clientId: pinned.clientId, scope: pinned.scopes, redirectUri: pinned.descriptor.redirectUri };
      clientName = pinned.descriptor.clientName;
    }
    checkedClient(authRequest?.clientId);
    const scopes = checkedScopes(authRequest.scope.filter(scope => ['files:read','files:write','files:propose','terminal:execute'].includes(scope)));
    const owner = await this.owner();
    const flowId = id(), bootstrap = randomSecret(), browser = randomSecret();
    const flow = { id: flowId, mode: pinned ? 'join' : 'oauth', authRequest, clientName: String(clientName || '请求应用').slice(0, 120), resource: this.resource, scopes, accountId: owner.accountId, actor: { ...owner.actor, sessionBinding: await sha256(browser) }, bootstrapHash: await sha256(bootstrap), browserHash: await sha256(browser), invitationId: pinned?.id || null, invitationHash: pinned?.secretHash || null, createdAt: this.now(), until: this.now() + 86400000, finishTaken: false };
    await this.storage.transaction(async tx => {
      const entries = await tx.list({ prefix: key('flow'), limit: 201 });
      const alive = item => (item.device ? item.until : item.createdAt + 300000) > this.now();
      for (const [k, item] of entries) if (!alive(item)) await tx.delete(k);
      if ([...entries.values()].filter(alive).length >= 200) throw fail('Too many pending connection requests.', 429);
      await tx.put(key('flow', flowId), flow);
    });
    return { flowId, bootstrap, browser };
  }
  async claim({ flowId, bootstrap, invitation, deviceId, keyHash, sessionHash, registering = false }) {
    if (!isAccountId(flowId) || !isDigest(bootstrap) || !isAccountId(deviceId) || !isDigest(keyHash) || !isDigest(sessionHash)) throw fail('Invalid native invitation claim.', 400);
    const bootstrapHash = await sha256(bootstrap);
    let supplied;
    if (invitation !== undefined && invitation !== null) { const [id, secret] = invitationParts(invitation); supplied = { id, hash: await sha256(secret) }; }
    return this.storage.transaction(async tx => {
      const flow = await tx.get(key('flow', flowId));
      if (!flow || flow.bootstrapHash !== bootstrapHash || flow.until <= this.now() || (!flow.device && this.now() - flow.createdAt > 300000)) throw fail('This native connection request expired.', 401);
      const invitationId = flow.invitationId || supplied?.id, invitationHash = flow.invitationHash || supplied?.hash;
      if (!invitationId || (flow.mode === 'oauth' && supplied && (supplied.id !== invitationId || supplied.hash !== invitationHash))) throw fail('Use this private instance’s installation invitation.', 403);
      const invite = await this.checkInvite(tx, invitationId, invitationHash, flowId);
      if (invite.accountId !== flow.accountId || (flow.mode === 'join') !== (invite.purpose === 'join') || (invite.clientId && invite.clientId !== flow.authRequest.clientId) || flow.scopes.some(s => !invite.scopes.includes(s))) throw fail('Invitation client or permissions do not match this request.', 403);
      const claim = { flowId, deviceId, keyHash, sessionHash };
      if (invite.claim && JSON.stringify(invite.claim) !== JSON.stringify(claim)) throw fail('Invitation is already bound to a different device or native session.', 403);
      if (registering) {
        const registration = await tx.get('device:' + deviceId);
        if (registration) {
          if (registration.kind !== 'private-instance' || registration.invitationId !== invite.id || registration.keyHash !== keyHash) throw fail('Existing device identity cannot be replaced.', 409);
        } else {
          const count = await tx.get('deviceCount') || 0;
          if (count >= 100) throw fail('Private device limit reached.', 429);
          await tx.put('device:' + deviceId, { kind: 'private-instance', invitationId: invite.id, keyHash }); await tx.put('deviceCount', count + 1);
        }
      }
      invite.claim = claim; invite.resumeUntil ||= this.now() + 86400000;
      flow.invitationId = invite.id; flow.invitationHash = invite.secretHash; flow.connectionId = invite.connectionId; flow.device ||= { deviceId, keyHash, sessionHash };
      if (flow.device.deviceId !== deviceId || flow.device.keyHash !== keyHash || flow.device.sessionHash !== sessionHash) throw fail('Native device changed during setup.', 403);
      await tx.put(key('invite', invite.id), invite); await tx.put(key('flow', flow.id), flow);
      return { reserved: true };
    });
  }
  /** Recovery authenticates an ALREADY enrolled computer, not a new enrollment.
   * Operator-enrolled legacy devices may explicitly authorize their retained local
   * roots once. Other devices may only recover the exact existing connection in
   * which that device already has shares. A key never grants access by itself.
   */
  async claimExisting({ flowId, bootstrap, device, sessionHash }) {
    const bootstrapHash = await sha256(bootstrap);
    return this.storage.transaction(async tx => {
      const flow = await tx.get(key('flow', flowId));
      if (!flow || flow.bootstrapHash !== bootstrapHash || flow.until <= this.now() || (!flow.device && this.now() - flow.createdAt > 300000)) throw fail('This native connection request expired.', 401);
      if (flow.mode !== 'oauth' || (flow.device && !flow.reuseExisting)) return false;
      const registration = await tx.get('device:' + device.deviceId);
      const legacy = registration === true; // Only the operator-authenticated /enroll writes true.
      const privateDevice = registration?.kind === 'private-instance' && registration.keyHash === device.keyHash;
      if (!legacy && !privateDevice) return false;
      if (flow.reuseExisting) {
        if (flow.device.deviceId !== device.deviceId || flow.device.keyHash !== device.keyHash || flow.device.epoch !== device.epoch || flow.device.sessionHash !== sessionHash) throw fail('Recovery belongs to another native device or session.', 403);
        await this.assertFlow(tx, flow); return true;
      }
      const ids = await tx.get('accounts:v3:connection-index:' + flow.accountId) || [];
      const matching = [];
      for (const id of ids) {
        const connection = await tx.get('accounts:v3:connection:' + id);
        if (connection && connection.clientId === flow.authRequest.clientId && connection.resource === this.resource) matching.push(connection);
      }
      // Revoked/ambiguous references are not a reason to recreate them silently.
      if (matching.length > 1 || matching.some(c => c.revoked)) throw fail('The previous connection was revoked or is ambiguous; explicit management is required.', 403);
      const connection = matching[0];
      const shares = connection?.shares.filter(s => s.deviceId === device.deviceId && s.deviceEpoch === device.epoch) || [];
      const addedScopes = connection ? flow.scopes.filter(s => !connection.scopes.includes(s)) : [];
      // Only this original OAuth flow may request the separately displayed
      // terminal scope; file scopes and other devices cannot be upgraded here.
      const terminalUpgrade = addedScopes.length === 1 && addedScopes[0] === 'terminal:execute';
      if (connection && (!shares.length || (addedScopes.length && !terminalUpgrade))) throw fail('This device or requested scope is not in the existing connection; access was not expanded.', 403);
      if (terminalUpgrade) flow.allowScopeUpgrade = true;
      if (!connection && !legacy) return false; // A join-only device cannot bootstrap another client.
      flow.reuseExisting = true;
      flow.connectionId = connection?.id || null;
      flow.recoveryEpoch = connection?.epoch || null;
      flow.recoveryRevision = connection?.revision ?? null;
      flow.recoveryRoots = connection ? shares.map(s => ({ rootId: s.rootId, mode: s.mode })) : null;
      flow.device = { deviceId: device.deviceId, keyHash: device.keyHash, epoch: device.epoch, sessionHash };
      await tx.put(key('flow', flowId), flow);
      return true; // Still no active share or OAuth code before native confirmation.
    });
  }
  async assertFlow(tx, flow) {
    const current = await tx.get(key('flow', flow.id));
    if (!current || current.until <= this.now() || current.cancelled || current.device?.deviceId !== flow.device?.deviceId || current.device?.sessionHash !== flow.device?.sessionHash || current.device?.epoch !== flow.device?.epoch) throw fail('Native pairing has expired, changed or been cancelled.', 403);
    if (current.reuseExisting || current.manageExisting) {
      const registration = await tx.get('device:' + current.device.deviceId);
      if (registration !== true && !(registration?.kind === 'private-instance' && registration.keyHash === current.device.keyHash)) throw fail('The previously enrolled device is unavailable.', 403);
      if (current.connectionId) {
        const connection = await tx.get('accounts:v3:connection:' + current.connectionId);
        if (!connection || connection.revoked || connection.epoch !== current.recoveryEpoch || connection.accountId !== current.accountId || connection.resource !== this.resource || connection.clientId !== current.authRequest.clientId || current.scopes.some(s => !connection.scopes.includes(s) && !(current.mode === 'oauth' && current.allowScopeUpgrade === true && s === 'terminal:execute'))) throw fail('The original private connection changed or was revoked.', 403);
        if (connection.revision !== current.recoveryRevision && !connection.shares.some(s => s.intentId === current.id)) throw fail('Shared folders changed after recovery started; stale authorization was not restored.', 403);
      }
    } else await this.checkInvite(tx, current.invitationId, current.invitationHash, current.id);
    if (current.mode === 'oauth' && !current.connectionId) {
      // A second bootstrap must not replace the one original client connection.
      // Joining uses an invitation pinned to that reference. This check runs
      // inside the same share-activation transaction, including concurrent setups.
      const ids = await tx.get('accounts:v3:connection-index:' + current.accountId) || [];
      for (const id of ids) {
        const existing = await tx.get('accounts:v3:connection:' + id);
        if (existing && !existing.revoked && existing.clientId === current.authRequest.clientId && existing.resource === this.resource && !existing.shares.some(share => share.intentId === current.id)) throw fail('This client already has a private connection. Use its join invitation; no second connection was created.');
      }
    }
  }
  async native({ action, flowId, secret, device, input = {}, invitation }) {
    if (!isAccountId(flowId) || !isDigest(secret) || !isAccountId(device?.deviceId) || !isDigest(device?.epoch) || !isDigest(device?.keyHash)) throw fail('Authenticated native device required.', 401);
    if (!['start','prepare','status','confirm','activate','cancel'].includes(action)) throw fail('Unknown pairing step.', 404);
    if (action === 'start') {
      exactFields(input, ['sessionSecret', 'reuseExisting']); if (!isDigest(input.sessionSecret) || (input.reuseExisting !== undefined && typeof input.reuseExisting !== 'boolean')) throw fail('Invalid native session.', 400);
      const sessionHash = await sha256(input.sessionSecret);
      const reused = input.reuseExisting === true && await this.claimExisting({ flowId, bootstrap: secret, device, sessionHash });
      if (!reused) await this.claim({ flowId, bootstrap: secret, invitation, deviceId: device.deviceId, keyHash: device.keyHash, sessionHash });
      return this.storage.transaction(async tx => {
        const flow = await tx.get(key('flow', flowId));
        if (flow.device.epoch && flow.device.epoch !== device.epoch) throw fail('Device epoch changed.', 403);
        flow.device.epoch = device.epoch; await tx.put(key('flow', flowId), flow);
        return { flowId, accountId: flow.accountId, displayName: new URL(this.resource).host, clientId: flow.authRequest.clientId, clientName: flow.clientName, resource: this.resource, deviceId: device.deviceId, deviceEpoch: device.epoch, scopes: flow.scopes, requestDigest: await sha256(JSON.stringify(flow.authRequest)), connectionId: flow.connectionId, callbackOrigin: new URL(flow.authRequest.redirectUri).origin, ...(flow.reuseExisting ? { reuseExisting: true, recoveryRoots: flow.recoveryRoots } : {}) };
      });
    }
    const flow = await this.storage.get(key('flow', flowId));
    if (!flow || flow.device?.deviceId !== device.deviceId || flow.device?.keyHash !== device.keyHash || flow.device?.epoch !== device.epoch || flow.device?.sessionHash !== await sha256(secret)) throw fail('Pairing session does not match this computer.', 401);
    const directory = new AccountDirectory(this.storage, { now: this.now, assertActorCurrent: tx => this.assertFlow(tx, flow), verifyDeviceConsent: async ({ action: step, proof, intent }) => {
      if (step !== action || proof !== secret || intent.id !== flowId || input.snapshotDigest !== intent.snapshotDigest || intent.deviceId !== device.deviceId || intent.deviceEpoch !== device.epoch) return null;
      return { intentId: intent.id, snapshotDigest: intent.snapshotDigest, deviceId: device.deviceId, deviceEpoch: device.epoch, phase: action === 'confirm' ? 'consented' : 'activated' };
    } });
    let args;
    if (action === 'prepare') {
      exactFields(input, ['roots','policyDigest']);
      if (flow.reuseExisting && flow.recoveryRoots) {
        const rank = { 'read-only': 0, review: 1, direct: 2 };
        if (!Array.isArray(input.roots) || input.roots.some(root => !flow.recoveryRoots.some(old => old.rootId === root.rootId && rank[root.mode] <= rank[old.mode]))) throw fail('Recovery cannot add folders or increase their permissions.', 403);
      }
      args = { intentId: flow.id, connectionId: flow.connectionId, clientId: flow.authRequest.clientId, resource: this.resource, deviceId: device.deviceId, deviceEpoch: device.epoch, roots: input.roots, scopes: flow.scopes, policyDigest: input.policyDigest, requestDigest: await sha256(JSON.stringify(flow.authRequest)), ...(flow.mode === 'oauth' && flow.allowScopeUpgrade === true ? { allowScopeUpgrade: true } : {}) };
    } else if (['confirm','activate'].includes(action)) { exactFields(input, ['snapshotDigest']); args = { intentId: flow.id, snapshotDigest: input.snapshotDigest, proof: secret }; }
    else { exactFields(input, []); args = { intentId: flow.id }; }
    const result = await directory.execute({ action, actor: flow.actor, input: args });
    if (action === 'activate' && result.phase === 'active') await this.storage.put(key('client', result.connectionId), { clientName: flow.clientName, redirectUri: flow.authRequest.redirectUri });
    return result;
  }
  async finish({ flowId, browser }) {
    if (!isAccountId(flowId) || !isDigest(browser)) throw fail('Original browser continuation required.', 401);
    const flow = await this.storage.get(key('flow', flowId));
    if (!flow || flow.browserHash !== await sha256(browser) || flow.until <= this.now() || flow.finishTaken) throw fail('Original browser request expired or already used.', 401);
    const directory = new AccountDirectory(this.storage, { now: this.now, assertActorCurrent: tx => this.assertFlow(tx, flow) });
    const intent = await directory.execute({ action: 'status', actor: flow.actor, input: { intentId: flowId } });
    if (intent.phase !== 'active') throw fail('The chosen folders have not been activated.');
    const connection = await this.storage.get('accounts:v3:connection:' + intent.connectionId);
    const grant = directory.grant(connection, flow.scopes); await directory.execute({ action: 'resolve', grant });
    if (flow.mode === 'join') return { joined: true, folderCount: intent.roots.length }; // NO token issuance; same original reference.
    await this.storage.transaction(async tx => {
      await this.assertFlow(tx, flow);
      const current = await tx.get(key('flow', flowId)); if (current.finishTaken) throw fail('OAuth continuation already consumed.');
      current.finishTaken = true; await tx.put(key('flow', flowId), current);
    });
    const remember = randomSecret();
    await this.storage.transaction(async tx => {
      const entries = await tx.list({ prefix: key('remember'), limit: 65 });
      for (const [k, value] of entries) if (value.until <= this.now()) await tx.delete(k);
      if ([...entries.values()].filter(value => value.until > this.now()).length >= 64) return;
      await tx.put(key('remember', await sha256(remember)), { grant, redirectUri: flow.authRequest.redirectUri, until: this.now() + 30 * 86400000 });
    });
    return { authRequest: flow.authRequest, accountId: flow.accountId, grant, remember };
  }
  async remembered({ secret, authRequest }) {
    if (!isDigest(secret)) return null;
    const saved = await this.storage.get(key('remember', await sha256(secret)));
    if (!saved || saved.until <= this.now() || saved.redirectUri !== authRequest.redirectUri || saved.grant.clientId !== authRequest.clientId || saved.grant.resource !== this.resource) return null;
    const scopes = checkedScopes(authRequest.scope.filter(s => ['files:read','files:write','files:propose','terminal:execute'].includes(s)));
    if (scopes.some(s => !saved.grant.scopes.includes(s))) return null;
    const grant = { ...saved.grant, scopes };
    try {
      const resolved = await new AccountDirectory(this.storage).execute({ action: 'resolve', grant });
      if (!resolved.devices.length) return null;
      return { accountId: grant.accountId, grant };
    } catch { return null; }
  }
}
