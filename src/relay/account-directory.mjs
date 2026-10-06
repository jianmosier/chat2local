import { randomSecret, sha256 } from '../shared/protocol.mjs';
import { exactFields, checkedClient, checkedResource, checkedScopes, checkedShares, checkedReferenceGrant, isAccountId, isDigest } from '../shared/connection-access.mjs';

const fail = (message, status = 409) => Object.assign(new Error(message), { status });
const newId = () => crypto.randomUUID().replaceAll('-', '');
const key = (kind, id) => `accounts:v3:${kind}:${id}`;
const receipt = intent => ({ version: 1, intentId: intent.id, accountId: intent.accountId, connectionId: intent.connectionId, deviceId: intent.deviceId, deviceEpoch: intent.deviceEpoch, snapshotDigest: intent.snapshotDigest, policyDigest: intent.policyDigest, requestDigest: intent.requestDigest, clientId: intent.clientId, resource: intent.resource, roots: intent.roots, scopes: intent.scopes, phase: intent.phase });

/** Private transactional aggregate in the existing Registry storage. Commands
 * are reachable ONLY through the server-owned AccountRepository/identity adapter.
 * verifyDeviceConsent MUST authenticate an exact native consent/activation receipt;
 * without it no grant/share can be activated. Never expose execute() as a public
 * JSON API or interpret public actor/device fields as authenticated identities.
 */
export class AccountDirectory {
  constructor(storage, { now = Date.now, verifyDeviceConsent, assertActorCurrent } = {}) {
    this.storage = storage; this.now = now; this.verifyDeviceConsent = verifyDeviceConsent; this.assertActorCurrent = assertActorCurrent;
  }
  async execute(command) {
    if (command?.action === 'resolve') {
      exactFields(command, ['action', 'grant']);
      return this.storage.transaction(tx => this.resolve(tx, checkedReferenceGrant(command.grant)));
    }
    exactFields(command, ['action', 'actor', 'input']);
    exactFields(command.actor, ['identityKey', 'sessionBinding']);
    if (!isDigest(command.actor.identityKey) || !isDigest(command.actor.sessionBinding)) throw fail('Verified server identity required.', 401);
    if (!['account', 'connections', 'prepare', 'status', 'confirm', 'activate', 'cancel', 'revoke-share', 'revoke-connection'].includes(command.action)) throw fail('Unknown account command.', 404);
    const input = command.input || {};
    // Authenticate native proofs outside a retryable storage transaction. The
    // verified digest is checked AGAIN against current immutable state inside it.
    let native;
    if (['confirm', 'activate'].includes(command.action)) {
      exactFields(input, ['intentId', 'snapshotDigest', 'proof']);
      if (!isAccountId(input.intentId) || !isDigest(input.snapshotDigest) || typeof input.proof !== 'string' || !input.proof || input.proof.length > 4096) throw fail('Exact consent proof required.', 400);
      if (typeof this.verifyDeviceConsent !== 'function') throw fail('Native consent verifier is not configured. No share granted.', 503);
      const pending = await this.storage.get(key('intent', input.intentId));
      const account = await this.storage.get(key('identity', command.actor.identityKey));
      if (!pending || !account || pending.accountId !== account.id || pending.snapshotDigest !== input.snapshotDigest) throw fail('Consent does not belong to this account.', 403);
      if (pending.phase === 'cancelled') throw fail('Consent has been cancelled.');
      native = await this.verifyDeviceConsent({ action: command.action, proof: input.proof, intent: structuredClone(pending) });
      if (!native || native.intentId !== pending.id || native.deviceId !== pending.deviceId || native.deviceEpoch !== pending.deviceEpoch || native.snapshotDigest !== pending.snapshotDigest || native.phase !== (command.action === 'confirm' ? 'consented' : 'activated')) throw fail('Native receipt does not match this consent.', 403);
    }
    return this.storage.transaction(async tx => {
      if (this.assertActorCurrent) await this.assertActorCurrent(tx, command.actor);
      let account = await tx.get(key('identity', command.actor.identityKey));
      if (!account) {
        if (command.action !== 'account') throw fail('Account has not been established.', 401);
        exactFields(input, []);
        account = { id: newId(), createdAt: this.now() };
        await tx.put(key('identity', command.actor.identityKey), account);
      }
      if (command.action === 'account') { exactFields(input, []); return { accountId: account.id }; }
      if (command.action === 'connections') {
        exactFields(input, input.clientId === undefined ? ['resource'] : ['clientId', 'resource']);
        const clientId = input.clientId === undefined ? null : checkedClient(input.clientId), resource = checkedResource(input.resource);
        const ids = await tx.get(key('connection-index', account.id)) || [];
        const found = [];
        for (const id of ids) { const item = await tx.get(key('connection', id)); if (item && !item.revoked && item.accountId === account.id && (!clientId || item.clientId === clientId) && item.resource === resource) found.push({ connectionId: item.id, clientId: item.clientId, scopes: item.scopes }); }
        return { accountId: account.id, connections: found };
      }
      if (command.action === 'prepare') return this.prepare(tx, account.id, command.actor.sessionBinding, input);
      if (['revoke-share', 'revoke-connection'].includes(command.action)) return this.revoke(tx, account.id, command.action, input);
      if (!['confirm', 'activate'].includes(command.action)) exactFields(input, ['intentId']);
      if (!isAccountId(input.intentId)) throw fail('Invalid consent ID.', 400);
      const intent = await tx.get(key('intent', input.intentId));
      if (!intent || intent.accountId !== account.id) throw fail('Unknown consent for this account.', 404);
      if (command.action === 'status') {
        if (intent.phase === 'active') {
          const live = await tx.get(key('connection', intent.connectionId));
          const retained = live && !live.revoked && live.epoch === intent.connectionEpoch && intent.roots.every(root => live.shares.some(share => share.intentId === intent.id && share.deviceId === intent.deviceId && share.rootId === root.rootId && share.mode === root.mode));
          return receipt(retained ? intent : { ...intent, phase: 'revoked' });
        }
        const expired = this.now() > (intent.phase === 'prepared' ? intent.expiresAt : intent.resumeUntil);
        return receipt(expired && intent.phase !== 'cancelled' ? { ...intent, phase: 'expired' } : intent);
      }
      if (command.action === 'cancel') {
        if (intent.phase === 'active') throw fail('Use explicit share revocation after activation.');
        intent.phase = 'cancelled'; await tx.put(key('intent', intent.id), intent); return receipt(intent);
      }
      if (intent.phase === 'cancelled') throw fail('Consent cancelled; it cannot be replayed.');
      if (intent.snapshotDigest !== input.snapshotDigest || native.snapshotDigest !== intent.snapshotDigest) throw fail('Consent snapshot changed.', 403);
      if (command.action === 'confirm' && command.actor.sessionBinding !== intent.sessionBinding) throw fail('Account session changed; stale page cannot confirm.', 403);
      const connection = await tx.get(key('connection', intent.connectionId));
      if (intent.phase === 'active') {
        if (!connection || connection.revoked || connection.epoch !== intent.connectionEpoch || !intent.roots.every(root => connection.shares.some(s => s.intentId === intent.id && s.deviceId === intent.deviceId && s.rootId === root.rootId && s.mode === root.mode))) throw fail('Previously activated share has been revoked.');
        return { ...receipt(intent), grant: this.grant(connection, intent.scopes) };
      }
      if (this.now() > (intent.phase === 'prepared' ? intent.expiresAt : intent.resumeUntil)) throw fail('Consent expired. No share granted.');
      if ((connection?.revision || 0) !== intent.connectionRevision || connection?.revoked) throw fail('Connection changed after the displayed consent.');
      const owner = await tx.get(key('device-owner', intent.deviceId));
      if (owner && (owner.accountId !== account.id || owner.epoch !== intent.deviceEpoch)) throw fail('Device belongs to another account or epoch.', 403);
      if (command.action === 'confirm') {
        if (intent.phase === 'prepared') { intent.phase = 'consented'; intent.consentedAt = this.now(); intent.resumeUntil = this.now() + 86400000; await tx.put(key('intent', intent.id), intent); }
        return receipt(intent); // No active share yet. Local activation must match.
      }
      if (intent.phase !== 'consented') throw fail('A matching explicit consent is required before activation.', 403);
      const connectionIndex = (await tx.get(key('connection-index', account.id))) || [];
      if (!connection && connectionIndex.length >= 20) throw fail('Account connection limit reached.', 429);
      const current = connection || { id: intent.connectionId, accountId: account.id, clientId: intent.clientId, resource: intent.resource, epoch: intent.connectionEpoch, scopes: intent.scopes, revision: 0, revoked: false, policy: 'explicit-shares', shares: [] };
      const other = current.shares.filter(share => share.deviceId !== intent.deviceId || !intent.roots.some(root => root.rootId === share.rootId));
      const added = intent.roots.map(root => ({ ...root, deviceId: intent.deviceId, deviceEpoch: intent.deviceEpoch, intentId: intent.id }));
      if (new Set([...other, ...added].map(s => s.deviceId)).size > 20 || other.length + added.length > 100) throw fail('Connection share limit reached.', 429);
      // Only an original validated OAuth request may stage a scope upgrade, and
      // it takes effect only after the exact native consent/activation receipts.
      // Existing token scopes remain a ceiling; joining a device cannot request it.
      if (intent.allowScopeUpgrade === true) current.scopes = checkedScopes([...new Set([...current.scopes, ...intent.scopes])]);
      current.shares = [...other, ...added]; current.revision++;
      await tx.put(key('device-owner', intent.deviceId), { accountId: account.id, epoch: intent.deviceEpoch });
      await tx.put(key('connection', current.id), current);
      if (!connection) await tx.put(key('connection-index', account.id), [...connectionIndex, current.id]);
      intent.phase = 'active'; await tx.put(key('intent', intent.id), intent);
      return { ...receipt(intent), grant: this.grant(current, intent.scopes) };
    });
  }
  async prepare(tx, accountId, sessionBinding, input) {
    exactFields(input, ['intentId', 'connectionId', 'clientId', 'resource', 'deviceId', 'deviceEpoch', 'roots', 'scopes', 'policyDigest', 'requestDigest', 'allowScopeUpgrade']);
    if (input.allowScopeUpgrade !== undefined && typeof input.allowScopeUpgrade !== 'boolean') throw fail('Invalid server authorization context.', 400);
    if (!isAccountId(input.intentId) || (input.connectionId !== null && !isAccountId(input.connectionId)) || !isAccountId(input.deviceId) || !isDigest(input.deviceEpoch) || !isDigest(input.policyDigest) || !isDigest(input.requestDigest)) throw fail('Invalid immutable consent snapshot.', 400);
    const roots = checkedShares(input.roots), scopes = checkedScopes(input.scopes), clientId = checkedClient(input.clientId), resource = checkedResource(input.resource);
    if (roots.some(r => r.mode === 'direct') && !scopes.includes('files:write')) throw fail('Direct sharing was not requested by this client.', 400);
    if (roots.some(r => r.mode === 'review') && !scopes.includes('files:propose')) throw fail('Review sharing was not requested by this client.', 400);
    const request = { ...input, roots, scopes, clientId, resource };
    const requestHash = await sha256(JSON.stringify(request));
    const previous = await tx.get(key('intent', input.intentId));
    if (previous) {
      if (previous.accountId !== accountId || previous.sessionBinding !== sessionBinding || previous.requestHash !== requestHash || previous.phase === 'cancelled') throw fail('Consent ID cannot be reused for another request.');
      return receipt(previous);
    }
    let connection = input.connectionId ? await tx.get(key('connection', input.connectionId)) : null;
    if (input.connectionId && (!connection || connection.accountId !== accountId || connection.clientId !== clientId || connection.resource !== resource || connection.revoked)) throw fail('Connection does not belong to this account/client/resource.', 403);
    if (connection && scopes.some(scope => !connection.scopes.includes(scope)) && input.allowScopeUpgrade !== true) throw fail('A new OAuth permission requires explicit connection reauthorization.', 403);
    const owner = await tx.get(key('device-owner', input.deviceId));
    if (owner && (owner.accountId !== accountId || owner.epoch !== input.deviceEpoch)) throw fail('Device ownership does not match.', 403);
    // Bound retained intents without using a browser session as the durable account.
    const indexKey = key('intent-index', accountId);
    const index = (await tx.get(indexKey) || []).filter(item => item.until > this.now());
    if (index.length >= 32) throw fail('Too many account setup attempts.', 429);
    const intent = { ...request, id: input.intentId, accountId, sessionBinding, requestHash, connectionId: connection?.id || newId(), connectionEpoch: connection?.epoch || randomSecret(), connectionRevision: connection?.revision || 0, phase: 'prepared', expiresAt: this.now() + 300000 };
    intent.snapshotDigest = await sha256(JSON.stringify({ accountId, connectionId: intent.connectionId, connectionEpoch: intent.connectionEpoch, connectionRevision: intent.connectionRevision, requestHash, sessionBinding }));
    await tx.put(key('intent', intent.id), intent);
    await tx.put(indexKey, [...index, { id: intent.id, until: this.now() + 86400000 }]);
    // Explicit cleanup of expired indexed records; never delete active shares.
    for (const old of (await tx.get(key('cleanup-index', accountId)) || [])) if (old.until <= this.now()) await tx.delete(key('intent', old.id));
    await tx.put(key('cleanup-index', accountId), [...index, { id: intent.id, until: this.now() + 86400000 }]);
    return receipt(intent);
  }
  grant(connection, scopes = connection.scopes) {
    return checkedReferenceGrant({ grantVersion: 3, accountId: connection.accountId, connectionId: connection.id, connectionEpoch: connection.epoch, clientId: connection.clientId, resource: connection.resource, scopes });
  }
  async resolve(tx, grant) {
    const connection = await tx.get(key('connection', grant.connectionId));
    if (!connection || connection.revoked || connection.accountId !== grant.accountId || connection.epoch !== grant.connectionEpoch || connection.clientId !== grant.clientId || connection.resource !== grant.resource || connection.policy !== 'explicit-shares') throw fail('Account connection is revoked or does not match this grant.', 403);
    const scopes = grant.scopes.filter(scope => connection.scopes.includes(scope));
    if (!scopes.includes('files:read')) throw fail('Read scope is required.', 403);
    const grouped = new Map();
    for (const share of connection.shares) {
      const owner = await tx.get(key('device-owner', share.deviceId));
      if (!owner || owner.accountId !== grant.accountId || owner.epoch !== share.deviceEpoch) continue;
      if (!grouped.has(share.deviceId)) grouped.set(share.deviceId, { deviceId: share.deviceId, epoch: share.deviceEpoch, roots: [] });
      grouped.get(share.deviceId).roots.push({ rootId: share.rootId, mode: share.mode });
    }
    return { connectionId: connection.id, accountId: connection.accountId, clientId: connection.clientId, resource: connection.resource, scopes, revision: connection.revision, devices: [...grouped.values()] };
  }
  async revoke(tx, accountId, action, input) {
    exactFields(input, action === 'revoke-connection' ? ['connectionId'] : ['connectionId', 'deviceId', 'rootId']);
    if (!isAccountId(input.connectionId)) throw fail('Invalid connection ID.', 400);
    const connection = await tx.get(key('connection', input.connectionId));
    if (!connection || connection.accountId !== accountId) throw fail('Connection does not belong to this account.', 403);
    if (action === 'revoke-connection') { connection.revoked = true; connection.epoch = randomSecret(); }
    else {
      checkedShares([{ rootId: input.rootId, mode: 'read-only' }]);
      if (!isAccountId(input.deviceId)) throw fail('Invalid device ID.', 400);
      connection.shares = connection.shares.filter(s => s.deviceId !== input.deviceId || s.rootId !== input.rootId);
    }
    connection.revision++; await tx.put(key('connection', connection.id), connection);
    return { revoked: true, revision: connection.revision };
  }
}
