import { isAccountId, isDigest, checkedShares, checkedScopes, checkedClient, checkedResource } from '../shared/connection-access.mjs';

const copy = value => structuredClone(value);
const matchReceipt = (intent, value) => {
  if (!value || value.version !== 1 || value.intentId !== intent.intentId || value.accountId !== intent.accountId || value.connectionId !== intent.connectionId || value.deviceId !== intent.deviceId || value.deviceEpoch !== intent.deviceEpoch || value.snapshotDigest !== intent.snapshotDigest || value.policyDigest !== intent.policyDigest || value.requestDigest !== intent.requestDigest || value.clientId !== intent.clientId || value.resource !== intent.resource || JSON.stringify(checkedShares(value.roots)) !== JSON.stringify(checkedShares(intent.roots)) || JSON.stringify([...value.scopes].sort()) !== JSON.stringify([...intent.scopes].sort())) throw new Error('Consent receipt differs from the displayed account/client/device/folders.');
  return value;
};

/** One explicit user decision, multiple authenticated implementation steps.
 * This is NOT an automatic clicker for the old OAuth/browser confirmation pages.
 * Adapters are server/native-owned and must enforce their identity/CSRF/device
 * boundaries. No default network, login, filesystem authorization or success.
 * Journal stores intent/progress under the application's private state protection.
 */
export class ConsentCoordinator {
  constructor({ journal, cloud, local }) {
    if (!journal?.load || !journal?.save || !cloud?.status || !cloud?.confirm || !cloud?.activate || !local?.assertCurrent || !local?.consentProof || !local?.activate) throw new Error('Complete, authenticated consent adapters are required.');
    this.journal = journal; this.cloud = cloud; this.local = local; this.active = new Map();
  }
  async stage(intent) {
    if (!intent || !isAccountId(intent.intentId) || !isAccountId(intent.accountId) || !isAccountId(intent.connectionId) || !isAccountId(intent.deviceId) || !isDigest(intent.snapshotDigest) || !isDigest(intent.policyDigest) || !isDigest(intent.deviceEpoch)) throw new Error('A validated consent intent is required.');
    checkedShares(intent.roots); checkedScopes(intent.scopes); checkedClient(intent.clientId); checkedResource(intent.resource);
    if (!isDigest(intent.requestDigest)) throw new Error('Validated client request digest required.');
    const old = await this.journal.load(intent.intentId);
    if (old) {
      if (old.intent.snapshotDigest !== intent.snapshotDigest || old.intent.policyDigest !== intent.policyDigest) throw new Error('Existing consent cannot be replaced with a different selection.');
      return this.view(old);
    }
    await this.local.assertCurrent(copy(intent));
    const record = { version: 1, intent: copy(intent), phase: 'awaiting-consent', userConfirmed: false, confirmations: 0 };
    await this.journal.save(intent.intentId, record);
    return this.view(record); // Folder browsing/preparation grants nothing.
  }
  async confirm(intentId, { snapshotDigest, confirmation } = {}) {
    if (confirmation !== 'allow-shared-folders-v1') throw new Error('Use the displayed Allow read/write and connect button.');
    if (this.active.has(intentId)) {
      const active = this.active.get(intentId);
      if (active.digest !== snapshotDigest) throw new Error('A different consent snapshot is already being processed.');
      return active.work;
    }
    const work = this.run(intentId, snapshotDigest, true).finally(() => this.active.delete(intentId));
    this.active.set(intentId, { digest: snapshotDigest, work }); return work;
  }
  async resume(intentId) {
    if (this.active.has(intentId)) return this.active.get(intentId).work;
    const work = this.run(intentId, undefined, false).finally(() => this.active.delete(intentId));
    this.active.set(intentId, { digest: null, work }); return work;
  }
  async run(intentId, digest, isUserConfirmation) {
    const record = await this.journal.load(intentId);
    if (!record || record.phase === 'cancelled') throw new Error('No resumable consent.');
    const intent = record.intent;
    if (isUserConfirmation && digest !== intent.snapshotDigest) throw new Error('The displayed consent has changed.');
    await this.local.assertCurrent(copy(intent));
    if (!record.userConfirmed) {
      if (!isUserConfirmation) return this.view(record);
      // Persist the ONE human decision before any potentially uncertain network result.
      record.userConfirmed = true; record.confirmations = 1; record.phase = 'confirming';
      await this.journal.save(intentId, record);
    }
    try {
      let remote = matchReceipt(intent, await this.cloud.status(intentId));
      if (remote.phase === 'cancelled') throw new Error('Consent was cancelled remotely.');
      if (remote.phase === 'prepared') {
        await this.local.assertCurrent(copy(intent));
        const proof = await this.local.consentProof(copy(intent));
        remote = matchReceipt(intent, await this.cloud.confirm(intentId, intent.snapshotDigest, proof));
      }
      if (!['consented', 'active'].includes(remote.phase)) throw new Error('Consent has not been authenticated by the account service.');
      await this.local.assertCurrent(copy(intent));
      // Local activation is scoped to this connection, idempotent, and must not
      // upgrade global/legacy roots. It returns a proof only after durable save.
      const activationProof = await this.local.activate(copy(intent), copy(remote));
      if (remote.phase !== 'active') remote = matchReceipt(intent, await this.cloud.activate(intentId, intent.snapshotDigest, activationProof));
      if (remote.phase !== 'active') throw new Error('Connection activation not confirmed.');
      record.phase = 'connected'; record.error = null;
      await this.journal.save(intentId, record);
      return this.view(record);
    } catch (error) {
      record.phase = 'resume-required'; record.error = 'Connection outcome is not confirmed. Resume this attempt; do not select folders or consent again.';
      await this.journal.save(intentId, record);
      throw error; // Never translates an uncertain outcome to success or writes a probe.
    }
  }
  view(record) {
    return { intentId: record.intent.intentId, phase: record.phase, requiresConsent: !record.userConfirmed, confirmationCount: record.confirmations, connected: record.phase === 'connected', fileReadWriteVerified: false, error: record.error || null };
  }
}
