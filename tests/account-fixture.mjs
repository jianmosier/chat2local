import { AccountIdentity, AccountRepository } from '../src/relay/account-identity.mjs';
import { AccountDirectory } from '../src/relay/account-directory.mjs';
import { randomSecret } from '../src/shared/protocol.mjs';

/** Isolated storage and identity fixtures. Not a production login/verifier. */
export class TransactionalMemory {
  constructor() { this.data = new Map(); this.tail = Promise.resolve(); }
  async get(key) { return structuredClone(this.data.get(key)); }
  transaction(fn) {
    const result = this.tail.then(async () => {
      const draft = structuredClone(this.data);
      const tx = { get: async key => structuredClone(draft.get(key)), put: async (key, value) => { draft.set(key, structuredClone(value)); }, delete: async key => draft.delete(key) };
      const value = await fn(tx); this.data = draft; return structuredClone(value);
    });
    this.tail = result.catch(() => {}); return result;
  }
}
export async function accountFixture() {
  let now = Date.now();
  const sessions = new Map(), proofs = new Map();
  const storage = new TransactionalMemory();
  const identity = new AccountIdentity({ now: () => now, verifySession: async request => sessions.get(request.headers.get('Fixture-Session')) || null });
  const directory = new AccountDirectory(storage, { now: () => now, verifyDeviceConsent: async ({ proof, intent }) => {
    const value = proofs.get(proof);
    return value?.intentId === intent.id ? structuredClone(value) : null;
  } });
  const repository = new AccountRepository(command => directory.execute(command));
  const login = async (subject = 'alice', issuer = 'https://identity.example.test', sessionId = randomSecret()) => {
    const token = randomSecret();
    sessions.set(token, { issuer, subject, sessionId, expiresAt: now + 172800000, displayName: 'Fixture account' });
    return identity.authenticate(new Request('https://relay.example.test/account', { headers: { 'Fixture-Session': token } }));
  };
  const principal = await login(); const account = await repository.act(principal, 'account');
  const prepare = async (changes = {}, owner = principal) => {
    const input = { intentId: crypto.randomUUID().replaceAll('-', ''), connectionId: null, clientId: 'fixture-chatgpt', resource: 'https://relay.example.test/mcp', deviceId: 'a'.repeat(32), deviceEpoch: 'b'.repeat(64), roots: [{ rootId: 'project-root', mode: 'direct' }], scopes: ['files:read', 'files:write'], policyDigest: 'c'.repeat(64), requestDigest: randomSecret(), ...changes };
    return { input, intent: await repository.act(owner, 'prepare', input) };
  };
  const proof = (intent, phase) => {
    const token = randomSecret();
    proofs.set(token, { intentId: intent.intentId, deviceId: intent.deviceId, deviceEpoch: intent.deviceEpoch, snapshotDigest: intent.snapshotDigest, phase });
    return token;
  };
  const confirm = (intent, owner = principal) => repository.act(owner, 'confirm', { intentId: intent.intentId, snapshotDigest: intent.snapshotDigest, proof: proof(intent, 'consented') });
  const activate = (intent, owner = principal) => repository.act(owner, 'activate', { intentId: intent.intentId, snapshotDigest: intent.snapshotDigest, proof: proof(intent, 'activated') });
  return { storage, directory, identity, repository, login, principal, account, prepare, proof, confirm, activate, tick: ms => { now += ms; } };
}
