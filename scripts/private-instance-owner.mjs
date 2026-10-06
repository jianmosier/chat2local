import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDeployment, canonicalOrigin } from './cloud-setup.mjs';
import { Store, defaultStateDir } from '../src/agent/store.mjs';
import { parseInstanceInvitation } from '../src/shared/instance-invitation.mjs';

/** Maintainer-only helper. The existing operator key stays in its OS-protected
 * vault and is used solely for this canonical instance's management endpoints.
 * The generated file contains a short-lived, one-device invitation, NOT that
 * operator key. No live setup flag, OAuth grant or folder is changed here.
 */
export async function ownerClient({ config, request = fetch, vault } = {}) {
  config ||= await loadDeployment();
  const origin = canonicalOrigin(config);
  if (config.vars?.PRIVATE_INSTANCE !== 'true' || config.vars?.ACCOUNT_CONNECTIONS === 'true') throw new Error('First review/enable private-instance mode on this deployment. Nothing was published or changed.');
  vault ||= new Store(path.join(path.dirname(defaultStateDir()), 'Chat2LocalOperator', `${config.account_id}-${config.name}`));
  const { secrets } = await vault.load();
  if (secrets.installation !== 'confirmed' || secrets.origin !== origin || !/^[a-f0-9]{64}$/.test(secrets.enrollmentKey || '')) throw new Error('Existing confirmed instance-operator credentials are unavailable. No other product credentials were used.');
  return async (action, input = {}) => {
    if (!['connections','invitations','revoke-invitation','installer-status','configure-installer'].includes(action)) throw new Error('Unsupported instance management action.');
    const route = action === 'installer-status' ? '/install/owner/status' : action === 'configure-installer' ? '/install/owner/configure' : '/instance/owner/' + action;
    const response = await request(origin + route, { method: 'POST', headers: { Authorization: 'Bearer ' + secrets.enrollmentKey, 'Content-Type': 'application/json' }, body: JSON.stringify(input), redirect: 'error', signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw new Error(`Instance management failed (${response.status}). No raw response or secret was displayed.`);
    return response.json();
  };
}
export async function writeInvitationFile(file, value) {
  if (!path.isAbsolute(file)) throw new Error('Choose an absolute output path outside the repository.');
  const parsed = parseInstanceInvitation(value.inviteUrl);
  if (!['connect','join'].includes(value.purpose) || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now()) throw new Error('Invalid invitation result.');
  const project = fileURLToPath(new URL('..', import.meta.url));
  const parent = await fs.realpath(path.dirname(file));
  const relative = path.relative(project, path.join(parent, path.basename(file)));
  if (!relative || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative))) throw new Error('Save the invitation outside the source repository.');
  const record = { version: 1, purpose: value.purpose, inviteUrl: value.inviteUrl, expiresAt: value.expiresAt };
  await fs.writeFile(file, JSON.stringify(record, null, 2), { flag: 'wx', mode: 0o600 });
  return { saved: true, file, origin: parsed.origin, purpose: record.purpose, expiresAt: record.expiresAt, operatorCredentialIncluded: false, foldersGranted: false };
}
async function cli(args) {
  const command = args.shift();
  if (!['list','connect','join','revoke'].includes(command)) throw new Error('Usage: private-instance-owner.mjs list | connect OUTPUT_FILE | join OUTPUT_FILE [CONNECTION_ID] | revoke INVITATION_ID');
  if ((command === 'list' && args.length) || (command === 'connect' && args.length !== 1) || (command === 'join' && ![1,2].includes(args.length)) || (command === 'revoke' && args.length !== 1)) throw new Error('Invalid private-instance command arguments.');
  const call = await ownerClient();
  if (command === 'list') return call('connections');
  if (command === 'revoke') return call('revoke-invitation', { invitationId: args[0] });
  const output = path.resolve(args[0]);
  try { await fs.lstat(output); throw new Error('Output already exists; no invitation was created.'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  let connectionId = args[1];
  if (command === 'join' && !connectionId) {
    const result = await call('connections');
    if (result.connections.length !== 1) throw new Error('Choose an exact connection from the owner list; none was guessed.');
    connectionId = result.connections[0].connectionId;
  }
  const value = await call('invitations', { purpose: command, ...(connectionId ? { connectionId } : {}) });
  return writeInvitationFile(output, value);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) cli(process.argv.slice(2)).then(value => console.log(JSON.stringify(value, null, 2))).catch(error => { console.error(error.message); process.exitCode = 1; });
