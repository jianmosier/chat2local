import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Store, openBrowser } from '../src/agent/store.mjs';
import { localNetworkOnly } from '../src/agent/network.mjs';
import { parseInstanceInvitation } from '../src/shared/instance-invitation.mjs';

export async function readInstanceFile(file, { now = Date.now(), allowLocal = false } = {}) {
  if (typeof file !== 'string' || !path.isAbsolute(file)) throw new Error('Select the absolute path of the private invitation file.');
  let value;
  try {
    const stat = await fs.lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 16384) throw new Error('invalid file');
    value = JSON.parse(await fs.readFile(file, 'utf8'));
  } catch { throw new Error('Invitation file is missing, unsafe or invalid. Its contents were not displayed.'); }
  if (!value || value.version !== 1 || !['connect','join'].includes(value.purpose) || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= now || Object.keys(value).some(k => !['version','purpose','inviteUrl','expiresAt'].includes(k))) throw new Error('Invitation is expired or has an unsupported format.');
  const parsed = parseInstanceInvitation(value.inviteUrl, allowLocal);
  return { ...value, ...parsed };
}
export async function joinInstance(file, options = {}) {
  return joinInvitation(await readInstanceFile(file, { allowLocal: options.allowLocal === true }), options);
}

/** In-memory import used by the independent installer. No invitation file needs
 * to be created or transferred by a user or a different computer. */
export async function joinInvitation(value, options = {}) {
  if (!value || !['connect','join'].includes(value.purpose) || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now()) throw new Error('Installer invitation expired or is invalid.');
  const invitation = { ...value, ...parseInstanceInvitation(value.inviteUrl, options.allowLocal === true) };
  localNetworkOnly();
  if (options.launch) await options.launch();
  else await promisify(execFile)(process.execPath, [fileURLToPath(new URL('./launch.mjs', import.meta.url)), '--no-browser'], { timeout: 20000, windowsHide: true, maxBuffer: 8192 });
  const store = options.store || new Store();
  const session = await store.readSession();
  const expectedOrigin = options.localOrigin || 'http://127.0.0.1:47631';
  const local = new URL(expectedOrigin);
  if (local.protocol !== 'http:' || local.hostname !== '127.0.0.1' || local.pathname !== '/' || local.search || local.hash || local.username || local.password || session.origin !== expectedOrigin || !/^[a-f0-9]{64}$/.test(session.token)) throw new Error('No verified local Chat2Local instance; no invitation was sent.');
  const request = options.request || fetch;
  const headers = { 'X-Chat2Local-Token': session.token };
  const check = await request(expectedOrigin + '/api/status', { headers, redirect: 'error', signal: AbortSignal.timeout(4000) });
  const state = check.ok ? await check.json() : null;
  if (state?.name !== 'chat2local' || state.instanceId !== session.instanceId) throw new Error('Local instance identity did not match; no invitation was sent.');
  const response = await request(expectedOrigin + '/api/instance/import-invitation', { method: 'POST', headers: { ...headers, Origin: expectedOrigin, 'Content-Type': 'application/json' }, body: JSON.stringify({ url: invitation.inviteUrl }), redirect: 'error', signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw new Error(`Local invitation import failed (${response.status}); existing identity/permissions were not replaced.`);
  const imported = await response.json();
  if (imported.imported !== true || imported.origin !== invitation.origin) throw new Error('Local import outcome did not match the selected instance.');
  if (invitation.purpose === 'join') await (options.openBrowser || openBrowser)(invitation.inviteUrl);
  return { imported: true, purpose: invitation.purpose, mcpUrl: invitation.origin + '/mcp', waitingFor: invitation.purpose === 'join' ? 'folder-selection-and-one-consent' : 'initial-original-plugin-connection', foldersGranted: false };
}
if (import.meta.main) {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--invitation-file') { console.error('Usage: node scripts/join-instance.mjs --invitation-file ABSOLUTE_PRIVATE_FILE'); process.exitCode = 1; }
  else joinInstance(path.resolve(args[1])).then(value => {
    console.log(JSON.stringify(value, null, 2));
    if (value.purpose === 'connect') console.log('Use this MCP address for the original ChatGPT plugin. OAuth will continue to this computer; no Google login is required.');
  }).catch(error => { console.error(error.message); process.exitCode = 1; });
}
