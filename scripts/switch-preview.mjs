import path from 'node:path';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { Store, openBrowser } from '../src/agent/store.mjs';
import { localNetworkOnly } from '../src/agent/network.mjs';
import { sameDirectory } from '../src/agent/platform.mjs';
import { VERSION } from '../src/shared/protocol.mjs';
import { verifiedLocalSession } from './cloud-setup.mjs';
import { verifyPackage } from './install-portable.mjs';

const execute = promisify(execFile);
export function assertIdlePreview(state, expectedVersion) {
  if (state?.name !== 'chat2local' || state.version !== expectedVersion || state.bridge !== 'connected' || state.paused !== false) throw new Error('The expected connected preview was not found. No process was stopped.');
  if (!Array.isArray(state.roots) || state.roots.length !== 1 || state.roots[0].label !== 'Chat2LocalDemo') throw new Error('Only the isolated demo-folder preview may be switched by this helper.');
  if (!Array.isArray(state.pending) || state.pending.length || state.folderPickerActive || state.setupActive || (state.queuedOperations ?? 0) !== 0) throw new Error('The preview is busy. No process was stopped.');
  if (state.lastRemoteCallAt && Date.now() - Date.parse(state.lastRemoteCallAt) < 5000) throw new Error('The preview was used very recently. No process was stopped.');
}
export function preservedState(state) {
  return JSON.stringify({ paused: state.paused, startup: state.startup, relay: state.relay, mcpUrl: state.mcpUrl, network: state.networkSettings, hasRemoteUse: state.hasRemoteUse,
    roots: state.roots.map(root => ({ id: root.id, path: root.path, write: root.write, writeMode: root.writeMode })).sort((a, b) => a.id.localeCompare(b.id)) });
}
function portClosed() {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port: 47631 });
    socket.setTimeout(1000, () => { socket.destroy(); reject(new Error('Local port state is uncertain.')); });
    socket.once('connect', () => { socket.destroy(); resolve(false); });
    socket.once('error', error => { error.code === 'ECONNREFUSED' ? resolve(true) : reject(error); });
  });
}
export async function switchPreview(directory, expectedVersion, { showBrowser = true } = {}) {
  localNetworkOnly();
  const target = path.resolve(directory);
  await verifyPackage(target); // Exact manifest and host architecture, before touching the preview.
  const store = new Store();
  const before = await verifiedLocalSession(store);
  assertIdlePreview(before.state, expectedVersion);
  const demo = path.join(path.dirname(store.directory), 'Chat2LocalDemo');
  if (!await sameDirectory(before.state.roots[0].path, demo)) throw new Error('The authorized folder is not the known isolated demo directory.');
  const snapshot = preservedState(before.state);
  if (before.state.version === VERSION) return { switched: false, version: VERSION, message: 'Requested version is already running.' };
  const response = await fetch(`${before.session.origin}/api/shutdown`, { method: 'POST', headers: { Origin: before.session.origin, 'X-Chat2Local-Token': before.session.token, 'Content-Type': 'application/json' }, body: '{}', redirect: 'error', signal: AbortSignal.timeout(5000) });
  if (!response.ok || (await response.json()).ok !== true) throw new Error('Normal preview shutdown was not confirmed. No kill or forced replacement was attempted.');
  let closed = false;
  for (let i = 0; i < 40; i++) { if (await portClosed()) { closed = true; break; } await delay(200); }
  if (!closed) throw new Error('The old listener is still present. No new instance was started.');
  const executable = path.join(target, 'runtime', process.platform === 'win32' ? 'node.exe' : 'node');
  await execute(executable, [path.join(target, 'scripts', 'launch.mjs'), '--no-browser'], { timeout: 45000, windowsHide: true, maxBuffer: 65536 });
  let after;
  for (let i = 0; i < 25; i++) {
    after = await verifiedLocalSession(store);
    if (after.state.version !== VERSION || preservedState(after.state) !== snapshot) throw new Error('The new preview state did not match the old grants/settings. Inspect locally; no automatic re-enrollment was attempted.');
    if (after.state.bridge === 'connected') break;
    await delay(400);
  }
  if (after.state.bridge !== 'connected') throw new Error('New local preview started, but relay reconnection was not confirmed. Existing identity/settings were retained.');
  if (showBrowser) await openBrowser(`${after.session.origin}/#${after.session.token}`);
  return { switched: true, from: expectedVersion, version: after.state.version, connected: true, grantsAndSettingsPreserved: true, roots: after.state.roots.map(root => ({ id: root.id, label: root.label, writeMode: root.writeMode })), websiteClientVerified: false };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [flag, directory, expectedVersion] = process.argv.slice(2);
  if (flag !== '--live' || !directory || !/^0\.1\.0-alpha\.[0-9]+$/.test(expectedVersion || '') || process.argv.length !== 5) {
    console.error('Usage: switch-preview.mjs --live VERIFIED_PACKAGE_DIRECTORY EXPECTED_RUNNING_VERSION'); process.exitCode = 1;
  } else switchPreview(directory, expectedVersion).then(result => console.log(JSON.stringify(result, null, 2))).catch(error => { console.error(error.message); process.exitCode = 1; });
}
