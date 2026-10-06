import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { Store, openBrowser } from '../src/agent/store.mjs';
import { NetworkManager } from '../src/agent/network.mjs';
import { platformInfo } from '../src/agent/platform.mjs';
import { relayOrigin, readLimited } from '../src/shared/protocol.mjs';
import { installPortable } from './install-portable.mjs';
import { joinInvitation } from './join-instance.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/** Runs on the NEW computer. Only this computer and its private relay are used;
 * there is no RPC to an already paired computer or owner-vault lookup. The
 * installer proof reaches its own browser by fragment, the polling proof never
 * reaches a browser. The invitation stays in memory and the agent's vault.
 */
export async function connectFromInstance(origin, options = {}) {
  origin = relayOrigin(origin, options.allowLocal === true);
  const store = options.store || new Store();
  const loaded = await store.load();
  if (loaded.config.paused || (loaded.secrets.identity && loaded.secrets.identity.origin !== origin)) throw new Error('Local access is paused or belongs to another private instance; it was not replaced.');
  const network = options.network || new NetworkManager(() => loaded.config.network, { allowLocal: options.allowLocal === true });
  const request = options.request || fetch;
  const call = async (action, input) => {
    // Import uses the loopback dispatcher; explicitly prepare the cloud route
    // again before every subsequent request. No global proxy settings change.
    await network.prepare(origin, true);
    let response;
    try { response = await request(origin + '/install/' + action, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Chat2Local-Installer': '1' }, body: JSON.stringify(input), redirect: 'error', signal: AbortSignal.timeout(15000) }); }
    catch { throw Object.assign(new Error('The private installer service is temporarily unreachable.'), { retryable: true }); }
    const result = JSON.parse(await readLimited(response, 16384));
    if (!response.ok) throw Object.assign(new Error(result.error || 'Installer request was rejected.'), { retryable: response.status >= 500 });
    return result;
  };
  const retry = async (action, input) => {
    for (let attempt = 0; ; attempt++) {
      try { return await call(action, input); }
      catch (error) { if (!error.retryable || attempt >= 2) throw error; await sleep(700 * (attempt + 1)); }
    }
  };
  const id = randomUUID().replaceAll('-', ''), secret = randomBytes(32).toString('hex'), browser = randomBytes(32).toString('hex');
  const started = await retry('start', { id, claimHash: hash(secret), browserHash: hash(browser), name: platformInfo().name || 'New computer' });
  if (started.id !== id || !Number.isSafeInteger(started.until) || started.until <= Date.now()) throw new Error('Installer response did not match this computer.');
  await (options.openBrowser || openBrowser)(origin + '/install#' + id + '.' + browser);
  const deadline = Math.min(started.until, Date.now() + 600000);
  while (Date.now() < deadline) {
    const value = await retry('claim', { id, secret });
    if (!value.waiting) {
      const imported = await joinInvitation(value, { store, allowLocal: options.allowLocal === true, ...(options.localOrigin ? { localOrigin: options.localOrigin } : {}), ...(options.localRequest ? { request: options.localRequest } : {}), launch: async () => {}, openBrowser: async () => {} });
      if (!imported.imported || imported.purpose !== 'join' || imported.mcpUrl !== origin + '/mcp') throw new Error('Local import did not match the intended instance.');
      await retry('ready', { id, secret });
      return { imported: true, browserContinuesAutomatically: true, waitingFor: 'choose-folder-and-confirm-once', foldersGranted: false };
    }
    await sleep(options.pollMs || 1500);
  }
  throw new Error('Installer login timed out. Existing computers and folder grants were not changed.');
}
async function cli(args) {
  if (args.length !== 2 || !['--install','--connect'].includes(args[0])) throw new Error('Usage: install-from-instance.mjs --install|--connect PRIVATE_HTTPS_ORIGIN');
  const origin = relayOrigin(args[1]);
  if (typeof process.getuid === 'function' && process.getuid() === 0) throw new Error('Run as your desktop user, without sudo/root.');
  if (args[0] === '--install') {
    console.log('chat2local: verifying package and installing to this computer...');
    const installed = await installPortable(fileURLToPath(new URL('..', import.meta.url)), { noBrowser: true });
    const node = path.join(installed.directory, 'runtime', process.platform === 'win32' ? 'node.exe' : 'node');
    // Never keep the application executing from the temporary download directory.
    // Stream status immediately; buffering stdout hid the browser/login step for minutes.
    await new Promise((resolve, reject) => {
      const child = spawn(node, [path.join(installed.directory, 'scripts/install-from-instance.mjs'), '--connect', origin], { stdio: 'inherit', windowsHide: true });
      let timedOut = false;
      const timer = setTimeout(() => { timedOut = true; child.kill(); }, 660000);
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('close', (code, signal) => {
        clearTimeout(timer);
        if (code === 0 && !timedOut) resolve();
        else reject(new Error(timedOut ? 'Installer login timed out; existing file permissions were retained.' : `Installer connection did not complete (${signal || code}). See the message above.`));
      });
    });
    return;
  }
  const existing = await new Store().load();
  if (existing.secrets.identity?.origin === origin && (existing.config.roots.length || existing.config.accountRoots?.length || existing.config.managedConnections?.length)) {
    console.log('Opening folder management for this connected computer. No installer login or re-pairing is required.');
    await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [fileURLToPath(new URL('./launch.mjs', import.meta.url)), '--manage'], { stdio: 'inherit', windowsHide: true });
      child.once('error', reject); child.once('close', code => code === 0 ? resolve() : reject(new Error('The local management launcher did not complete.')));
    });
    return;
  }
  console.log('Opening this instance\'s installation page on THIS computer. No existing computer needs to be online.');
  console.log(JSON.stringify(await connectFromInstance(origin), null, 2));
}
// Node >=24.14 is required. Native entry detection works through /var -> /private/var
// and other directory aliases; comparing argv spelling to a resolved ESM URL does not.
if (import.meta.main) cli(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
