import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { Store, defaultStateDir } from '../src/agent/store.mjs';
import { relayOrigin, VERSION } from '../src/shared/protocol.mjs';
import { buildPortable } from './build-portable.mjs';
import { installPortable } from './install-portable.mjs';
import { joinInvitation } from './join-instance.mjs';
import { passwordSetup } from './setup-installer-password.mjs';
import { ensureSubdomain } from './workers-subdomain.mjs';

const project = fileURLToPath(new URL('..', import.meta.url));
const configuration = path.join(project, 'wrangler.local.jsonc');
export function deploymentPlan({ accountId, subdomain, name, namespaceId }) {
  if (!/^[a-f0-9]{32}$/.test(accountId || '') || !/^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/.test(subdomain || '') || !/^chat2local-[a-f0-9]{12}$/.test(name || '') || !/^[a-f0-9]{32}$/.test(namespaceId || '')) throw Error('Invalid generated private deployment.');
  return { name, account_id: accountId, main: 'src/relay/worker.mjs', compatibility_date: '2026-09-18', compatibility_flags: ['global_fetch_strictly_public'], workers_dev: true, preview_urls: false, vars: { PUBLIC_ORIGIN: `https://${name}.${subdomain}.workers.dev`, PRIVATE_INSTANCE: 'true', MULTI_DEVICE: 'true', CUSTOM_CONNECTOR_ENABLED: 'true', DEVELOPER_HANDOFF: 'true', PUBLIC_BOOTSTRAP_URL: `https://raw.githubusercontent.com/jianmosier/chat2local/v${VERSION}/install.sh` }, kv_namespaces: [{ binding: 'OAUTH_KV', id: namespaceId }], durable_objects: { bindings: [{ name: 'DEVICES', class_name: 'Device' }, { name: 'REGISTRY', class_name: 'Registry' }] }, exports: { Device: { type: 'durable-object', storage: 'sqlite' }, Registry: { type: 'durable-object', storage: 'sqlite' } }, observability: { enabled: false } };
}
async function command(file, args, { input, visible = false, timeout = 300000, env = process.env } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { cwd: project, windowsHide: true, env: { ...env, WRANGLER_SEND_METRICS: 'false', NO_COLOR: '1', NODE_USE_ENV_PROXY: '1' }, stdio: visible ? 'inherit' : ['pipe','pipe','pipe'] });
    let output = '', timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeout);
    if (!visible) {
      child.stdout.on('data', bytes => { output += bytes; if (output.length > 1024 * 1024) child.kill(); });
      child.stderr.on('data', () => {}); child.stdin.on('error', () => {}); child.stdin.end(input || '');
    }
    child.once('error', () => { clearTimeout(timer); reject(Error('Cannot start the setup subprocess.')); });
    child.once('close', code => { clearTimeout(timer); if (code === 0 && !timedOut) resolve(output); else reject(Error(timedOut ? 'Setup timed out. Verify the recorded step before retrying.' : 'Setup command did not complete; existing configuration was retained.')); });
  });
}
const wrangler = (args, options) => command(process.execPath, ['--use-env-proxy', path.join(project, 'node_modules/wrangler/bin/wrangler.js'), ...args], options);
export async function npmEntry() {
  const candidates = [process.env.CHAT2LOCAL_NPM_CLI, process.env.npm_execpath, path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'), path.resolve(path.dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js')].filter(Boolean);
  for (const candidate of candidates) { try { if ((await fs.stat(candidate)).isFile() && path.basename(candidate) === 'npm-cli.js') return candidate; } catch { /* Try the runtime's next standard npm location. */ } }
  throw Error('The bootstrap runtime must include npm for cloud setup. Use the public bootstrap, not an unrelated Node executable.');
}
async function save(file, value) { const temp = file + '.next'; await fs.writeFile(temp, JSON.stringify(value, null, 2), { mode: 0o600 }); await fs.rename(temp, file); }
async function localPackage() {
  const target = `${process.platform}-${process.arch}`;
  const name = `Chat2Local-${target}-public`;
  const directory = path.join(project, 'dist', name);
  try { await fs.stat(directory); } catch (error) { if (error.code !== 'ENOENT') throw error; await buildPortable(name, target); }
  return installPortable(directory, { noBrowser: true });
}
async function startNative(installed, args) {
  return command(path.join(installed.directory, 'runtime', process.platform === 'win32' ? 'node.exe' : 'node'), [path.join(installed.directory, 'scripts', 'install-from-instance.mjs'), ...args], { visible: true, timeout: 720000 });
}
export async function setup(args = process.argv.slice(2)) {
  if (args.includes('--help')) { console.log('chat2local setup: no arguments creates YOUR Cloudflare instance; --instance HTTPS_ORIGIN joins an existing instance. Re-running on a connected computer opens folder management.'); return; }
  if (args.length && (args.length !== 2 || args[0] !== '--instance')) throw Error('Use --instance HTTPS_ORIGIN, or no arguments.');
  if (typeof process.getuid === 'function' && process.getuid() === 0) throw Error('Run without sudo/root.');
  const store = new Store(), loaded = await store.load();
  const joinOrigin = args.length ? relayOrigin(args[1]) : loaded.secrets.identity?.origin;
  if (loaded.config.paused || (joinOrigin && loaded.secrets.identity && loaded.secrets.identity.origin !== joinOrigin)) throw Error('This computer is paused or belongs to a different instance. Its identity was not replaced.');
  if (joinOrigin) { const installed = await localPackage(); await startNative(installed, ['--connect', joinOrigin]); return; }
  // New self-hosting is explicit and separate from adding folders or devices.
  if (!process.stdin.isTTY) throw Error('Run setup in an interactive terminal for your cloud account authorization.');
  const readline = createInterface({ input: process.stdin, output: process.stdout });
  try {
    try { await fs.stat(path.join(project, 'node_modules/wrangler/bin/wrangler.js')); }
    catch { console.log('Installing pinned setup dependencies locally...'); await command(process.execPath, [await npmEntry(), 'ci', '--ignore-scripts', '--no-audit', '--no-fund'], { visible: true }); }
    let who;
    try { who = JSON.parse(await wrangler(['whoami','--json'])); }
    catch { console.log('Sign in to YOUR Cloudflare account in the browser. No password or token is copied into ChatGPT.'); await wrangler(['login'], { visible: true }); who = JSON.parse(await wrangler(['whoami','--json'])); }
    if (!who.loggedIn || !Array.isArray(who.accounts) || !who.accounts.length) throw Error('No authorized Cloudflare account is available.');
    let account = who.accounts[0];
    if (who.accounts.length > 1) { who.accounts.forEach((a, i) => console.log(`${i + 1}. ${a.name}`)); const choice = Number(await readline.question('Choose your Cloudflare account number: ')); account = who.accounts[choice - 1]; if (!account) throw Error('No account selected.'); }
    const directory = path.join(project, '.artifacts'); await fs.mkdir(directory, { recursive: true });
    const stateFile = path.join(directory, 'selfhost-setup.json');
    let state;
    try { state = JSON.parse(await fs.readFile(stateFile, 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (state && state.accountId !== account.id) throw Error('Setup belongs to another cloud account; it was not replaced.');
    if (!state) {
      try { await fs.stat(configuration); throw Error('A deployment already exists here. It will not be overwritten by new-instance setup.'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
      const accepted = await readline.question('Create a private chat2local Worker and OAuth storage in this account? Provider quotas/costs apply. [y/N] ');
      if (!/^y(es)?$/i.test(accepted.trim())) { console.log('Cancelled. No cloud resource created.'); return; }
      state = { accountId: account.id, name: 'chat2local-' + randomBytes(6).toString('hex') }; await save(stateFile, state);
    }
    const authorization = JSON.parse(await wrangler(['auth','token','--json']));
    if (!['oauth','api_token'].includes(authorization.type) || typeof authorization.token !== 'string') throw Error('Unsupported official cloud authentication.');
    const cloud = async (method, route, body) => {
      const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${account.id}/${route}`, { method, headers: { Authorization: `Bearer ${authorization.token}`, 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}), redirect: 'error', signal: AbortSignal.timeout(30000) });
      const result = await response.json(); if (!response.ok || result.success !== true) throw Error(`Cloud request failed (${response.status}); no automatic mutation retry.`); return result.result;
    };
    let domain = await ensureSubdomain({ accountId: account.id, token: authorization.token });
    if (!domain.registered) {
      const name = (await readline.question('Choose your account workers.dev subdomain (one-time provider setting): ')).trim();
      domain = await ensureSubdomain({ accountId: account.id, token: authorization.token, mode: 'register', name });
    }
    state.subdomain = domain.subdomain; await save(stateFile, state);
    if (!state.namespaceId) {
      const title = state.name + '-oauth'; const found = [];
      for (let page = 1; page <= 10; page++) { const batch = await cloud('GET', `storage/kv/namespaces?per_page=100&page=${page}`); found.push(...batch.filter(n => n.title === title)); if (batch.length < 100) break; if (page === 10) throw Error('Namespace listing is incomplete; no new namespace was created.'); }
      if (found.length > 1) throw Error('Ambiguous setup storage; no namespace was guessed.');
      const namespace = found[0] || await cloud('POST', 'storage/kv/namespaces', { title }); state.namespaceId = namespace.id; await save(stateFile, state);
    }
    const config = deploymentPlan(state); await save(configuration, config);
    const vault = new Store(path.join(path.dirname(defaultStateDir()), 'Chat2LocalOperator', `${config.account_id}-${config.name}`));
    const previous = await vault.load();
    const key = previous.secrets.enrollmentKey || randomBytes(32).toString('hex');
    if (previous.secrets.origin && previous.secrets.origin !== config.vars.PUBLIC_ORIGIN) throw Error('Operator vault belongs to another instance.');
    await vault.saveSecrets({ ...previous.secrets, enrollmentKey: key, origin: config.vars.PUBLIC_ORIGIN, installation: previous.secrets.installation || 'pending' });
    console.log('Deploying your private gateway...');
    await wrangler(['deploy','--config',configuration], { visible: true });
    if (previous.secrets.installation !== 'confirmed') await wrangler(['secret','put','ENROLLMENT_KEY','--config',configuration], { input: key + '\n' });
    await vault.saveSecrets({ ...previous.secrets, enrollmentKey: key, origin: config.vars.PUBLIC_ORIGIN, installation: 'confirmed' });
    const installed = await localPackage();
    const response = await fetch(config.vars.PUBLIC_ORIGIN + '/instance/owner/invitations', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + key }, body: JSON.stringify({ purpose: 'connect', ttlSeconds: 900, scopes: ['files:read','files:write','files:propose'] }), redirect: 'error', signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw Error('Initial device setup could not be prepared. Do not repeat folder authorization.');
    const invitation = await response.json();
    await joinInvitation({ version: 1, purpose: 'connect', inviteUrl: invitation.inviteUrl, expiresAt: invitation.expiresAt }, { launch: async () => {}, openBrowser: async () => {} });
    console.log(`Add ONE chat2local app in ChatGPT using this MCP endpoint:\n${config.vars.PUBLIC_ORIGIN}/mcp`);
    console.log('Then choose your folders in the local authorization page. No Google login or manual invitation file is required.');
    console.log(`Daily management entry: ${installed.managementEntry}`);
    await passwordSetup();
  } finally { readline.close(); }
}
if (import.meta.main) setup().catch(error => { console.error(error.message); process.exitCode = 1; });
