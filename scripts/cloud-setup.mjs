import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { Store, defaultStateDir, openBrowser } from '../src/agent/store.mjs';

const project = fileURLToPath(new URL('../', import.meta.url));
const configuration = path.join(project, 'wrangler.local.jsonc');
const wrangler = path.join(project, 'node_modules', 'wrangler', 'bin', 'wrangler.js');

export async function loadDeployment() {
  // The local deployment file is written as strict JSON, even with a .jsonc extension.
  const config = JSON.parse(await fs.readFile(configuration, 'utf8'));
  if (!/^[a-f0-9]{32}$/.test(config.account_id) || !/^chat2local-[a-z0-9-]{1,45}$/.test(config.name)) throw new Error('Invalid private deployment identity.');
  if (config.vars?.ALLOW_LOOPBACK || config.vars?.TEST_DIAGNOSTICS || config.observability?.enabled !== false) throw new Error('Refusing development flags or enabled payload logging in a public deployment.');
  return config;
}
export function canonicalOrigin(config) {
  const url = new URL(config.vars?.PUBLIC_ORIGIN);
  if (url.protocol !== 'https:' || url.pathname !== '/' || url.username || url.password || url.search || url.hash || url.hostname.endsWith('.invalid')) throw new Error('Configure the actual public HTTPS origin first.');
  return url.origin;
}
export async function publicCheck(config, request = fetch) {
  const origin = canonicalOrigin(config);
  const get = (route, options = {}) => request(`${origin}${route}`, { redirect: 'error', signal: AbortSignal.timeout(15_000), ...options });
  const health = await get('/healthz');
  if (!health.ok || (await health.json()).name !== 'chat2local-relay') throw new Error('Public relay health check failed.');
  const locked = await get('/mcp');
  if (locked.status !== 401 || !locked.headers.get('www-authenticate')?.includes('resource_metadata=')) throw new Error('MCP must require OAuth before connecting this computer.');
  const resource = await (await get('/.well-known/oauth-protected-resource/mcp')).json();
  const issuer = await (await get('/.well-known/oauth-authorization-server')).json();
  if (resource.resource !== `${origin}/mcp` || !resource.authorization_servers?.includes(origin) || issuer.issuer !== origin || !issuer.code_challenge_methods_supported?.includes('S256')) throw new Error('OAuth discovery, canonical issuer, or PKCE check failed.');
  const enrollment = await get('/enroll', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  if (enrollment.status !== 401) throw new Error('Device enrollment must require an operator key.');
  return { origin, mcpUrl: `${origin}/mcp`, authentication: 'OAuth', publicHealth: true, unauthenticatedMcpStatus: 401, enrollmentLocked: true, pkce: 'S256', websiteClientVerified: false };
}
const operatorStore = config => new Store(path.join(path.dirname(defaultStateDir()), 'Chat2LocalOperator', `${config.account_id}-${config.name}`));
function runWrangler(args, input = '') {
  return new Promise((resolve, reject) => {
    // Secret input stays on stdin; never in process arguments, console, or project files.
    const child = spawn(process.execPath, [wrangler, ...args], { cwd: project, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, WRANGLER_SEND_METRICS: 'false' } });
    let output = ''; const timer = setTimeout(() => { child.kill(); reject(new Error('Cloud command timed out. Verify its result before retrying.')); }, 90_000);
    const collect = data => { output = (output + data.toString()).slice(-32_000); };
    child.stdout.on('data', collect); child.stderr.on('data', collect);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', code => { clearTimeout(timer); code === 0 ? resolve() : reject(new Error(`Cloud command failed (${code}); no credential output was returned. Review Wrangler status locally.`)); });
    child.stdin.on('error', () => {}); child.stdin.end(input);
  });
}
export async function verifiedLocalSession(store = new Store(), request = fetch) {
  const session = await store.readSession();
  if (session.origin !== 'http://127.0.0.1:47631' || !/^[a-f0-9]{64}$/.test(session.token)) throw new Error('No valid default Chat2Local session. Launch the portable app first.');
  const response = await request(`${session.origin}/api/status`, { headers: { 'X-Chat2Local-Token': session.token }, signal: AbortSignal.timeout(4000), redirect: 'error' });
  const state = response.ok ? await response.json() : null;
  if (state?.name !== 'chat2local' || state.instanceId !== session.instanceId) throw new Error('Local instance could not be verified; no changes made.');
  return { session, state };
}
export async function run(mode) {
  const config = await loadDeployment();
  if (mode === 'onboarding') {
    await openBrowser(`https://dash.cloudflare.com/${config.account_id}/workers/onboarding`);
    console.log('Opened official Cloudflare Workers onboarding. Complete provider prompts yourself; no plan upgrade or terms acceptance is automated.');
    return;
  }
  if (mode === 'verify') { console.log(JSON.stringify(await publicCheck(config), null, 2)); return; }
  if (mode === 'install-secret') {
    // This command is deliberately explicit and separate from launch and verification.
    canonicalOrigin(config);
    const vault = operatorStore(config); const loaded = await vault.load();
    if (loaded.secrets.enrollmentKey) throw new Error('An operator key already exists locally. This command does not rotate or overwrite existing credentials.');
    const key = randomBytes(32).toString('hex');
    await vault.saveSecrets({ enrollmentKey: key, origin: canonicalOrigin(config), installation: 'pending' });
    await runWrangler(['secret', 'put', 'ENROLLMENT_KEY', '--config', configuration], key + '\n');
    await vault.saveSecrets({ enrollmentKey: key, origin: canonicalOrigin(config), installation: 'confirmed' });
    console.log('Enrollment key installed and stored with the local OS credential protection. Key was not printed or put in the repository.');
    return;
  }
  if (mode === 'connect-local') {
    const checked = await publicCheck(config);
    const { session, state } = await verifiedLocalSession();
    const sample = path.join(path.dirname(defaultStateDir()), 'Chat2LocalDemo').toLowerCase();
    if (state.roots.some(root => root.path.toLowerCase() !== sample)) throw new Error('This panel has non-demo folders authorized. Register the relay manually after reviewing these permissions; automatic enrollment refused.');
    if (state.relay && state.relay !== checked.origin) throw new Error('Another relay is configured. It will not be replaced.');
    if (!state.relay) {
      const { secrets } = await operatorStore(config).load();
      if (secrets.installation !== 'confirmed' || secrets.origin !== checked.origin || !/^[a-f0-9]{64}$/.test(secrets.enrollmentKey)) throw new Error('Confirmed operator key not available.');
      const response = await fetch(`${session.origin}/api/enroll`, { method: 'POST', headers: { Origin: session.origin, 'X-Chat2Local-Token': session.token, 'Content-Type': 'application/json' }, body: JSON.stringify({ origin: checked.origin, enrollmentToken: secrets.enrollmentKey }), redirect: 'error', signal: AbortSignal.timeout(25_000) });
      if (!response.ok) throw new Error(`Local enrollment failed (${response.status}); inspect the local panel.`);
    }
    await openBrowser(`${session.origin}/#${session.token}`);
    console.log('Public relay verified and this computer enrolled. Existing folder permissions are unchanged. Use Connect ChatGPT to bind this browser, then confirm in the ChatGPT authorization page; no copied pairing code is required.');
    return;
  }
  throw new Error('Usage: node scripts/cloud-setup.mjs onboarding|verify|install-secret|connect-local');
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) run(process.argv[2]).catch(error => { console.error(error.message); process.exitCode = 1; });
