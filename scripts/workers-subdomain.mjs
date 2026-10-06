import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDeployment } from './cloud-setup.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const validName = value => typeof value === 'string' && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value);

// Use Wrangler's supported authentication command. Capture its output in memory;
// never print credentials, copy the credential file, or include secrets in argv.
async function authorizedToken() {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(root, 'node_modules/wrangler/bin/wrangler.js'), 'auth', 'token', '--json', '--config', path.join(root, 'wrangler.local.jsonc')], {
      cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, WRANGLER_SEND_METRICS: 'false', NO_COLOR: '1' },
    });
    let output = ''; let settled = false;
    const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); output = ''; error ? reject(error) : resolve(value); };
    const timer = setTimeout(() => { child.kill(); finish(new Error('Wrangler authentication lookup timed out.')); }, 30_000);
    child.stdout.on('data', data => { output += data; if (output.length > 24_000) { child.kill(); finish(new Error('Unexpected authentication output; discarded.')); } });
    child.stderr.on('data', () => {});
    child.once('error', () => finish(new Error('Could not start the installed Wrangler.')));
    child.once('close', code => {
      if (settled) return;
      if (code !== 0) return finish(new Error('Wrangler authentication is not available. Use its normal login flow.'));
      try {
        const result = JSON.parse(output);
        if (!['oauth', 'api_token'].includes(result.type) || typeof result.token !== 'string' || result.token.length < 20 || /[\r\n]/.test(result.token)) throw new Error();
        finish(null, result.token);
      } catch { finish(new Error('Unsupported authentication output; no credentials displayed.')); }
    });
  });
}

export async function ensureSubdomain({ accountId, token, mode = 'status', name }, request = fetch) {
  if (!/^[a-f0-9]{32}$/.test(accountId) || !['status', 'register'].includes(mode)) throw new Error('Invalid account or mode.');
  if (mode === 'register' && !validName(name)) throw new Error('Invalid requested subdomain.');
  const endpoint = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/subdomain`;
  const call = async method => {
    let response;
    try {
      response = await request(endpoint, {
        method, redirect: 'error', signal: AbortSignal.timeout(20_000),
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        ...(method === 'PUT' ? { body: JSON.stringify({ subdomain: name }) } : {}),
      });
    } catch { throw new Error(`Cloudflare ${method} did not return a confirmed result. Check status before retrying; no automatic replay.`); }
    let value;
    try { value = await response.json(); } catch { throw new Error('Cloudflare returned an unreadable response.'); }
    const codes = Array.isArray(value.errors) ? value.errors.map(e => Number(e.code)).filter(Number.isFinite) : [];
    if (response.ok && value.success === true && validName(value.result?.subdomain)) return value.result.subdomain;
    if (method === 'GET' && response.status === 404 && codes.includes(10007)) return null;
    // Wrangler uses code 10007 for a missing account subdomain; some API versions return 400.
    if (method === 'GET' && response.status === 400 && codes.includes(10007)) return null;
    throw new Error(`Cloudflare ${method} refused (HTTP ${response.status}; codes ${codes.join(',') || 'none'}). No fallback mutation was attempted.`);
  };
  const existing = await call('GET');
  if (existing) return { registered: true, subdomain: existing, changed: false };
  if (mode === 'status') return { registered: false, subdomain: null, changed: false };
  const created = await call('PUT');
  if (created !== name) throw new Error('Creation response differs from the requested name. Stop and verify account state.');
  const verified = await call('GET');
  if (verified !== name) throw new Error('Creation was accepted, but readback is not confirmed. Do not retry the registration blindly.');
  return { registered: true, subdomain: verified, changed: true };
}

export async function run(args = process.argv.slice(2)) {
  const [mode, name, ...extra] = args;
  if (extra.length || !['status', 'register'].includes(mode) || (mode === 'status' && name)) throw new Error('Usage: node scripts/workers-subdomain.mjs status | register <name>');
  const config = await loadDeployment();
  const token = await authorizedToken();
  const result = await ensureSubdomain({ accountId: config.account_id, token, mode, name });
  console.log(JSON.stringify({ ...result, ...(result.subdomain ? { proposedMcpUrl: `https://${config.name}.${result.subdomain}.workers.dev/mcp` } : {}), workerDeploymentVerified: false }, null, 2));
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) run().catch(error => { console.error(error.message); process.exitCode = 1; });
