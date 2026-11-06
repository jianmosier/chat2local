import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import os from 'node:os';
import { packageEntries, writeTarGz } from './archive.mjs';
import { VERSION } from '../src/shared/protocol.mjs';
import { isPrivatePublicationPath } from './public-path-policy.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export const excludedScripts = new Set(['build-mac-codex-handoff.mjs', 'export-mac-handoff.mjs', 'stage-mac-handoff.mjs', 'publish-public.mjs']);
// Public product documentation has one source; internal notes are not exported.
export const publicDocuments = Object.freeze(['README.md']);
// Explicit Rust source inventory: no target caches, local Cargo config or binaries.
export const rustSourceFiles = Object.freeze([
  'Cargo.toml', 'Cargo.lock',
  'crates/oidc-token-core/Cargo.toml', 'crates/oidc-token-core/src/lib.rs', 'crates/oidc-token-core/src/value.rs', 'crates/oidc-token-core/src/verify.rs', 'crates/oidc-token-core/src/tests.rs',
  'crates/oidc-token-wasm/Cargo.toml', 'crates/oidc-token-wasm/src/lib.rs',
  'crates/oidc-decision-core/Cargo.toml', 'crates/oidc-decision-core/src/lib.rs', 'crates/oidc-decision-core/src/tests.rs',
  'crates/oidc-decision-wasm/Cargo.toml', 'crates/oidc-decision-wasm/src/lib.rs',
  'crates/oauth-compat-core/Cargo.toml', 'crates/oauth-compat-core/src/lib.rs', 'crates/oauth-compat-core/src/value.rs', 'crates/oauth-compat-core/src/tests.rs',
  'crates/oauth-compat-core/LICENSE.oauth-provider.txt', 'crates/oauth-compat-core/src/provider/mod.rs', 'crates/oauth-compat-core/src/provider/value.rs', 'crates/oauth-compat-core/src/provider/runtime.rs', 'crates/oauth-compat-core/src/provider/operations.rs',
  'crates/oauth-compat-core/src/provider/operations/client.rs', 'crates/oauth-compat-core/src/provider/operations/grant.rs', 'crates/oauth-compat-core/src/provider/operations/token.rs',
  'crates/oauth-compat-wasm/Cargo.toml', 'crates/oauth-compat-wasm/src/lib.rs',
  'crates/native-agent/Cargo.toml', 'crates/native-agent/src/main.rs',
  'crates/agent-controller/src/native.rs', 'crates/agent-controller/src/ui.rs', 'crates/agent-controller/src/consent.rs', 'crates/agent-controller/src/guide.rs',
  'crates/agent-controller/ui/index.html', 'crates/agent-controller/ui/panel.js', 'crates/agent-controller/ui/panel.css',
  'crates/agent-controller/ui/recovery.js', 'crates/agent-controller/src/workflow.rs', 'crates/agent-controller/src/workflow_value.rs', 'crates/agent-controller/src/onboarding.rs', 'crates/agent-controller/src/sharing.rs', 'crates/agent-controller/src/setup.rs',
  'crates/agent-controller/Cargo.toml',
  'crates/agent-controller/src/lib.rs',
  'crates/agent-controller/src/bridge.rs',
  'crates/agent-controller/src/controller.rs',
  'crates/agent-controller/src/fixture.rs',
  'crates/agent-controller/src/persistence.rs',
  'crates/agent-controller/src/runtime.rs',
  'crates/agent-controller/src/tools.rs',
  'crates/agent-controller/src/operations.rs',
  'crates/agent-controller/src/terminal.rs', 'crates/agent-controller/src/network.rs', 'crates/agent-controller/src/network_query.rs',
  'crates/agent-controller/src/value.rs',
  'crates/agent-controller/src/owner.rs', 'crates/agent-controller/src/platform.rs', 'crates/agent-platform/src/windows_shell.rs',
  'crates/agent-controller/src/management.rs',
  'crates/agent-controller/src/http.rs',
  'crates/agent-controller-fixture/Cargo.toml',
  'crates/agent-controller-fixture/src/main.rs',
  'crates/agent-platform/src/windows_owner.rs',
  'crates/agent-platform/src/windows_adapters.rs',
  'crates/agent-platform/src/windows_control_pipe.rs',
  'crates/native-store/src/write_fence.rs',
  'crates/agent-transport/Cargo.toml', 'crates/agent-transport/src/lib.rs', 'crates/agent-transport/src/policy.rs', 'crates/agent-transport/src/tls.rs', 'crates/agent-transport/src/transport.rs',
  'crates/agent-transport/data/node-24.21.0-roots.pem', 'crates/agent-transport/data/node-24.21.0-policy.json',
  'crates/agent-transport-fixture/Cargo.toml', 'crates/agent-transport-fixture/src/main.rs',
  'crates/native-store/Cargo.toml', 'crates/native-store/src/lib.rs', 'crates/native-store/src/codec.rs', 'crates/native-store/src/fs.rs', 'crates/native-store/src/location.rs', 'crates/native-store/src/tests.rs',
  'crates/native-store-fixture/Cargo.toml', 'crates/native-store-fixture/src/main.rs', 'crates/agent-platform/src/windows_dpapi.rs',
  'crates/js-value-compat/Cargo.toml', 'crates/js-value-compat/src/lib.rs', 'crates/js-value-compat/src/parse.rs', 'crates/js-value-compat/src/stringify.rs',
  'crates/js-value-compat-fixture/Cargo.toml', 'crates/js-value-compat-fixture/src/lib.rs', 'crates/js-value-compat-fixture/src/main.rs',
  'crates/protocol/Cargo.toml', 'crates/protocol/src/lib.rs',
  'crates/policy/Cargo.toml', 'crates/policy/src/lib.rs',
  'crates/agent-platform/Cargo.toml', 'crates/agent-platform/src/lib.rs', 'crates/agent-platform/src/windows.rs',
  'crates/readonly/Cargo.toml', 'crates/readonly/src/main.rs',
  'crates/writer/Cargo.toml', 'crates/writer/src/main.rs',
  'crates/operation-core/Cargo.toml', 'crates/operation-core/src/lib.rs',
  'crates/operation-wasm/Cargo.toml', 'crates/operation-wasm/src/lib.rs',
  'crates/agent-lifecycle-core/Cargo.toml', 'crates/agent-lifecycle-core/src/lib.rs',
  'crates/agent-lifecycle-wasm/Cargo.toml', 'crates/agent-lifecycle-wasm/src/lib.rs',
  'crates/terminal-runner/Cargo.toml', 'crates/terminal-runner/src/main.rs', 'crates/terminal-runner/src/windows.rs',
  'crates/terminal-store/Cargo.toml', 'crates/terminal-store/src/main.rs', 'crates/agent-platform/src/windows_terminal_store.rs',
  'crates/relay-device-core/Cargo.toml', 'crates/relay-device-core/src/lib.rs',
  'crates/relay-device-wasm/Cargo.toml', 'crates/relay-device-wasm/src/lib.rs',
  'crates/relay-registry-core/Cargo.toml', 'crates/relay-registry-core/src/lib.rs',
  'crates/relay-registry-core/src/values.rs', 'crates/relay-registry-core/src/basic.rs', 'crates/relay-registry-core/src/common.rs',
  'crates/relay-registry-core/src/account.rs', 'crates/relay-registry-core/src/onboarding.rs',
  'crates/relay-registry-core/src/instance.rs', 'crates/relay-registry-core/src/install.rs',
  'crates/relay-registry-wasm/Cargo.toml', 'crates/relay-registry-wasm/src/lib.rs',
  'crates/agent-platform/src/windows_write.rs', 'crates/agent-platform/src/windows_security.rs',
  'crates/agent-platform/src/windows_metadata.rs',
  'experiments/worker-rust/.gitignore', 'experiments/worker-rust/Cargo.toml', 'experiments/worker-rust/Cargo.lock',
  'experiments/worker-rust/build.mjs', 'experiments/worker-rust/probe.test.mjs',
  'experiments/worker-rust/src/lib.rs',
]);
export function inspectPublicText(relative, text, privateValues = []) {
  const normalized = text.replaceAll('\\.', '.').replaceAll('\\\\', '\\');
  if (privateValues.some(value => typeof value === 'string' && value.length >= 4 && (text.includes(value) || normalized.includes(value)))) throw Error(`Private deployment value found in ${relative}; publication stopped.`);
  if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|github_pat_[A-Za-z0-9_]{35,}|gh[pousr]_[A-Za-z0-9]{30,}|sk-proj-[A-Za-z0-9_-]{30,}/.test(text)) throw Error(`Credential-like content found in ${relative}; publication stopped.`);
  // Generic machine-name patterns only. Actual owner values stay on the build host.
  const machine = /\b(?:DESKTOP|LAPTOP)-[A-Z0-9]{7}\b|\b[A-Z][A-Z0-9-]{2,62}\.local(?![\w.-])/.test(normalized);
  const hostLiteral = /["'`][a-z0-9][a-z0-9-]{2,62}\.local(?=["'`/])|https?:\/\/[a-z0-9][a-z0-9-]{2,62}\.local\b|^[a-z0-9][a-z0-9-]{2,62}\.local$/im.test(normalized);
  if (machine || hostLiteral) throw Error(`Personal installation metadata found in ${relative}; publication stopped.`);
}
export async function privatePublicationValues(directory = root) {
  const values = [os.hostname(), os.homedir(), os.homedir().replaceAll('\\', '/')];
  try {
    const config = JSON.parse(await fs.readFile(path.join(directory, 'wrangler.local.jsonc'), 'utf8'));
    values.push(config.account_id, config.vars?.PUBLIC_ORIGIN, ...(config.kv_namespaces || []).map(n => n.id));
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  // Optional private values for other devices; never part of the public allowlist.
  try {
    const file = path.join(directory, '.artifacts', 'publication-private-values.json');
    const stat = await fs.lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536) throw Error('Unsafe private publication input.');
    const additional = JSON.parse(await fs.readFile(file, 'utf8'));
    if (!Array.isArray(additional) || additional.some(value => typeof value !== 'string' || value.length < 4)) throw Error('Invalid private publication input.');
    values.push(...additional);
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  return [...new Set(values.filter(value => typeof value === 'string' && value.length >= 4))];
}
export async function buildPublic(output = path.join(root, '.artifacts', 'public-' + VERSION)) {
  output = path.resolve(output);
  try { await fs.lstat(output); throw Error('Public output already exists; choose a new output.'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const files = ['.gitignore','LICENSE','package.json','package-lock.json','tsconfig.json','wrangler.jsonc','install.sh','install.ps1','start-chat2local.cmd','start-chat2local.sh', ...publicDocuments, ...rustSourceFiles];
  for (const folder of ['src','scripts','tests']) for (const file of await packageEntries(path.join(root, folder), folder + '/')) {
    if (folder === 'scripts' && excludedScripts.has(path.basename(file))) continue;
    if (file === 'tests/mac-handoff.test.mjs') continue;
    files.push(file);
  }
  const privateValues = await privatePublicationValues();
  const bytesByName = new Map();
  for (const relative of files) {
    if (isPrivatePublicationPath(relative)) throw Error('Private source path found in ' + relative + '; publication stopped.');
    const file = path.join(root, relative), stat = await fs.lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 2 * 1024 * 1024) throw Error('Unsafe public source file: ' + relative);
    const bytes = await fs.readFile(file); const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    inspectPublicText(relative, text, privateValues); bytesByName.set(relative, bytes);
  }
  if (!/export const DEFAULT_RELAY = '';/.test(bytesByName.get('src/shared/setup.mjs').toString())) throw Error('A public package cannot default to a maintainer instance.');
  const directory = path.join(output, 'chat2local'); await fs.mkdir(directory, { recursive: true });
  const manifest = { product: 'chat2local-source', version: VERSION, files: {} };
  for (const [relative, bytes] of [...bytesByName].sort(([a],[b]) => a.localeCompare(b))) {
    const file = path.join(directory, relative); await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, bytes, { flag: 'wx', mode: relative.endsWith('.sh') ? 0o755 : 0o644 });
    manifest.files[relative] = hash(bytes);
  }
  await fs.writeFile(path.join(directory, 'SOURCE-SHA256.json'), JSON.stringify(manifest, null, 2), { flag: 'wx' });
  const archive = path.join(output, `chat2local-source-v${VERSION}.tar.gz`);
  await writeTarGz(directory, archive);
  const checksum = hash(await fs.readFile(archive));
  await fs.writeFile(archive + '.sha256', `${checksum}  ${path.basename(archive)}\n`, { flag: 'wx' });
  const report = { directory, archive, sha256: checksum, files: files.length, version: VERSION, includesPersonalConfig: false, includesPrivateHandoff: false, published: false };
  await fs.writeFile(path.join(output, 'publication-report.json'), JSON.stringify(report, null, 2));
  return report;
}
if (import.meta.main) buildPublic(process.argv[2]).then(value => console.log(JSON.stringify(value, null, 2))).catch(error => { console.error(error.message); process.exitCode = 1; });
