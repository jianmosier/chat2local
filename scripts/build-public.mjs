import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import os from 'node:os';
import { packageEntries, writeTarGz } from './archive.mjs';
import { VERSION } from '../src/shared/protocol.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export const excludedScripts = new Set(['build-mac-codex-handoff.mjs', 'export-mac-handoff.mjs', 'stage-mac-handoff.mjs', 'publish-public.mjs']);
// Public product documentation has one source; internal notes are not exported.
export const publicDocuments = Object.freeze(['README.md']);
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
  const files = ['.gitignore','LICENSE','package.json','package-lock.json','tsconfig.json','wrangler.jsonc','install.sh','install.ps1','start-chat2local.cmd','start-chat2local.sh', ...publicDocuments];
  for (const folder of ['src','scripts','tests']) for (const file of await packageEntries(path.join(root, folder), folder + '/')) {
    if (folder === 'scripts' && excludedScripts.has(path.basename(file))) continue;
    if (file === 'tests/mac-handoff.test.mjs') continue;
    files.push(file);
  }
  const privateValues = await privatePublicationValues();
  const bytesByName = new Map();
  for (const relative of files) {
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
