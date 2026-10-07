import fs from 'node:fs/promises';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { inspectPublicText, privatePublicationValues } from './build-public.mjs';

// Read-only audit. Reports locations/categories, never matching secret contents.
const forbidden = /(?:^|\/)(?:\.artifacts|\.wrangler|codex|\.ssh|\.env(?:\.[^/]*)?|wrangler\.local\.jsonc|vault\.json|session\.json|settings\.json|audit\.jsonl|HANDOFF\.md)(?:\/|$)/;
const runtime = /(?:^|\/)runtime\/(?:node|node\.exe)$/;
const limit = 2 * 1024 * 1024;
export function inspectAuditEntry(name, bytes, privateValues = []) {
  if (forbidden.test(name)) return { location: name, category: 'private-file' };
  if (bytes.length > limit) return { location: name, category: 'oversized-unscanned' };
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { return { location: name, category: 'non-text-unscanned' }; }
  try { inspectPublicText(name, text, privateValues); }
  catch (error) { return { location: name, category: error.message.startsWith('Credential') ? 'credential-pattern' : error.message.startsWith('Private') ? 'private-value' : 'machine-metadata' }; }
  return null;
}
export async function auditTree(directory, privateValues = []) {
  const result = { scope: 'tree', files: 0, runtimeBinariesExcluded: [], findings: [] };
  async function visit(folder, prefix = '') {
    for (const item of await fs.readdir(folder, { withFileTypes: true })) {
      const name = prefix + item.name;
      if (name === '.git') continue; // Git objects require the separate --git audit.
      const file = path.join(folder, item.name), stat = await fs.lstat(file);
      if (stat.isSymbolicLink() || (stat.isFile() && stat.nlink !== 1)) { result.findings.push({ location: name, category: 'unsafe-link' }); continue; }
      if (forbidden.test(name)) { result.findings.push({ location: name, category: 'private-file' }); continue; }
      if (stat.isDirectory()) { await visit(file, name + '/'); continue; }
      if (!stat.isFile()) { result.findings.push({ location: name, category: 'unsupported-entry' }); continue; }
      result.files++;
      if (runtime.test(name)) { result.runtimeBinariesExcluded.push(name); continue; }
      if (stat.size > limit) { result.findings.push({ location: name, category: 'oversized-unscanned' }); continue; }
      const found = inspectAuditEntry(name, await fs.readFile(file), privateValues);
      if (found) result.findings.push(found);
    }
  }
  await visit(path.resolve(directory));
  result.passed = result.findings.length === 0;
  return result;
}
export function auditGit(directory, privateValues = []) {
  const git = args => execFileSync('git', ['-C', path.resolve(directory), ...args], { maxBuffer: 16 * 1024 * 1024, timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'] });
  const result = { scope: 'all-fetched-reachable-git-objects', commits: 0, blobs: 0, findings: [] };
  const commits = git(['rev-list', '--all']).toString('utf8').trim().split('\n').filter(Boolean);
  for (const sha of commits) {
    if (!/^[a-f0-9]{40}$/.test(sha)) throw Error('Invalid Git commit identity.');
    result.commits++;
    const entry = inspectAuditEntry('commit:' + sha, git(['show', '-s', '--format=%an%n%ae%n%cn%n%ce%n%B', sha]), privateValues);
    if (entry) result.findings.push(entry);
  }
  const objects = git(['rev-list', '--objects', '--all']).toString('utf8').trim().split('\n').filter(Boolean);
  for (const item of objects) {
    const split = item.indexOf(' '), sha = split < 0 ? item : item.slice(0, split), name = split < 0 ? '' : item.slice(split + 1);
    if (!/^[a-f0-9]{40}$/.test(sha)) throw Error('Invalid Git object identity.');
    if (git(['cat-file', '-t', sha]).toString().trim() !== 'blob') continue;
    result.blobs++;
    const location = sha + ':' + name;
    if (forbidden.test(name)) { result.findings.push({ location, category: 'private-file' }); continue; }
    if (Number(git(['cat-file', '-s', sha]).toString().trim()) > limit) { result.findings.push({ location, category: 'oversized-unscanned' }); continue; }
    const entry = inspectAuditEntry(name, git(['cat-file', 'blob', sha]), privateValues);
    if (entry) result.findings.push({ ...entry, location });
  }
  result.passed = result.findings.length === 0;
  return result;
}
if (import.meta.main) {
  const [mode, directory, ...extra] = process.argv.slice(2);
  try {
    if (!['--tree', '--git'].includes(mode) || !directory || extra.length) throw Error('Usage: audit-public.mjs --tree PUBLIC_DIRECTORY | --git PUBLIC_CHECKOUT');
    const privateValues = await privatePublicationValues();
    const result = mode === '--tree' ? await auditTree(directory, privateValues) : auditGit(directory, privateValues);
    console.log(JSON.stringify(result, null, 2));
    if (!result.passed) process.exitCode = 1;
  } catch { console.error('Public audit could not complete; no pass result is available.'); process.exitCode = 1; }
}
