import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';

export async function checkSource(directory, manifestPath) {
  const info = await fs.lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) throw Error('Source directory is unsafe.');
  const raw = await fs.readFile(manifestPath, 'utf8');
  if (raw.length > 256 * 1024) throw Error('Source manifest is oversized.');
  const value = JSON.parse(raw);
  if (value.product !== 'chat2local-source' || !value.files || typeof value.files !== 'object') throw Error('Invalid source manifest.');
  const entries = Object.entries(value.files);
  if (!entries.length || entries.length > 1000) throw Error('Invalid source file count.');
  for (const [relative, expected] of entries) {
    if (!/^[A-Za-z0-9_.\-/]+$/.test(relative) || relative.startsWith('/') || relative.split('/').some(p => !p || p === '.' || p === '..') || !/^[a-f0-9]{64}$/.test(expected)) throw Error('Unsafe source manifest entry.');
    let cursor = directory;
    for (const name of relative.split('/')) { cursor = path.join(cursor, name); if ((await fs.lstat(cursor)).isSymbolicLink()) throw Error('Source contains a link.'); }
    const stat = await fs.lstat(cursor);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > 2 * 1024 * 1024) throw Error('Source contains an unsafe file.');
    if (createHash('sha256').update(await fs.readFile(cursor)).digest('hex') !== expected) throw Error(`Existing source was modified: ${relative}. Nothing was overwritten.`);
  }
  return { verified: true, files: entries.length, version: value.version };
}
if (import.meta.main) checkSource(process.argv[2], process.argv[3]).then(value => console.log(JSON.stringify(value))).catch(error => { console.error(error.message); process.exitCode = 1; });
