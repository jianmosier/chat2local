import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
export const root = fileURLToPath(new URL('..', import.meta.url));
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export async function sourceFiles(sourceRoot = root) {
  const files = ['Cargo.toml', 'Cargo.lock', 'scripts/build-rust-transport.mjs', 'scripts/transport-artifact.mjs', 'scripts/test-rust-transport.mjs', 'tests/rust-transport.test.mjs', 'tests/transport-fixture.mjs'];
  for (const crate of ['agent-transport', 'agent-transport-fixture']) {
    files.push(`crates/${crate}/Cargo.toml`);
    for (const entry of await fs.readdir(path.join(sourceRoot, `crates/${crate}`), { recursive: true, withFileTypes: true })) {
      if (entry.isFile() && /\.(rs|pem|json)$/.test(entry.name)) files.push(path.relative(sourceRoot, path.join(entry.parentPath, entry.name)).split(path.sep).join('/'));
    }
  }
  return files.sort();
}
export async function readTransportArtifact(executable, { sourceRoot = root } = {}) {
  const manifest = JSON.parse(await fs.readFile(path.join(path.dirname(executable), 'manifest.json'), 'utf8'));
  const files = await sourceFiles(sourceRoot);
  if (manifest.v !== 1 || manifest.fixtureOnly !== true || manifest.executable !== path.basename(executable) || manifest.opensslVersion !== '3.5.8' || !/^[a-f0-9]{64}$/.test(manifest.opensslManifestSha256 ?? '') || Object.keys(manifest.sources ?? {}).sort().join('\n') !== files.join('\n')) throw Error('Transport fixture manifest mismatch.');
  for (const file of files) if (hash(await fs.readFile(path.join(sourceRoot, file))) !== manifest.sources[file]) throw Error('Stale transport fixture source: ' + file);
  if (hash(await fs.readFile(executable)) !== manifest.sha256) throw Error('Transport fixture binary mismatch.');
  return manifest;
}
