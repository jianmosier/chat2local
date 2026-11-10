import fs from 'node:fs/promises';
import path from 'node:path';
import { sourceFiles as decisionSources, projectRoot, hash, dependencyPaths } from './oidc-artifact.mjs';
import { validateModule } from './rust-relay-artifact.mjs';
export { projectRoot, hash, dependencyPaths };
export async function sourceFiles() {
  const files = [...await decisionSources(), 'src/relay/rust-oidc-token.mjs', 'scripts/build-rust-oidc-token.mjs', 'scripts/oidc-token-artifact.mjs'];
  for (const crate of ['oidc-token-core', 'oidc-token-wasm', 'js-value-compat']) {
    files.push(`crates/${crate}/Cargo.toml`);
    for (const file of await fs.readdir(path.join(projectRoot, 'crates', crate, 'src'), { recursive: true })) if (file.endsWith('.rs')) files.push(`crates/${crate}/src/${file.replaceAll('\\', '/')}`);
  }
  return [...new Set(files)].sort();
}
export async function readArtifact(directory) {
  const manifest = JSON.parse(await fs.readFile(path.join(directory, 'manifest.json'), 'utf8'));
  if (manifest.v !== 1 || manifest.kind !== 'oidc-token-verification' || manifest.profileABI !== 1 || manifest.entry !== 'worker.mjs'
    || manifest.platform !== 'workerd-1.20260918.1' || manifest.crypto !== 'rsa-0.9.10-public-pkcs1v15-sha256'
    || manifest.maxWireBytes !== 16777216 || manifest.maxMemoryBytes !== 268435456) throw Error('Invalid OIDC token artifact profile.');
  const result = { manifest, entry: path.join(directory, manifest.entry) };
  if (hash(await fs.readFile(result.entry)) !== manifest.artifacts?.[manifest.entry]) throw Error('Stale OIDC token Worker.');
  for (const [field, prefix, pages, pathKey, bytesKey] of [['oidcWasm', 'oidc-core', 256, 'oidcWasmPath', 'oidcBytes'], ['oidcTokenWasm', 'oidc-token-core', 4096, 'oidcTokenWasmPath', 'oidcTokenBytes']]) {
    if (!new RegExp(`^${prefix}-[a-f0-9]{64}\\.wasm$`).test(manifest[field])) throw Error('Invalid OIDC token module filename.');
    const file = path.join(directory, manifest[field]), bytes = await fs.readFile(file);
    if (manifest[field] !== `${prefix}-${hash(bytes)}.wasm` || hash(bytes) !== manifest.artifacts?.[manifest[field]]) throw Error('Stale OIDC token WASM.');
    validateModule(bytes, pages); result[pathKey] = file; result[bytesKey] = bytes;
  }
  if ((await sourceFiles()).some(file => !Object.hasOwn(manifest.sources || {}, file))) throw Error('Incomplete OIDC token source inventory.');
  for (const [file, expected] of Object.entries(manifest.sources)) {
    if (file.includes('..') || !/^(src\/|crates\/(oidc-decision-(core|wasm)|oidc-token-(core|wasm)|js-value-compat)\/|scripts\/|Cargo\.(toml|lock)$|package(?:-lock)?\.json$)/.test(file)
      || hash(await fs.readFile(path.join(projectRoot, file))) !== expected) throw Error('Stale or invalid OIDC token source: ' + file);
  }
  for (const [name, file] of Object.entries(dependencyPaths)) if (hash(await fs.readFile(file)) !== manifest.dependencies?.[name]) throw Error('Stale OIDC token dependency: ' + name);
  return result;
}
