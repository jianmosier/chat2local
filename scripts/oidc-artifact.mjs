import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { projectRoot, hash, validateModule } from './rust-relay-artifact.mjs';
export { projectRoot, hash };
export const dependencyPaths = {
  provider: createRequire(import.meta.url).resolve('@cloudflare/workers-oauth-provider'),
  verifier: createRequire(import.meta.url).resolve('oauth4webapi'),
};
export async function sourceFiles() {
  const files = ['Cargo.toml', 'Cargo.lock', 'package.json', 'package-lock.json', 'scripts/build-rust-oidc.mjs', 'scripts/oidc-artifact.mjs', 'scripts/rust-relay-artifact.mjs'];
  for (const directory of ['src/relay', 'src/shared', 'crates/oidc-decision-core', 'crates/oidc-decision-wasm']) {
    for (const file of await fs.readdir(path.join(projectRoot, directory), { recursive: true })) {
      if (directory === 'src/relay' && /^rust-(?!oidc\.mjs$)/.test(file)) continue;
      if (/\.(mjs|js|rs)$/.test(file) || file === 'Cargo.toml') files.push(directory + '/' + file.replaceAll('\\', '/'));
    }
  }
  return files.sort();
}
export async function readArtifact(directory) {
  const manifest = JSON.parse(await fs.readFile(path.join(directory, 'manifest.json'), 'utf8'));
  if (manifest.v !== 1 || manifest.kind !== 'oidc-login-decisions' || manifest.profileABI !== 1 || manifest.entry !== 'worker.mjs'
    || !/^oidc-core-[a-f0-9]{64}\.wasm$/.test(manifest.oidcWasm)) throw Error('Invalid OIDC artifact manifest.');
  const entry = path.join(directory, manifest.entry), oidcWasmPath = path.join(directory, manifest.oidcWasm);
  const oidcBytes = await fs.readFile(oidcWasmPath);
  if (manifest.oidcWasm !== `oidc-core-${hash(oidcBytes)}.wasm` || hash(oidcBytes) !== manifest.artifacts?.[manifest.oidcWasm]
    || hash(await fs.readFile(entry)) !== manifest.artifacts?.[manifest.entry]) throw Error('Stale OIDC artifact.');
  validateModule(oidcBytes);
  const required = await sourceFiles();
  if (required.some(file => !Object.hasOwn(manifest.sources || {}, file))) throw Error('Incomplete OIDC source inventory.');
  for (const [file, expected] of Object.entries(manifest.sources)) {
    if (file.includes('..') || !/^(src\/|crates\/oidc-decision-(core|wasm)\/|scripts\/|Cargo\.(toml|lock)$|package(?:-lock)?\.json$)/.test(file)
      || hash(await fs.readFile(path.join(projectRoot, file))) !== expected) throw Error('Stale or invalid OIDC source binding: ' + file);
  }
  for (const [name, file] of Object.entries(dependencyPaths)) {
    if (hash(await fs.readFile(file)) !== manifest.dependencies?.[name]) throw Error('Stale OIDC dependency binding: ' + name);
  }
  return { manifest, entry, oidcWasmPath, oidcBytes };
}
