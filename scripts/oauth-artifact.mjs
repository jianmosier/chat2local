import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { projectRoot, hash, validateModule } from './rust-relay-artifact.mjs';
export { projectRoot, hash };
export const oauthCrates = ['relay-device-core','relay-device-wasm','relay-registry-core','relay-registry-wasm','oauth-compat-core','oauth-compat-wasm','js-value-compat'];
export const providerPath = createRequire(import.meta.url).resolve('@cloudflare/workers-oauth-provider');
export const providerSha256 = 'ec5e19e794e665f9c8c5234554f8d46db6d269424e78f44ace9f6f48fbe96fca';
export async function crateFiles() {
  const files = [];
  for (const crate of oauthCrates) {
    files.push(`crates/${crate}/Cargo.toml`);
    for (const file of await fs.readdir(path.join(projectRoot,'crates',crate,'src'), { recursive:true })) if (file.endsWith('.rs')) files.push(`crates/${crate}/src/${file.replaceAll('\\','/')}`);
  }
  return files;
}
export async function runtimeFiles() {
  const files = [];
  for (const directory of ['src/relay','src/shared']) for (const file of await fs.readdir(path.join(projectRoot,directory), {recursive:true})) if (/\.(mjs|js)$/.test(file)) files.push(directory+'/'+file.replaceAll('\\','/'));
  return files;
}
export async function readArtifact(directory, { requireProvider = false } = {}) {
  const manifest = JSON.parse(await fs.readFile(path.join(directory,'manifest.json'),'utf8'));
  const full=manifest.v===2&&manifest.kind==='oauth-provider-device-registry'&&manifest.profile==='chat2local-enabled-oauth-0.10.3'&&manifest.abi===2&&JSON.stringify(manifest.operations)==='["fetch","cors","lookupClient","parseAuthRequest","completeAuthorization","listUserGrants","revokeGrant"]';
  if (!(full || !requireProvider && manifest.v===1 && manifest.kind==='oauth-bearer-device-registry') || manifest.entry !== 'worker.mjs' || manifest.provider?.version !== '0.10.3' || manifest.provider?.sha256 !== providerSha256 || hash(await fs.readFile(providerPath)) !== providerSha256) throw Error('Invalid OAuth artifact/provider binding.');
  const result = { manifest, entry:path.join(directory, manifest.entry) };
  const modules = [['wasm','device-core',256,'wasmPath','bytes'], ['registryWasm','registry-core',1024,'registryWasmPath','registryBytes'], ['oauthWasm','oauth-core',4096,'oauthWasmPath','oauthBytes']];
  if (hash(await fs.readFile(result.entry)) !== manifest.artifacts?.[manifest.entry]) throw Error('Stale OAuth Worker artifact.');
  for (const [field,prefix,pages,pathKey,bytesKey] of modules) {
    if (!new RegExp(`^${prefix}-[a-f0-9]{64}\\.wasm$`).test(manifest[field])) throw Error('Invalid OAuth module filename.');
    const modulePath = path.join(directory, manifest[field]), bytes = await fs.readFile(modulePath);
    if (manifest[field] !== `${prefix}-${hash(bytes)}.wasm` || hash(bytes) !== manifest.artifacts?.[manifest[field]]) throw Error('Stale OAuth WASM artifact.');
    validateModule(bytes,pages); result[pathKey] = modulePath; result[bytesKey] = bytes;
  }
  const required = [...await crateFiles(), ...await runtimeFiles(), 'Cargo.toml','Cargo.lock','package.json','package-lock.json','scripts/build-rust-oauth.mjs','scripts/oauth-artifact.mjs','scripts/rust-relay-artifact.mjs'];
  if(full)required.push('scripts/build-rust-oauth-provider.mjs','crates/oauth-compat-core/LICENSE.oauth-provider.txt');
  if (required.some(file => !Object.hasOwn(manifest.sources ?? {}, file))) throw Error('Incomplete OAuth source inventory.');
  for (const [file,expected] of Object.entries(manifest.sources)) {
    if (file.includes('..') || !/^(src\/|crates\/|scripts\/|Cargo\.(toml|lock)$|package(?:-lock)?\.json$)/.test(file) || hash(await fs.readFile(path.join(projectRoot,file))) !== expected) throw Error('Stale or invalid OAuth source binding: '+file);
  }
  return result;
}
