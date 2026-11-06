import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { build } from 'esbuild';
import { argumentsFor, validateModule } from './rust-relay-artifact.mjs';
import { projectRoot, hash, providerPath, providerSha256, crateFiles, runtimeFiles } from './oauth-artifact.mjs';
const args = process.argv.slice(2), profileIndex=args.indexOf('--profile');
const profile=profileIndex<0?'bearer':args.splice(profileIndex,2)[1];
if(!['bearer','provider'].includes(profile))throw Error('Invalid OAuth profile.');
const parsed = argumentsFor(args);
if (!args.includes('--out-dir')) parsed.output = path.join(projectRoot,'.artifacts/rust-oauth');
const { target, output } = parsed;
if (hash(await fs.readFile(providerPath)) !== providerSha256) throw Error('OAuth provider source differs from pinned 0.10.3.');
// A candidate is immutable; rebuilding requires a new output directory.
await fs.mkdir(output, { recursive:true });
if ((await fs.readdir(output)).length) throw Error('OAuth artifact output must be empty.');
const modules = {};
for (const [crate,prefix,pages] of [['relay-device','device',256],['relay-registry','registry',1024],['oauth-compat','oauth',4096]]) {
  const result = spawnSync('cargo',['rustc','--locked','--release','--target','wasm32-unknown-unknown','--target-dir',target,'-p',`chat2local-${crate}-wasm`,'--','-C',`link-arg=--max-memory=${pages*65536}`],{cwd:projectRoot,stdio:'inherit',shell:false,windowsHide:true});
  if (result.error || result.status !== 0) throw Error('Required '+prefix+' WASM build failed.');
  const bytes = await fs.readFile(path.join(target,`wasm32-unknown-unknown/release/chat2local_${crate.replaceAll('-','_')}_wasm.wasm`)); validateModule(bytes,pages);
  modules[prefix] = { bytes, file:`${prefix}-core-${hash(bytes)}.wasm` };
}
const bundle = await build({absWorkingDir:projectRoot,stdin:{resolveDir:projectRoot,sourcefile:'rust-oauth-entry.mjs',contents:`
import deviceModule from './${modules.device.file}';
import registryModule from './${modules.registry.file}';
import oauthModule from './${modules.oauth.file}';
import { Device as OriginalDevice, Registry as OriginalRegistry } from './src/relay/state.mjs';
import { RustDeviceSessionCore } from './src/relay/rust-device-session.mjs';
import { RustRegistryRunner } from './src/relay/rust-registry.mjs';
import { RustOAuthBearer } from './src/relay/rust-oauth.mjs';
import { RustOAuthProvider } from './src/relay/rust-oauth-provider.mjs';
import { AuthorizationError } from '@cloudflare/workers-oauth-provider';
import { createRelayWorker } from './src/relay/worker.mjs';
const bearer = new RustOAuthBearer(oauthModule);
export default createRelayWorker(${profile==='provider'?'{ providerDriver: new RustOAuthProvider(oauthModule, { authorizationErrorClass: AuthorizationError }) }':'{ authenticateBearer: (request, env, options) => bearer.authenticate(request, env, options) }'});
export class Device extends OriginalDevice { constructor(ctx, env) { super(ctx, env, () => new RustDeviceSessionCore(deviceModule)); } }
export class Registry extends OriginalRegistry { constructor(ctx, env) { super(ctx, env, () => new RustRegistryRunner(registryModule)); } }
`},bundle:true,write:false,metafile:true,format:'esm',platform:'neutral',mainFields:['module','main'],external:['cloudflare:workers','*.wasm']});
const entry = bundle.outputFiles[0].contents, sources = {};
const inputs = new Set([...Object.keys(bundle.metafile.inputs).filter(file => file !== 'rust-oauth-entry.mjs' && !file.startsWith('..') && !file.includes('node_modules/')), ...await crateFiles(), ...await runtimeFiles(), 'Cargo.toml','Cargo.lock','package.json','package-lock.json','scripts/build-rust-oauth.mjs','scripts/build-rust-oauth-provider.mjs','scripts/oauth-artifact.mjs','scripts/rust-relay-artifact.mjs','crates/oauth-compat-core/LICENSE.oauth-provider.txt']);
for (const file of [...inputs].sort()) sources[file] = hash(await fs.readFile(path.join(projectRoot,file)));
const artifacts = {'worker.mjs':hash(entry)}; await fs.writeFile(path.join(output,'worker.mjs'),entry);
for (const {bytes,file} of Object.values(modules)) { artifacts[file] = hash(bytes); await fs.writeFile(path.join(output,file),bytes); }
await fs.writeFile(path.join(output,'manifest.json'),JSON.stringify({v:profile==='provider'?2:1,kind:profile==='provider'?'oauth-provider-device-registry':'oauth-bearer-device-registry',...(profile==='provider'?{profile:'chat2local-enabled-oauth-0.10.3',abi:2,operations:['fetch','cors','lookupClient','parseAuthRequest','completeAuthorization','listUserGrants','revokeGrant']}:{}),entry:'worker.mjs',wasm:modules.device.file,registryWasm:modules.registry.file,oauthWasm:modules.oauth.file,provider:{version:'0.10.3',sha256:providerSha256},artifacts,sources},null,2)+'\n');
console.log('Local OAuth '+profile+' + Device + Registry entry built: '+output);
