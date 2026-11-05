import path from 'node:path';
import fs from 'node:fs/promises';
import { readArtifact as readRelayArtifact, projectRoot, hash } from '../scripts/rust-relay-artifact.mjs';
import { readArtifact as readOAuthArtifact } from '../scripts/oauth-artifact.mjs';
import { readArtifact as readOidcArtifact } from '../scripts/oidc-artifact.mjs';
import { readArtifact as readOidcTokenArtifact } from '../scripts/oidc-token-artifact.mjs';
const oidcTokenDirectory = process.env.CHAT2LOCAL_OIDC_TOKEN_TEST_ARTIFACT_DIR;
if (process.env.CHAT2LOCAL_OIDC_TOKEN_TEST_REQUIRED === '1' && !oidcTokenDirectory) throw Error('Strict OIDC token tests require an explicit artifact directory.');
if (oidcTokenDirectory && Object.keys(process.env).some(key => /^CHAT2LOCAL_(OIDC|OAUTH(?:_PROVIDER)?|DEVICE|REGISTRY)_TEST_(ARTIFACT_DIR|REQUIRED|DENY_LEGACY)$/.test(key) && process.env[key] && process.env[key] !== '0')) throw Error('Independent OIDC token tests cannot select another Rust relay profile.');
const oidcDirectory = process.env.CHAT2LOCAL_OIDC_TEST_ARTIFACT_DIR;
if (process.env.CHAT2LOCAL_OIDC_TEST_REQUIRED === '1' && !oidcDirectory) throw Error('Strict OIDC tests require an explicit artifact directory.');
if (oidcDirectory && ['CHAT2LOCAL_DEVICE_TEST_ARTIFACT_DIR', 'CHAT2LOCAL_REGISTRY_TEST_ARTIFACT_DIR', 'CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR', 'CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR',
  'CHAT2LOCAL_DEVICE_TEST_DENY_LEGACY', 'CHAT2LOCAL_REGISTRY_TEST_DENY_LEGACY', 'CHAT2LOCAL_OAUTH_TEST_DENY_LEGACY', 'CHAT2LOCAL_OAUTH_PROVIDER_TEST_DENY_LEGACY',
  'CHAT2LOCAL_DEVICE_TEST_REQUIRED', 'CHAT2LOCAL_REGISTRY_TEST_REQUIRED', 'CHAT2LOCAL_OAUTH_TEST_REQUIRED', 'CHAT2LOCAL_OAUTH_PROVIDER_TEST_REQUIRED'].some(key => process.env[key] && process.env[key] !== '0')) throw Error('Independent OIDC tests cannot select another Rust relay profile.');
const deviceDirectory = process.env.CHAT2LOCAL_DEVICE_TEST_ARTIFACT_DIR, registryDirectory = process.env.CHAT2LOCAL_REGISTRY_TEST_ARTIFACT_DIR;
if (deviceDirectory && registryDirectory && path.resolve(deviceDirectory) !== path.resolve(registryDirectory)) throw Error('Device and Registry artifact directories must agree.');
const providerDirectory = process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR;
const providerRequired = process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_REQUIRED === '1' || !!providerDirectory || process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_DENY_LEGACY === '1';
if(providerDirectory && process.env.CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR && path.resolve(providerDirectory)!==path.resolve(process.env.CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR))throw Error('OAuth provider and bearer artifact directories must agree.');
const oauthDirectory = providerDirectory || process.env.CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR;
if (oauthDirectory && [deviceDirectory,registryDirectory].some(value => value && path.resolve(value) !== path.resolve(oauthDirectory))) throw Error('OAuth, Device and Registry artifact directories must agree.');
if ((providerRequired || process.env.CHAT2LOCAL_OAUTH_TEST_REQUIRED === '1' || process.env.CHAT2LOCAL_OAUTH_TEST_DENY_LEGACY === '1') && !oauthDirectory) throw Error('Strict OAuth tests require an explicit artifact directory.');
const directory = oidcTokenDirectory || oidcDirectory || oauthDirectory || registryDirectory || deviceDirectory;
export const readArtifact = oidcTokenDirectory ? readOidcTokenArtifact : oidcDirectory ? readOidcArtifact : oauthDirectory ? directory => readOAuthArtifact(directory,{requireProvider:providerRequired}) : readRelayArtifact;
export async function denyLegacyProviderEntry(artifact) {
  let contents=await fs.readFile(artifact.entry,'utf8');const original=hash(contents),replacements=[];
  for(const name of ['handleClientRegistration','parseTokenEndpointRequest','handleTokenRequest','handleAuthorizationCodeGrant','handleRefreshTokenGrant','handleRevocationRequest','revokeToken','parseAuthRequest','lookupClient','completeAuthorization','listUserGrants','revokeGrant','handleApiRequest']){
    const pattern=new RegExp('async '+name+'\\([^\\n]*\\) \\{','g'),matches=[...contents.matchAll(pattern)];
    if(matches.length!==1)throw Error('Strict provider fixture expected one legacy '+name+', found '+matches.length);
    contents=contents.replace(pattern,match=>match+' throw Error("Fixture forbids legacy OAuth business: '+name+'");');replacements.push(name);
  }
  const pattern=/tokenExchangeCallback: \(options\) => \(/g;
  if([...contents.matchAll(pattern)].length!==1)throw Error('Strict provider fixture must identify original scope callback.');
  contents=contents.replace(pattern,'tokenExchangeCallback: (options) => { throw Error("Fixture forbids legacy OAuth scope callback"); return (');
  // The source callback has one return object; close the injected function at its boundary.
  const end='scopes: options.requestedScope.filter((scope) => SCOPES.includes(scope)) } })';
  if(contents.split(end).length!==2)throw Error('Strict provider scope callback boundary changed.');
  contents=contents.replace(end,end+'; }');replacements.push('tokenExchangeCallback');
  const sha256=hash(contents),entry=path.join(path.dirname(artifact.entry),'strict-oauth-provider-'+sha256+'.mjs');
  await fs.writeFile(entry,contents);await fs.writeFile(entry+'.json',JSON.stringify({original,instrumented:sha256,replacements},null,2));return entry;
}
export async function denyLegacyBearerEntry(artifact) {
  const original = await fs.readFile(artifact.entry,'utf8'), needle = 'async handleApiRequest(request, env, ctx) {';
  if (original.split(needle).length !== 2) throw Error('Strict fixture must identify exactly one legacy OAuth bearer implementation.');
  const contents = original.replace(needle, needle+' throw Error("Fixture forbids legacy OAuth bearer authentication");'), sha256 = hash(contents);
  const entry = path.join(path.dirname(artifact.entry),'strict-oauth-host-'+sha256+'.mjs');
  await fs.writeFile(entry,contents); await fs.writeFile(path.join(path.dirname(artifact.entry),'strict-oauth-host-'+sha256+'.json'),JSON.stringify({original:hash(original),instrumented:sha256,replacements:1},null,2)); return entry;
}
export async function denyLegacyEntry(artifact) {
  const original=await fs.readFile(artifact.entry,'utf8'),needle='return storage.transaction(legacy);';
  if(original.split(needle).length!==2)throw Error('Strict fixture must replace exactly one selected legacy Registry branch.');
  const contents=original.replace(needle,'throw Error("Fixture forbids legacy Registry transactions");'),sha256=hash(contents);
  const entry=path.join(path.dirname(artifact.entry),'strict-registry-host-'+sha256+'.mjs');
  await fs.writeFile(entry,contents);await fs.writeFile(path.join(path.dirname(artifact.entry),'strict-registry-host.json'),JSON.stringify({original:hash(original),instrumented:sha256,replacements:1},null,2));
  return entry;
}
export async function relayEntry() {
  if (!directory) {
    if (process.env.CHAT2LOCAL_DEVICE_TEST_REQUIRED === '1' || process.env.CHAT2LOCAL_REGISTRY_TEST_REQUIRED === '1') throw Error('Strict relay tests require an explicit artifact directory.');
    return path.join(projectRoot, 'src/relay/worker.mjs');
  }
  const artifact=await readArtifact(directory);
  let entry = process.env.CHAT2LOCAL_REGISTRY_TEST_DENY_LEGACY==='1'?await denyLegacyEntry(artifact):artifact.entry;
  if(process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_DENY_LEGACY==='1')entry=await denyLegacyProviderEntry({...artifact,entry});
  else if (process.env.CHAT2LOCAL_OAUTH_TEST_DENY_LEGACY === '1') entry = await denyLegacyBearerEntry({...artifact,entry});
  return entry;
}
export async function relayRuntime(bundle) {
  if (!directory) return { modules: true, script: bundle.outputFiles[0].text };
  const artifact = await readArtifact(directory);
  return { modulesRoot: directory, modules: [
    { type: 'ESModule', path: path.join(directory, 'test-worker.mjs'), contents: bundle.outputFiles[0].text },
    ...(artifact.wasmPath ? [{ type: 'CompiledWasm', path: artifact.wasmPath }] : []),
    ...(artifact.registryWasmPath ? [{ type: 'CompiledWasm', path: artifact.registryWasmPath }] : []),
    ...(artifact.oauthWasmPath ? [{type:'CompiledWasm',path:artifact.oauthWasmPath}] : []),
    ...(artifact.oidcWasmPath ? [{type:'CompiledWasm',path:artifact.oidcWasmPath}] : []),
    ...(artifact.oidcTokenWasmPath ? [{type:'CompiledWasm',path:artifact.oidcTokenWasmPath}] : []),
  ] };
}
