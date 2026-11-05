import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs/promises';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { readArtifact, projectRoot, hash } from '../scripts/oauth-artifact.mjs';
import { tokenRow } from './oauth-fixture.mjs';
const directory=process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR??process.env.CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR??path.join(projectRoot,'.artifacts/rust-oauth');
let artifact,reason;try{artifact=await readArtifact(directory,{requireProvider:process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_REQUIRED==='1'||!!process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR});}catch(error){if(process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_REQUIRED==='1'||process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR||process.env.CHAT2LOCAL_OAUTH_TEST_REQUIRED==='1'||process.env.CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR)throw error;reason='Build explicit OAuth artifact';}
const options={skip:reason},origin='http://localhost',resource=origin+'/mcp';
const evidence=[];
async function runtime(mode) {
  const rust=mode.startsWith('rust'),bundle=await build({entryPoints:[rust?artifact.entry:path.join(projectRoot,'src/relay/worker.mjs')],bundle:true,write:false,format:'esm',platform:'neutral',mainFields:['module','main'],external:['cloudflare:workers','*.wasm']});
  let source=bundle.outputFiles[0].text;const ordinaryHash=hash(source);
  if(mode.includes('denied')||mode.includes('trap')||mode.includes('sequence')) {
    const needle='async handleApiRequest(request, env, ctx) {';assert.equal(source.split(needle).length,2);
    source=source.replace(needle,needle+' globalThis.__oauthLegacyCalls=(globalThis.__oauthLegacyCalls||0)+1; throw Error("Legacy bearer fixture denied");');
  }
  if(mode.includes('trap')||mode.includes('sequence')) {
    if(artifact.manifest.v===2){
      const matches=[...source.matchAll(/new RustOAuthProvider\(([^()]*)\)/g)];assert.equal(matches.length,1);
      const replacement=mode.includes('trap')?`new RustOAuthProvider(${matches[0][1]}, {instantiate(module) { const e=new WebAssembly.Instance(module,{}).exports; return {exports:{...e,provider_command() {globalThis.__oauthCoreCalls=(globalThis.__oauthCoreCalls||0)+1;throw new WebAssembly.RuntimeError('fixture');}}};}})`:
        `new RustOAuthProvider(${matches[0][1]}, {instantiate(module) { const e=new WebAssembly.Instance(module,{}).exports; let bytes; return {exports:{...e,provider_command(n){globalThis.__oauthCoreCalls=(globalThis.__oauthCoreCalls||0)+1;const r=e.provider_command(n);e.output_read(0);const v=JSON.parse(new TextDecoder().decode(new Uint8Array(e.memory.buffer,e.output_ptr(),e.output_len())));v.result.effects[0].id=999;bytes=new TextEncoder().encode(JSON.stringify(v));return r;},output_len(){return bytes.length;},output_read(){new Uint8Array(e.memory.buffer,e.output_ptr(),bytes.length).set(bytes);return bytes.length;}}};}})`;
      source=source.replace(matches[0][0],replacement);
    }else{
    const matches=[...source.matchAll(/new RustOAuthBearer\(([^()]*)\)/g)];assert.equal(matches.length,1);
    const replacement=mode.includes('trap')?`new RustOAuthBearer(${matches[0][1]}, {instantiate(module) { const e=new WebAssembly.Instance(module,{}).exports; return {exports:{...e,command() {globalThis.__oauthCoreCalls=(globalThis.__oauthCoreCalls||0)+1;throw new WebAssembly.RuntimeError('fixture');}}};}})`:
      `new RustOAuthBearer(${matches[0][1]}, {instantiate(module) { const e=new WebAssembly.Instance(module,{}).exports; let bytes; return {exports:{...e,command(n){globalThis.__oauthCoreCalls=(globalThis.__oauthCoreCalls||0)+1;const r=e.command(n);e.output_read(0);const v=JSON.parse(new TextDecoder().decode(new Uint8Array(e.memory.buffer,e.output_ptr(),e.output_len())));v.result.sequence=999;bytes=new TextEncoder().encode(JSON.stringify(v));return r;},output_len(){return bytes.length;},output_read(){new Uint8Array(e.memory.buffer,e.output_ptr(),bytes.length).set(bytes);return bytes.length;}}};}})`;
    source=source.replace(matches[0][0],replacement);
    }
  }
  const selected=path.join(directory,'oauth-http-selected-'+hash(source)+'.mjs');await fs.writeFile(selected,source);
  const wrapper=await build({stdin:{resolveDir:projectRoot,contents:`import selected from ${JSON.stringify(selected)}; export {Device,Registry} from ${JSON.stringify(selected)};
export default {async fetch(request,env,ctx){if(new URL(request.url).pathname==='/fixture/counters')return Response.json({legacy:globalThis.__oauthLegacyCalls||0,core:globalThis.__oauthCoreCalls||0});if(new URL(request.url).pathname==='/fixture/helpers')return Response.json({initialized:globalThis.__oauthHelpers||false});const response=await selected.fetch(request,env,ctx);globalThis.__oauthHelpers=Boolean(env.OAUTH_PROVIDER && typeof env.OAUTH_PROVIDER.lookupClient==='function');return response;}};`},bundle:true,write:false,format:'esm',platform:'neutral',mainFields:['module','main'],external:['cloudflare:workers','*.wasm']});
  evidence.push({mode,ordinarySha256:ordinaryHash,selectedSha256:hash(source),wrapperSha256:hash(wrapper.outputFiles[0].text)});
  return convertV4MiniflareOptions({modulesRoot:directory,modules:[{type:'ESModule',path:path.join(directory,'oauth-http-wrapper.mjs'),contents:wrapper.outputFiles[0].text},...(rust?[artifact.wasmPath,artifact.registryWasmPath,artifact.oauthWasmPath].map(p=>({type:'CompiledWasm',path:p})):[])],compatibilityDate:'2026-09-20',compatibilityFlags:['nodejs_compat','global_fetch_strictly_public'],kvNamespaces:['OAUTH_KV'],durableObjects:{DEVICES:{className:'Device',useSQLite:true},REGISTRY:{className:'Registry',useSQLite:true}},bindings:{ALLOW_LOOPBACK:'true',ACCOUNT_CONNECTIONS:'true'}});
}
const mcp=(mf,token,pathname='/mcp',extra={})=>mf.dispatchFetch(origin+pathname,{method:'POST',headers:{'Content-Type':'application/json',...(token===undefined?{}:{Authorization:'Bearer '+token}),...extra},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'fixture',version:'1'}}})});
async function responseShape(response){return {status:response.status,headers:Object.fromEntries(response.headers),body:await response.text()};}
test('ordinary workerd candidate matches original Worker with v1/v2/v3, >1MiB fields, CORS and prefix/error distinctions',options,async t=>{
  const mf=new Miniflare(await runtime('js'));t.after(()=>mf.dispose());await mf.ready;let kv=await mf.getKVNamespace('OAUTH_KV');
  const props=[{deviceId:'a'.repeat(32),epoch:'b'.repeat(64),scopes:['files:read']},{grantVersion:2,devices:[{deviceId:'a'.repeat(32),epoch:'b'.repeat(64)}],scopes:['files:read']},{grantVersion:3,accountId:'c'.repeat(32),connectionId:'d'.repeat(32),connectionEpoch:'e'.repeat(64),clientId:'fixture-client',resource,scopes:['files:read']}];
  const fixtures=[];for(let i=0;i<props.length;i++){const f=await tokenRow({token:`user:grant${i}:secret`,props:props[i],row:{audience:resource}});fixtures.push(f);await kv.put(f.key,f.text);}
  const large=await tokenRow({token:'user:large:secret',props:{...props[0],unknown:'x'.repeat(1_100_000),utf16:'\ud800'},row:{audience:resource,future:'y'.repeat(1_100_000)}});fixtures.push(large);await kv.put(large.key,large.text);
  const deep=await tokenRow({token:'user:deep:secret',props:props[0],row:{audience:resource}}),nested=value=>{for(let i=0;i<600;i++)value=[value];return value;},deepRow=JSON.parse(deep.text);
  deep.text=JSON.stringify({...deepRow,expiresAt:nested(deepRow.expiresAt),wrappedEncryptionKey:nested(deepRow.wrappedEncryptionKey),grant:{encryptedProps:nested(deepRow.grant.encryptedProps)}});fixtures.push(deep);await kv.put(deep.key,deep.text);
  const tamper={...fixtures[0],key:fixtures[0].key,text:JSON.stringify({...JSON.parse(fixtures[0].text),wrappedEncryptionKey:'broken'})};
  const measure=async(sharedHelper=true)=>{
    await mcp(mf);assert.equal((await(await mf.dispatchFetch(origin+'/fixture/helpers')).json()).initialized,false);
    const results=[];for(const f of fixtures)results.push(await responseShape(await mcp(mf,f.token)));
    assert.equal((await(await mf.dispatchFetch(origin+'/fixture/helpers')).json()).initialized,sharedHelper);
    for(const [token,pathname,headers] of [[undefined,'/mcp',{}],['bad','/mcp',{Origin:origin}],[fixtures[1].token,'/mcpfoo',{}],[fixtures[1].token,'/mcp/child',{}],[fixtures[1].token,'/mcp',{Origin:origin}]])results.push(await responseShape(await mcp(mf,token,pathname,headers)));
    results.push(await responseShape(await mf.dispatchFetch(resource,{method:'OPTIONS',headers:{Origin:origin}})));
    await kv.put(tamper.key,tamper.text);results.push(await responseShape(await mcp(mf,fixtures[0].token)));await kv.put(fixtures[0].key,fixtures[0].text);return results;
  };
  const expected=await measure();assert.deepEqual(expected.slice(0,fixtures.length).map(v=>v.status),fixtures.map(()=>200));
  await mf.setOptions(await runtime('rust'));kv=await mf.getKVNamespace('OAUTH_KV');assert.deepEqual(await measure(artifact.manifest.v===1),expected);
  evidence.push({largePlaintextUnknownUnits:1_100_000,largeTokenUnknownUnits:1_100_000,largeTokenRowUtf8Bytes:Buffer.byteLength(large.text),nestedExpiryAndBase64Depth:600,ordinaryCases:expected.length});
});
test('separate legacy-denied positive control, Rust success, traps and wrong sequence prove no bearer fallback',options,async t=>{
  const mf=new Miniflare(await runtime('js-denied'));t.after(()=>mf.dispose());await mf.ready;let kv=await mf.getKVNamespace('OAUTH_KV');
  const fixture=await tokenRow({props:{deviceId:'a'.repeat(32),epoch:'b'.repeat(64),scopes:['files:read']},row:{audience:resource}});await kv.put(fixture.key,fixture.text);
  assert.equal((await mcp(mf,fixture.token)).status,400);assert.deepEqual(await(await mf.dispatchFetch(origin+'/fixture/counters')).json(),{legacy:1,core:0});
  await mf.setOptions(await runtime('rust-denied'));assert.equal((await mcp(mf,fixture.token)).status,200);assert.equal((await mcp(mf,'bad')).status,401);assert.deepEqual(await(await mf.dispatchFetch(origin+'/fixture/counters')).json(),{legacy:0,core:0});
  for(const mode of ['rust-trap','rust-sequence']){await mf.setOptions(await runtime(mode));kv=await mf.getKVNamespace('OAUTH_KV');assert.equal((await mcp(mf,fixture.token)).status,400);assert.deepEqual(await(await mf.dispatchFetch(origin+'/fixture/counters')).json(),{legacy:0,core:1});assert.equal(await kv.get(fixture.key),fixture.text);}
  evidence.push({legacyDeniedPositiveCalls:1,rustDeniedLegacyCalls:0,trapCalls:1,sequenceCalls:1});
  if(process.env.CHAT2LOCAL_OAUTH_HTTP_RECEIPT)await fs.writeFile(process.env.CHAT2LOCAL_OAUTH_HTTP_RECEIPT,JSON.stringify({artifactSha256:hash(await fs.readFile(path.join(directory,'manifest.json'))),provider:artifact.manifest.provider,evidence},null,2)+'\n');
});
