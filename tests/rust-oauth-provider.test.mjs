import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs/promises';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { isDeepStrictEqual } from 'node:util';
import { RustOAuthProvider } from '../src/relay/rust-oauth-provider.mjs';
import { encodeValue,decodeValue } from '../src/relay/rust-oauth-values.mjs';
import { readArtifact,projectRoot } from '../scripts/oauth-artifact.mjs';
import {clockCrypto,kvFixture,originalDriver,origin,resource,registration,form,flow} from './oauth-provider-fixture.mjs';
const directory=process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR??process.env.CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR;
const required=process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_REQUIRED==='1'||!!process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR;
if(required&&!directory)throw Error('Strict OAuth provider tests require an explicit artifact directory.');
let artifact,reason='Build explicit OAuth provider artifact';if(directory){const selected=await readArtifact(directory,{requireProvider:required});if(selected.manifest.v===2){artifact=selected;reason=false;}}
const wasm={skip:reason},module=artifact&&new WebAssembly.Module(artifact.oauthBytes);
function rustDriver(clock,options={}){const p=new RustOAuthProvider(module,{now:clock.now,random:clock.random,subtle:clock.subtle,...options});return{provider:p,fetch:(r,e)=>p.fetch(r,e,{},{origin,defaultHandler:{fetch:()=>new Response('default')},apiHandler:{fetch:(_r,_e,ctx)=>Response.json(ctx.props)}}),parseAuthRequest:(r,e)=>p.parseAuthRequest(r,e,{origin}),lookupClient:(id,e)=>p.lookupClient(id,e,{origin}),completeAuthorization:(o,e)=>p.completeAuthorization(o,e,{origin})};}
async function shape(response){return {status:response.status,headers:[...response.headers],body:await response.text()};}
test('lossless provider values preserve UTF16, IEEE754, undefined and own prototype keys',()=>{
  const value={text:'\ud800',negativeZero:-0,infinity:Infinity,negativeInfinity:-Infinity,nan:NaN,undefined:undefined,array:[undefined,null,'\udfff']};Object.defineProperty(value,'__proto__',{value:{future:true},enumerable:true});
  const decoded=decodeValue(encodeValue(value));assert.deepEqual(decoded,value);assert.equal(Object.getPrototypeOf(decoded),Object.prototype);assert.equal(Object.hasOwn(decoded,'__proto__'),true);
});
test('strict provider selectors fail for missing, conflicting and v1 profiles',async()=>{
  const clean={...process.env};for(const k of Object.keys(clean))if(/^CHAT2LOCAL_(OAUTH|DEVICE|REGISTRY)_/.test(k))delete clean[k];delete clean.NODE_TEST_CONTEXT;
  for(const selection of [{CHAT2LOCAL_OAUTH_PROVIDER_TEST_REQUIRED:'1'},{CHAT2LOCAL_OAUTH_PROVIDER_TEST_DENY_LEGACY:'1'},{CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR:'one',CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR:'two'}]){const result=spawnSync(process.execPath,['--input-type=module','-e',"await import('./tests/relay-runtime.mjs')"],{cwd:projectRoot,env:{...clean,...selection},encoding:'utf8',windowsHide:true});assert.equal(result.status,1);}
  for(const file of ['rust-device.test.mjs','rust-registry.test.mjs','rust-oauth-provider.test.mjs']){const result=spawnSync(process.execPath,['--test','--test-name-pattern=selection-unmatched','tests/'+file],{cwd:projectRoot,env:{...clean,CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR:path.join(os.tmpdir(),'missing-oauth-provider-'+crypto.randomUUID())},encoding:'utf8',windowsHide:true});assert.equal(result.status,1);assert.match(result.stdout+result.stderr,/ENOENT/);}
  const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'oauth-v1-reject-'));try{await fs.writeFile(path.join(temporary,'manifest.json'),JSON.stringify({v:1,kind:'oauth-bearer-device-registry'}));await assert.rejects(readArtifact(temporary,{requireProvider:true}),/Invalid OAuth artifact/);}finally{await fs.rm(path.join(temporary,'manifest.json'));await fs.rmdir(temporary);}
});
test('original provider differential: DCR/code/previous refresh/downscope/cleanup matches raw persisted text and TTL',wasm,async()=>{
  const execute=async rust=>{const clock=clockCrypto(),restore=clock.install(),kv=kvFixture(clock),env={OAUTH_KV:kv};try{const driver=rust?rustDriver(clock):await originalDriver();const client=await(await driver.fetch(registration({client_name:'\ud800'}),env)).json();const f=await flow(driver,env,client),first=await(await driver.fetch(form(f.exchange),env)).json();const second=await(await driver.fetch(form({client_id:client.client_id,grant_type:'refresh_token',refresh_token:first.refresh_token,scope:'files:read files:read unknown'}),env)).json();const previous=await(await driver.fetch(form({client_id:client.client_id,grant_type:'refresh_token',refresh_token:first.refresh_token}),env)).json();const revoke=await shape(await driver.fetch(form({client_id:client.client_id,token:second.access_token,token_type_hint:'refresh_token'}),env));const next=await flow(driver,env,client,{revokeExistingGrants:true});return {client,f,first,second,previous,revoke,next,rows:kv.snapshot(),effects:kv.effects};}finally{restore();}};
  const expected=await execute(false),actual=await execute(true);assert.ok(isDeepStrictEqual(actual,expected),'provider result, exact KV text, options and effect order must match original');
});
test('request-local facade ignores inherited legacy helper and covers actual default/api handlers',wasm,async()=>{
  const clock=clockCrypto(),kv=kvFixture(clock),p=rustDriver(clock).provider;let legacy=0,seen;
  const stale={lookupClient(){legacy++;throw Error('legacy');}},env={OAUTH_KV:kv,OAUTH_PROVIDER:stale};
  const response=await p.fetch(new Request(origin+'/authorize'),env,{},{origin,defaultHandler:{async fetch(_r,local){seen=local;assert.notEqual(local.OAUTH_PROVIDER,stale);assert.equal(await local.OAUTH_PROVIDER.lookupClient('absent'),null);return new Response('facade');}},apiHandler:{fetch(){throw Error('unexpected dispatch');}}});assert.equal(await response.text(),'facade');assert.notEqual(seen,env);assert.equal(env.OAUTH_PROVIDER,stale);assert.equal(legacy,0);assert.equal(Object.hasOwn(seen.OAUTH_PROVIDER,'createClient'),false);
});
test('parallel delete rejection returns before sibling drain, without replay or parent delete',wasm,async()=>{
  const clock=clockCrypto(),kv=kvFixture(clock),p=rustDriver(clock).provider,env={OAUTH_KV:kv};await kv.put('grant:user:g','{}');await kv.put('token:user:g:a','{}');await kv.put('token:user:g:b','{}');
  let release;const hold=new Promise(r=>release=r);kv.setHook(async(stage,e)=>{if(stage==='before'&&e.op==='delete'){if(e.key.endsWith(':a'))throw Error('first delete failed');if(e.key.endsWith(':b'))await hold;}});
  await assert.rejects(p.revokeGrant('g','user',env,{origin}),/first delete failed/);assert.equal(p.drains.size,1);assert.equal(kv.rows.has('token:user:g:b'),true);assert.equal(kv.rows.has('grant:user:g'),true);release();await Promise.all([...p.drains]);assert.equal(kv.rows.has('token:user:g:b'),false);assert.equal(kv.rows.has('grant:user:g'),true);assert.equal(kv.effects.filter(e=>e.op==='delete').length,2);
});
test('wrong primitive type and WASM trap fail closed before dispatch, without mutations',wasm,async()=>{
  let dispatch=0;const options={origin,defaultHandler:{fetch(){dispatch++;return new Response('unexpected');}},apiHandler:{fetch(){dispatch++;return new Response('unexpected');}}};
  const bad=rustDriver(clockCrypto(),{instantiate(module){const e=new WebAssembly.Instance(module,{}).exports;return{exports:{...e,provider_command(){throw new WebAssembly.RuntimeError('fixture');}}};}}).provider;
  await assert.rejects(bad.fetch(new Request(origin+'/authorize'),{OAUTH_KV:{}},{},options),{code:'EOAUTHCORE'});
  const clock=clockCrypto(),kv=kvFixture(clock),p=rustDriver(clock).provider;kv.get=async()=>({wrong:true});await assert.rejects(p.lookupClient('client',{OAUTH_KV:kv},{origin}),{code:'EOAUTHCORE'});assert.equal(dispatch,0);assert.equal(kv.effects.length,0);assert.equal(p.drains.size,0);
});
