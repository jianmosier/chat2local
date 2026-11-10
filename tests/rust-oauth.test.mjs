import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { readArtifact, projectRoot } from '../scripts/oauth-artifact.mjs';
import { RustOAuthBearer } from '../src/relay/rust-oauth.mjs';
import { memoryKV, tokenRow, request, oracle, rustResult, resource, scopes } from './oauth-fixture.mjs';
const directory=process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR??process.env.CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR??path.join(projectRoot,'.artifacts/rust-oauth');
let artifact,reason;try{artifact=await readArtifact(directory,{requireProvider:process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_REQUIRED==='1'||!!process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR});}catch(error){if(process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_REQUIRED==='1'||process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR||process.env.CHAT2LOCAL_OAUTH_TEST_REQUIRED==='1'||process.env.CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR)throw error;reason='Build explicit OAuth artifact';}
const options={skip:reason},compiled=artifact&&new WebAssembly.Module(artifact.oauthBytes);
const runner=opts=>new RustOAuthBearer(compiled,opts);
test('strict OAuth selection rejects absent or conflicting artifact selectors',()=>{
  const clean={...process.env};for(const key of Object.keys(clean))if(/^CHAT2LOCAL_(OAUTH(?:_PROVIDER)?|DEVICE|REGISTRY)_TEST_/.test(key))delete clean[key];
  delete clean.NODE_TEST_CONTEXT;
  for(const selection of [{CHAT2LOCAL_OAUTH_TEST_REQUIRED:'1'},{CHAT2LOCAL_OAUTH_TEST_DENY_LEGACY:'1'},{CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR:'one',CHAT2LOCAL_DEVICE_TEST_ARTIFACT_DIR:'two'}]){
    const result=spawnSync(process.execPath,['--input-type=module','-e',"await import('./tests/relay-runtime.mjs')"],{cwd:projectRoot,env:{...clean,...selection},encoding:'utf8',windowsHide:true});assert.equal(result.status,1);assert.match(result.stderr,/explicit artifact directory|directories must agree/);
  }
  for(const file of ['rust-device.test.mjs','rust-registry.test.mjs']){
    const result=spawnSync(process.execPath,['--test','--test-name-pattern=nonexistent-selection-probe','tests/'+file],{cwd:projectRoot,env:{...clean,CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR:path.join(os.tmpdir(),'c2l-missing-oauth-'+crypto.randomUUID())},encoding:'utf8',windowsHide:true});assert.equal(result.status,1);assert.match(result.stdout+result.stderr,/ENOENT/);
  }
});
async function compare(fixture,req=request('Bearer '+fixture.token),r=runner()) {
  const js=memoryKV([[fixture.key,fixture.text]]),rust=memoryKV([[fixture.key,fixture.text]]);
  const expected=await oracle(req,js),actual=await rustResult(r,req,rust);assert.deepEqual(actual,expected);assert.deepEqual(rust.reads,js.reads);assert.deepEqual(rust.writes,[]);return actual;
}
test('bearer header, exact token text and token-row truthiness match original provider',options,async()=>{
  const fixture=await tokenRow();
  for(const header of [undefined,'bearer '+fixture.token,'Bearer','Basic x','Bearer a:b','Bearer a:b:c:d','Bearer '+fixture.token])await compare(fixture,request(header));
  for(const token of ['::','u::x',':g:x','u:g:', 'u:g: space', 'u:g:x\tinside','ü:gránt:sécret'])await compare(await tokenRow({token}));
  for(const text of ['null','false','0','""','true','1','[]','{}','"nonempty"','{'])await compare({...fixture,text});
});
test('expiry JavaScript coercion, exact audience and URL policy match pinned provider',options,async()=>{
  const fixture=await tokenRow(),base=JSON.parse(fixture.text),now=Date.now(),second=Math.floor(now/1000);
  const old=Date.now;Date.now=()=>now;
  try {
    for(const expiresAt of [undefined,null,false,true,0,second-1,second,second+1,String(second),' 0x10 ','0b10','0o10','+Infinity','-Infinity','NaN','1_0','\u0085','\ufeff',[],[null],[second],[1,2],{}, {valueOf:1},{toString:0},{toString:null}])await compare({...fixture,text:JSON.stringify({...base,expiresAt})},request('Bearer '+fixture.token),runner({now:()=>now}));
    for(const audience of [undefined,null,false,resource,[resource],[],[resource,resource],resource+'/',resource+'?x=1',{},1])await compare({...fixture,text:JSON.stringify({...base,audience})});
    for(const url of [resource,resource+'?q=a',resource+'/child',resource+'foo'])await compare(fixture,request('Bearer '+fixture.token,url));
  } finally {Date.now=old;}
});
test('wrapped crypto, property errors, JSON unknown UTF16, nonfatal UTF8 and BOM match provider',options,async()=>{
  const fixture=await tokenRow(),base=JSON.parse(fixture.text);
  for(const change of [{grant:null},{grant:undefined},{grant:1},{grant:{}},{wrappedEncryptionKey:null},{wrappedEncryptionKey:'broken'},{wrappedEncryptionKey:base.wrappedEncryptionKey.slice(1)},{grant:{encryptedProps:'broken'}},{grant:{encryptedProps:base.grant.encryptedProps.slice(4)}}])await compare({...fixture,text:JSON.stringify({...base,...change})});
  for(const plaintext of [Buffer.from('{"unknown":"\\ud800","n":9007199254740993,"z":-0,"x":1e309,"__proto__":{"keep":true}}'),Buffer.from('[1,null,"\\udfff"]'),Buffer.from('null'),Buffer.from('\ufeff{"bom":true}'),Buffer.from([123,34,120,34,58,34,255,34,125]),Buffer.from('{'),Buffer.from('undefined')])await compare(await tokenRow({plaintext}));
});
test('direct original handler props preserve negative zero and overflowing JSON numbers before serialization',options,async()=>{
  const fixture=await tokenRow({plaintext:Buffer.from('{"negativeZero":-0,"positive":1e309,"negative":-1e309,"nested":[-0,1e309,-1e309],"unknown":"\\ud800"}')});
  const {props}=await compare(fixture);assert.ok(Object.is(props.negativeZero,-0));assert.equal(props.positive,Infinity);assert.equal(props.negative,-Infinity);assert.ok(Object.is(props.nested[0],-0));assert.equal(props.nested[1],Infinity);assert.equal(props.nested[2],-Infinity);assert.equal(props.unknown,'\ud800');
});
test('600 nested singleton arrays retain original expiry and base64 coercion',options,async()=>{
  const fixture=await tokenRow(),row=JSON.parse(fixture.text),nest=value=>{for(let i=0;i<600;i++)value=[value];return value;};
  for(const change of [{expiresAt:nest(Math.floor(Date.now()/1000)+3600)},{wrappedEncryptionKey:nest(row.wrappedEncryptionKey)},{grant:{encryptedProps:nest(row.grant.encryptedProps)}},{expiresAt:nest(null)},{expiresAt:nest({toString:0})}])await compare({...fixture,text:JSON.stringify({...row,...change})});
});
test('greater-than-one-MiB unknown props and token fields pass chunked transport without data loss',options,async()=>{
  const text='x'.repeat(1_100_000),fixture=await tokenRow({props:{future:text,lone:'\ud800'},row:{unknown:text}});
  const result=await compare(fixture);assert.equal(result.props.future.length,1_100_000);assert.equal(result.props.lone,'\ud800');assert.ok(Buffer.byteLength(fixture.text)>2_000_000);
});
test('each concurrent request has private core memory and crypto keys with final cleanup',options,async()=>{
  const instances=[],r=runner({instantiate(module){const i=new WebAssembly.Instance(module,{});instances.push(i);return i;}});
  const fixtures=await Promise.all(Array.from({length:20},(_,i)=>tokenRow({token:`user${i}:grant${i}:secret${i}`,props:{owner:i}})));
  await Promise.all(fixtures.map(async(fixture,i)=>{const result=await compare(fixture,request('Bearer '+fixture.token),r);assert.equal(result.props.owner,i);}));
  assert.equal(instances.length,20);for(const instance of instances)assert.equal(new Uint8Array(instance.exports.memory.buffer).some(n=>n!==0),false);
});
function corrupt(mutate) { return runner({instantiate(module){const e=new WebAssembly.Instance(module,{}).exports;let output;
  return {exports:{...e,command(n){const status=e.command(n);if(status===0){const length=e.output_len();assert.ok(length<1_048_576);e.output_read(0);const value=JSON.parse(new TextDecoder().decode(new Uint8Array(e.memory.buffer,e.output_ptr(),length)));mutate(value);output=new TextEncoder().encode(JSON.stringify(value));}return status;},output_len:()=>output.length,output_read(offset){const chunk=output.subarray(offset,offset+1_048_576);new Uint8Array(e.memory.buffer,e.output_ptr(),chunk.length).set(chunk);return chunk.length;}}};}}); }
test('wrong serial/type/sequence, premature accept and traps never read or dispatch a fallback',options,async()=>{
  const fixture=await tokenRow();
  for(const mutate of [v=>v.serial++,v=>v.result.sequence++,v=>v.result.op.type='kv_put',v=>v.result={kind:'accept',propsJson:'{}'},v=>v.result.op={type:'decrypt',key:1},()=>{throw new WebAssembly.RuntimeError('fixture');}]) {
    const kv=memoryKV([[fixture.key,fixture.text]]);await assert.rejects(corrupt(mutate).authenticate(request('Bearer '+fixture.token),{OAUTH_KV:kv},{resource,scopes}),e=>e.code==='EOAUTHCORE');assert.deepEqual(kv.reads,[]);assert.deepEqual(kv.writes,[]);
  }
  for(const failAt of [1,2,3,4,5,6,7]){
    let count=0;const r=runner({instantiate(module){const e=new WebAssembly.Instance(module,{}).exports;return{exports:{...e,command(n){if(++count===failAt)throw new WebAssembly.RuntimeError('fixture');return e.command(n);}}};}}),kv=memoryKV([[fixture.key,fixture.text]]);
    await assert.rejects(r.authenticate(request('Bearer '+fixture.token),{OAUTH_KV:kv},{resource,scopes}),e=>e.code==='EOAUTHCORE');assert.equal(count,failAt);assert.ok(kv.reads.length<=1);assert.deepEqual(kv.writes,[]);
  }
});
test('artifact reader rejects missing, stale and unbound OAuth inputs',options,async t=>{
  const temp=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-oauth-artifact-'));t.after(()=>fs.rm(temp,{recursive:true,force:true}));await assert.rejects(readArtifact(temp));await fs.cp(directory,temp,{recursive:true});const manifest=structuredClone(artifact.manifest);delete manifest.sources['crates/oauth-compat-core/src/value.rs'];await fs.writeFile(path.join(temp,'manifest.json'),JSON.stringify(manifest));await assert.rejects(readArtifact(temp),/Incomplete/);
});
