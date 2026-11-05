import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { NativeAccountOnboarding } from '../src/agent/account-onboarding.mjs';
import { FolderManagement } from '../src/agent/folder-management.mjs';
import { AccountIdentity, accountPrincipal } from '../src/relay/account-identity.mjs';
import { prepareUpgrade } from '../scripts/upgrade-session.mjs';
import { TerminalService } from '../src/agent/terminal.mjs';
import { terminalShell } from '../src/agent/terminal/shell.mjs';
import { readJsonCompatArtifact, sourceFiles } from '../scripts/json-compat-artifact.mjs';
const root=fileURLToPath(new URL('..',import.meta.url));
const executable=process.env.CHAT2LOCAL_JSON_COMPAT_TEST_EXECUTABLE||path.join(root,'.artifacts/rust-json-compat/chat2local-js-value-compat-fixture'+(process.platform==='win32'?'.exe':''));
const wasmPath=process.env.CHAT2LOCAL_JSON_COMPAT_TEST_WASM||path.join(root,'.artifacts/rust-json-compat/json-compat.wasm');
let module,reason,artifact;
try{artifact=await readJsonCompatArtifact({executable,wasm:wasmPath});module=new WebAssembly.Module(artifact.wasmBytes);}catch(error){
  const explicit=process.env.CHAT2LOCAL_JSON_COMPAT_TEST_REQUIRED==='1'||process.env.CHAT2LOCAL_JSON_COMPAT_TEST_EXECUTABLE||process.env.CHAT2LOCAL_JSON_COMPAT_TEST_WASM;
  const absent=await fs.stat(path.join(root,'.artifacts/rust-json-compat')).then(()=>false,err=>{if(err.code==='ENOENT')return true;throw err;});
  if(explicit||!absent)throw error;reason='Build JSON compatibility fixtures';
}
const selected={skip:reason},units=text=>Array.from({length:text.length},(_,i)=>text.charCodeAt(i)),hash=text=>createHash('sha256').update(text).digest('hex');
const parseRequest=text=>({op:'roundtrip',input:units(text)});
function execute(requests){
  const child=spawnSync(executable,[],{input:requests.map(value=>JSON.stringify(value)).join('\n')+'\n',encoding:'utf8',maxBuffer:32*1024*1024,timeout:30000,windowsHide:true,env:{...process.env,PATH:''}});
  assert.ifError(child.error);assert.equal(child.status,0,child.stderr);assert.equal(child.stderr,'');
  const native=child.stdout.trimEnd().split('\n').map(line=>JSON.parse(line));assert.equal(native.length,requests.length);
  const e=new WebAssembly.Instance(module,{}).exports;assert.deepEqual(WebAssembly.Module.imports(module),[]);
  const wasm=requests.map(request=>{const bytes=Buffer.from(JSON.stringify(request));assert.ok(bytes.length<=4*1024*1024);new Uint8Array(e.memory.buffer,e.input_ptr(),bytes.length).set(bytes);assert.equal(e.command(bytes.length),0);return JSON.parse(Buffer.from(e.memory.buffer,e.output_ptr(),e.output_len()).toString());});
  assert.deepEqual(native,wasm,'native and WASM use identical Rust semantics');return native;
}
function assertOracle(requests,values){const results=execute(requests);results.forEach((result,index)=>{const json=JSON.stringify(values[index]);assert.deepEqual(result,{ok:true,defined:json!==undefined,json:json??null,sha256:json===undefined?null:hash(json)});if(json!==undefined)assert.equal(JSON.stringify(JSON.parse(result.json)),json);});return results;}
async function capture(call){const original=JSON.stringify,seen=[];JSON.stringify=(value,...args)=>{const text=original(value,...args);seen.push({value,text});return text;};try{return{value:await call(),seen};}finally{JSON.stringify=original;}}

test('Node oracle covers insertion order, duplicate keys, array indices and prototype-named data',selected,()=>{
  const texts=['{"b":1,"2":2,"10":3,"a":4,"b":5,"0":6,"01":7,"-0":8,"4294967294":9,"4294967295":10,"00":11}',
    '{"__proto__":{"polluted":true},"constructor":1,"prototype":2,"__proto__":3}',
    '{"nested":{"x":1,"10":2,"1":3,"x":4},"list":[null,true,false,"x"]}', ' [ ] ','{}','null','true','false'];
  assertOracle(texts.map(parseRequest),texts.map(JSON.parse));assert.equal({}.polluted,undefined);
});
test('raw and escaped UTF16 preserve isolated surrogates, pairs, controls and Unicode without normalization',selected,()=>{
  const texts=['"\ud800"','"\udfff"','"\ud800\ud800\udc00\udfff"','"\\ud800"','"\\uD83D\\uDE00"','"汉字😀é é\u2028\u2029"','"\\b\\t\\n\\f\\r\\u0000\\u001f\\/\\\\\\\""','{"\ud800":"\udfff","\\ud800":"replaced"}'];
  assertOracle(texts.map(parseRequest),texts.map(JSON.parse));
});
test('decimal parsing matches JS rounding, overflow and exact exponent formatting boundaries',selected,()=>{
  const texts=['-0','0','1e400','-1e400','1e-400','-1e-400','9007199254740993','9007199254740995','1000000000000000128','1e-7','1e-6','1e20','1e21','5e-324','2.2250738585072014e-308','1.7976931348623157e308','1.00000000000000011102230246251565404236316680908203125'];
  assertOracle(texts.map(parseRequest),texts.map(JSON.parse));
});
test('50,000 deterministic f64 bit patterns match actual Node shortest-roundtrip bytes and SHA256',selected,()=>{
  let state=0x95e11a2b7c5d9f01n;const mask=(1n<<64n)-1n,bits=['8000000000000000','7ff0000000000000','fff0000000000000','7ff8000000000001','0000000000000001','7fefffffffffffff'];
  for(let i=0;i<50000;i++){state^=state<<13n;state&=mask;state^=state>>7n;state^=state<<17n;state&=mask;bits.push(state.toString(16).padStart(16,'0'));}
  const view=new DataView(new ArrayBuffer(8)),values=bits.map(value=>{view.setBigUint64(0,BigInt('0x'+value));return view.getFloat64(0);});
  assertOracle([{op:'numbers',bits}],[values]);
});
test('internal undefined, array holes and nonfinite values retain JSON.stringify distinctions',selected,()=>{
  const values=[];values.length=2;values[1]=undefined;values.push(NaN,Infinity,-0);
  assertOracle([{op:'undefined'},{op:'special'}],[undefined,{omit:undefined,nil:NaN,values,negativeZero:-0}]);
});
test('shared containers serialize twice while an array ancestor cycle is refused',selected,()=>{
  const child={x:1};assertOracle([{op:'shared'}],[[child,child]]);assert.equal(execute([{op:'cycle-array'}])[0].error,'Cycle');
});
test('replacement, removal and append preserve nested unknown-field positions and safe __proto__ data',selected,()=>{
  const text='{"b":1,"unknown":{"later":"\\ud800","2":2,"first":1},"a":3}',value=JSON.parse(text);
  const mutations=[{key:units('b'),value:units('4')},{path:[units('unknown')],key:units('first'),value:units('5')},{key:units('a'),remove:true},{key:units('a'),value:units('null')},{key:units('__proto__'),value:units('{"safe":true}')},{key:units('omit')}];
  value.b=4;value.unknown.first=5;delete value.a;value.a=null;Object.defineProperty(value,'__proto__',{value:{safe:true},enumerable:true});value.omit=undefined;
  assertOracle([{...parseRequest(text),mutations}],[value]);
});
test('deterministic generated JSON values and duplicate-key number lexemes match both runtimes',selected,()=>{
  let n=0x12345678;const next=()=>{n=(Math.imul(n,1664525)+1013904223)>>>0;return n;};
  const generate=depth=>{if(depth===0)return ['null','true','false',JSON.stringify(String.fromCharCode(next()%65536)),String(next())+'e-'+next()%330][next()%5];const parts=Array.from({length:next()%6},()=>generate(depth-1));return next()%2?'['+parts.join(',')+']':'{'+parts.map((v,i)=>JSON.stringify(['2','01','b','a','b','__proto__'][i])+':'+v).join(',')+'}';};
  const texts=Array.from({length:400},()=>generate(3));assertOracle(texts.map(parseRequest),texts.map(JSON.parse));
});
test('malformed JSON is an error rather than missing/null; limits and cycles are distinct refusals',selected,()=>{
  const texts=['',' ','undefined','NaN','Infinity','+1','01','-01','1.','1e','--1','[1,]','{"x":1,}','{"x" 1}','[','{"x":}','"\n"','"\\v"','"\\u0ff"','nullx','\ufeff{}'];
  for(const text of texts)assert.throws(()=>JSON.parse(text));
  for(const result of execute(texts.map(parseRequest)))assert.equal(result.error,'Syntax');
  const limits={input_units:100,nodes:100,depth:100,output_bytes:100};
  const requests=[{...parseRequest('{}'),limits:{...limits,input_units:1}},{...parseRequest('[0]'),limits:{...limits,depth:0}},{...parseRequest('[0]'),limits:{...limits,nodes:2}},{...parseRequest('"😀"'),limits:{...limits,output_bytes:5}},{op:'cycle'}];
  assert.deepEqual(execute(requests).map(result=>result.error),['Limit','Limit','Limit','Limit','Cycle']);
});
test('iterative parse/stringify/drop support deep legacy fields and a wide ordered object',selected,()=>{
  const deep='['.repeat(20000)+'0'+']'.repeat(20000),wide='{'+Array.from({length:10000},(_,i)=>'"key'+i+'":'+i).join(',')+'}';
  const results=execute([parseRequest(deep),parseRequest(wide),{...parseRequest(deep),op:'clone'}]);assert.equal(results[0].json,deep);assert.equal(results[1].json,JSON.stringify(JSON.parse(wide)));assert.equal(results[2].json,deep);
  let value=JSON.parse(results[0].json);for(let i=0;i<20000;i++)value=value[0];assert.equal(value,0);
});

test('original native consent policy digest and assertCurrent survive Rust JSON roundtrips; changed permissions reject',selected,async t=>{
  const base=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-json-consent-'));t.after(()=>fs.rm(base,{recursive:true,force:true,maxRetries:10,retryDelay:100}));
  const shared=path.join(base,'shared'),state=path.join(base,'state');await fs.mkdir(shared);await fs.mkdir(state);const stat=await fs.stat(shared,{bigint:true});
  const identity={deviceId:'a'.repeat(32),origin:'https://fixture.test'},selection={id:'r1',path:await fs.realpath(shared),write:true,writeMode:'direct',dev:String(stat.dev),ino:String(stat.ino),future:JSON.parse('{"z":"\\ud800","10":1,"1":2,"a":3}')};
  let config={paused:false,roots:[selection],accountRoots:[{id:'retained',intentId:'b'.repeat(32),unknown:{last:1,first:2}}],terminalGrants:[{rootId:'retained',allow:true,unknown:{z:2,a:1}}]};
  let local={flowId:'c'.repeat(32),deviceId:identity.deviceId,origin:identity.origin,revision:7,accessProfile:'project',selections:[selection]};
  const service=new NativeAccountOnboarding({store:{directory:state},getConfig:()=>config,getIdentity:()=>identity,getRevision:()=>7});
  const first=await capture(()=>service.policy(local));assert.equal(first.seen.length,1);const result=execute([parseRequest(first.seen[0].text)])[0];assert.equal(result.sha256,first.value);
  local.policyDigest=first.value;const serialized=execute([parseRequest(JSON.stringify({config,local}))])[0];({config,local}=JSON.parse(serialized.json));
  assert.equal(service.policy(local),first.value);await service.assertCurrent(local,{intentId:local.flowId,policyDigest:first.value});
  config.roots[0].writeMode='review';await assert.rejects(()=>service.assertCurrent(local,{intentId:local.flowId,policyDigest:first.value}),/发生变化/);
});
test('original management request receipt and account identity digests use Rust-identical bytes',selected,async()=>{
  const input={connectionId:'d'.repeat(32),requestId:'e'.repeat(32),folders:[{mode:'direct',path:'fixture/😀/\ud800'}]},requestJson=JSON.stringify(input);
  const receipt=execute([parseRequest(requestJson)])[0];const local={management:true,managementRequestDigest:receipt.sha256,context:{}};
  const manager=new FolderManagement({store:{readPrivateRecord:async key=>key.startsWith('onboarding-intent-')?{}:local}});manager.current=()=>({});manager.inspect=async()=>({accepted:true});
  const captured=await capture(()=>manager.performManagement('prepare',JSON.parse(receipt.json)));assert.deepEqual(captured.value,{accepted:true});assert.equal(captured.seen[0].text,requestJson);
  await assert.rejects(()=>manager.performManagement('prepare',{...input,folders:[{...input.folders[0],mode:'review'}]}),/不能更换/);
  const claims={issuer:'https://fixture.test/issuer',subject:'fixture-user',sessionId:'session-\ud800-😀',expiresAt:2000000},identity=new AccountIdentity({verifySession:async()=>claims,now:()=>1000000});
  const account=await capture(async()=>accountPrincipal(await identity.authenticate({})));const outputs=execute(account.seen.filter(row=>Array.isArray(row.value)).map(row=>parseRequest(row.text)));
  assert.equal(outputs[0].sha256,account.value.identityKey);assert.equal(outputs[1].sha256,account.value.sessionBinding);
});
test('original controlled-upgrade fingerprint accepts unchanged Rust data and rejects actual permission changes',selected,async()=>{
  let saved=JSON.parse('{"config":{"roots":[{"id":"keep","writeMode":"direct","unknown":{"z":"\\ud800","2":1,"a":2}}],"paused":false},"secrets":{"fixture":"synthetic-only","unknown":{"b":1,"a":2}}}'),running=true,version='old';
  const store={load:async()=>saved,readSession:async()=>({origin:'http://127.0.0.1:47631',token:'a'.repeat(64),instanceId:'fixture'})};
  const call=async(_session,route)=>{if(route==='/api/shutdown'){running=false;return{ok:true};}if(!running)throw Object.assign(Error('fixture closed'),{code:'ECONNREFUSED'});return{name:'chat2local',instanceId:'fixture',version,paused:false,pending:[]};};
  const before=await capture(()=>prepareUpgrade('new',{store,call,wait:async()=>{}}));const input=before.seen.find(row=>row.value?.config===saved.config);assert.ok(input);
  const result=execute([parseRequest(input.text)])[0];assert.equal(result.sha256,hash(input.text));saved=JSON.parse(result.json);running=true;version='new';await before.value.verify();
  saved.config.roots=[];await assert.rejects(()=>before.value.verify(),/retain/);
});
test('original terminal inputHash accepts Rust-identical BOM/lone-surrogate commands without launching a process',selected,async()=>{
  const args={requestId:'a'.repeat(32),rootId:'fixture-root',command:'echo "\ufeff😀\ud800"',cwd:'.',timeoutMs:1000},access={connectionId:'b'.repeat(32),resource:'https://fixture.test/mcp',deviceId:'c'.repeat(32)};
  const values=[args.command,args.cwd,args.timeoutMs,terminalShell(args.command).shell,args.rootId,access.connectionId,access.resource,access.deviceId],result=execute([parseRequest(JSON.stringify(values))])[0];
  let statusCalls=0;const service={journal:{assertAvailable(){},read:async()=>({inputHash:result.sha256})},invoke:async()=>{statusCalls++;return{status:'retained'};}};
  assert.deepEqual(await TerminalService.prototype.execute.call(service,args,access,{}),{status:'retained'});assert.equal(statusCalls,1);
  await assert.rejects(()=>TerminalService.prototype.execute.call(service,{...args,command:args.command+' changed'},access,{}),/different command/);assert.equal(statusCalls,1);
});
test('selected missing native fixture cannot silently fall back, and WASM has no runtime imports',selected,()=>{
  const result=spawnSync(process.execPath,['--input-type=module','-e',"await import('./tests/rust-json-compat.test.mjs')"],{cwd:root,encoding:'utf8',env:{...process.env,CHAT2LOCAL_JSON_COMPAT_TEST_REQUIRED:'1',CHAT2LOCAL_JSON_COMPAT_TEST_EXECUTABLE:path.join(root,'.artifacts/absent-json-fixture.exe'),CHAT2LOCAL_JSON_COMPAT_TEST_WASM:wasmPath}});assert.notEqual(result.status,0);assert.match(result.stderr,/ENOENT|JSON fixture artifact/);assert.deepEqual(WebAssembly.Module.imports(module),[]);
});
test('strict direct runs reject stale sources and missing/corrupt artifacts before executing the fixture',selected,async t=>{
  const base=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-json-artifact-'));t.after(()=>fs.rm(base,{recursive:true,force:true,maxRetries:10,retryDelay:100}));
  const artifacts=path.join(base,'artifacts'),sources=path.join(base,'sources');await fs.mkdir(artifacts);await fs.mkdir(sources);
  const copiedExe=path.join(artifacts,path.basename(executable)),copiedWasm=path.join(artifacts,path.basename(wasmPath)),manifestPath=path.join(artifacts,'manifest.json');
  await fs.copyFile(executable,copiedExe);await fs.copyFile(wasmPath,copiedWasm);await fs.writeFile(manifestPath,JSON.stringify(artifact.manifest));
  for(const file of sourceFiles){await fs.mkdir(path.dirname(path.join(sources,file)),{recursive:true});await fs.copyFile(path.join(root,file),path.join(sources,file));}
  await readJsonCompatArtifact({executable:copiedExe,wasm:copiedWasm,sourceRoot:sources});
  await fs.appendFile(path.join(sources,'crates/js-value-compat/src/lib.rs'),'\n// stale isolated fixture copy\n');
  await assert.rejects(()=>readJsonCompatArtifact({executable:copiedExe,wasm:copiedWasm,sourceRoot:sources}),/stale source/);
  const direct=()=>spawnSync(process.execPath,['--input-type=module','-e',"await import('./tests/rust-json-compat.test.mjs')"],{cwd:root,encoding:'utf8',env:{...process.env,CHAT2LOCAL_JSON_COMPAT_TEST_REQUIRED:'1',CHAT2LOCAL_JSON_COMPAT_TEST_EXECUTABLE:copiedExe,CHAT2LOCAL_JSON_COMPAT_TEST_WASM:copiedWasm}});
  const stale=structuredClone(artifact.manifest);stale.sources['crates/js-value-compat/src/lib.rs']='0'.repeat(64);await fs.writeFile(manifestPath,JSON.stringify(stale));
  let result=direct();assert.notEqual(result.status,0);assert.match(result.stderr,/stale source/);
  await fs.writeFile(manifestPath,JSON.stringify(artifact.manifest));await fs.appendFile(copiedExe,Buffer.from([0]));
  result=direct();assert.notEqual(result.status,0);assert.match(result.stderr,/binary hash mismatch/);
  await fs.copyFile(executable,copiedExe);await fs.appendFile(copiedWasm,Buffer.from([0]));
  result=direct();assert.notEqual(result.status,0);assert.match(result.stderr,/binary hash mismatch/);
  await fs.copyFile(wasmPath,copiedWasm);await fs.rm(copiedExe);result=direct();assert.notEqual(result.status,0);assert.match(result.stderr,/ENOENT/);
  await fs.rm(manifestPath);result=direct();assert.notEqual(result.status,0);assert.match(result.stderr,/ENOENT/);
});
