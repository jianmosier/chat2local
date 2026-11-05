import { readArtifact } from './relay-runtime.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs/promises';
import os from 'node:os';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { projectRoot, hash } from '../scripts/rust-relay-artifact.mjs';
import { RustRegistryRunner } from '../src/relay/rust-registry.mjs';
import { consumeBudget } from '../src/relay/request-budget.mjs';
import { rosterStorageRoute } from '../src/relay/device-roster.mjs';
import { registryTransaction } from '../src/relay/registry-transaction.mjs';
import { sha256 } from '../src/shared/protocol.mjs';
import { accountFixture } from './account-fixture.mjs';
import { AccountDirectory } from '../src/relay/account-directory.mjs';
import { OnboardingStore } from '../src/relay/onboarding-store.mjs';
import { denyLegacyEntry } from './relay-runtime.mjs';

export const EXPECTED_REGISTRY_OPERATIONS = Object.freeze([
  'registry.selfEnroll','registry.enroll','registry.ticket.inspect','budget.consume','roster.linkTicket.create','roster.linkTicket.consume','roster.append',
  'account.resolve','account.execute','onboarding.records','onboarding.flow.create','onboarding.device.provision','onboarding.native.start','onboarding.finish.take',
  'instance.owner.ensure','instance.manage','instance.shares.remove','instance.invitation.create','instance.invitation.revoke','instance.invitation.pin','instance.flow.create',
  'instance.invitation.claim','instance.recovery.claim','instance.native.bindEpoch','instance.finish.take','instance.remember.store','install.password.configure','install.rate.consume',
  'install.session.create','install.ticket.create','install.context.ticket','install.context.session','install.authorize.check','install.authorize.pin','install.authorize.advance','install.claim.ticket','install.ticket.ready',
]);
const directory=process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR??process.env.CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR??process.env.CHAT2LOCAL_REGISTRY_TEST_ARTIFACT_DIR??path.join(projectRoot,'.artifacts/rust-registry');
let artifact,reason;try{artifact=await readArtifact(directory);}catch(error){if(process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_REQUIRED==='1'||process.env.CHAT2LOCAL_OAUTH_PROVIDER_TEST_ARTIFACT_DIR||process.env.CHAT2LOCAL_OAUTH_TEST_REQUIRED==='1'||process.env.CHAT2LOCAL_OAUTH_TEST_ARTIFACT_DIR||process.env.CHAT2LOCAL_REGISTRY_TEST_REQUIRED==='1'||process.env.CHAT2LOCAL_REGISTRY_TEST_ARTIFACT_DIR)throw error;reason='Build combined Registry artifact';}
const wasm={skip:reason},compiled=artifact&&new WebAssembly.Module(artifact.registryBytes);
const runner=options=>new RustRegistryRunner(compiled,options);
const NOW=1_000_000,ID='a'.repeat(32),HASH='b'.repeat(64),SECOND='c'.repeat(64);
const coverage=[];
const runtimeEvidence=[];
function recordCoverage(events,fixture,mf){
  for(const event of events.filter(e=>e.kind==='rust-decided')){
    const completion=events.find(e=>e.kind==='tx-completed'&&e.transaction===event.transaction&&e.attempt===event.attempt&&e.op===event.op);
    assert.ok(completion,fixture+': decision has a matching real transaction completion');
    assert.equal(completion.outcome,event.outcome==='normal'?'commit':'abort');
    coverage.push({fixture,runtime:mf.fixtureEvidence.id,case:event.case||fixture,op:event.op,branch:event.branch,transaction:event.transaction,attempt:event.attempt,outcome:completion.outcome});
  }
}
class Memory {
  constructor(entries=[]){this.data=new Map(entries);this.effects=[];this.tail=Promise.resolve();}
  transaction(fn){const result=this.tail.then(async()=>{const draft=structuredClone(this.data);const tx={get:async key=>structuredClone(draft.get(key)),put:async(key,v)=>{this.effects.push('put');draft.set(key,structuredClone(v));},delete:async key=>{this.effects.push('delete');for(const k of Array.isArray(key)?key:[key])draft.delete(k);},list:async({prefix,limit})=>new Map([...draft].filter(([k])=>k.startsWith(prefix)).sort(([a],[b])=>a<b?-1:a>b?1:0).slice(0,limit).map(([k,v])=>[k,structuredClone(v)]))};const value=await fn(tx);this.data=draft;return value;});this.tail=result.catch(()=>{});return result;}
}

test('Registry ABI basic budget matches JS and preserves unknown root cycles, Map aliases, typed bytes, Date and BigInt',wasm,async()=>{
  const value={count:1,until:NOW+5000,future:{date:new Date(321),bytes:new Uint8Array([1,2]),big:12n}};value.self=value;value.map=new Map([['root',value]]);
  const a=new Memory([['budget:register',value]]),b=new Memory([['budget:register',value]]);
  const js=await consumeBudget(a,{bucket:'register'},NOW),rust=await consumeBudget(b,{bucket:'register'},NOW,runner());assert.deepEqual(await rust.json(),await js.json());assert.deepEqual(b.data,a.data);
  const saved=b.data.get('budget:register');assert.equal(saved.self,saved);assert.equal(saved.map.get('root'),saved);assert.equal(saved.future.big,12n);
});

test('Registry diagnostic observers cannot turn a committed operation into failure or replace an abort error',wasm,async()=>{
  const store=new Memory(),r=runner({trace(){throw Error('observer only');}});
  const answer=await registryTransaction(store,r,'registry.enroll',{value:{deviceId:ID}},()=>assert.fail('Rust selected legacy callback'));
  assert.equal(answer.httpStatus,200);assert.equal(store.data.get('device:'+ID),true);assert.equal(store.data.get('deviceCount'),1);assert.equal(store.effects.length,2);
  const expected=Error('original storage failure');await assert.rejects(r.transaction({transaction:fn=>fn({get:async()=>{throw expected;}})},'registry.enroll',{value:{deviceId:ID}}),e=>e===expected);
});

test('known malformed counters fail closed and unknown BigInt/opaque payloads count toward the graph bound',wasm,async()=>{
  for(const count of ['0x64',' 100 ',1n,NaN,Infinity]){const store=new Memory([['deviceCount',count]]);await assert.rejects(runner().transaction(store,'registry.enroll',{value:{deviceId:ID}}));assert.equal(store.data.has('device:'+ID),false);}
  const huge=1n<<2_000_000n;const value={count:0,until:NOW+1,future:Array(40).fill(huge)},store=new Memory([['budget:register',value]]);
  await assert.rejects(consumeBudget(store,{bucket:'register'},NOW,runner()),e=>e.code==='EREGISTRY');assert.equal(store.effects.length,0);
  const extra={date:new Date(4),regex:/fixture/gi,error:new Error('retained',{cause:new Map([['x',5n]])})};
  const small=new Memory([['budget:register',{count:0,until:NOW+1,extra}]]);await consumeBudget(small,{bucket:'register'},NOW,runner());assert.equal(small.data.get('budget:register').extra.regex.source,'fixture');assert.equal(small.data.get('budget:register').extra.error.cause.get('x'),5n);
});

test('malformed abort decisions cannot masquerade as a business 401 or alter rollback',wasm,async()=>{
  for(const decision of [null,{op:'install.context.session',branch:'capacity',outcome:'abort'},{op:'roster.linkTicket.create',branch:'capacity',outcome:'normal'},{op:'roster.linkTicket.create',branch:'invented',outcome:'abort'}]){
    const r=runner({instantiate(module){const real=new WebAssembly.Instance(module,{}).exports;let length=0;return{exports:{...real,output_len:()=>length,command(n){const result=real.command(n);length=real.output_len();if(result===0){const data=JSON.parse(Buffer.from(real.memory.buffer,real.output_ptr(),length));if(data.result.kind==='abort'){data.result.decision=decision;data.result.status=401;const bytes=Buffer.from(JSON.stringify(data));new Uint8Array(real.memory.buffer,real.output_ptr(),bytes.length).set(bytes);length=bytes.length;}}return result;}}};}});
    const entries=[['link-ticket:expired',{expiresAt:0}],...Array.from({length:200},(_,i)=>['link-ticket:'+i,{expiresAt:NOW+10}])],store=new Memory(entries);
    await assert.rejects(r.transaction(store,'roster.linkTicket.create',{value:{csrfHash:HASH,proofHash:SECOND,previousHash:null}},{now:()=>NOW}),e=>e.code==='EREGISTRY'&&e.status!==401);
    assert.equal(store.data.size,201);assert.equal(store.data.has('link-ticket:expired'),true);
  }
});

test('malformed effect capabilities, sequence, keys, references and patches abort before any storage mutation',wasm,async()=>{
  const cases=[
    ['install.context.ticket',{id:ID,browser:HASH},e=>({...e,effect:{type:'put',key:'install:v1:ticket:'+ID,value:{t:'null'}}})],
    ['instance.invitation.revoke',{invitationId:ID},e=>({...e,effect:{type:'put',key:'accounts:v3:connection:'+ID,value:{t:'null'}}})],
    ['account.execute',{command:{action:'status',actor:{identityKey:HASH,sessionBinding:SECOND},input:{intentId:ID}},guard:{kind:'none'}},e=>({...e,effect:{type:'put',key:'accounts:v3:intent:'+ID,value:{t:'null'}}})],
    ['registry.enroll',{value:{deviceId:ID}},e=>({...e,seq:2})],
    ['registry.enroll',{value:{deviceId:ID}},e=>({...e,effect:{type:'get',key:'accounts:v3:identity:'+HASH,readId:1}})],
    ['registry.enroll',{value:{deviceId:ID}},e=>({...e,effect:{type:'put',key:'device:'+ID,value:{t:'r',v:999999}}})],
    ['registry.enroll',{value:{deviceId:ID}},e=>({...e,graph:{nodes:[],patches:[{target:1,field:'count',value:{t:'n',v:'3'}}]}})],
    ['roster.linkTicket.create',{value:{csrfHash:HASH,proofHash:SECOND,previousHash:null}},e=>({...e,effect:{type:'list',prefix:'link-ticket:',limit:1026,readId:1}})],
  ];
  for(const [op,input,mutate]of cases){let injected=false;
    const r=runner({instantiate(module){const real=new WebAssembly.Instance(module,{}).exports;let length=0;return{exports:{...real,output_len:()=>length,command(n){const result=real.command(n);length=real.output_len();if(result===0){const data=JSON.parse(Buffer.from(real.memory.buffer,real.output_ptr(),length));if(!injected&&data.result.kind==='need'){injected=true;data.result=mutate(data.result);const bytes=Buffer.from(JSON.stringify(data));new Uint8Array(real.memory.buffer,real.output_ptr(),bytes.length).set(bytes);length=bytes.length;}}return result;}}};}});
    const store=new Memory();await assert.rejects(r.transaction(store,op,input),e=>e.code==='EREGISTRY');assert.equal(injected,true,op);assert.equal(store.effects.length,0);assert.equal(store.data.size,0);
  }
});

test('injected transaction callback retry rebuilds Rust attempts while native proof verifies only once',wasm,async()=>{
  const events=[],f=await accountFixture({runner:runner({trace:e=>events.push(e)})});const {intent}=await f.prepare();const original=f.storage.transaction.bind(f.storage),verify=f.directory.verifyDeviceConsent;let proofs=0,callbacks=0;
  f.directory.verifyDeviceConsent=async input=>{proofs++;return verify(input);};
  f.storage.transaction=fn=>original(async tx=>{callbacks++;await fn(tx);throw Error('injected retry rollback');}).catch(error=>{assert.equal(error.message,'injected retry rollback');return original(async tx=>{callbacks++;return fn(tx);});});
  assert.equal((await f.confirm(intent)).phase,'consented');assert.equal(proofs,1);assert.equal(callbacks,2);
  const attempts=events.filter(e=>e.kind==='rust-decided'&&e.branch==='confirm-prepared');assert.deepEqual(attempts.map(e=>e.attempt),[1,2]);assert.equal(attempts[0].transaction,attempts[1].transaction);
});

test('records checkpoint preserves per-row clock reversals, original list counting, delete order and fresh attempts',wasm,async()=>{
  for(const entries of [[],[['onboarding:v1:login:old',{until:100,bindingId:SECOND,value:{fixture:true}}],['onboarding:v1:session-binding:'+SECOND,{until:100}]]]){
    const stores=[new Memory(entries),new Memory(entries)],clocks=[];
    for(let i=0;i<2;i++){let calls=0;const times=[100,90,110];const now=()=>{const value=times[Math.min(calls,times.length-1)];calls++;return value;};await new OnboardingStore(stores[i],now,i?runner():undefined).records({action:'put',kind:'login',secret:HASH,value:{fixture:true},ttl:1});clocks.push(calls);}
    assert.deepEqual(stores[1].data,stores[0].data);assert.deepEqual(stores[1].effects,stores[0].effects);assert.equal(clocks[1],clocks[0]);
    if(entries.length)assert.deepEqual(stores[1].effects,['delete','delete','put']);
  }
  const original=[['onboarding:v1:login:old',{until:0,bindingId:SECOND,value:{fixture:true}}],['onboarding:v1:session-binding:'+SECOND,{until:0}]];
  for(const failAt of [1,2]){const store=new Memory(original),tx=store.transaction.bind(store);let hit=0;
    store.transaction=fn=>tx(actual=>fn({...actual,delete:async key=>{await actual.delete(key);if(++hit===failAt)throw Error('fixture cleanup delete '+failAt);}}));
    await assert.rejects(new OnboardingStore(store,()=>100,runner()).records({action:'put',kind:'login',secret:HASH,value:{fixture:true},ttl:1}),e=>e.message==='fixture cleanup delete '+failAt);assert.equal(hit,failAt);assert.deepEqual([...store.data],original);
    store.transaction=tx;await new OnboardingStore(store,()=>100,runner()).records({action:'put',kind:'login',secret:HASH,value:{fixture:true},ttl:1});assert.equal(store.data.size,1);
  }
});

test('checkpoint rejects a repeated delete acknowledgement and a new attempt cannot reuse the sealed cursor',wasm,async()=>{
  let pending='',injected=false;const r=runner({instantiate(module){const e=new WebAssembly.Instance(module,{}).exports;return{exports:{...e,command(n){const command=JSON.parse(Buffer.from(e.memory.buffer,e.input_ptr(),n));if(!injected&&pending==='delete'&&command.command.type==='resume'){injected=true;command.command.seq=1;const bytes=Buffer.from(JSON.stringify(command));new Uint8Array(e.memory.buffer,e.input_ptr(),bytes.length).set(bytes);n=bytes.length;}const code=e.command(n);if(code===0){const out=JSON.parse(Buffer.from(e.memory.buffer,e.output_ptr(),e.output_len()));pending=out.result.effect?.type||'';}return code;}}};}});
  const original=[['onboarding:v1:login:old',{until:0}]],store=new Memory(original),input={action:'put',kind:'login',secret:HASH,value:{fixture:true},ttl:1};
  await assert.rejects(new OnboardingStore(store,()=>100,r).records(input),e=>e.code==='EREGISTRY');assert.equal(injected,true);assert.equal(store.effects.includes('delete'),true);assert.deepEqual([...store.data],original);
  await new OnboardingStore(store,()=>100,r).records(input);assert.equal(store.data.size,1);
});

test('roster expiry cleanup snapshots and 257 row upper bound use bounded delete batches before capacity outcome',wasm,async()=>{
  const entries=Array.from({length:257},(_,i)=>['link-ticket:'+String(i).padStart(4,'0'),{expiresAt:NOW-1}]);const store=new Memory(entries);let calls=0;
  const start=performance.now();const result=await runner().transaction(store,'roster.linkTicket.create',{value:{csrfHash:HASH,proofHash:SECOND,previousHash:null}},{now:()=>{calls++;return NOW;}});
  assert.equal(result.httpStatus,200);assert.equal(store.data.size,1);assert.equal(store.effects.filter(x=>x==='delete').length,3);assert.equal(calls,258);assert.ok(performance.now()-start<15000);
  const full=new Memory(Array.from({length:201},(_,i)=>['link-ticket:'+i,{expiresAt:NOW+1000}]));await assert.rejects(runner().transaction(full,'roster.linkTicket.create',{value:{csrfHash:HASH,proofHash:SECOND,previousHash:null}},{now:()=>NOW}),e=>e.status===429);assert.equal(full.data.size,201);
});

test('Account real WASM covers nine actions, idempotent activation, owner ceilings and ordered cycle snapshots',wasm,async()=>{
  for (const backend of [undefined,runner()]) {
    const f=await accountFixture({runner:backend});
    const {input,intent}=await f.prepare();
    assert.deepEqual(await f.repository.act(f.principal,'prepare',input),intent);
    assert.equal((await f.repository.act(f.principal,'status',{intentId:intent.intentId})).phase,'prepared');
    const stored=f.storage.data.get('accounts:v3:intent:'+intent.intentId);stored.roots[0].back=stored;
    stored.future={date:new Date(12),map:new Map([['self',stored]]),big:31n,bytes:new Uint8Array([4,7])};
    const confirmed=await f.confirm(intent);assert.equal(confirmed.phase,'consented');
    const active=await f.activate(confirmed);assert.equal(active.phase,'active');
    const connection=f.storage.data.get('accounts:v3:connection:'+active.connectionId);
    assert.equal(connection.shares[0].back.phase,'consented');
    assert.equal(connection.shares[0].back.future.map.get('self'),connection.shares[0].back);
    assert.equal(f.storage.data.get('accounts:v3:intent:'+intent.intentId).phase,'active');
    assert.equal((await f.confirm(active)).phase,'active');assert.equal((await f.activate(active)).phase,'active');
    const listed=await f.repository.act(f.principal,'connections',{resource:input.resource});assert.equal(listed.connections.length,1);
    const resolved=await f.directory.execute({action:'resolve',grant:active.grant});assert.equal(resolved.devices.length,1);
    const outsider=await f.login('other');await f.repository.act(outsider,'account');await assert.rejects(f.repository.act(outsider,'status',{intentId:intent.intentId}),e=>e.status===404);
    await f.repository.act(f.principal,'revoke-share',{connectionId:active.connectionId,deviceId:input.deviceId,rootId:input.roots[0].rootId});
    assert.equal((await f.repository.act(f.principal,'status',{intentId:intent.intentId})).phase,'revoked');
    await assert.rejects(f.activate(active),e=>e.status===409);
    await f.repository.act(f.principal,'revoke-connection',{connectionId:active.connectionId});await assert.rejects(f.directory.execute({action:'resolve',grant:active.grant}),e=>e.status===403);
    const second=await f.prepare({deviceId:'d'.repeat(32),deviceEpoch:'e'.repeat(64)});assert.equal((await f.repository.act(f.principal,'cancel',{intentId:second.intent.intentId})).phase,'cancelled');assert.equal((await f.repository.act(f.principal,'status',{intentId:second.intent.intentId})).phase,'cancelled');
  }
});

test('required projections keep unrelated business names and proof material opaque below the host graph bound',wasm,async()=>{
  const frames=[];const r=runner({instantiate(module){const e=new WebAssembly.Instance(module,{}).exports;return{exports:{...e,command(n){frames.push(JSON.parse(Buffer.from(e.memory.buffer,e.input_ptr(),n)));return e.command(n);}}};}});
  const value={authRequest:'x'.repeat(300000),password:'fixture-password',pepper:'fixture-pepper',token:'fixture-token'};value.self=value;value.map=new Map([['self',value]]);
  const storage=new Memory([['onboarding:v1:login:'+HASH,{until:NOW+1,value}]]);
  const received=await r.transaction(storage,'onboarding.records',{action:'get',kind:'login',key:'onboarding:v1:login:'+HASH},{now:()=>NOW});assert.equal(received.authRequest.length,300000);assert.equal(received.self,received);assert.equal(received.map.get('self'),received);
  const accountId='c'.repeat(32),connectionId='d'.repeat(32),actor={identityKey:HASH,sessionBinding:SECOND};
  const accountStore=new Memory([['accounts:v3:identity:'+HASH,{id:accountId}],['accounts:v3:connection-index:'+accountId,[connectionId]],['accounts:v3:connection:'+connectionId,{id:connectionId,accountId,clientId:'fixture',resource:'https://relay.example.test/mcp',revoked:false,scopes:['files:read'],authRequest:'x'.repeat(300000),password:'fixture-password',pepper:'fixture-pepper',token:'fixture-token'}]]);
  const found=await new AccountDirectory(accountStore,{runner:r}).execute({action:'connections',actor,input:{resource:'https://relay.example.test/mcp'}});assert.equal(found.connections.length,1);
  const f=await accountFixture({runner:r});const {intent}=await f.prepare();await f.confirm(intent);
  const projected=[];const walk=v=>{if(v?.t==='s')projected.push(String.fromCharCode(...v.v));else if(Array.isArray(v))v.forEach(walk);else if(v&&typeof v==='object')Object.values(v).forEach(walk);};frames.forEach(walk);
  assert.equal(projected.some(v=>v.length===300000||['fixture-password','fixture-pepper','fixture-token'].includes(v)),false);
  for(const frame of frames)if(frame.command.type==='graph')for(const node of frame.command.nodes)assert.equal(node.props.some(([key])=>key==='proof'||key==='sessionSecret'),false);
});

async function runtime(rust,privateInstance=false,persist,existing,strict=false){
  const entry=rust?(strict?await denyLegacyEntry(artifact):artifact.entry):path.join(projectRoot,'src/relay/worker.mjs');
  const bundle=await build({stdin:{resolveDir:projectRoot,sourcefile:'registry-fixture.mjs',contents:`
import { Registry as ProductionRegistry } from ${JSON.stringify(entry)};
import { AccountDirectory } from './src/relay/account-directory.mjs';
import { OnboardingStore } from './src/relay/onboarding-store.mjs';
import { PrivateInstance } from './src/relay/private-instance.mjs';
import { InstallPortal } from './src/relay/install-portal.mjs';
import { consumeBudget } from './src/relay/request-budget.mjs';
import { RustRegistryRunner } from './src/relay/rust-registry.mjs';
export class Registry extends ProductionRegistry {
  constructor(ctx,env){super(ctx,env);this.events=[];this.case='main-chain';this.raceHits=0;if(this.registryRunner){this.registryRunner.trace=event=>{if(this.events.length<20000)this.events.push({...event,case:this.case});};const run=this.registryRunner.transaction.bind(this.registryRunner);this.registryRunner.transaction=async(storage,op,input,options)=>{if(this.race&&this.race.op===op&&(!this.race.action||this.race.action===input.command?.action)){const race=this.race;this.race=null;this.raceHits++;if(race.remove)await ctx.storage.delete(race.key);else await ctx.storage.put(race.key,race.value);}return run(storage,op,input,options);};}}
  async fetch(request){const route=new URL(request.url).pathname;
    if(route==='/test/seed'){const {entries}=await request.json();await this.ctx.storage.deleteAll();for(const [key,value]of entries)await this.ctx.storage.put(key,value);return Response.json({ok:true});}
    if(route==='/test/put'){const {key,value}=await request.json();await this.ctx.storage.put(key,value);return Response.json({ok:true});}
    if(route==='/test/has'){const {key}=await request.json();return Response.json({present:await this.ctx.storage.get(key)!==undefined});}
    if(route==='/test/race'){this.race=await request.json();this.case=this.race.case;return Response.json({armed:true});}
    if(route==='/test/race-state')return Response.json({hits:this.raceHits});
    if(route==='/test/case'){this.case=(await request.json()).case;return Response.json({ok:true});}
    if(route==='/test/remember-full'){for(let i=0;i<65;i++)await this.ctx.storage.put('instance:v1:remember:'+String(i).padStart(2,'0'),{until:i===0?0:Date.now()+600000});this.case='remember-full-cleanup-commit';await this.registryRunner.transaction(this.ctx.storage,'instance.remember.store',{resource:'https://fixture.test/mcp',remember:'${HASH}',grant:{},redirectUri:'https://fixture.test/cb'});const saved=await this.ctx.storage.list({prefix:'instance:v1:remember:'});return Response.json({count:saved.size,expiredRetained:saved.has('instance:v1:remember:00')});}
    if(route==='/test/ticket-graph'){const {key,csrfHash,kind}=await request.json();const value={csrfHash,expiresAt:Date.now()+600000};value.unknown=kind==='bigint'?1n:value;await this.ctx.storage.put(key,value);return Response.json({ok:true});}
    if(route==='/test/graph'){const {action}=await request.json();if(action==='seed'){const value={count:1,until:Date.now()+600000,future:{big:12n,date:new Date(123),bytes:new Uint8Array([3,7])}};value.self=value;value.map=new Map([['root',value]]);await this.ctx.storage.put('budget:register',value);}if(action==='consume')await consumeBudget(this.ctx.storage,{bucket:'register'},Date.now(),this.registryRunner);const value=await this.ctx.storage.get('budget:register');return Response.json({count:value.count,self:value.self===value,map:value.map.get('root')===value,big:value.future.big===12n,date:value.future.date.getTime(),bytes:[...value.future.bytes]});}
    if(route==='/test/boundary'){const {kind}=await request.json();await this.ctx.storage.deleteAll();const prefix=kind==='roster'?'link-ticket:':'onboarding:v1:login:',count=kind==='roster'?257:1025;for(let start=0;start<count;start+=128){const records={};for(let i=start;i<Math.min(count,start+128);i++)records[prefix+String(i).padStart(4,'0')]={expiresAt:0,until:kind==='capacity'&&i>=25?Date.now()+600000:0,value:{fixture:true}};await this.ctx.storage.put(records);}return Response.json({count});}
    if(route==='/test/rates'){const {kind}=await request.json();await this.ctx.storage.deleteAll();const value=kind==='null'?[null]:kind==='undefined'?[undefined]:kind==='hole'?Array(1):[123];await this.ctx.storage.put('selfRates',value);return Response.json({ok:true});}
    if(route==='/test/events')return Response.json(this.events);
    if(route==='/test/storage-effects')return Response.json(this.storageEffects||[]);
    if(route==='/test/measure'){
      const {route:target,value}=await request.json();if(!['/link-ticket/new','/onboarding/records'].includes(target))throw Error('Unknown measurement route');this.storageEffects=[];
      const storage=new Proxy(this.ctx.storage,{get:(object,name)=>name==='transaction'?fn=>object.transaction(tx=>fn(new Proxy(tx,{get:(current,method)=>['get','list','put','delete'].includes(method)?async(...args)=>{const result=await current[method](...args);this.storageEffects.push({type:method,deleteKeys:method==='delete'?(Array.isArray(args[0])?args[0].length:1):0});return result;}:typeof current[method]==='function'?current[method].bind(current):current[method]}))):typeof object[name]==='function'?object[name].bind(object):object[name]});
      return ProductionRegistry.prototype.fetch.call({ctx:{storage},env:this.env,registryRunner:this.registryRunner},new Request('http://fixture'+target,{method:'POST',body:JSON.stringify(value)}));
    }
    if(route==='/test/legacy'){this.registryRunner=null;try{return await super.fetch(new Request('http://fixture/enroll',{method:'POST',body:JSON.stringify({deviceId:'${ID}'})}));}catch(error){return Response.json({error:error.message},{status:500});}}
    if(route==='/test/account-guard'){try{return Response.json(await new OnboardingStore(this.ctx.storage,Date.now,this.registryRunner).directory().execute(await request.json()));}catch(error){return Response.json({error:error.message},{status:error.status||500});}}
    if(route==='/test/account'){try{const command=await request.json();return Response.json(await new AccountDirectory(this.ctx.storage,{runner:this.registryRunner,verifyDeviceConsent:async({action,proof,intent})=>proof==='fixture-native'?{intentId:intent.id,deviceId:intent.deviceId,deviceEpoch:intent.deviceEpoch,snapshotDigest:intent.snapshotDigest,phase:action==='confirm'?'consented':'activated'}:null}).execute(command));}catch(error){return Response.json({error:error.message},{status:error.status||500});}}
    if(route==='/test/snapshot')return Response.json([...await this.ctx.storage.list()]);
    if(route==='/test/rollback'){
      const {group='basic',mode='storage',failAt=1}=await request.json();let writes=0,deletes=0,hit=false;
      const storage=new Proxy(this.ctx.storage,{get:(target,name)=>name==='transaction'?fn=>target.transaction(tx=>fn(new Proxy(tx,{get:(t,n)=>n==='put'?async(...args)=>{await t.put(...args);writes++;if(mode==='storage'){hit=true;throw Error('fixture after real put');}}:n==='delete'?async(...args)=>{await t.delete(...args);deletes++;if(group==='cleanup'&&mode==='storage'&&deletes===failAt){hit=true;throw Error('fixture after real delete');}}:typeof t[n]==='function'?t[n].bind(t):t[n]}))):typeof target[name]==='function'?target[name].bind(target):target[name]});
      const r=mode!=='storage'?new RustRegistryRunner(this.registryRunner.module,{instantiate:module=>{const e=new WebAssembly.Instance(module,{}).exports;let length=0;return{exports:{...e,output_len:()=>length,command(n){if((group==='cleanup'?deletes===failAt:writes)&&mode==='trap'){hit=true;throw new WebAssembly.RuntimeError(group==='cleanup'?'fixture after real delete trap':'fixture after real put trap');}const result=e.command(n);length=e.output_len();if(result===0&&mode==='complete'){const data=JSON.parse(new TextDecoder().decode(new Uint8Array(e.memory.buffer,e.output_ptr(),length)));if(data.result.kind==='complete'){hit=true;data.result.value={t:'u'};const bytes=new TextEncoder().encode(JSON.stringify(data));new Uint8Array(e.memory.buffer,e.output_ptr(),bytes.length).set(bytes);length=bytes.length;}}return result;}}};}}):this.registryRunner;
      try{if(group==='basic')await consumeBudget(storage,{bucket:'register'},Date.now(),r);
        else if(group==='account')await new AccountDirectory(storage,{runner:r}).execute({action:'account',actor:{identityKey:'${HASH}',sessionBinding:'${SECOND}'},input:{}});
        else if(group==='onboarding')await new OnboardingStore(storage,Date.now,r).records({action:'put',kind:'login',secret:'${HASH}',value:{fixture:true},ttl:60});
        else if(group==='cleanup')await new OnboardingStore(storage,Date.now,r).records({action:'put',kind:'login',secret:'${HASH}',value:{fixture:true},ttl:60});
        else if(group==='instance')await new PrivateInstance(storage,'https://fixture.test/mcp',Date.now,r).owner();
        else if(group==='install')await new InstallPortal(storage,'https://fixture.test/mcp','${HASH}',Date.now,r).configure({password:'fixture-password-only'});
        else throw Error('unknown fixture');return Response.json({unexpected:true});
      }catch(error){return Response.json({writes,deletes,hit,error:error.message,code:error.code||null});}
    }
    try{return await super.fetch(request);}catch(error){return Response.json({error:error.message},{status:error.status||500});}
  }
}
export default {fetch(request,env){return env.REGISTRY.get(env.REGISTRY.idFromName('registry-v1')).fetch(request);}};
`},bundle:true,write:false,format:'esm',platform:'neutral',mainFields:['module','main'],external:['cloudflare:workers','*.wasm']});
  const options=convertV4MiniflareOptions({name:'registry-gate-fixture',...(persist?{durableObjectsPersist:persist}:{}),bindings:privateInstance?{PRIVATE_INSTANCE:'true',ENROLLMENT_KEY:HASH}:{ACCOUNT_CONNECTIONS:'true'},modulesRoot:directory,modules:[{type:'ESModule',path:path.join(directory,'registry-fixture.mjs'),contents:bundle.outputFiles[0].text},...(rust?[{type:'CompiledWasm',path:artifact.wasmPath},{type:'CompiledWasm',path:artifact.registryWasmPath},...(artifact.oauthWasmPath?[{type:'CompiledWasm',path:artifact.oauthWasmPath}]:[])]:[])],compatibilityDate:'2026-09-20',compatibilityFlags:['nodejs_compat','global_fetch_strictly_public'],host:'127.0.0.1',port:0,durableObjects:{REGISTRY:{className:'Registry',useSQLite:true,unsafeUniqueKey:'registry-gate-fixture-only'}}});
  const mf=existing||new Miniflare(options);if(existing)await mf.setOptions(options);mf.fixtureOptions=options;
  mf.fixtureEvidence={id:runtimeEvidence.length+1,artifactClass:rust?(strict?'instrumented-strict':'normal-generated'):'default-js',fixtureSha256:hash(bundle.outputFiles[0].text),...(rust?{workerSha256:hash(await fs.readFile(entry)),originalWorkerSha256:artifact.manifest.artifacts['worker.mjs'],deviceSha256:artifact.manifest.artifacts[artifact.manifest.wasm],registrySha256:artifact.manifest.artifacts[artifact.manifest.registryWasm]}:{})};runtimeEvidence.push(mf.fixtureEvidence);
  await mf.ready;return mf;
}
const request=(mf,route,value={})=>mf.dispatchFetch('http://fixture'+route,{method:'POST',body:JSON.stringify(value)});
const json=async response=>({status:response.status,value:await response.json()});
test('actual workerd selected Registry decides all seven basic sites and matches original JS results/storage',wasm,async t=>{
  const a=await runtime(false),b=await runtime(true);t.after(async()=>{await a.dispose();await b.dispose();});
  const call=async(route,value)=>{const [js,rust]=await Promise.all([request(a,route,value).then(json),request(b,route,value).then(json)]);assert.deepEqual(rust,js,route);return rust;};
  const seed=entries=>Promise.all([request(a,'/test/seed',{entries}),request(b,'/test/seed',{entries})]);
  await seed([]);assert.equal((await call('/self-enroll',{deviceId:ID,keyHash:HASH,ipHash:SECOND})).status,200);assert.equal((await call('/self-enroll',{deviceId:ID,keyHash:SECOND,ipHash:SECOND})).status,409);
  await seed([]);await call('/enroll',{deviceId:ID});await call('/enroll',{deviceId:ID});assert.deepEqual(await (await request(b,'/test/snapshot')).json(),await (await request(a,'/test/snapshot')).json());
  const ticket='d'.repeat(64),csrf='e'.repeat(64);await seed([['ticket:'+await sha256(ticket),{csrfHash:await sha256(csrf),expiresAt:Date.now()+100000,authRequest:{future:1}}]]);
  await call('/ticket/peek',{ticket,csrf});await call('/ticket/consume',{ticket,csrf});await call('/ticket/consume',{ticket,csrf});
  await seed([['budget:register',{count:99,until:Date.now()+100000}]]);await call('/budget',{bucket:'register'});assert.equal((await call('/budget',{bucket:'register'})).status,429);
  await seed([]);await call('/link-ticket/new',{csrfHash:HASH,proofHash:SECOND,previousHash:null});await call('/link-ticket/consume',{csrfHash:HASH,proofHash:SECOND,previousHash:null});
  await seed([]);await call('/roster/append',{sessionHash:HASH,previousHash:null,device:{deviceId:ID,epoch:SECOND,description:{name:'fixture'}}});
  const events=await (await request(b,'/test/events')).json();const decided=new Set(events.filter(e=>e.kind==='rust-decided').map(e=>e.op));assert.deepEqual([...decided].sort(),EXPECTED_REGISTRY_OPERATIONS.slice(0,7).sort());
  assert.ok(events.some(e=>e.kind==='tx-completed'&&e.outcome==='commit'));
  recordCoverage(events,'basic HTTP responses and persisted enrollment',b);
  for(const kind of ['null','undefined','hole','primitive']){await Promise.all([request(a,'/test/rates',{kind}),request(b,'/test/rates',{kind})]);const [js,rust]=await Promise.all([request(a,'/self-enroll',{deviceId:ID,keyHash:HASH,ipHash:SECOND}),request(b,'/self-enroll',{deviceId:ID,keyHash:HASH,ipHash:SECOND})]);assert.equal(rust.status,js.status,kind);if(['null','undefined'].includes(kind)){assert.equal(rust.status,500);assert.equal((await (await request(b,'/test/snapshot')).json()).some(([key])=>key==='deviceCount'),false);}else assert.equal(rust.status,200);}
});

test('actual workerd all five aggregates roll back after a confirmed real put for storage faults and WASM traps',wasm,async t=>{
  const mf=await runtime(true);t.after(()=>mf.dispose());
  for(const group of ['basic','account','onboarding','instance','install'])for(const mode of ['storage','trap']){
    const original=[['fixture:retained',{value:'unchanged'}]];await request(mf,'/test/seed',{entries:original});
    const response=await(await request(mf,'/test/rollback',{group,mode})).json();
    assert.equal(response.hit,true,group+' '+mode+' reached fault after real put');assert.equal(response.writes,1);
    assert.equal(response.error,mode==='storage'?'fixture after real put':'fixture after real put trap');
    assert.deepEqual(await(await request(mf,'/test/snapshot')).json(),original,group+' '+mode+' full rollback');
  }
});

test('actual workerd checkpoint rolls back each real cleanup mutation and a capacity abort',wasm,async t=>{
  const mf=await runtime(true);t.after(()=>mf.dispose());
  const original=[['onboarding:v1:login:old',{until:0,bindingId:SECOND,value:{fixture:true}}],['onboarding:v1:session-binding:'+SECOND,{until:0}]];
  for(const mode of ['storage','trap'])for(const failAt of [1,2]){await request(mf,'/test/seed',{entries:original});const result=await(await request(mf,'/test/rollback',{group:'cleanup',mode,failAt})).json();assert.equal(result.hit,true);assert.equal(result.deletes,failAt);assert.equal(result.writes,0);assert.equal(result.error,mode==='storage'?'fixture after real delete':'fixture after real delete trap');assert.deepEqual(await(await request(mf,'/test/snapshot')).json(),original);}
  await request(mf,'/test/boundary',{kind:'capacity'});const before=await(await request(mf,'/test/snapshot')).json();await request(mf,'/test/case',{case:'records-capacity-cleanup-rollback'});
  assert.equal((await request(mf,'/onboarding/records',{action:'put',kind:'login',secret:HASH,value:{fixture:true},ttl:60})).status,429);assert.deepEqual(await(await request(mf,'/test/snapshot')).json(),before);
  const events=await(await request(mf,'/test/events')).json();assert.equal(events.filter(e=>e.case==='records-capacity-cleanup-rollback'&&e.kind==='host-effect'&&e.type==='delete').length,25);assert.ok(events.some(e=>e.case==='records-capacity-cleanup-rollback'&&e.kind==='rust-decided'&&e.outcome==='abort'));recordCoverage(events,'Checkpoint cleanup fault and capacity rollback',mf);
});

test('actual workerd 257 and 1025 row cleanup bounds report wall time and real effect counts for both backends',wasm,async t=>{
  const results=[];
  for(const rust of [false,true]){const mf=await runtime(rust);t.after(()=>mf.dispose());for(const kind of ['roster','identity']){
    await request(mf,'/test/boundary',{kind});const before=await(await request(mf,'/test/events')).json(),start=performance.now();
    const response=await request(mf,'/test/measure',kind==='roster'?{route:'/link-ticket/new',value:{csrfHash:HASH,proofHash:SECOND,previousHash:null}}:{route:'/onboarding/records',value:{action:'put',kind:'login',secret:HASH,value:{fixture:true},ttl:60}});
    assert.equal(response.status,200,JSON.stringify(await response.json()));const wallMs=performance.now()-start;
    assert.equal((await(await request(mf,'/test/snapshot')).json()).length,1);
    const events=(await(await request(mf,'/test/events')).json()).slice(before.length),storage=await(await request(mf,'/test/storage-effects')).json();results.push({backend:rust?'rust':'js',kind,rows:kind==='roster'?257:1025,wallMs,rustHostEffects:rust?events.filter(e=>e.kind==='host-effect').length:null,storageEffects:storage.length,deleteKeys:storage.reduce((sum,effect)=>sum+effect.deleteKeys,0),storageCounts:Object.fromEntries(['get','list','put','delete'].map(type=>[type,storage.filter(value=>value.type===type).length]))});
  }}
  for(const row of results){assert.equal(row.deleteKeys,row.rows);assert.equal(row.storageCounts.delete,row.kind==='roster'?(row.backend==='rust'?3:1):1025);assert.equal(row.storageCounts.list,1);assert.equal(row.storageCounts.put,1);}
  console.log('Registry actual workerd boundary measurements (wall time, not CPU quota): '+JSON.stringify(results));
  if(process.env.CHAT2LOCAL_REGISTRY_TEST_COVERAGE_DIR){await fs.mkdir(process.env.CHAT2LOCAL_REGISTRY_TEST_COVERAGE_DIR,{recursive:true});await fs.writeFile(path.join(process.env.CHAT2LOCAL_REGISTRY_TEST_COVERAGE_DIR,'registry-boundaries.json'),JSON.stringify(results,null,2));}
});

test('actual persistent namespace JS to Rust to JS preserves unknown graphs and consumed tickets',wasm,async t=>{
  const persist=await fs.mkdtemp(path.join(os.tmpdir(),'chat2local-registry-switch-'));t.after(()=>fs.rm(persist,{recursive:true,force:true,maxRetries:10,retryDelay:100}));let mf;
  t.after(async()=>{await mf?.dispose();});
  mf=await runtime(false,false,persist);await request(mf,'/test/graph',{action:'seed'});
  const ticket='d'.repeat(64),csrf='e'.repeat(64),awaitHash=await sha256(ticket);await request(mf,'/test/put',{key:'ticket:'+awaitHash,value:{csrfHash:await sha256(csrf),expiresAt:Date.now()+600000,authRequest:{retained:true}}});
  const accountId='1'.repeat(32),connectionId='2'.repeat(32),resource='https://fixture.test/mcp',grant={grantVersion:3,accountId,connectionId,connectionEpoch:HASH,clientId:'fixture',resource,scopes:['files:read']};
  await request(mf,'/test/put',{key:'accounts:v3:identity:'+HASH,value:{id:accountId}});await request(mf,'/test/put',{key:'accounts:v3:connection:'+connectionId,value:{id:connectionId,accountId,epoch:HASH,revision:1,clientId:'fixture',resource,policy:'explicit-shares',scopes:['files:read'],shares:[{deviceId:ID,deviceEpoch:SECOND,rootId:'project',intentId:ID,mode:'direct'}],revoked:false}});
  mf=await runtime(true,false,persist,mf);
  assert.deepEqual(await(await request(mf,'/test/has',{key:'ticket:'+awaitHash})).json(),{present:true});
  assert.equal((await request(mf,'/ticket/consume',{ticket,csrf})).status,200);assert.deepEqual(await(await request(mf,'/test/graph',{action:'consume'})).json(),{count:2,self:true,map:true,big:true,date:123,bytes:[3,7]});
  assert.equal((await request(mf,'/accounts/resolve',grant)).status,200);assert.equal((await request(mf,'/test/account',{action:'revoke-connection',actor:{identityKey:HASH,sessionBinding:SECOND},input:{connectionId}})).status,200);
  mf=await runtime(false,false,persist,mf);
  assert.equal((await request(mf,'/ticket/consume',{ticket,csrf})).status,403);assert.deepEqual(await(await request(mf,'/test/graph',{action:'consume'})).json(),{count:3,self:true,map:true,big:true,date:123,bytes:[3,7]});
  assert.equal((await request(mf,'/accounts/resolve',grant)).status,403);
});

test('actual workerd concurrent enroll and consume serialize exactly one successful mutation',wasm,async t=>{
  for(const rust of [false,true]){const mf=await runtime(rust);t.after(()=>mf.dispose());
    const enroll=await Promise.all(Array.from({length:4},()=>request(mf,'/self-enroll',{deviceId:ID,keyHash:HASH,ipHash:SECOND})));assert.deepEqual(enroll.map(r=>r.status),[200,200,200,200]);
    assert.equal((await(await request(mf,'/test/snapshot')).json()).find(([key])=>key==='deviceCount')[1],1);
    const ticket='d'.repeat(64),csrf='e'.repeat(64);await request(mf,'/test/put',{key:'ticket:'+await sha256(ticket),value:{csrfHash:await sha256(csrf),expiresAt:Date.now()+600000,authRequest:{retained:true}}});
    const consume=await Promise.all(Array.from({length:4},()=>request(mf,'/ticket/consume',{ticket,csrf})));assert.equal(consume.filter(r=>r.status===200).length,1);
  }
});

test('actual workerd HTTP serialization and malformed completion fail inside the transaction after real writes',wasm,async t=>{
  for(const rust of [false,true]){const mf=await runtime(rust);t.after(()=>mf.dispose());const ticket='d'.repeat(64),csrf='e'.repeat(64),key='ticket:'+await sha256(ticket);
    for(const kind of ['bigint','cycle']){await request(mf,'/test/ticket-graph',{key,csrfHash:await sha256(csrf),kind});const response=await request(mf,'/ticket/consume',{ticket,csrf});assert.equal(response.status,500);assert.deepEqual(await(await request(mf,'/test/has',{key})).json(),{present:true});}
    if(rust){await request(mf,'/test/seed',{entries:[]});const result=await(await request(mf,'/test/rollback',{group:'basic',mode:'complete'})).json();assert.equal(result.hit,true);assert.equal(result.writes,1);assert.equal(result.error,'Registry response unavailable.');assert.deepEqual(await(await request(mf,'/test/snapshot')).json(),[]);}
  }
});

test('actual workerd Account persists all nine actions and Registry resolve uses the selected runner',wasm,async t=>{
  const mf=await runtime(true);t.after(()=>mf.dispose());const actor={identityKey:HASH,sessionBinding:SECOND};
  const act=async(action,input={})=>{const result=await request(mf,'/test/account',{action,actor,input});const body=await result.json();assert.equal(result.status,200,JSON.stringify(body));return body;};
  await act('account');const input={intentId:ID,connectionId:null,clientId:'fixture',resource:'https://relay.example.test/mcp',deviceId:'d'.repeat(32),deviceEpoch:HASH,roots:[{rootId:'project',mode:'direct'}],scopes:['files:read','files:write'],policyDigest:HASH,requestDigest:SECOND};
  const intent=await act('prepare',input);assert.deepEqual(await act('prepare',input),intent);assert.equal((await act('status',{intentId:ID})).phase,'prepared');
  assert.equal((await request(mf,'/test/account',{action:'prepare',actor,input:{...input,requestDigest:HASH}})).status,409);
  const proof={intentId:ID,snapshotDigest:intent.snapshotDigest,proof:'fixture-native'};await act('confirm',proof);await act('confirm',proof);const [active,concurrent]=await Promise.all([act('activate',proof),act('activate',proof)]);assert.deepEqual(concurrent,active);await act('activate',proof);await act('confirm',proof);
  assert.equal((await act('connections',{resource:input.resource})).connections.length,1);assert.equal((await json(await request(mf,'/accounts/resolve',active.grant))).value.devices.length,1);
  await act('revoke-share',{connectionId:active.connectionId,deviceId:input.deviceId,rootId:'project'});assert.equal((await act('status',{intentId:ID})).phase,'revoked');await act('revoke-connection',{connectionId:active.connectionId});
  assert.equal((await(await request(mf,'/test/snapshot')).json()).find(([key])=>key==='accounts:v3:intent:'+ID)[1].phase,'active');
  const other='e'.repeat(32);await act('prepare',{...input,intentId:other});await act('cancel',{intentId:other});assert.equal((await act('status',{intentId:other})).phase,'cancelled');
  const expired='f'.repeat(32);await act('prepare',{...input,intentId:expired});const saved=(await(await request(mf,'/test/snapshot')).json()).find(([key])=>key==='accounts:v3:intent:'+expired)[1];await request(mf,'/test/put',{key:'accounts:v3:intent:'+expired,value:{...saved,expiresAt:0}});assert.equal((await act('status',{intentId:expired})).phase,'expired');assert.equal((await(await request(mf,'/test/snapshot')).json()).find(([key])=>key==='accounts:v3:intent:'+expired)[1].phase,'prepared');
  const events=await(await request(mf,'/test/events')).json();for(const action of ['account','connections','prepare','status','cancel','confirm-prepared','activate','revoke-share','revoke-connection','active-idempotent-confirm','active-idempotent-activate'])assert.ok(events.some(e=>e.kind==='rust-decided'&&e.op==='account.execute'&&e.branch===action),action);assert.ok(events.some(e=>e.op==='account.resolve'&&e.kind==='rust-decided'));
  const guarded={action:'account',actor,input:{}};assert.equal((await request(mf,'/test/account-guard',guarded)).status,401);
  await request(mf,'/test/seed',{entries:[['onboarding:v1:session-binding:'+actor.sessionBinding,{identityKey:actor.identityKey,until:Date.now()+60000}]]});assert.equal((await request(mf,'/test/account-guard',guarded)).status,200);
  await request(mf,'/test/seed',{entries:[]});assert.equal((await request(mf,'/test/account-guard',guarded)).status,401);assert.deepEqual(await(await request(mf,'/test/snapshot')).json(),[]);
  recordCoverage(await(await request(mf,'/test/events')).json(),'Account nine action responses and current session guard',mf);
});

test('actual workerd Onboarding five sites complete native enrollment once and recheck revoked current sessions',wasm,async t=>{
  for(const rust of [false,true]){
    const mf=await runtime(rust);t.after(()=>mf.dispose());
    const call=async(action,value)=>{const r=await request(mf,'/onboarding/'+action,value),body=await r.json();assert.equal(r.status,200,JSON.stringify(body));return body;};
    const session={issuer:'https://identity.example.test',subject:'fixture',sessionId:HASH,expiresAt:Date.now()+3600000};
    const actor={identityKey:await sha256(JSON.stringify([session.issuer,session.subject])),sessionBinding:await sha256(JSON.stringify([session.issuer,session.subject,session.sessionId]))};
    await call('records',{action:'put',kind:'session',secret:SECOND,value:session,ttl:3600});assert.deepEqual(await call('records',{action:'get',kind:'session',secret:SECOND}),session);
    await call('records',{action:'put',kind:'login',secret:HASH,value:{browserHash:SECOND,fixture:true},ttl:60});assert.equal((await call('records',{action:'take',kind:'login',secret:HASH,value:{browserHash:SECOND}})).fixture,true);
    const resource='https://relay.example.test/mcp',authRequest={clientId:'onboard-fixture',scope:['files:read','files:write'],redirectUri:'https://client.example.test/callback'};
    const flow=await call('start',{actor,displayName:'Fixture',clientName:'Client',authRequest,resource});const secret='e'.repeat(64),device={deviceId:ID,epoch:HASH};
    await call('provision',{flowId:flow.flowId,bootstrap:flow.bootstrap,deviceId:ID,keyHash:SECOND,sessionHash:await sha256(secret)});
    const native=(action,input={})=>call('native',{action,flowId:flow.flowId,secret:action==='start'?flow.bootstrap:secret,device,input});
    await native('start',{sessionSecret:secret});
    if(rust){const key='onboarding:v1:session-binding:'+actor.sessionBinding,saved=(await(await request(mf,'/test/snapshot')).json()).find(([k])=>k===key)[1];await request(mf,'/test/race',{op:'account.execute',action:'prepare',key,remove:true,case:'current-session-revoked-after-precheck'});assert.equal((await request(mf,'/onboarding/native',{action:'prepare',flowId:flow.flowId,secret,device,input:{roots:[{rootId:'fixture',mode:'direct'}],policyDigest:HASH}})).status,401);assert.equal((await(await request(mf,'/test/race-state')).json()).hits,1);await request(mf,'/test/put',{key,value:saved});await request(mf,'/test/case',{case:'main-chain'});}
    const intent=await native('prepare',{roots:[{rootId:'fixture',mode:'direct'}],policyDigest:HASH});await native('confirm',{snapshotDigest:intent.snapshotDigest});await native('activate',{snapshotDigest:intent.snapshotDigest});
    const finish=await call('finish',{flowId:flow.flowId,browser:flow.browser,actor});assert.equal(finish.grant.grantVersion,3);assert.equal((await request(mf,'/onboarding/finish',{flowId:flow.flowId,browser:flow.browser,actor})).status,401);
    await call('records',{action:'delete',kind:'session',secret:SECOND});assert.equal((await request(mf,'/onboarding/native',{action:'status',flowId:flow.flowId,secret,device,input:{}})).status,401);
    if(rust){const events=await(await request(mf,'/test/events')).json();for(const op of EXPECTED_REGISTRY_OPERATIONS.filter(op=>op.startsWith('onboarding.')))assert.ok(events.some(e=>e.op===op&&e.kind==='rust-decided'),op);assert.ok(events.some(e=>e.kind==='rust-decided'&&e.case==='current-session-revoked-after-precheck'&&e.outcome==='abort'));recordCoverage(events,'Onboarding enrollment and session revocation',mf);}
  }
});

test('actual workerd PrivateInstance twelve sites preserve native claims, recovery, removal and current invite guards',wasm,async t=>{
  for(const rust of [false,true]){
    const mf=await runtime(rust,true);t.after(()=>mf.dispose());const resource='https://private.example.test/mcp';
    const call=async(action,input={})=>{const r=await request(mf,'/instance/'+action,{resource,input}),body=await r.json();assert.equal(r.status,200,action+': '+JSON.stringify(body));return body;};
    const authRequest={clientId:'fixture-private',scope:['files:read','files:write'],redirectUri:'https://client.example.test/callback'};
    const invite=await call('createInvitation',{purpose:'connect',clientId:authRequest.clientId});const flow=await call('makeFlow',{authRequest,clientName:'Private client'});
    const device={deviceId:ID,epoch:HASH,keyHash:SECOND},secret='e'.repeat(64),rootId='11111111-1111-1111-1111-111111111111';
    const claim={flowId:flow.flowId,bootstrap:flow.bootstrap,invitation:invite.invitation,deviceId:ID,keyHash:SECOND,sessionHash:await sha256(secret),registering:true};await Promise.all([call('claim',claim),call('claim',claim)]);
    const native=(action,input={})=>call('native',{action,flowId:flow.flowId,secret:action==='start'?flow.bootstrap:secret,device,input,...(action==='start'?{invitation:invite.invitation}:{})});
    await native('start',{sessionSecret:secret});
    if(rust){const key='instance:v1:flow:'+flow.flowId,saved=(await(await request(mf,'/test/snapshot')).json()).find(([k])=>k===key)[1];await request(mf,'/test/race',{op:'account.execute',action:'prepare',key,value:{...saved,cancelled:true},case:'current-private-flow-revoked-after-precheck'});assert.equal((await request(mf,'/instance/native',{resource,input:{action:'prepare',flowId:flow.flowId,secret,device,input:{roots:[{rootId,mode:'direct'}],policyDigest:HASH}}})).status,403);assert.equal((await(await request(mf,'/test/race-state')).json()).hits,1);await request(mf,'/test/put',{key,value:saved});await request(mf,'/test/case',{case:'main-chain'});}
    if(rust){const key='instance:v1:invite:'+invite.invitationId,saved=(await(await request(mf,'/test/snapshot')).json()).find(([k])=>k===key)[1];await request(mf,'/test/race',{op:'account.execute',action:'prepare',key,value:{...saved,revoked:true},case:'current-invitation-revoked-after-precheck'});assert.equal((await request(mf,'/instance/native',{resource,input:{action:'prepare',flowId:flow.flowId,secret,device,input:{roots:[{rootId,mode:'direct'}],policyDigest:HASH}}})).status,403);assert.equal((await(await request(mf,'/test/race-state')).json()).hits,2);await request(mf,'/test/put',{key,value:saved});await request(mf,'/test/case',{case:'main-chain'});}
    const intent=await native('prepare',{roots:[{rootId,mode:'direct'}],policyDigest:HASH});await native('confirm',{snapshotDigest:intent.snapshotDigest});const active=await native('activate',{snapshotDigest:intent.snapshotDigest});await native('activate',{snapshotDigest:intent.snapshotDigest});
    const finish=await call('finish',{flowId:flow.flowId,browser:flow.browser});assert.equal(finish.grant.connectionId,active.connectionId);assert.ok((await call('remembered',{secret:finish.remember,authRequest})).grant);
    const install=async(action,input)=>{const r=await request(mf,'/install/'+action,{resource,input}),body=await r.json();assert.equal(r.status,200,'install '+action+': '+JSON.stringify(body));return body;};
    const password='isolated-fixture-password-only';await install('configure',{password});const login=await install('login',{password,network:SECOND});
    const ticketId='f'.repeat(32),claimSecret='1'.repeat(64),browserSecret='2'.repeat(64);await install('start',{id:ticketId,claimHash:await sha256(claimSecret),browserHash:await sha256(browserSecret),name:'Fixture computer'});
    assert.equal((await install('context',{id:ticketId,browser:browserSecret})).authenticated,false);
    assert.equal((await install('context',{id:ticketId,browser:browserSecret,session:login.session})).authenticated,true);
    assert.equal((await install('claim',{id:ticketId,secret:claimSecret})).waiting,true);
    if(rust){const key='install:v1:password',saved=(await(await request(mf,'/test/snapshot')).json()).find(([k])=>k===key)[1];await request(mf,'/test/race',{op:'install.authorize.pin',key,value:{...saved,epoch:SECOND},case:'current-installer-session-revoked-after-check'});assert.equal((await request(mf,'/install/authorize',{resource,input:{id:ticketId,browser:browserSecret,session:login.session,connectionId:null}})).status,401);assert.equal((await(await request(mf,'/test/race-state')).json()).hits,3);await request(mf,'/test/put',{key,value:saved});await request(mf,'/test/case',{case:'main-chain'});}
    if(rust){const key='install:v1:ticket:'+ticketId,saved=(await(await request(mf,'/test/snapshot')).json()).find(([k])=>k===key)[1];await request(mf,'/test/race',{op:'install.authorize.pin',key,value:{...saved,until:0},case:'current-installer-ticket-expired-after-check'});assert.equal((await request(mf,'/install/authorize',{resource,input:{id:ticketId,browser:browserSecret,session:login.session,connectionId:null}})).status,401);assert.equal((await(await request(mf,'/test/race-state')).json()).hits,4);await request(mf,'/test/put',{key,value:saved});await request(mf,'/test/case',{case:'main-chain'});}
    await install('authorize',{id:ticketId,browser:browserSecret,session:login.session,connectionId:null});assert.equal((await install('claim',{id:ticketId,secret:claimSecret})).waiting,false);
    await install('ready',{id:ticketId,secret:claimSecret});assert.ok((await install('context',{id:ticketId,browser:browserSecret,session:login.session})).nextUrl);await install('logout',{session:login.session});assert.equal((await install('context',{id:ticketId,browser:browserSecret,session:login.session})).authenticated,false);
    const recovered=await call('makeFlow',{authRequest,clientName:'Recovery'});const recoverySecret='f'.repeat(64);const recovery=await call('native',{action:'start',flowId:recovered.flowId,secret:recovered.bootstrap,device,input:{sessionSecret:recoverySecret,reuseExisting:true}});assert.equal(recovery.reuseExisting,true);
    const managed=await call('manage',{action:'connections',device,input:{}});assert.equal(managed.connections.length,1);const manage={action:'start',device,input:{flowId:'d'.repeat(32),connectionId:active.connectionId,sessionSecret:secret}};const initial=await call('manage',manage);
    await request(mf,'/test/put',{key:'instance:v1:client:'+active.connectionId,value:{clientName:'Updated client',redirectUri:'https://new-client.example.test/callback'}});
    const current=await call('manage',manage);assert.equal(current.clientName,'Updated client');assert.equal(current.callbackOrigin,'https://new-client.example.test');assert.equal(current.requestDigest,initial.requestDigest);
    const join=await call('createInvitation',{purpose:'join',connectionId:active.connectionId});await call('makeFlow',{invitation:join.invitation});await call('revokeInvitation',{invitationId:join.invitationId});assert.equal((await request(mf,'/instance/makeFlow',{resource,input:{invitation:join.invitation}})).status,403);
    const removed=await call('manage',{action:'remove',device,input:{requestId:'c'.repeat(32),connectionId:active.connectionId,rootIds:[rootId],expectedRevision:managed.connections[0].revision}});assert.equal(removed.removed,true);
    await call('revokeInvitation',{invitationId:invite.invitationId});assert.equal((await request(mf,'/instance/native',{resource,input:{action:'status',flowId:flow.flowId,secret,device,input:{}}})).status,403);
    const snapshot=await(await request(mf,'/test/snapshot')).json();assert.equal(snapshot.find(([key])=>key==='deviceCount')[1],1);
    if(rust){const events=await(await request(mf,'/test/events')).json();for(const op of EXPECTED_REGISTRY_OPERATIONS.filter(op=>op.startsWith('instance.')||op.startsWith('install.')))assert.ok(events.some(e=>e.op===op&&e.kind==='rust-decided'),op);for(const value of ['current-private-flow-revoked-after-precheck','current-invitation-revoked-after-precheck','current-installer-session-revoked-after-check','current-installer-ticket-expired-after-check'])assert.ok(events.some(e=>e.kind==='rust-decided'&&e.case===value&&e.outcome==='abort'),value);recordCoverage(events,'Private and Install HTTP state transitions and final device count',mf);}
  }
});

test('instrumented actual workerd rejects a deliberately disconnected runner instead of a legacy transaction',wasm,async t=>{
  const mf=await runtime(true,false,undefined,undefined,true);t.after(()=>mf.dispose());
  assert.equal((await request(mf,'/enroll',{deviceId:ID})).status,200);
  const response=await request(mf,'/test/legacy');assert.equal(response.status,500);assert.equal((await response.json()).error,'Fixture forbids legacy Registry transactions');
});

test('combined artifacts reject missing Registry WASM, old Device-only manifests and stale later aggregate modules',wasm,async t=>{
  const target=await fs.mkdtemp(path.join(projectRoot,'.artifacts/registry-stale-'));t.after(()=>fs.rm(target,{recursive:true,force:true,maxRetries:10,retryDelay:100}));
  for(const name of [artifact.manifest.entry,artifact.manifest.wasm,artifact.manifest.registryWasm,...(artifact.manifest.oauthWasm?[artifact.manifest.oauthWasm]:[])])await fs.copyFile(path.join(directory,name),path.join(target,name));
  const write=value=>fs.writeFile(path.join(target,'manifest.json'),JSON.stringify(value));
  await write({...artifact.manifest,v:1,kind:undefined});await assert.rejects(readArtifact(target),/artifact/);
  await write({...artifact.manifest,sources:{...artifact.manifest.sources,'crates/relay-registry-core/src/install.rs':'0'.repeat(64)}});await assert.rejects(readArtifact(target),/Stale.*source/);
  await write(artifact.manifest);await fs.rm(path.join(target,artifact.manifest.registryWasm));await assert.rejects(readArtifact(target),e=>e.code==='ENOENT');
});

test('actual workerd remember-full normal completion commits only expired cleanup',wasm,async t=>{
  const mf=await runtime(true,true);t.after(()=>mf.dispose());assert.deepEqual(await(await request(mf,'/test/remember-full')).json(),{count:64,expiredRetained:false});
  const events=await(await request(mf,'/test/events')).json();assert.ok(events.some(e=>e.kind==='rust-decided'&&e.branch==='remember-full'));recordCoverage(events,'Direct core capacity fixture: remember-full commits cleanup',mf);
});

test('static 37 sites exactly match actual workerd Rust decisions bound to completed transaction attempts',wasm,async()=>{
  const files=['state','request-budget','device-roster','account-directory','onboarding-store','private-instance','install-portal'];
  const sites=[];for(const name of files){const source=await fs.readFile(path.join(projectRoot,'src/relay',name+'.mjs'),'utf8');for(const match of source.matchAll(/registry(?:Transaction|Response)\([^;]*?['"]([a-z][\w.]+)['"]/g))sites.push(match[1]);}
  assert.equal(sites.length,37);assert.deepEqual(sites.sort(),[...EXPECTED_REGISTRY_OPERATIONS].sort());
  const actual=[...new Set(coverage.map(row=>row.op))].sort();assert.deepEqual(actual,[...EXPECTED_REGISTRY_OPERATIONS].sort());
  const result={expected:EXPECTED_REGISTRY_OPERATIONS,actual,missing:[],count:37,requiredSkip:0,registryWasm:artifact.manifest.registryWasm,runtimes:runtimeEvidence,decisions:coverage};
  console.log('Registry actual workerd coverage: 37/37, missing=0; decisions='+coverage.length);
  if(process.env.CHAT2LOCAL_REGISTRY_TEST_COVERAGE_DIR){await fs.mkdir(process.env.CHAT2LOCAL_REGISTRY_TEST_COVERAGE_DIR,{recursive:true});await fs.writeFile(path.join(process.env.CHAT2LOCAL_REGISTRY_TEST_COVERAGE_DIR,'registry-coverage.json'),JSON.stringify(result,null,2));}
});
