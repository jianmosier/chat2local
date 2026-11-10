import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {Store} from '../src/agent/store.mjs';
import {stateDirectory,existingStateDirectory,sameDirectory} from '../src/agent/platform.mjs';
import {readNativeStoreArtifact,sourceFiles,root as sourceRoot} from '../scripts/native-store-artifact.mjs';
import {createHash} from 'node:crypto';
import {NativeAccountOnboarding} from '../src/agent/account-onboarding.mjs';
import {FolderManagement} from '../src/agent/folder-management.mjs';
import {ConsentCoordinator} from '../src/agent/consent-coordinator.mjs';
import {prepareUpgrade} from '../scripts/upgrade-session.mjs';
const executable=process.env.CHAT2LOCAL_NATIVE_STORE_TEST_EXECUTABLE??path.resolve('.artifacts/rust-native-store/chat2local-native-store-fixture.exe');
let available=false;try{await fs.access(path.dirname(executable));available=true;}catch(error){if(error.code!=='ENOENT')throw error;}
if(available||process.env.CHAT2LOCAL_NATIVE_STORE_TEST_REQUIRED==='1'||process.env.CHAT2LOCAL_NATIVE_STORE_TEST_EXECUTABLE)await readNativeStoreArtifact(executable);
const native={skip:!available};
async function fixture(t){const dir=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-native-store-'));t.after(()=>fs.rm(dir,{recursive:true,force:true,maxRetries:10,retryDelay:100}));await fs.writeFile(path.join(dir,'.chat2local-native-store-fixture'),'synthetic-native-store-fixture\n');return{dir,store:new Store(dir),call:request=>call(dir,request)};}
function call(dir,request){const p=spawnSync(executable,['--state-dir',dir],{input:JSON.stringify(request)+'\n',encoding:'utf8',env:{...process.env,PATH:'',Path:''},windowsHide:true,shell:false,timeout:30000,maxBuffer:32*1024*1024});assert.equal(p.error,undefined);assert.equal(p.status,0,p.stderr);return JSON.parse(p.stdout);}
const value=result=>{assert.equal(result.ok,true,result.message);return result.value;};
const save=(f,target,data,key)=>value(f.call({op:'save',target,json:JSON.stringify(data),key}));
const read=(f,target,key)=>{const v=value(f.call({op:'read',target,key}));return v.missing?null:JSON.parse(v.json);};
const utf16=text=>Array.from({length:text.length},(_,i)=>text.charCodeAt(i));
const flow=n=>'onboarding-flow-'+n.toString(16).padStart(32,'0');
const term=n=>'terminal-'+n.toString(16).padStart(8,'0')+'-0000-0000-0000-000000000000';

test('native fixture requires an explicit synthetic directory and authentic fresh artifact',native,async t=>{
  const p=spawnSync(executable,[],{env:{...process.env,PATH:'',Path:''},encoding:'utf8',windowsHide:true});assert.notEqual(p.status,0);
  const f=await fixture(t);const m=await readNativeStoreArtifact(executable);assert.equal(m.fixtureOnly,true);assert.deepEqual(value(f.call({op:'load'})),{configJson:JSON.stringify({version:1,roots:[],paused:false,startup:false,relay:''}),secretsJson:'{}'});assert.deepEqual((await fs.readdir(f.dir)).sort(),['.chat2local-native-store-fixture']);
});
test('selected native Store fixture fails closed for missing stale and corrupt artifacts',native,async t=>{
  const f=await fixture(t),copyRoot=path.join(f.dir,'sources'),copyBin=path.join(f.dir,'artifacts');await fs.mkdir(copyBin);
  const manifest=await readNativeStoreArtifact(executable);for(const file of await sourceFiles()){const target=path.join(copyRoot,file);await fs.mkdir(path.dirname(target),{recursive:true});await fs.copyFile(path.join(sourceRoot,file),target);}
  const copy=path.join(copyBin,path.basename(executable));await fs.copyFile(executable,copy);await fs.writeFile(path.join(copyBin,'manifest.json'),JSON.stringify(manifest));await readNativeStoreArtifact(copy,{sourceRoot:copyRoot});
  const source=path.join(copyRoot,'crates/native-store/src/lib.rs');await fs.appendFile(source,'\n// private stale negative\n');await assert.rejects(()=>readNativeStoreArtifact(copy,{sourceRoot:copyRoot}),/Stale/);await fs.copyFile(path.join(sourceRoot,'crates/native-store/src/lib.rs'),source);
  await fs.appendFile(copy,Buffer.from([0]));await assert.rejects(()=>readNativeStoreArtifact(copy,{sourceRoot:copyRoot}),/binary mismatch/);await fs.rm(copy);await assert.rejects(()=>readNativeStoreArtifact(copy,{sourceRoot:copyRoot}),/ENOENT/);
});
test('actual JS Store and native DPAPI exchange every legacy record format with native PATH excluding Node',native,async t=>{
  const f=await fixture(t);const config={version:1,roots:[{id:'root',path:f.dir,mode:'review'}],paused:false,startup:false,relay:'https://example.test','00':'unknown',future:{'2':'index','a':'😀\ud800',nested:[null,false,1e21]}};
  const secrets={deviceId:'fixture',privateKey:'fixture-key',connections:{c:{resource:'fixture-resource',scopes:['files:read']}},future:{constructor:1,'__proto__':'value'}};
  await f.store.saveConfig(config);await f.store.saveSecrets(secrets);await f.store.saveSession({token:'fixture-only'});
  const records=[['management-sessions',{sessions:[{id:'fixture-session',receipt:{a:1}}]}],[flow(1),{phase:'consented',roots:config.roots,unknown:'中文'}],['onboarding-intent-'+'1'.repeat(32),{phase:'prepared',digest:'unchanged'}],[term(1),{requestId:'legacy-no-new-validation',inputHash:'raw-hash',state:'running',unknown:'kept'}]];
  for(const[key,data]of records)await f.store.savePrivateRecord(key,data);
  assert.deepEqual(JSON.parse(value(f.call({op:'load'})).configJson),config);assert.deepEqual(read(f,'secrets'),secrets);assert.deepEqual(read(f,'session'),{token:'fixture-only'});
  for(const[key,data]of records)assert.deepEqual(read(f,'private',key),data);
  for(const target of ['config','secrets','session']){value(f.call({op:'patch',target,path:[utf16('futureNative')],json:'{"x":"😀\\ud800","0":-0}'}));}
  for(const[key]of records){value(f.call({op:'patch',target:'private',key,path:[utf16('futureNative')],json:'{"seen":true}'}));assert.deepEqual((await f.store.readPrivateRecord(key)).futureNative,{seen:true});}
  const loaded=await f.store.load();assert.equal(loaded.secrets.deviceId,'fixture');assert.deepEqual(loaded.config.roots,config.roots);assert.deepEqual(loaded.config.futureNative,{0:0,x:'😀\ud800'});assert.deepEqual((await f.store.readSession()).futureNative,{0:0,x:'😀\ud800'});
  assert.equal(await fs.readFile(path.join(f.dir,'settings.json'),'utf8'),JSON.stringify(loaded.config,null,2));
  for(const file of ['vault.json','session.json'])assert.equal(JSON.parse(await fs.readFile(path.join(f.dir,file),'utf8')).format,'windows-dpapi-v1');
});
test('missing differs from corrupt settings, unsupported envelopes and corrupt DPAPI; no reset or write',native,async t=>{
  const f=await fixture(t);assert.equal(read(f,'private',flow(2)),null);assert.equal(f.call({op:'read',target:'session'}).code,'ENOENT');
  for(const bytes of [Buffer.from('{bad'),Buffer.from('null'),Buffer.from('{"version":1,"roots":[],"paused":0}'),Buffer.from('\ufeff{"version":1,"roots":[],"paused":false}')]){await fs.writeFile(path.join(f.dir,'settings.json'),bytes);assert.equal(f.call({op:'load'}).ok,false);assert.deepEqual(await fs.readFile(path.join(f.dir,'settings.json')),bytes);await assert.rejects(f.store.load());}
  await fs.writeFile(path.join(f.dir,'settings.json'),Buffer.concat([Buffer.from('{"version":1,"roots":[],"paused":false,"unknown":"'),Buffer.from([0xff]),Buffer.from('"}')]));assert.equal(JSON.parse(value(f.call({op:'load'})).configJson).unknown,'�');
  for(const envelope of [{format:'posix-permissions-only',data:'e30='},{format:'future',data:'e30='},{format:'windows-dpapi-v1',data:'AAAA'}]){const bytes=JSON.stringify(envelope);await fs.writeFile(path.join(f.dir,'vault.json'),bytes);assert.equal(f.call({op:'load'}).ok,false);assert.equal(await fs.readFile(path.join(f.dir,'vault.json'),'utf8'),bytes);}
});
test('private path, junction and hardlink checks reject unsafe reads while preserving fixture targets',native,async t=>{
  const f=await fixture(t);for(const key of ['../vault','onboarding-flow-0',term(1).toUpperCase()])assert.equal(f.call({op:'read',target:'private',key}).ok,false);
  save(f,'private',{kept:true},flow(1));const file=f.store.privateRecordPath(flow(1)),bytes=await fs.readFile(file);await fs.link(file,path.join(f.dir,'alias'));
  assert.equal(f.call({op:'read',target:'private',key:flow(1)}).ok,false);await assert.rejects(f.store.readPrivateRecord(flow(1)));assert.deepEqual(await fs.readFile(file),bytes);
  await fs.rename(path.join(f.dir,'onboarding'),path.join(f.dir,'original'));await fs.symlink(path.join(f.dir,'original'),path.join(f.dir,'onboarding'),'junction');assert.equal(f.call({op:'read',target:'private',key:flow(1)}).ok,false);assert.equal(f.call({op:'save',target:'private',key:flow(2),json:'{}'}).ok,false);
});
test('UTF16 private and UTF8 terminal limits retain the old write/read distinction and large vault support',native,async t=>{
  const f=await fixture(t);const emoji='😀'.repeat(32767);save(f,'private',emoji,flow(1));assert.equal(read(f,'private',flow(1)),emoji);assert.equal(f.call({op:'save',target:'private',key:flow(1),json:JSON.stringify(emoji+'x')}).code,'ELIMIT');
  const terminal='x'.repeat(512*1024-2);save(f,'private',terminal,term(1));assert.equal(read(f,'private',term(1)),terminal);assert.equal(f.call({op:'save',target:'private',key:term(1),json:JSON.stringify(terminal+'x')}).code,'ELIMIT');
  const bmp='中'.repeat(65534);save(f,'private',bmp,flow(2));assert.equal(f.call({op:'read',target:'private',key:flow(2)}).ok,false);await assert.rejects(f.store.readPrivateRecord(flow(2)));
  save(f,'secrets',{large:'x'.repeat(1100000)});assert.equal((await f.store.load()).secrets.large.length,1100000);assert.equal(read(f,'secrets').large.length,1100000);
});
test('capacity counts all entries, keeps terminal reservations and preserves false/null truthiness',native,async t=>{
  const f=await fixture(t);save(f,'private',{},flow(1));save(f,'private',false,flow(2));const dir=path.join(f.dir,'onboarding');await Promise.all(Array.from({length:126},(_,i)=>fs.writeFile(path.join(dir,'unowned-'+i),'x')));
  save(f,'private',{updated:true},flow(1));assert.equal(f.call({op:'save',target:'private',key:flow(2),json:'{}'}).code,'ECAPACITY');assert.equal(f.call({op:'save',target:'private',key:flow(3),json:'{}'}).code,'ECAPACITY');
  save(f,'private',{},term(1));const terminal=path.join(f.dir,'terminal');await Promise.all(Array.from({length:2047},(_,i)=>fs.writeFile(path.join(terminal,'reservation-'+i),'x')));save(f,'private',{updated:true},term(1));assert.equal(f.call({op:'save',target:'private',key:term(2),json:'{}'}).code,'ECAPACITY');assert.equal((await fs.readdir(terminal)).length,2048);
});
test('cleanup needs 64 owned entries, ages strictly after 48h, preserves current and hardlinks',native,async t=>{
  const f=await fixture(t);save(f,'private',{current:true},flow(0));const dir=path.join(f.dir,'onboarding'),old=new Date(Date.now()-49*3600000);
  const fill=async i=>{const file=f.store.privateRecordPath(flow(i));await fs.writeFile(file,'old-placeholder');await fs.utimes(file,old,old);};await Promise.all(Array.from({length:62},(_,i)=>fill(i+1)));save(f,'private',{current:true},flow(0));assert.equal((await fs.readdir(dir)).length,63);
  await fill(63);await fs.link(f.store.privateRecordPath(flow(1)),path.join(f.dir,'outside-hardlink'));await fs.utimes(f.store.privateRecordPath(flow(0)),old,old);save(f,'private',{current:true},flow(0));assert.deepEqual((await fs.readdir(dir)).sort(),[path.basename(f.store.privateRecordPath(flow(0))),path.basename(f.store.privateRecordPath(flow(1)))].sort());
});
test('atomic rename failure leaves existing target intact and removes only its own temp',native,async t=>{
  const f=await fixture(t);await fs.mkdir(path.join(f.dir,'settings.json'));await fs.writeFile(path.join(f.dir,'settings.json/owned'),'keep');assert.equal(f.call({op:'save',target:'config',json:'{}'}).ok,false);assert.equal(await fs.readFile(path.join(f.dir,'settings.json/owned'),'utf8'),'keep');assert.deepEqual((await fs.readdir(f.dir)).sort(),['.chat2local-native-store-fixture','settings.json']);
});
test('state-directory precedence, target path spelling, old-directory conflicts and actual identity match JS',native,async t=>{
  const f=await fixture(t);for(const platform of ['win32','darwin','linux'])for(const home of ['C:\\Users\\fixture','C:','/tmp/home/../person','//server/share/home'])for(const env of [{},{CHAT2LOCAL_STATE_DIR:'../explicit//path'},{LOCALAPPDATA:'C:\\a\\..\\b',XDG_STATE_HOME:'/state//one/../two'}])assert.equal(value(f.call({op:'location',platform,home,env})).path,stateDirectory({platform,home,env}));
  const home=path.join(f.dir,'home'),legacy=path.join(home,'.local/share/Chat2Local');await fs.mkdir(legacy,{recursive:true});await fs.writeFile(path.join(legacy,'vault.json'),'exists');assert.equal(value(f.call({op:'existing',platform:'linux',home:'home',env:{}})).path,existingStateDirectory({platform:'linux',home,env:{}}));
  const preferred=stateDirectory({platform:'linux',home,env:{}});await fs.mkdir(preferred,{recursive:true});await fs.writeFile(path.join(preferred,'settings.json'),'exists');assert.equal(f.call({op:'existing',platform:'linux',home:'home',env:{}}).code,'ECONFLICT');assert.throws(()=>existingStateDirectory({platform:'linux',home,env:{}}));
  await fs.mkdir(path.join(f.dir,'a'));await fs.mkdir(path.join(f.dir,'b'));await fs.symlink(path.join(f.dir,'a'),path.join(f.dir,'link'),'junction');for(const [first,second]of[['a','link'],['a','b']])assert.equal(value(f.call({op:'same',first,second})).same,await sameDirectory(path.join(f.dir,first),path.join(f.dir,second)));
});

test('original policy and management digests survive actual native disk mutation without permission changes',native,async t=>{
  const f=await fixture(t),shared=path.join(f.dir,'shared');await fs.mkdir(shared);const stat=await fs.stat(shared,{bigint:true});
  // State directory is a sibling of the shared folder: approveRoot must see the
  // original real filesystem identity, not a mocked stat or permission decision.
  const state=path.join(f.dir,'state');await fs.mkdir(state);await fs.writeFile(path.join(state,'.chat2local-native-store-fixture'),'synthetic-native-store-fixture\n');const store=new Store(state),g={...f,dir:state,store,call:request=>call(state,request)};
  const identity={deviceId:'a'.repeat(32),origin:'https://fixture.test'},selection={id:'r1',path:await fs.realpath(shared),write:true,writeMode:'direct',dev:String(stat.dev),ino:String(stat.ino),future:{z:'\ud800',10:1,1:2,a:3}};
  let config={version:1,paused:false,roots:[selection],accountRoots:[{id:'retained',intentId:'b'.repeat(32),unknown:{last:1,first:2}}],terminalGrants:[{rootId:'retained',allow:true}]};
  let local={flowId:'c'.repeat(32),deviceId:identity.deviceId,origin:identity.origin,revision:7,accessProfile:'project',selections:[selection]};
  const service=new NativeAccountOnboarding({store,getConfig:()=>config,getIdentity:()=>identity,getRevision:()=>7});local.policyDigest=service.policy(local);await store.saveConfig(config);await store.saveSecrets({identity,unknown:{b:1,a:2}});await store.savePrivateRecord('onboarding-flow-'+local.flowId,local);
  const original=local.policyDigest;value(g.call({op:'patch',target:'private',key:'onboarding-flow-'+local.flowId,path:[utf16('n1Unknown')],json:'{"x":"\\ud800"}'}));
  // Replacing the same existing field retains its member position and therefore
  // the original policy's JSON bytes. All authorization fields remain intact.
  value(g.call({op:'patch',target:'config',path:[utf16('paused')],json:'false'}));config=(await store.load()).config;local=await store.readPrivateRecord('onboarding-flow-'+local.flowId);assert.equal(service.policy(local),original);await service.assertCurrent(local,{intentId:local.flowId,policyDigest:original});
  const input={connectionId:'d'.repeat(32),requestId:'e'.repeat(32),folders:[{mode:'direct',path:shared}]};const digest=createHash('sha256').update(JSON.stringify(input)).digest('hex');await store.savePrivateRecord('onboarding-flow-'+input.requestId,{flowId:input.requestId,management:true,managementRequestDigest:digest,context:{}});await store.savePrivateRecord('onboarding-intent-'+input.requestId,{});
  value(g.call({op:'patch',target:'private',key:'onboarding-flow-'+input.requestId,path:[utf16('n1Unknown')],json:'1'}));const manager=new FolderManagement({store});manager.current=()=>({});manager.inspect=async()=>({accepted:true});assert.deepEqual(await manager.performManagement('prepare',input),{accepted:true});await assert.rejects(()=>manager.performManagement('prepare',{...input,folders:[{mode:'review',path:shared}]}),/不能更换/);
  value(g.call({op:'patch',target:'config',path:[utf16('roots'),utf16('0'),utf16('writeMode')],json:'"review"'}));config=(await store.load()).config;await assert.rejects(()=>service.assertCurrent(local,{intentId:local.flowId,policyDigest:original}),/发生变化/);
});
test('original controlled-upgrade fingerprint accepts JS to native to JS data and rejects permission mutation',native,async t=>{
  const f=await fixture(t);await f.store.saveConfig({version:1,roots:[{id:'keep',writeMode:'direct',future:{z:'\ud800',2:1,a:2}}],paused:false});await f.store.saveSecrets({deviceId:'retained',future:{b:1,a:2}});await f.store.saveSession({origin:'http://127.0.0.1:47631',token:'a'.repeat(64),instanceId:'fixture'});
  let running=true,version='old';const invoke=async(_session,route)=>{if(route==='/api/shutdown'){running=false;return{ok:true};}if(!running)throw Object.assign(Error('fixture closed'),{code:'ECONNREFUSED'});return{name:'chat2local',instanceId:'fixture',version,paused:false,pending:[]};};
  const before=await prepareUpgrade('new',{store:f.store,call:invoke,wait:async()=>{}});const loaded=value(f.call({op:'load'}));value(f.call({op:'save',target:'config',json:loaded.configJson}));value(f.call({op:'save',target:'secrets',json:loaded.secretsJson}));running=true;version='new';await before.verify();value(f.call({op:'patch',target:'config',path:[utf16('roots')],json:'[]'}));await assert.rejects(()=>before.verify(),/retain/);
});
test('saved one-time consent resumes across JS native JS journals without asking or confirming again',native,async t=>{
  const f=await fixture(t),id='a'.repeat(32);const intent={version:1,intentId:id,accountId:'b'.repeat(32),connectionId:'c'.repeat(32),deviceId:'d'.repeat(32),deviceEpoch:'e'.repeat(64),snapshotDigest:'f'.repeat(64),policyDigest:'1'.repeat(64),requestDigest:'2'.repeat(64),clientId:'https://fixture.test/client',resource:'https://fixture.test/mcp',roots:[{rootId:'retained',mode:'direct'}],scopes:['files:read','files:write']};
  let remote={...intent,phase:'prepared'},confirmations=0,activations=0,lose=true;
  const adapters={journal:{load:id=>f.store.readPrivateRecord('onboarding-intent-'+id),save:(id,record)=>f.store.savePrivateRecord('onboarding-intent-'+id,record)},cloud:{status:async()=>remote,confirm:async()=>{confirmations++;remote={...intent,phase:'consented'};if(lose){lose=false;throw Error('fixture lost response after consent');}return remote;},activate:async()=>{activations++;return remote={...intent,phase:'active'};}},local:{assertCurrent:async value=>assert.equal(value.policyDigest,intent.policyDigest),consentProof:async()=> 'fixture-proof',activate:async()=> 'fixture-local-activation'}};
  const first=new ConsentCoordinator(adapters);await first.stage(intent);await assert.rejects(()=>first.confirm(id,{snapshotDigest:intent.snapshotDigest,confirmation:'allow-shared-folders-v1'}),/lost response/);
  value(f.call({op:'patch',target:'private',key:'onboarding-intent-'+id,path:[utf16('n1Unknown')],json:'{"stillHere":true}'}));
  const nativeJournal={load:async id=>read(f,'private','onboarding-intent-'+id),save:async(id,record)=>save(f,'private',record,'onboarding-intent-'+id)};
  const restored=new ConsentCoordinator({...adapters,journal:nativeJournal});const result=await restored.resume(id);assert.equal(result.connected,true);assert.equal(result.confirmationCount,1);assert.equal(confirmations,1);assert.equal(activations,1);const persisted=await f.store.readPrivateRecord('onboarding-intent-'+id);assert.equal(persisted.userConfirmed,true);assert.equal(persisted.phase,'connected');assert.deepEqual(persisted.n1Unknown,{stillHere:true});assert.deepEqual(persisted.intent,intent);
});
