import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs/promises';
import path from 'node:path';
import { readControllerArtifact } from '../scripts/controller-artifact.mjs';
import { agent,page,data,cloud,firstFlow,until,post } from './native-account-fixture.mjs';
const executable=process.env.CHAT2LOCAL_CONTROLLER_TEST_EXECUTABLE;
if(process.env.CHAT2LOCAL_CONTROLLER_TEST_REQUIRED==='1'&&!executable)throw Error('Required native controller missing.');
if(executable)await readControllerArtifact(executable);
const native={skip:!executable,timeout:60000};
test('native account and instance page sessions are profile/path bound and grant no control authority',native,async t=>{
 const f=await agent(t,executable,'http://127.0.0.1:9');const a=await page(f,'account'),i=await page(f,'instance');
 assert.notEqual(a.nonce,i.nonce);assert.equal((await a.call('start',{origin:'http://127.0.0.1:9',flow:'x'})).status,409);
 const cross=await fetch(f.ready.origin+'/instance-connect/status',{method:'POST',headers:{Origin:f.ready.origin,'Content-Type':'application/json',Cookie:a.cookie},body:JSON.stringify({nonce:a.nonce,flowId:'a'.repeat(32)})});assert.equal(cross.status,403);
 assert.equal((await f.api('/api/root/add',{path:f.folder,write:false},{'X-Chat2Local-Token':'',Cookie:i.cookie,'X-Chat2Local-Manager':'1'})).status,401);
 assert.equal((await f.api('/api/instance/import-invitation',{url:'https://foreign.invalid/instance/invite#'+'a'.repeat(32)+'.'+'b'.repeat(64)},{Origin:'https://foreign.invalid'})).status,403);
 assert.deepEqual((await f.store.load()).config.roots,[]);assert.equal((await f.store.load()).secrets.identity,undefined);
 for(const route of ['/shares','/folders.js','/recovery.js','/account-connect.js','/instance-connect.js'])assert.equal((await fetch(f.ready.origin+route)).status,200,route);
});

test('native pending enrollment publication failures preserve one identity; cancelled network admission submits no credential',native,async t=>{
 const r=await cloud(t),f=await agent(t,executable,r.origin),p=await firstFlow(f,r);
 await f.control({op:'arm',point:'workflow:publish:vault',kind:'error'});assert.equal((await p.call('start',p.bootstrap)).status,503);assert.equal((await f.store.load()).secrets.accountEnrollmentPending,undefined);
 await f.control({op:'arm',point:'workflow:publish:flow',kind:'error'});assert.equal((await p.call('start',p.bootstrap)).status,503);const pending=(await f.store.load()).secrets.accountEnrollmentPending;assert.ok(pending);assert.equal(await f.store.readPrivateRecord('onboarding-flow-'+p.flowId),null);
 await f.control({op:'hold',point:'workflow:send'});const started=p.call('start',p.bootstrap);await until(async()=>((await f.control({op:'inspect'})).entered['workflow:send']||0)>0);const changed={...p.bootstrap,flow:p.flowId+'.'+'0'.repeat(64)};assert.equal((await p.call('start',changed)).status,409);await data(await f.api('/api/pause',{paused:true}));await f.control({op:'release',point:'workflow:send'});assert.equal((await started).status,409);assert.deepEqual((await f.store.load()).secrets.accountEnrollmentPending,pending);assert.equal((await f.store.load()).secrets.identity,undefined);const probe=await post(r.origin+'/device/'+pending.deviceId+'/metadata',{name:'Not initialized',platform:'win32',arch:'x64',system:'Windows'},{Authorization:'Bearer '+pending.deviceKey});assert.equal(probe.status,401);assert.equal((await f.store.load()).config.accountRoots,undefined);
});

test('native actual grant publication is fenced by disconnect, permanent fault and close with held path/listener drainage',{...native,timeout:180000},async t=>{
 for(const cause of ['disconnect','fault','close'])await t.test(cause,async t=>{
  const r=await cloud(t),f=await agent(t,executable,r.origin),p=await firstFlow(f,r);await data(await p.call('start',p.bootstrap));const staged=await data(await p.call('choose',{flowId:p.flowId}));const before=await fs.readFile(path.join(f.directory,'settings.json'));await f.control({op:'hold',point:'workflow:publish:grant'});
  const input={nonce:p.nonce,flowId:p.flowId,snapshotDigest:staged.snapshotDigest,confirmation:'allow-shared-folders-v1'};let request;const confirmation=cause==='disconnect'?new Promise(resolve=>{request=http.request(f.ready.origin+'/instance-connect/confirm',{method:'POST',headers:{Origin:f.ready.origin,Cookie:p.cookie,'Content-Type':'application/json'}},response=>{response.resume();resolve(response);});request.on('error',resolve);request.end(JSON.stringify(input));}):p.call('confirm',input);
  await until(async()=>((await f.control({op:'inspect'})).entered['workflow:publish:grant']||0)>0);await assert.rejects(fs.rename(f.folder,f.folder+'-replacement'));
  if(cause==='disconnect'){const count=(await f.control({op:'inspect'})).requestDisconnects;request.destroy();await confirmation;await until(async()=>(await f.control({op:'inspect'})).requestDisconnects>count);}else if(cause==='fault'){await f.control({op:'arm',point:'core:snapshot',kind:'error'});await f.control({op:'trigger',point:'snapshot'});assert.equal((await(await f.api('/api/status')).json()).nativeFault,true);}else{await f.control({op:'trigger',point:'close'});assert.equal(f.child.exitCode,null);const server=net.createServer();const error=await new Promise(resolve=>{server.once('error',resolve);server.listen({host:'127.0.0.1',port:f.port,exclusive:true},()=>{server.close();resolve(null);});});assert.equal(error?.code,'EADDRINUSE');}
  await f.control({op:'release',point:'workflow:publish:grant'});if(cause!=='disconnect')assert.notEqual((await confirmation).status,200);if(cause==='close')await until(()=>f.child.exitCode!==null);else await until(async()=>!(await f.control({op:'inspect'})).pendingPersistence);assert.deepEqual(await fs.readFile(path.join(f.directory,'settings.json')),before);assert.equal((await f.store.load()).config.accountRoots,undefined);assert.equal((await f.store.readPrivateRecord('onboarding-intent-'+p.flowId)).confirmations,1);
 });
});
test('native invitation import is scoped, persisted and refuses stale publication after pause',native,async t=>{
 const f=await agent(t,executable,'http://127.0.0.1:9');const url='http://127.0.0.1:9/instance/invite#'+'a'.repeat(32)+'.'+'b'.repeat(64);
 await f.control({op:'hold',point:'workflow:publish:vault'});const pending=f.api('/api/instance/import-invitation',{url});
 const {until}=await import('./native-account-fixture.mjs');await until(async()=>((await f.control({op:'inspect'})).entered['workflow:publish:vault']||0)>0);
 await f.control({op:'arm',point:'core:snapshot',kind:'error'});await f.control({op:'trigger',point:'snapshot'});const pause=await f.api('/api/pause',{paused:true});assert.equal(pause.status,503);await f.control({op:'release',point:'workflow:publish:vault'});assert.equal((await pending).status,409);
 assert.equal((await f.store.load()).secrets.privateInstanceInvitation,undefined);assert.deepEqual((await f.store.load()).config.roots,[]);
});


test('native folder cancellation invalidates selected onboarding flow before its durable publication',native,async t=>{
 const r=await cloud(t),f=await agent(t,executable,r.origin),p=await firstFlow(f,r);await data(await p.call('start',p.bootstrap));await f.control({op:'hold',point:'workflow:publish:flow'});const selected=p.call('choose',{flowId:p.flowId});await until(async()=>((await f.control({op:'inspect'})).entered['workflow:publish:flow']||0)>0);assert.equal((await f.control({op:'inspect'})).pickerActive,false);assert.equal((await f.api('/api/folder/cancel',{})).status,200);await f.control({op:'release',point:'workflow:publish:flow'});assert.equal((await selected).status,409);assert.equal((await f.store.readPrivateRecord('onboarding-flow-'+p.flowId)).selection,undefined);assert.equal((await f.store.load()).config.accountRoots,undefined);
});

test('native cancelSetup covers preparation, committed remote handoff and submitted owned browser capture',{...native,timeout:180000},async t=>{
 const r=await cloud(t,{developer:true}),f=await agent(t,executable,r.origin),p=await firstFlow(f,r);await data(await p.call('start',p.bootstrap));const selected=await data(await p.call('choose',{flowId:p.flowId}));await data(await p.call('confirm',{flowId:p.flowId,snapshotDigest:selected.snapshotDigest,confirmation:'allow-shared-folders-v1'}));await until(async()=>(await(await f.api('/api/status')).json()).bridge==='connected');
 for(const point of ['workflow:send','workflow:response:handoff','workflow:browser-submitted'])await t.test(point,async()=>{
  const starts=(await f.control({op:'inspect'})).helperStarts,entered=(await f.control({op:'inspect'})).entered[point]||0;await f.control({op:'hold',point});const pending=f.api('/api/setup/start',{});await until(async()=>((await f.control({op:'inspect'})).entered[point]||0)>entered);assert.equal((await f.control({op:'inspect'})).setupActive,true);if(point==='workflow:browser-submitted')assert.equal((await f.control({op:'inspect'})).helperStarts,starts+1);await data(await f.api('/api/pause',{paused:true}));assert.equal((await(await f.api('/api/status')).json()).paused,true);await f.control({op:'release',point});const cancelled=await pending;assert.equal(cancelled.status,point==='workflow:browser-submitted'?503:409);if(point==='workflow:browser-submitted')assert.match((await cancelled.json()).error,/may have occurred/);await until(async()=>!(await f.control({op:'inspect'})).setupActive);await until(async()=>!(await f.control({op:'inspect'})).helperActive);assert.equal((await f.control({op:'inspect'})).helperStarts,starts+Number(point==='workflow:browser-submitted'));assert.equal((await f.store.load()).config.accountRoots.length,1);await data(await f.api('/api/pause',{paused:false}));await until(async()=>(await(await f.api('/api/status')).json()).bridge==='connected');
 });
});
