import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { readControllerArtifact } from '../scripts/controller-artifact.mjs';
import { fixture, relay, until } from './native-bridge-fixture.mjs';
const executable=process.env.CHAT2LOCAL_CONTROLLER_TEST_EXECUTABLE;
if(process.env.CHAT2LOCAL_CONTROLLER_TEST_REQUIRED==='1'&&!executable)throw Error('Required native controller missing.');
if(executable)await readControllerArtifact(executable);
const native={skip:!executable,timeout:60000};
async function setup(t){const r=await relay(t), f=await fixture(t,executable,r.origin,{externalRoot:true});return {r,f};}
async function folder(t){const p=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-consent-'));t.after(()=>fs.rm(p,{recursive:true,force:true}));return p;}
test('native legacy consent keeps identity, unknowns, expected mode and paused mode changes',native,async t=>{
 const {f}=await setup(t);const before=(await f.store.load()).config;const old=await fs.readFile(path.join(f.directory,'settings.json'));
 const duplicate=await f.api('/api/root/add',{path:f.folder.toLowerCase(),writeMode:'direct',confirmDirect:true});assert.equal(duplicate.status,200,await duplicate.clone().text());assert.equal((await duplicate.json()).alreadyAuthorized,true);assert.deepEqual(await fs.readFile(path.join(f.directory,'settings.json')),old);
 const p=await folder(t);assert.equal((await f.api('/api/root/add',{path:p,writeMode:'direct'})).status,400);assert.equal((await f.api('/api/root/add',{path:p,write:true,writeMode:'review'})).status,400);
 const added=await(await f.api('/api/root/add',{path:p,write:true})).json();assert.equal(added.writeMode,'review');
 assert.equal((await f.api('/api/root/set-mode',{id:added.id,writeMode:'direct',expectedWriteMode:'read-only',confirmDirect:true})).status,409);
 assert.equal((await f.api('/api/pause',{paused:true})).status,200);assert.equal((await f.api('/api/root/add',{path:await folder(t),write:false})).status,409);
 assert.equal((await f.api('/api/root/set-mode',{id:added.id,writeMode:'direct',expectedWriteMode:'review',confirmDirect:true})).status,200);
 const after=(await f.store.load()).config;assert.deepEqual(after.unknown,before.unknown);assert.deepEqual(after.accountRoots,before.accountRoots);assert.deepEqual(after.terminalGrants,before.terminalGrants);
 assert.equal((await f.api('/api/root/set-mode',{id:f.account,writeMode:'direct',expectedWriteMode:'read-only',confirmDirect:true})).status,404);
});
test('native guide explicit consent is idempotent, session observations advisory and cancellation preserves grants',native,async t=>{
 const {f}=await setup(t),requestId=randomUUID();const input={path:f.folder,expectedRootId:f.root,expectedWriteMode:'read-only',requestId,confirmDirect:true};
 const response=await f.api('/api/guide/authorize',input);assert.equal(response.status,200,await response.clone().text());assert.equal((await response.json()).attemptId,requestId);
 const saved=await fs.readFile(path.join(f.directory,'settings.json'));assert.equal((await f.api('/api/guide/authorize',input)).status,200);assert.deepEqual(await fs.readFile(path.join(f.directory,'settings.json')),saved);
 const observed=await(await f.api('/api/guide/session-tools',{attemptId:requestId,tools:['write_file','list_devices']})).json();assert.equal(observed.complete,false);assert.equal(observed.capabilities.fileAccessGranted,false);assert.deepEqual(await fs.readFile(path.join(f.directory,'settings.json')),saved);
 assert.equal((await f.api('/api/guide/session-tools',{attemptId:requestId,tools:['write_file','write_file']})).status,400);
 const roots=(await f.store.load()).config.roots;assert.equal((await f.api('/api/guide/cancel',{attemptId:requestId})).status,200);assert.deepEqual((await f.store.load()).config.roots,roots);
 const manager=await f.api('/api/management/session',{}),cookie=manager.headers.get('set-cookie').split(';')[0];for(const route of ['/api/root/add','/api/root/set-mode','/api/guide/authorize','/api/guide/cancel','/api/guide/session-tools'])assert.equal((await f.api(route,{}, {'X-Chat2Local-Token':'','X-Chat2Local-Manager':'1',Cookie:cookie})).status,401);
});
test('native consent holds actual path identity until publication and cancels only captured selections',native,async t=>{
 const {f}=await setup(t),p=await folder(t);await f.control({op:'hold',point:'consent:publish'});const pending=f.api('/api/root/add',{path:p,write:false});await until(async()=>(await f.control({op:'inspect'})).entered['consent:publish']);
 await assert.rejects(fs.rename(p,p+'-moved'));assert.equal((await f.api('/api/folder/cancel',{})).status,200);await f.control({op:'release',point:'consent:publish'});assert.equal((await pending).status,200);
 const selected=await folder(t);await f.control({op:'platform-config',picker:{mode:'selected',path:selected}});await f.control({op:'hold',point:'consent:publish'});const pick=f.api('/api/folder/select',{write:false});await until(async()=>(await f.control({op:'inspect'})).entered['consent:publish']===2);
 assert.equal((await f.api('/api/folder/cancel',{})).status,200);await f.control({op:'release',point:'consent:publish'});assert.deepEqual(await(await pick).json(),{cancelled:true});assert.equal((await f.store.load()).config.roots.some(r=>r.path===selected),false);
});
test('native disconnected, faulted and closing consent never publishes after its held rename gate',native,async t=>{
 for(const cause of ['disconnect','fault','close'])await t.test(cause,async t=>{
  const {f}=await setup(t),p=await folder(t),before=await fs.readFile(path.join(f.directory,'settings.json'));await f.control({op:'hold',point:'consent:publish'});
  let request;const pending=cause==='disconnect'?new Promise(resolve=>{request=http.request(f.ready.origin+'/api/root/add',{method:'POST',headers:{Origin:f.ready.origin,'Content-Type':'application/json','X-Chat2Local-Token':f.session.token}},r=>{r.resume();resolve(r);});request.on('error',resolve);request.end(JSON.stringify({path:p,write:false}));}):f.api('/api/root/add',{path:p,write:false});
  await until(async()=>(await f.control({op:'inspect'})).entered['consent:publish']);
  if(cause==='disconnect'){const count=(await f.control({op:'inspect'})).requestDisconnects;request.destroy();await pending;await until(async()=>(await f.control({op:'inspect'})).requestDisconnects>count);}
  else if(cause==='fault'){await f.control({op:'arm',point:'core:snapshot',kind:'error'});await f.control({op:'trigger',point:'snapshot'});}else await f.control({op:'trigger',point:'close'});
  await f.control({op:'release',point:'consent:publish'});if(cause!=='disconnect')assert.notEqual((await pending).status,200);
  await until(async()=>!(await f.control({op:'inspect'})).pendingPersistence).catch(e=>{if(cause!=='close')throw e;});assert.deepEqual(await fs.readFile(path.join(f.directory,'settings.json')),before);
 });
});
test('native UI assets are explicit, retain CSP and do not turn manager cookies into grant proof',native,async t=>{
 const {f}=await setup(t);for(const [url,type] of [['/folders','text/html'],['/native-panel.js','text/javascript'],['/native-panel.css','text/css']]){const r=await fetch(f.ready.origin+url);assert.equal(r.status,200);assert.ok(r.headers.get('content-type').startsWith(type));assert.match(r.headers.get('content-security-policy'),/default-src 'none'/);}
 assert.equal((await fetch(f.ready.origin+'/native.rs')).status,501);assert.equal((await fetch(f.ready.origin+'/native-panel.js?token=x')).status,400);
});
test('native consent save failure preserves grants, while postcommit audit failure returns saved permission warning',native,async t=>{
 const {f}=await setup(t),p=await folder(t),before=await fs.readFile(path.join(f.directory,'settings.json'));
 await f.control({op:'arm',point:'save',kind:'error'});assert.equal((await f.api('/api/root/add',{path:p,write:false})).status,503);assert.deepEqual(await fs.readFile(path.join(f.directory,'settings.json')),before);
 await fs.mkdir(path.join(f.directory,'audit.jsonl'));
 const r=await f.api('/api/root/set-mode',{id:f.root,expectedWriteMode:'read-only',writeMode:'direct',confirmDirect:true});assert.equal(r.status,200);assert.match((await r.json()).warning,/权限已保存/);assert.equal((await f.store.load()).config.roots[0].writeMode,'direct');
});
test('native consent strict dedup refuses an unsafe old root rather than treating it as absent',native,async t=>{
 const p=await folder(t),link=path.join(p,'link'),target=await folder(t);await fs.symlink(target,link,'junction');
 const r=await relay(t),f=await fixture(t,executable,r.origin,{externalRoot:true,before:async({store,config})=>{config.roots.push({id:randomUUID(),label:'Unsafe old link',path:link,write:false});await store.saveConfig(config);}});
 const before=await fs.readFile(path.join(f.directory,'settings.json'));assert.equal((await f.api('/api/root/add',{path:await folder(t),write:false})).status,400);assert.deepEqual(await fs.readFile(path.join(f.directory,'settings.json')),before);
});
