import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {readControllerArtifact} from '../scripts/controller-artifact.mjs';
import {fixture,relay,until} from './native-bridge-fixture.mjs';
const executable=process.env.CHAT2LOCAL_CONTROLLER_TEST_EXECUTABLE;
if(process.env.CHAT2LOCAL_CONTROLLER_TEST_REQUIRED==='1'&&!executable)throw Error('Required controller fixture missing.');
if(executable)await readControllerArtifact(executable);
const native={skip:!executable,timeout:40000};
async function setup(t){const r=await relay(t),f=await fixture(t,executable,r.origin,{externalRoot:true,before:async({store,config})=>{config.roots[0].writeMode='direct';config.roots[0].write=true;await store.saveConfig(config);}});f.access.roots[0].mode='direct';f.access.scopes.push('files:write','files:propose');await until(()=>r.sockets.length);return{r,f};}
const sha=s=>createHash('sha256').update(s).digest('hex');
test('native commands create replace backup proposal approval and volatile status',native,async t=>{
 const {r,f}=await setup(t);const write=await r.call('write_file',{rootId:f.root,path:'new.txt',content:'first\n',expectedHash:null},f.access);assert.equal(write.error,undefined,JSON.stringify(write));assert.equal(write.result.status,'written');assert.equal(await fs.readFile(path.join(f.folder,'new.txt'),'utf8'),'first\n');
 const changed=await r.call('write_file',{rootId:f.root,path:'new.txt',content:'second\n',expectedHash:sha('first\n')},f.access);assert.equal(changed.result.status,'written');const backups=(await fs.readdir(path.join(f.directory,'rust-writes'))).filter(n=>n.endsWith('.before'));assert.ok((await Promise.all(backups.map(n=>fs.readFile(path.join(f.directory,'rust-writes',n),'utf8')))).includes('first\n'));
 const conflict=await r.call('write_file',{rootId:f.root,path:'new.txt',content:'bad',expectedHash:null},f.access);assert.equal(conflict.result.status,'failed');assert.equal(await fs.readFile(path.join(f.folder,'new.txt'),'utf8'),'second\n');
 const proposed=await r.call('propose_write',{rootId:f.root,path:'new.txt',content:'reviewed\n',expectedHash:sha('second\n')},f.access);assert.equal(proposed.result.status,'pending');assert.equal(await fs.readFile(path.join(f.folder,'new.txt'),'utf8'),'second\n');const status=await(await f.api('/api/status')).json();assert.equal(status.pending[0].content,'reviewed\n');
 const response=await f.api('/api/approve',{operationId:proposed.result.operationId,approved:true});assert.equal(response.status,200);assert.equal((await response.json()).status,'approved');assert.equal(await fs.readFile(path.join(f.folder,'new.txt'),'utf8'),'reviewed\n');assert.equal((await r.call('operation_status',{operationId:proposed.result.operationId},f.access)).result.status,'approved');
 const manager=await f.api('/api/management/session',{});assert.equal(manager.status,200);const denial=await f.api('/api/approve',{operationId:proposed.result.operationId,approved:false},{'X-Chat2Local-Token':'','X-Chat2Local-Manager':'1',Cookie:manager.headers.get('set-cookie').split(';')[0]});assert.equal(denial.status,401);
});
test('native terminal real PowerShell output dedup query and explicit terminal-only grant',native,async t=>{
 const {r,f}=await setup(t);f.access.scopes=['files:read','terminal:execute'];const requestId=randomUUID();const args={rootId:f.root,requestId,command:"[Console]::Out.Write('native-terminal'); [Console]::Error.Write('stderr-ok')",timeoutMs:5000};
 const start=await r.call('terminal_execute',args,f.access);assert.equal(start.error,undefined,JSON.stringify(start));assert.ok(['running','succeeded'].includes(start.result.status));
 const done=await until(async()=>{const result=await r.call('terminal_status',{rootId:f.root,requestId},f.access);assert.equal(result.error,undefined,JSON.stringify(result));return result.result.outcomeKnown&&result.result;},15000);assert.equal(done.status,'succeeded');assert.equal(done.stdout,'native-terminal');assert.equal(done.stderr,'stderr-ok');assert.equal(done.terminationConfirmed,true);
 const again=await r.call('terminal_execute',args,f.access);assert.equal(again.result.stdout,'native-terminal');assert.equal(again.result.startedAt,done.startedAt);assert.equal(typeof(await r.call('terminal_execute',{...args,command:'different'},f.access)).error,'string');
});

test('native malformed approval leaves writes healthy and policy changes cancel pending proposals',native,async t=>{
 const {r,f}=await setup(t);assert.equal((await f.api('/api/approve',{operationId:'bad',approved:true})).status,400);
 const args={rootId:f.root,path:'proposal.txt',content:'pending',expectedHash:null};
 const proposed=await r.call('propose_write',args,f.access);assert.equal(proposed.result.status,'pending');
 assert.equal((await f.api('/api/pause',{paused:true})).status,200);assert.equal((await f.api('/api/pause',{paused:false})).status,200);
 assert.equal((await f.api('/api/approve',{operationId:proposed.result.operationId,approved:true})).status,400);
 const written=await r.call('write_file',{...args,content:'healthy'},f.access);assert.equal(written.result.status,'written');
 const next=await r.call('propose_write',{...args,path:'removed.txt'},f.access);assert.equal(next.result.status,'pending');
 assert.equal((await f.api('/api/root/remove',{id:f.root})).status,200);assert.equal((await(await f.api('/api/status')).json()).pending.length,0);
});

test('native known COMMIT receipt uses only public fields when operation finish fails',native,async t=>{
 const {r,f}=await setup(t);await f.control({op:'arm',point:'operation:finish',kind:'error'});
 const result=await r.call('write_file',{rootId:f.root,path:'committed.txt',content:'known',expectedHash:null},f.access);
 assert.equal(result.result.status,'written');assert.equal(await fs.readFile(path.join(f.folder,'committed.txt'),'utf8'),'known');
 assert.deepEqual(Object.keys(result.result).sort(),['authorization','backupSaved','message','operationId','path','sha256','status'].sort());
 assert.ok((await r.call('write_file',{rootId:f.root,path:'frozen.txt',content:'never',expectedHash:null},f.access)).error);
});

test('native restrictive fault save succeeds while a prepared write holds directory guards',native,async t=>{
 const {r,f}=await setup(t);await f.control({op:'hold',point:'write:ready'});const id=randomUUID();
 r.sockets.at(-1).send(JSON.stringify({kind:'call',id,tool:'write_file',args:{rootId:f.root,path:'refused.txt',content:'never',expectedHash:null},connectionAccess:f.access}));
 await until(async()=>(await f.control({op:'inspect'})).entered['write:ready']);
 await f.control({op:'arm',point:'core:snapshot',kind:'error'});assert.equal((await f.control({op:'trigger',point:'snapshot'})).fault,true);
 const response=await f.api('/api/pause',{paused:true});assert.equal(response.status,200,await response.text());assert.equal((await f.store.load()).config.paused,true);
 assert.equal((await f.api('/api/root/remove',{id:f.root})).status,200);assert.equal((await f.store.load()).config.roots.length,0);
 await f.control({op:'release',point:'write:ready'});await until(async()=>(await(await f.api('/api/status')).json()).queuedOperations===0);
 await assert.rejects(fs.access(path.join(f.folder,'refused.txt')));assert.equal(r.messages.some(m=>m.id===id),false);
});

test('native terminal progress is saved independently of STARTED status and cancel',native,async t=>{
 const {r,f}=await setup(t);await f.control({op:'hold',point:'save'});const requestId=randomUUID();
 const start=await r.call('terminal_execute',{rootId:f.root,requestId,command:'Start-Sleep -Seconds 10',timeoutMs:20000},f.access);assert.equal(start.result.status,'running');
 await until(async()=>(await f.control({op:'inspect'})).pendingPersistence>0);
 const status=await r.call('terminal_status',{rootId:f.root,requestId},f.access);assert.equal(status.result.status,'running');
 assert.equal((await(await f.api('/api/status')).json()).lastRemoteCallAt!==undefined,true);
 const cancel=await r.call('terminal_cancel',{rootId:f.root,requestId},f.access);assert.equal(cancel.result.status,'cancelled');
 assert.notEqual((await f.store.load()).config.remoteUseConfirmed,true);
 await f.control({op:'release',point:'save'});await until(async()=>(await f.store.load()).config.remoteUseConfirmed===true);
 assert.ok((await r.call('terminal_execute',{rootId:f.root,requestId:randomUUID(),command:'never',timeoutMs:'100'},f.access)).error);
});

test('native actual pending PREPARE pipe I/O does not block close and retains cleanup ownership',native,async t=>{
 const {r,f}=await setup(t);await f.control({op:'terminal-stall',timeoutMs:10000});const id=randomUUID(),requestId=randomUUID();
 r.sockets.at(-1).send(JSON.stringify({kind:'call',id,tool:'terminal_execute',args:{rootId:f.root,requestId,command:"Set-Content -LiteralPath never-run.txt 'forbidden';#"+'x'.repeat(12000),timeoutMs:5000},connectionAccess:f.access}));
 await until(async()=>{const i=await f.control({op:'inspect'});return i.observedPendingControlIo>0&&i.pendingControlIo>0;});
 const held=await f.control({op:'inspect'});assert.ok(held.terminalSupervisors>0);assert.ok(held.pendingControlIo>0);assert.equal(f.child.exitCode,null);
 // Healthy HTTP status intentionally shares the command FIFO. Trigger close
 // independently while PREPARE is still pending, before that FIFO can finish.
 assert.equal((await f.control({op:'trigger',point:'close'})).closing,true);
 // Cancellation may complete before the next control request. The owned host
 // must drain it before exiting; do not require cleanup to remain artificially slow.
 await until(()=>f.child.exitCode!==null,15000);assert.equal(f.child.exitCode,0);await assert.rejects(fs.access(path.join(f.folder,'never-run.txt')));
 assert.equal(r.messages.some(m=>m.id===id),false);
});

test('native Store rotates audit onto an existing destination repeatedly',native,async t=>{
 const {r,f}=await setup(t),audit=path.join(f.directory,'audit.jsonl'),previous=path.join(f.directory,'audit.jsonl.previous');
 await fs.writeFile(previous,'older audit');
 for(const round of [1,2]){
  const bytes=Buffer.from((JSON.stringify({fixtureRound:round})+'\n').repeat(60000));assert.ok(bytes.length>1024*1024);
  await fs.writeFile(audit,bytes);
  const read=await r.call('read_file',{rootId:f.root,path:'hello.txt'},f.access);assert.equal(read.error,undefined,read.error);
  assert.deepEqual(await fs.readFile(previous),bytes);
  const current=(await fs.readFile(audit,'utf8')).trim().split('\n').map(JSON.parse);assert.equal(current.at(-1).action,'read');
 }
});

test('native terminal rechecks actual session generation at RUN admission',native,async t=>{
 const {r,f}=await setup(t);await f.control({op:'hold',point:'terminal:ready'});const id=randomUUID();
 r.sockets.at(-1).send(JSON.stringify({kind:'call',id,tool:'terminal_execute',args:{rootId:f.root,requestId:randomUUID(),command:"Set-Content -LiteralPath owner-changed-never.txt 'forbidden'",timeoutMs:5000},connectionAccess:f.access}));
 await until(async()=>(await f.control({op:'inspect'})).entered['terminal:ready']);
 await f.store.saveSession({...f.session,instanceId:randomUUID()});const replacement=await fs.readFile(path.join(f.directory,'session.json'));
 await f.control({op:'release',point:'terminal:ready'});
 await until(async()=>(await f.control({op:'inspect'})).terminalSupervisors===0);
 await assert.rejects(fs.access(path.join(f.folder,'owner-changed-never.txt')));
 assert.deepEqual(await fs.readFile(path.join(f.directory,'session.json')),replacement);
 const response=r.messages.find(m=>m.id===id);assert.ok(!response||response.error||!['running','succeeded'].includes(response.result?.status));
 await f.control({op:'trigger',point:'close'});await until(()=>f.child.exitCode!==null,10000);assert.equal(f.child.exitCode,0);
 assert.deepEqual(await fs.readFile(path.join(f.directory,'session.json')),replacement);
});

test('native close requested before helper spawn reaches owned cleanup without protocol timeout',native,async t=>{
 const {r,f}=await setup(t);await f.control({op:'terminal-stall',timeoutMs:10000});await f.control({op:'hold',point:'terminal:spawn'});const id=randomUUID();
 r.sockets.at(-1).send(JSON.stringify({kind:'call',id,tool:'terminal_execute',args:{rootId:f.root,requestId:randomUUID(),command:"Set-Content -LiteralPath early-close-never.txt 'forbidden';#"+'x'.repeat(12000),timeoutMs:5000},connectionAccess:f.access}));
 await until(async()=>(await f.control({op:'inspect'})).entered['terminal:spawn']);
 assert.equal((await f.control({op:'trigger',point:'close'})).closing,true);
 await until(async()=>(await f.control({op:'inspect'})).closing);
 const start=performance.now();await f.control({op:'release',point:'terminal:spawn'});
 await until(()=>f.child.exitCode!==null,7000);assert.equal(f.child.exitCode,0);assert.ok(performance.now()-start<7000);
 await assert.rejects(fs.access(path.join(f.folder,'early-close-never.txt')));assert.equal(r.messages.some(m=>m.id===id),false);
});

test('native terminal journal retains the existing per-call budget across delayed reads and reservation receipts',native,async t=>{
 const {r,f}=await setup(t);
 for(const point of ['journal','journal:reserved']){
  await f.control({op:'hold',point});const id=randomUUID(),requestId=randomUUID();
  r.sockets.at(-1).send(JSON.stringify({kind:'call',id,tool:'terminal_execute',args:{rootId:f.root,requestId,command:"Write-Output 'delayed journal'"},connectionAccess:f.access}));
  await until(async()=>(await f.control({op:'inspect'})).entered[point]);
  await new Promise(resolve=>setTimeout(resolve,2000));assert.equal(r.messages.some(m=>m.id===id),false);
  await f.control({op:'release',point});const response=await until(()=>r.messages.find(m=>m.id===id));assert.equal(response.error,undefined,JSON.stringify(response));
  const done=await until(async()=>{const value=await r.call('terminal_status',{rootId:f.root,requestId},f.access);return value.result?.outcomeKnown&&value.result;});assert.equal(done.status,'succeeded');
 }
 const observed=(await f.control({op:'inspect'})).observations;
 for(const operation of ['read','reserve'])assert.ok(observed.some(x=>x.point===`journal:${operation}:confirmed-ok`&&x.elapsedMs>=1800));
});

test('native terminal expiration after actual reservation never grants RUN or readback launch',native,async t=>{
 const {r,f}=await setup(t);await f.control({op:'hold',point:'journal:reserved',timeoutMs:60000});const id=randomUUID(),requestId=randomUUID();
 const args={rootId:f.root,requestId,command:"Set-Content -LiteralPath expired-never.txt 'forbidden'"},begin=performance.now();
 r.sockets.at(-1).send(JSON.stringify({kind:'call',id,tool:'terminal_execute',args,connectionAccess:f.access}));
 await until(async()=>(await f.control({op:'inspect'})).entered['journal:reserved']);
 const record=await f.store.readPrivateRecord('terminal-'+requestId);assert.equal(record.status,'starting');
 const response=await until(()=>r.messages.find(m=>m.id===id),22000);assert.match(response.error,/EPERSISTENCE: Terminal journal reserve/);assert.ok(performance.now()-begin>=14500);
 const held=await f.control({op:'inspect'});assert.equal(held.terminalSupervisors,0);assert.ok(held.pendingTerminalPersistence>0);await assert.rejects(fs.access(path.join(f.folder,'expired-never.txt')));
 await f.control({op:'release',point:'journal:reserved'});await until(async()=>(await f.control({op:'inspect'})).pendingTerminalPersistence===0);
 assert.equal((await r.call('terminal_execute',args,f.access)).result.status,'interrupted');await assert.rejects(fs.access(path.join(f.folder,'expired-never.txt')));
});

test('native close retains actual delayed read and reservation work without granting RUN',native,async t=>{
 for(const point of ['journal','journal:reserved']){
  const {r,f}=await setup(t);await f.control({op:'hold',point,timeoutMs:60000});const id=randomUUID();
  r.sockets.at(-1).send(JSON.stringify({kind:'call',id,tool:'terminal_execute',args:{rootId:f.root,requestId:randomUUID(),command:"Set-Content -LiteralPath closing-journal-never.txt 'forbidden'"},connectionAccess:f.access}));
  await until(async()=>(await f.control({op:'inspect'})).entered[point]);await new Promise(resolve=>setTimeout(resolve,1500));assert.equal(r.messages.some(m=>m.id===id),false);
  assert.equal((await f.control({op:'trigger',point:'close'})).closing,true);assert.ok((await f.control({op:'inspect'})).pendingTerminalPersistence>0);assert.equal(f.child.exitCode,null);
  await f.control({op:'release',point});await until(()=>f.child.exitCode!==null,20000);assert.equal(f.child.exitCode,0);assert.equal(r.messages.some(m=>m.id===id),false);await assert.rejects(fs.access(path.join(f.folder,'closing-journal-never.txt')));
 }
});
