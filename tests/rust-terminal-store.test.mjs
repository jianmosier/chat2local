import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { Store, powershell } from '../src/agent/store.mjs';
import { RustTerminalRecords, configuredTerminalStore } from '../src/agent/terminal/rust-job-store.mjs';
import { TerminalService } from '../src/agent/terminal.mjs';
import { TerminalJobStore } from '../src/agent/terminal/job-store.mjs';
import { RustTerminalProcessRunner } from '../src/agent/terminal/rust-process-runner.mjs';
import { approveRoot } from '../src/agent/files/path-policy.mjs';
import { rootPermission } from '../src/agent/permissions.mjs';
import { startController } from '../src/agent/main.mjs';

const executable = process.env.CHAT2LOCAL_TERMINAL_STORE_TEST_EXECUTABLE ?? path.resolve('target/debug/chat2local-terminal-store.exe');
let available = process.platform === 'win32';
try { await fs.access(executable); } catch { available = false; }
if (!available && process.env.CHAT2LOCAL_TERMINAL_STORE_TEST_REQUIRED === '1') throw Error('Required native terminal journal helper is unavailable.');
const native = { skip: available ? false : 'Build the Windows terminal-store helper' };
const record = (requestId = randomUUID()) => ({ requestId, rootId: 'root', connectionId: 'a'.repeat(32), deviceId: 'b'.repeat(32), resource: 'https://fixture.example.test/mcp', inputHash: 'c'.repeat(64), status: 'starting', stdout:'', stderr:'', outcomeKnown:false, unknown: { lone: '\ud800', array:[1,true,null], future:'保留' } });
async function fixture(t) {
  const outer = await fs.mkdtemp(path.join(os.tmpdir(),'c2l-terminal-store-')), base=path.join(outer,'state'); await fs.mkdir(base);
  t.after(() => fs.rm(outer,{recursive:true,force:true,maxRetries:10,retryDelay:100}));
  const store = new Store(base), native = new RustTerminalRecords({ stateDir: base, executable });
  return { outer, base, store, native, file: id => path.join(base,'terminal',`terminal-${id}.json`) };
}

test('terminal journal selection is independent and defaults to JS', () => {
  assert.equal(configuredTerminalStore({},{}),undefined);
  assert.equal(configuredTerminalStore({terminalStoreBackend:'js'},{CHAT2LOCAL_TERMINAL_STORE_BACKEND:'rust'}),undefined);
  assert.throws(()=>configuredTerminalStore({terminalStoreBackend:'invalid'},{}),/must be/);
});
test('actual native DPAPI reads JS journal and writes original envelope readable by JS', native, async t => {
  const f = await fixture(t), value = record();
  assert.equal(await f.native.read(value.requestId),null); // Private fixture directory; old JS encryption stays unchanged.
  await f.store.savePrivateRecord('terminal-'+value.requestId,value);
  assert.deepEqual(await f.native.read(value.requestId),value);
  const next = {...value,status:'running',futureTop:'unchanged'};
  await f.native.save(next);
  assert.deepEqual(await f.store.readPrivateRecord('terminal-'+value.requestId),next);
  const envelope=JSON.parse(await fs.readFile(f.file(value.requestId),'utf8')); assert.equal(envelope.format,'windows-dpapi-v1'); assert.equal(JSON.stringify(envelope).includes('unchanged'),false);
  f.store.savePrivateRecord=()=>{throw Error('JS encryption is forbidden');};
  const created=record(); assert.equal((await f.native.reserve(created)).kind,'created'); assert.deepEqual(await f.native.read(created.requestId),created);
});
test('concurrent independent native helpers grant exactly one reservation and reject owner/hash or state regression', native, async t => {
  const f=await fixture(t), value=record();
  const copies=Array.from({length:6},()=>new RustTerminalRecords({stateDir:f.base,executable}));
  const replies=await Promise.all(copies.map(copy=>copy.reserve(value)));
  assert.equal(replies.filter(reply=>reply.kind==='created').length,1); assert.equal(replies.filter(reply=>reply.kind==='existing').length,5);
  for(const patch of [{inputHash:'d'.repeat(64)},{connectionId:'d'.repeat(32)},{resource:'https://other.example.test/mcp'},{deviceId:'d'.repeat(32)},{rootId:'different'}]) await assert.rejects(()=>f.native.reserve({...value,...patch}),e=>e.code==='ECONFLICT');
  await f.native.save({...value,status:'running'}); await f.native.save({...value,status:'succeeded',outcomeKnown:true});
  await assert.rejects(()=>f.native.save({...value,status:'running'}),e=>e.code==='ESTALE');
  assert.equal((await f.native.read(value.requestId)).status,'succeeded');
});
test('ordered job snapshots publish in order and keep detached caller mutations out', native, async t => {
  const f=await fixture(t), value=record();await f.native.reserve(value);
  const journal=new TerminalJobStore(f.store,f.native),job={record:{...value,status:'running',future:{value:1}},persist:Promise.resolve()};
  const first=journal.save(job);job.record.future.value=2;job.record.status='succeeded';const final=journal.save(job);job.record.future.value=3;
  await Promise.all([first,final]);assert.equal((await f.native.read(value.requestId)).future.value,2);assert.equal((await f.native.read(value.requestId)).status,'succeeded');
});
test('only absent records are missing; malformed envelope, DPAPI, hardlinks and junctions fail closed', native, async t => {
  const f=await fixture(t), value=record(); assert.equal(await f.native.read(value.requestId),null);
  await fs.writeFile(f.file(value.requestId),'{'); await assert.rejects(()=>f.native.read(value.requestId));
  await fs.writeFile(f.file(value.requestId),JSON.stringify({format:'windows-dpapi-v1',data:'AAAA'})); await assert.rejects(()=>f.native.read(value.requestId));
  await fs.unlink(f.file(value.requestId)); await f.native.reserve(value);
  const link=path.join(f.base,'hardlink'); await fs.link(f.file(value.requestId),link); await assert.rejects(()=>f.native.read(value.requestId)); await fs.unlink(link);
  const other=await fixture(t); await fs.symlink(path.join(f.base,'terminal'),path.join(other.base,'terminal'),'junction'); await assert.rejects(()=>other.native.read(value.requestId));
});

const psSecurity = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new();Import-Module ($PSHOME+'\\Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop;$p=[Console]::In.ReadToEnd();";
const sddl = file => powershell(psSecurity+"(Get-Acl -LiteralPath $p).Sddl",file);
test('native directory inheritance and record DACL stay private; ADS rejects without changing metadata', native, async t => {
  const f=await fixture(t), value=record(); await f.native.reserve(value);
  const directoryBefore=await sddl(path.join(f.base,'terminal')), before=await sddl(f.file(value.requestId));
  assert.match(directoryBefore,/OICI/); await f.native.save({...value,status:'running'}); assert.equal(await sddl(f.file(value.requestId)),before);
  await fs.writeFile(f.file(value.requestId)+':extra','preserve'); await assert.rejects(()=>f.native.save({...value,status:'succeeded'}));
  assert.equal(await fs.readFile(f.file(value.requestId)+':extra','utf8'),'preserve'); await fs.unlink(f.file(value.requestId)+':extra');
  assert.equal(await sddl(path.join(f.base,'terminal')),directoryBefore);
});


test('native plaintext/read/capacity bounds keep old reservations and allow existing updates at capacity', native, async t => {
  const f=await fixture(t), value={...record(),padding:''};
  value.padding='x'.repeat(512*1024-Buffer.byteLength(JSON.stringify(value))); assert.equal(Buffer.byteLength(JSON.stringify(value)),512*1024);
  await f.native.reserve(value); assert.deepEqual(await f.native.read(value.requestId),value);
  await assert.rejects(()=>f.native.reserve({...value,requestId:randomUUID(),padding:value.padding+'x'}),/512/);
  await Promise.all(Array.from({length:2047},(_,n)=>fs.writeFile(path.join(f.base,'terminal',`retained-${n}`),'')));
  await assert.rejects(()=>f.native.reserve(record()),e=>e.code==='ECAPACITY');
  await f.native.save({...value,status:'running'}); assert.equal((await f.native.read(value.requestId)).status,'running');
  const big=record(); await fs.writeFile(f.file(big.requestId),Buffer.alloc(1024*1024+1)); await assert.rejects(()=>f.native.read(big.requestId));
  assert.equal((await fs.readdir(path.join(f.base,'terminal'))).length,2049);
});

async function serviceFixture(t, overrides={}) {
  const f=await fixture(t), project=path.join(f.outer,'project'); await fs.mkdir(project);
  const root={...await approveRoot(project,f.base,true),...rootPermission('direct')}, value=record(), access={version:1,connectionId:value.connectionId,deviceId:value.deviceId,resource:value.resource,roots:[{rootId:root.id,mode:'direct'}],scopes:['files:read','files:write','terminal:execute']};
  const config={version:1,roots:[root],paused:false,startup:false,relay:'',terminalGrants:[{rootId:root.id,connectionId:access.connectionId,resource:access.resource,enabled:true}]};
  const options={store:f.store,getConfig:()=>config,getDevice:()=>({deviceId:access.deviceId}),journalFactory:()=>f.native,...overrides};
  const terminal=new TerminalService(options); t.after(()=>terminal.close());
  const args=command=>({requestId:randomUUID(),rootId:root.id,command});
  return {...f,root,config,access,options,terminal,args,project};
}
async function wait(terminal,args,access) {
  for(let n=0;n<120;n++) { const value=await terminal.invoke('terminal_status',{rootId:args.rootId,requestId:args.requestId},access); if(['succeeded','failed','cancelled','timed-out','interrupted'].includes(value.status)) return value; await new Promise(resolve=>setTimeout(resolve,50)); }
  throw Error('Terminal fixture deadline');
}
test('actual command reservation is durable, JS encryption forbidden and restart never replays', native, async t => {
  const f=await serviceFixture(t); f.store.savePrivateRecord=()=>{throw Error('JS seal forbidden');};
  const args=f.args("Add-Content -LiteralPath 'once.txt' -Value 'one'; Write-Output 'journal-native'");
  await f.terminal.invoke('terminal_execute',args,f.access); const done=await wait(f.terminal,args,f.access); assert.equal(done.status,'succeeded');
  await f.terminal.jobs.get(args.requestId).persist; assert.equal((await f.native.read(args.requestId)).status,'succeeded');
  const restarted=new TerminalService(f.options); t.after(()=>restarted.close());
  assert.equal((await restarted.invoke('terminal_execute',args,f.access)).status,'succeeded');
  assert.equal((await fs.readFile(path.join(f.project,'once.txt'),'utf8')).trim(),'one');
  const reserved={...record(),requestId:randomUUID(),rootId:f.root.id}; await f.native.reserve(reserved);
  assert.equal((await restarted.invoke('terminal_status',{rootId:f.root.id,requestId:reserved.requestId},f.access)).status,'interrupted');
});
test('native reservation with indefinitely pending later saves releases STARTED, cancellation and close', native, async t => {
  const runner=process.env.CHAT2LOCAL_TERMINAL_TEST_EXECUTABLE??path.resolve('target/debug/chat2local-terminal-runner.exe');
  const f=await serviceFixture(t,{runnerFactory:options=>new RustTerminalProcessRunner({...options,executable:runner})});
  f.native.save=()=>new Promise(()=>{});const args=f.args('Start-Sleep -Seconds 30');
  const result=await Promise.race([f.terminal.invoke('terminal_execute',args,f.access),new Promise((_,reject)=>setTimeout(()=>reject(Error('STARTED blocked on journal')),3000).unref())]);assert.equal(result.status,'running');
  await f.terminal.invoke('terminal_cancel',{rootId:f.root.id,requestId:args.requestId},f.access);
  const done=await wait(f.terminal,args,f.access);assert.equal(done.status,'cancelled');assert.match(done.message,/pending/);
  await Promise.race([f.terminal.close(),new Promise((_,reject)=>setTimeout(()=>reject(Error('close blocked on journal')),3000).unref())]);
  assert.equal((await f.native.read(args.requestId)).status,'starting');
});

function fakeHelper(onRequest) {
  const child=new EventEmitter(); child.stdout=new PassThrough(); child.stderr=new PassThrough(); child.stdin=new PassThrough(); child.kill=()=>false;
  let text=''; child.stdin.on('data',chunk=>{text+=chunk;}); child.stdin.on('finish',()=>onRequest(JSON.parse(text),child)); return child;
}
const receipt=(request,child,kind,recordJson=request.recordJson)=>{child.stdout.end(JSON.stringify({v:1,nonce:request.nonce,ok:true,result:{kind,recordJson}}));child.emit('close',0);};
test('late created receipt after another save froze the instance cannot RUN; reservation is retained', native, async t => {
  let reserveRequest, saveRequest, launches=0;
  const f=await serviceFixture(t,{runnerFactory:()=>({start(){launches++;},close:async()=>{}})});
  const transport=new RustTerminalRecords({stateDir:f.base,executable,spawnHelper:()=>fakeHelper((request,child)=>{
    if(request.op==='read') receipt(request,child,'missing',null);
    else if(request.op==='reserve') reserveRequest={request,child}; else saveRequest={request,child};
  })});
  f.terminal.journal.records=transport;
  const pending=f.terminal.invoke('terminal_execute',f.args('Write-Output impossible'),f.access); const rejected=assert.rejects(pending,/unknown/);
  while(!reserveRequest) await new Promise(resolve=>setTimeout(resolve,5));
  const save=transport.save({...record(),status:'running'}); const failedSave=assert.rejects(save,/unknown/);
  while(!saveRequest) await new Promise(resolve=>setTimeout(resolve,5));
  saveRequest.child.emit('close',1); await failedSave;
  await f.native.reserve(JSON.parse(reserveRequest.request.recordJson));
  receipt(reserveRequest.request,reserveRequest.child,'created'); await rejected;
  assert.equal(launches,0); assert.equal((await f.native.read(reserveRequest.request.requestId)).status,'starting');
});
test('missing helper, corrupt ABI and unconfirmed close freeze without fallback or another spawn', async () => {
  for(const mode of ['bad','hang','missing']) {
    let calls=0; const backend=new RustTerminalRecords({stateDir:os.tmpdir(),executable:path.join(os.tmpdir(),'no-such-terminal-store.exe'),timeoutMs:30,closeMs:20,
      ...(mode==='missing'?{}:{spawnHelper:()=>{calls++;return fakeHelper((request,child)=>{if(mode==='bad'){child.stdout.end('{}');child.emit('close',0);}});}})});
    await assert.rejects(()=>backend.reserve(record()),/unknown/); assert.equal(backend.frozen,true);
    await assert.rejects(async()=>backend.reserve(record()),/unknown/); assert.equal(calls,mode==='missing'?0:1);
  }
});

const harness=process.env.CHAT2LOCAL_TERMINAL_STORE_TEST_HARNESS;
if(process.env.CHAT2LOCAL_TERMINAL_STORE_TEST_REQUIRED==='1'&&!harness) throw Error('Required test-only native journal harness is missing.');
test('actual helper interruption at four publication stages never permits RUN; lost ACK remains reserved on restart', {skip:!available||!harness}, async t => {
  for(const stage of ['before-write','after-write','before-rename','after-rename']) {
    let launches=0;
    const f=await serviceFixture(t,{runnerFactory:()=>({start(){launches++;},close:async()=>{}})}), args=f.args('Write-Output never');
    const backend=new RustTerminalRecords({stateDir:f.base,executable,spawnHelper:()=>fakeHelper((request,proxy)=>{
      const crash=request.op==='reserve';
      const child=spawn(crash?harness:executable,crash?['--exact','windows_terminal_store::tests::crash_fixture','--nocapture']:[],{windowsHide:true,stdio:['pipe','pipe','pipe'],env:{...process.env,...(crash?{C2L_JOURNAL_FIXTURE_POINT:stage}:{})}});
      proxy.kill=()=>child.kill(); child.stdout.pipe(proxy.stdout);child.stderr.pipe(proxy.stderr);child.on('error',error=>proxy.emit('error',error));child.once('close',code=>proxy.emit('close',code));child.stdin.end(JSON.stringify(request));
    })});
    f.terminal.journal.records=backend;
    await assert.rejects(()=>f.terminal.invoke('terminal_execute',args,f.access),/unknown/); assert.equal(launches,0);
    await assert.rejects(()=>f.terminal.invoke('terminal_execute',args,f.access),/unknown/); assert.equal(launches,0);
    const persisted=await f.native.read(args.requestId);
    if(stage==='after-rename') {
      assert.equal(persisted.status,'starting'); const restarted=new TerminalService({...f.options,runnerFactory:()=>({start(){launches++;},close:async()=>{}})});t.after(()=>restarted.close());
      assert.equal((await restarted.invoke('terminal_execute',args,f.access)).status,'interrupted');assert.equal(launches,0);
    } else assert.equal(persisted,null);
  }
});

test('actual controller composes native journal and native execution with retained restart status', native, async t => {
  const f=await serviceFixture(t), config={...f.config,installationId:randomUUID(),remoteUseConfirmed:true};
  f.store.load=async()=>({config,secrets:{identity:{deviceId:f.access.deviceId,origin:f.access.resource.slice(0,-4),deviceKey:'e'.repeat(64)}}});
  const originalSave=f.store.savePrivateRecord.bind(f.store);f.store.savePrivateRecord=(key,value)=>{if(key.startsWith('terminal-'))throw Error('JS terminal sealing forbidden');return originalSave(key,value);};
  const runner=process.env.CHAT2LOCAL_TERMINAL_TEST_EXECUTABLE??path.resolve('target/debug/chat2local-terminal-runner.exe');
  const options={port:0,store:f.store,terminalStoreBackend:'rust',terminalStoreExecutable:executable,terminalBackend:'rust',terminalExecutable:runner,network:{prepare:()=>new Promise(()=>{}),status:()=>({}),close(){}}};
  const app=await startController(options);t.after(()=>app.close());app.bridge.stop();
  const args=f.args("Add-Content -LiteralPath 'controller-once.txt' -Value 'one'; Write-Output 'native-persist'");
  await app.bridge.invoke('terminal_execute',args,undefined,f.access);
  let result;for(let n=0;n<100;n++){result=await app.bridge.invoke('terminal_status',{rootId:f.root.id,requestId:args.requestId},undefined,f.access);if(result.status==='succeeded')break;await new Promise(resolve=>setTimeout(resolve,50));}
  assert.equal(result.status,'succeeded');assert.match(result.stdout,/native-persist/);
  for(let n=0;n<100&&(await f.native.read(args.requestId)).status!=='succeeded';n++) await new Promise(resolve=>setTimeout(resolve,20));
  assert.equal((await f.native.read(args.requestId)).status,'succeeded');
  const headers={'X-Chat2Local-Token':app.token};assert.equal((await fetch(app.origin+'/api/status',{headers})).status,200);await app.close();
  const restarted=await startController(options);t.after(()=>restarted.close());restarted.bridge.stop();
  assert.equal((await restarted.bridge.invoke('terminal_execute',args,undefined,f.access)).status,'succeeded');
  assert.equal((await fs.readFile(path.join(f.project,'controller-once.txt'),'utf8')).trim(),'one');
});
