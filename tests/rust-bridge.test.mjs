import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { platformInfo } from '../src/agent/platform.mjs';
import { deviceDescription } from '../src/shared/device-grants.mjs';
import { readControllerArtifact } from '../scripts/controller-artifact.mjs';
import { fixture,relay,until } from './native-bridge-fixture.mjs';
const executable=process.env.CHAT2LOCAL_CONTROLLER_TEST_EXECUTABLE;
if(process.env.CHAT2LOCAL_CONTROLLER_TEST_REQUIRED==='1'&&!executable)throw Error('Required controller fixture missing.');
if(executable)await readControllerArtifact(executable);
const native={skip:!executable,timeout:30000};
test('native persistent Bridge executes four real reads with scoped authorization and preserves saved grants',native,async t=>{
  const r=await relay(t),f=await fixture(t,executable,r.origin);await until(()=>r.sockets.length===1);
  assert.match(r.protocols[0],/connection-access-v1/);assert.match(r.protocols[0],/terminal-jobs-v1/);
  const computer=(await r.call('list_devices',{},f.access)).result.devices[0];
  assert.deepEqual(Object.fromEntries(['name','platform','arch','system'].filter(key=>key in computer).map(key=>[key,computer[key]])),deviceDescription(platformInfo()));
  assert.equal(computer.deviceId,f.device);assert.equal(computer.installationId,f.config.installationId);
  const roots=(await r.call('list_roots',{},f.access)).result;assert.equal(roots.length,2);assert.equal(roots[0].terminalLocalEnabled,true);assert.equal(roots[0].terminalAllowed,false);assert.equal(roots[0].terminalStatus,'unavailable');
  assert.equal((await r.call('list_roots')).result.length,1);
  assert.ok((await r.call('list_directory',{rootId:f.root},f.access)).result.entries.some(e=>e.name==='hello.txt'));
  assert.equal((await r.call('read_file',{rootId:f.account,path:'hello.txt'},f.access)).result.content,'native read\n');
  for(const access of [null,{...f.access,deviceId:'d'.repeat(32)},{...f.access,extra:true},{...f.access,scopes:[]},{...f.access,roots:[]},{...f.access,resource:r.origin+'/mcp?x'}])for(const tool of ['list_devices','list_roots'])assert.equal(typeof(await r.call(tool,{},access)).error,'string');
  assert.equal(typeof(await r.call('list_devices',{deviceId:f.device},f.access)).error,'string');
  for(const tool of ['propose_write','write_file','operation_status','terminal_execute','terminal_status','terminal_cancel'])assert.equal(typeof(await r.call(tool,{},f.access)).error,'string');
  assert.equal((await r.call('read_file',{rootId:f.root,path:'hello.txt'},f.access,{extra:'accepted'})).result.content,'native read\n');
  const saved=(await f.store.load()).config;assert.deepEqual(saved.terminalGrants,f.config.terminalGrants);assert.deepEqual(saved.unknown,f.config.unknown);assert.equal(saved.remoteUseConfirmed,true);
  const audit=(await fs.readFile(path.join(f.directory,'audit.jsonl'),'utf8')).trim().split('\n').map(JSON.parse);assert.equal(audit.length,2);assert.deepEqual(Object.keys(audit[0]),['at','action','rootId','path']);assert.equal(audit[0].action,'read');
});
for(const [point,kind]of [['core:admit','error'],['core:snapshot','panic'],['core:bridgeEvent','panic'],['effect','error'],['core:finish','error']])test(`native permanent fault from actual ${point} ${kind} retains authenticated restriction lane`,native,async t=>{
  const r=await relay(t),f=await fixture(t,executable,r.origin);await until(()=>r.sockets.length===1);
  await f.control({op:'arm',point,kind});
  if(point==='core:snapshot')await f.control({op:'trigger',point:'snapshot'});
  else if(point==='core:bridgeEvent'||point==='effect'){r.sockets[0].send('pong');if(point==='effect')r.sockets[0].terminate();}
  else {const response=await f.api('/api/pause',{paused:true});if(point==='core:finish')assert.equal(response.status,200);}
  await until(async()=>(await f.control({op:'inspect'})).fault);
  const status=await(await f.api('/api/status')).json();assert.equal(status.nativeFault,true);assert.equal(status.paused,true);
  assert.equal((await f.api('/api/pause',{paused:false})).status,503);assert.equal((await f.api('/api/management/session',{})).status,503);
  assert.equal((await f.api('/api/root/remove',{id:f.root})).status,200);assert.equal((await f.store.load()).config.roots.length,0);
});
test('native fault while actual save is held retains listener until ordered restrictive persistence drains',native,async t=>{
  const r=await relay(t),f=await fixture(t,executable,r.origin);await until(()=>r.sockets.length===1);
  await f.control({op:'hold',point:'save',timeoutMs:20000});const pending=f.api('/api/root/remove',{id:f.root});await until(async()=>(await f.control({op:'inspect'})).entered.save);
  await f.control({op:'arm',point:'core:snapshot',kind:'error'});await f.control({op:'trigger',point:'snapshot'});
  assert.equal((await f.api('/api/pause',{paused:true})).status,503);assert.equal((await f.api('/api/status')).status,200);assert.equal((await f.store.load()).config.paused,false);
  assert.equal((await f.api('/api/shutdown',{})).status,200);assert.equal(f.child.exitCode,null);
  await f.control({op:'release',point:'save'});assert.equal((await pending).status,200);await f.exited;const saved=(await f.store.load()).config;assert.equal(saved.paused,true);assert.equal(saved.roots.length,0);
});
test('native held read cannot disclose after fault and restrictive pause',native,async t=>{
  const r=await relay(t),f=await fixture(t,executable,r.origin);await until(()=>r.sockets.length===1);
  await f.control({op:'hold',point:'read',timeoutMs:15000});const id=randomUUID();r.sockets[0].send(JSON.stringify({kind:'call',id,tool:'read_file',args:{rootId:f.root,path:'hello.txt'},connectionAccess:f.access}));
  await until(async()=>(await f.control({op:'inspect'})).entered.read);
  await f.control({op:'arm',point:'core:snapshot',kind:'error'});await f.control({op:'trigger',point:'snapshot'});assert.equal((await f.api('/api/pause',{paused:true})).status,200);
  await f.control({op:'release',point:'read'});await new Promise(r=>setTimeout(r,100));assert.equal(r.messages.some(m=>m.id===id),false);
});

test('native persistent Bridge uses verified WSS directly and through HTTP and HTTPS CONNECT',native,async t=>{
  const {mint,proxy}=await import('./transport-fixture.mjs');
  if(!process.env.CHAT2LOCAL_TRANSPORT_TEST_EXECUTABLE)throw Error('Fresh transport fixture required for synthetic TLS certificates.');
  const ca=await mint(),leaf=await mint({issuer_cert:ca.cert,issuer_key:ca.key,dns:['relay.example.test']}),outer=await mint({issuer_cert:ca.cert,issuer_key:ca.key,dns:['proxy.example.test']});
  for(const mode of ['direct','http','https']){
    const r=await relay(t,{certificate:leaf});const origin=`https://relay.example.test:${r.port}`;let intermediary;
    const transport={env:{},ca:ca.cert,addresses:{'relay.example.test':`127.0.0.1:${r.port}`}};
    if(mode!=='direct'){intermediary=await proxy({target:r,certificate:mode==='https'?outer:undefined});t.after(()=>intermediary.close());transport.addresses['proxy.example.test']=`127.0.0.1:${intermediary.port}`;}
    const f=await fixture(t,executable,origin,{transport,before:async({store,config})=>{config.network=mode==='direct'?{mode:'direct'}:{mode:'proxy',proxy:`${mode}://proxy.example.test:${intermediary.port}`};await store.saveConfig(config);}});
    await until(()=>r.sockets.length===1);assert.equal((await r.call('read_file',{rootId:f.root,path:'hello.txt'},f.access)).result.content,'native read\n');
    assert.equal((await r.call('list_roots',{},f.access)).result.length,2);
    if(intermediary){assert.ok(intermediary.seen.tunnels>=2);assert.equal(intermediary.seen.isolated,true);}
    assert.equal((await f.api('/api/shutdown',{})).status,200);await f.exited;
  }
});
test('native Bridge roundtrip carries all ten commands through ordinary workerd Device',{...native,timeout:40000},async t=>{
  const {build}=await import('esbuild');const {Miniflare,convertV4MiniflareOptions}=await import('miniflare');
  const epoch='e'.repeat(64),key='c'.repeat(64);
  const bundle=await build({stdin:{resolveDir:process.cwd(),sourcefile:'native-bridge-ordinary-device-test.mjs',contents:`
    import {Device as ProductionDevice} from './src/relay/worker.mjs';
    import {sha256} from './src/shared/protocol.mjs';
    export class TestDevice extends ProductionDevice {
      async fetch(request){const route=new URL(request.url).pathname;
        if(route==='/test-seed'){await this.ctx.storage.put('identity',{keyHash:await sha256('${key}'),epoch:'${epoch}',revoked:false});return Response.json({ok:true});}
        if(route==='/test-state'){const sockets=this.ctx.getWebSockets('device');return Response.json({online:this.sockets().length>0,capability:sockets[0]?.deserializeAttachment()});}
        return super.fetch(request);
      }
    }
    export default {fetch(request,env){const url=new URL(request.url);url.pathname=url.pathname.replace(/^\\/device\\/[a-f0-9]{32}/,'');return env.DEVICES.get(env.DEVICES.idFromName('native-bridge-synthetic')).fetch(new Request(url,request));}};
  `},bundle:true,write:false,format:'esm',platform:'neutral',mainFields:['module','main'],external:['cloudflare:workers','*.wasm']});
  const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script:bundle.outputFiles[0].text,compatibilityDate:'2026-09-20',compatibilityFlags:['nodejs_compat'],host:'127.0.0.1',port:0,durableObjects:{DEVICES:{className:'TestDevice',useSQLite:true}}}));t.after(()=>mf.dispose());
  const origin=(await mf.ready).origin;assert.equal((await mf.dispatchFetch('http://fixture/test-seed',{method:'POST'})).status,200);
  const f=await fixture(t,executable,origin,{externalRoot:true,before:async({store,config})=>{config.roots[0].write=true;config.roots[0].writeMode='direct';await store.saveConfig(config);}});
  f.access.roots[0].mode='direct';f.access.scopes.push('files:write','files:propose');
  const state=await until(async()=>{const s=await(await mf.dispatchFetch('http://fixture/test-state')).json();return s.online&&s;});assert.equal(state.capability.connectionAccess,true);assert.equal(state.capability.terminal,true);
  const invoke=async(tool,args)=>{const response=await mf.dispatchFetch('http://fixture/invoke',{method:'POST',body:JSON.stringify({epoch,tool,args,connectionAccess:f.access})});assert.equal(response.status,200,await response.clone().text());const body=await response.json();assert.equal(body.error,undefined,JSON.stringify(body));return body.result;};
  for(const [tool,args]of [['list_devices',{}],['list_roots',{}],['list_directory',{rootId:f.root}],['read_file',{rootId:f.root,path:'hello.txt'}]]){
    const result=await invoke(tool,args);if(tool==='read_file')assert.equal(result.content,'native read\n');
  }
  const written=await invoke('write_file',{rootId:f.root,path:'direct.txt',content:'native direct through Device',expectedHash:null});assert.equal(written.status,'written');assert.equal(await fs.readFile(path.join(f.folder,'direct.txt'),'utf8'),'native direct through Device');
  const proposed=await invoke('propose_write',{rootId:f.root,path:'approved.txt',content:'native approval through Device',expectedHash:null});assert.equal(proposed.status,'pending');await assert.rejects(fs.access(path.join(f.folder,'approved.txt')));
  assert.equal((await invoke('operation_status',{operationId:proposed.operationId})).status,'pending');
  const approval=await f.api('/api/approve',{operationId:proposed.operationId,approved:true});assert.equal(approval.status,200);assert.equal((await approval.json()).status,'approved');
  assert.equal((await invoke('operation_status',{operationId:proposed.operationId})).status,'approved');assert.equal(await fs.readFile(path.join(f.folder,'approved.txt'),'utf8'),'native approval through Device');
  const requestId=randomUUID(),args={rootId:f.root,requestId};
  assert.equal((await invoke('terminal_execute',{...args,command:"Write-Output 'native terminal through Device'; Start-Sleep -Seconds 20",timeoutMs:30000})).status,'running');
  assert.equal((await invoke('terminal_status',args)).status,'running');
  const cancelled=await invoke('terminal_cancel',args);assert.equal(cancelled.status,'cancelled');assert.equal(cancelled.terminationConfirmed,true);
  assert.equal((await f.api('/api/shutdown',{})).status,200);await f.exited;
});
test('native actual heartbeat sends at25 and50seconds and reconnects after missing pong exceeds65seconds',{...native,timeout:95000},async t=>{
  const r=await relay(t,{pong:false}),f=await fixture(t,executable,r.origin);await until(()=>r.sockets.length===1);const started=Date.now();
  await until(()=>r.sockets.length===2,85000);assert.equal(r.pings.length,2);assert.ok(r.pings[0]-started>=24000);assert.ok(r.pings[1]-r.pings[0]>=24000);assert.ok(Date.now()-started>=75000);assert.equal((await f.control({op:'inspect'})).fault,false);
});

test('native completed read held before socket submission is suppressed after fault and root revocation',native,async t=>{
  const r=await relay(t),f=await fixture(t,executable,r.origin);await until(()=>r.sockets.length===1);
  await f.control({op:'hold',point:'reply',timeoutMs:15000});const id=randomUUID();r.sockets[0].send(JSON.stringify({kind:'call',id,tool:'read_file',args:{rootId:f.root,path:'hello.txt'},connectionAccess:f.access}));
  await until(async()=>(await f.control({op:'inspect'})).entered.reply);assert.equal((await f.store.load()).config.remoteUseConfirmed,true);
  await f.control({op:'arm',point:'core:snapshot',kind:'error'});await f.control({op:'trigger',point:'snapshot'});assert.equal((await f.api('/api/root/remove',{id:f.root})).status,200);
  await f.control({op:'release',point:'reply'});await new Promise(r=>setTimeout(r,100));assert.equal(r.messages.some(m=>m.id===id),false);
});

for(const restriction of ['pause','root removal'])test(`native completed read held before submission is suppressed by normal ${restriction} without fault`,native,async t=>{
  const r=await relay(t),f=await fixture(t,executable,r.origin);await until(()=>r.sockets.length===1);
  await f.control({op:'hold',point:'reply',timeoutMs:15000});const id=randomUUID();r.sockets[0].send(JSON.stringify({kind:'call',id,tool:'read_file',args:{rootId:f.root,path:'hello.txt'},connectionAccess:f.access}));
  await until(async()=>(await f.control({op:'inspect'})).entered.reply);assert.equal((await f.store.load()).config.remoteUseConfirmed,true);
  const response=restriction==='pause'?await f.api('/api/pause',{paused:true}):await f.api('/api/root/remove',{id:f.root});assert.equal(response.status,200);assert.equal((await f.control({op:'inspect'})).fault,false);
  await f.control({op:'release',point:'reply'});
  const later=await r.call('list_roots',{},f.access);if(restriction==='pause')assert.equal(typeof later.error,'string');else assert.equal(later.result.length,1);
  assert.equal(r.messages.some(m=>m.id===id),false);
});

test('native failed progress save leaves live progress retryable and next successful call confirms durability',native,async t=>{
  const r=await relay(t),f=await fixture(t,executable,r.origin);await until(()=>r.sockets.length===1);
  await f.control({op:'arm',point:'progress',kind:'error'});
  assert.equal((await r.call('list_roots',{},f.access)).result.length,2);
  assert.notEqual((await f.store.load()).config.remoteUseConfirmed,true);assert.equal(typeof(await(await f.api('/api/status')).json()).guideWarning,'string');
  assert.equal((await r.call('list_devices',{},f.access)).result.devices[0].deviceId,f.device);
  const saved=(await f.store.load()).config;assert.equal(saved.remoteUseConfirmed,true);assert.deepEqual(saved.unknown,f.config.unknown);assert.equal((await(await f.api('/api/status')).json()).guideWarning,undefined);
});

test('native failed guide readback progress save preserves completed read and retries evidence after durable save',native,async t=>{
  const r=await relay(t);const guideId=randomUUID();const filename=`chat2local-check-${guideId}.txt`;const content=`chat2local connection check\nrequest: ${guideId}\nstage: updated\n`;
  const f=await fixture(t,executable,r.origin,{before:async({store,config,root,folder,device})=>{
    config.roots[0].write=true;config.roots[0].writeMode='direct';config.remoteUseConfirmed=true;config.connectionGuide={version:1,id:guideId,rootId:root,startedAt:'2026-01-01T00:00:00.000Z',deviceId:device,origin:r.origin,unknown:'\ud800',evidence:{createdAt:'created',updatedAt:'updated',unknown:{n:7}}};
    await fs.writeFile(path.join(folder,filename),content);await store.saveConfig(config);
  }});await until(()=>r.sockets.length===1);
  await f.control({op:'arm',point:'progress',kind:'error'});
  assert.equal((await r.call('read_file',{rootId:f.root,path:filename},f.access)).result.content,content);
  let saved=(await f.store.load()).config;assert.equal(saved.connectionGuide.evidence.readBackAt,undefined);assert.equal(typeof(await(await f.api('/api/status')).json()).guideWarning,'string');
  assert.equal((await r.call('read_file',{rootId:f.root,path:filename},f.access)).result.content,content);
  saved=(await f.store.load()).config;assert.match(saved.connectionGuide.evidence.readBackAt,/^\d{4}-/);assert.equal(saved.connectionGuide.unknown,'\ud800');assert.deepEqual(saved.connectionGuide.evidence.unknown,{n:7});assert.equal((await(await f.api('/api/status')).json()).guideWarning,undefined);
  assert.equal((await fs.readFile(path.join(f.directory,'audit.jsonl'),'utf8')).trim().split('\n').length,2);
});

test('native business panic while authority mutexes are held recovers authenticated restrictions and drains the actual host',native,async t=>{
  const r=await relay(t),f=await fixture(t,executable,r.origin);await until(()=>r.sockets.length===1);
  await f.control({op:'arm',point:'business',kind:'panic'});const id=randomUUID();r.sockets[0].send(JSON.stringify({kind:'call',id,tool:'list_roots',args:{},connectionAccess:f.access}));
  await until(async()=>(await f.control({op:'inspect'})).fault);
  let status=await(await f.api('/api/status')).json();assert.equal(status.nativeFault,true);assert.equal(status.paused,true);assert.equal((await f.store.load()).config.paused,false);
  assert.equal((await f.api('/api/pause',{paused:true})).status,200);assert.equal((await f.api('/api/root/remove',{id:f.root})).status,200);
  status=await until(async()=>{const s=await(await f.api('/api/status')).json();return s.queuedOperations===0&&s.pendingPersistence===0&&s;});assert.equal(status.nativeFault,true);
  const saved=(await f.store.load()).config;assert.equal(saved.paused,true);assert.equal(saved.roots.length,0);assert.deepEqual(saved.unknown,f.config.unknown);assert.equal(r.messages.some(message=>message.id===id),false);
  assert.equal((await f.api('/api/shutdown',{})).status,200);const [code]=await f.exited;assert.equal(code,0);
});
