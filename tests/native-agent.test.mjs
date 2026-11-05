import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { randomUUID, createHash } from 'node:crypto';
import { Store } from '../src/agent/store.mjs';
import { freePort } from './controller-fixture.mjs';
import { until } from './native-bridge-fixture.mjs';
import { readNativeAgentArtifact } from '../scripts/native-agent-artifact.mjs';
import { installPortable, managementEntryContent } from '../scripts/install-portable.mjs';
import { VERSION } from '../src/shared/protocol.mjs';
const executable=process.env.CHAT2LOCAL_NATIVE_AGENT_TEST_EXECUTABLE,exec=promisify(execFile);
if(process.env.CHAT2LOCAL_NATIVE_AGENT_TEST_REQUIRED==='1'&&!executable)throw Error('Required formal native Agent missing.');
if(executable)await readNativeAgentArtifact(executable);
const native={skip:!executable,timeout:60000},env={SystemRoot:process.env.SystemRoot,PATH:path.join(process.env.SystemRoot,'System32')};
async function capturedLaunch(args) {
 const child=spawn(executable,args,{env,windowsHide:true,stdio:['ignore','pipe','pipe']});let stdout='',stderr='',exit=false,outEnd=false,errEnd=false;
 child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);child.on('exit',()=>exit=true);child.stdout.on('end',()=>outEnd=true);child.stderr.on('end',()=>errEnd=true);
 let timer;try {const [code]=await Promise.race([once(child,'close'),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error(`Launcher did not close capture pipes: exit=${exit}, stdoutEOF=${outEnd}, stderrEOF=${errEnd}`)),15000);})]);assert.equal(code,0,stderr);assert.equal(exit,true);assert.equal(outEnd,true);assert.equal(errEnd,true);return {stdout,stderr};}finally{clearTimeout(timer);}
}
test('formal native version is accurate, no state marker, no fixture switches or environment activation',native,async t=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-formal-version-'));t.after(()=>fs.rm(directory,{recursive:true,force:true}));const v=JSON.parse((await exec(executable,['--version'],{env:{...env,CHAT2LOCAL_STATE_DIR:directory,CHAT2LOCAL_CONTROLLER_FIXTURE_PUBLICATION_DELAY_MS:'5000'},cwd:directory,windowsHide:true})).stdout);assert.equal(v.name,'chat2local-native-agent');assert.equal(v.fixtureOnly,false);assert.equal(v.fullAgent,false);assert.equal(v.upgradeReady,false);assert.deepEqual(await fs.readdir(directory),[]);
 for(const args of [['--fixture-only'],['--control-stdin'],['--fixture-platform','x']])await assert.rejects(exec(executable,args,{env,windowsHide:true}));
});
test('formal launcher starts once, background survives parent and matching repeated launch reuses it',native,async t=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-formal-launch-')),port=await freePort(),store=new Store(directory);let session;
 const stop=async()=>{if(session)await fetch(session.origin+'/api/shutdown',{method:'POST',headers:{Origin:session.origin,'Content-Type':'application/json','X-Chat2Local-Token':session.token},body:'{}'}).catch(()=>{});};
 t.after(async()=>{session??=await store.readSession().catch(()=>null);await stop();if(session)await until(()=>{try{process.kill(session.pid,0);return false;}catch{return true;}},15000);await fs.rm(directory,{recursive:true,force:true});});
 const folder=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-formal-old-root-'));t.after(()=>fs.rm(folder,{recursive:true,force:true}));const legacy=(await store.load()).config;legacy.roots=[{id:randomUUID(),label:'Legacy root',path:folder,write:false,opaque:{keep:['中文','\ud800']}}];await store.saveConfig(legacy);
 const args=['--state-dir',directory,'--port',String(port),'--no-browser'];const first=await capturedLaunch(args);const ready=JSON.parse(first.stdout);session=await store.readSession();assert.equal(ready.pid,session.pid);assert.equal(ready.reused,false);assert.equal(first.stdout.includes(session.token),false);assert.doesNotThrow(()=>process.kill(session.pid,0));
 const second=JSON.parse((await capturedLaunch(args)).stdout);assert.equal(second.reused,true);assert.equal(second.pid,session.pid);assert.equal(session.profile,'chat2local-native-agent');assert.equal(session.fixtureOnly,false);assert.equal((await fs.readdir(directory)).some(s=>s.includes('synthetic')),false);
 const response=await fetch(session.origin+'/api/status',{headers:{'X-Chat2Local-Token':session.token}}),status=await response.json();assert.equal(response.status,200);assert.equal(status.startupAvailable,false);assert.equal(status.name,'chat2local-native-agent');
 assert.deepEqual(status.roots[0].opaque,legacy.roots[0].opaque);assert.deepEqual((await store.load()).config.roots,legacy.roots);
 const html=await fetch(session.origin+'/folders');assert.equal(html.status,200);assert.match(await html.text(),/native-panel.js/);
});
test('formal background closes ready pipe while continuing and rejects changed helper before state write',native,async t=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-formal-background-')),port=await freePort(),store=new Store(directory);const child=spawn(executable,['--background','--ready-stdout','--state-dir',directory,'--port',String(port)],{env,windowsHide:true,stdio:['ignore','pipe','pipe']});const exited=once(child,'exit');let output='';child.stdout.on('data',b=>output+=b);
 t.after(async()=>{if(child.exitCode===null){const s=await store.readSession();await fetch(s.origin+'/api/shutdown',{method:'POST',headers:{Origin:s.origin,'Content-Type':'application/json','X-Chat2Local-Token':s.token},body:'{}'});await exited;}await fs.rm(directory,{recursive:true,force:true});});
 await once(child.stdout,'end');assert.equal(child.exitCode,null);const s=await store.readSession();assert.equal(JSON.parse(output).pid,s.pid);assert.equal(output.includes(s.token),false);
 const packageDir=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-formal-tamper-'));t.after(()=>fs.rm(packageDir,{recursive:true,force:true}));await fs.cp(path.dirname(executable),packageDir,{recursive:true});await fs.appendFile(path.join(packageDir,'chat2local-terminal-runner.exe'),'tamper');const untouched=path.join(packageDir,'untouched');await assert.rejects(exec(path.join(packageDir,path.basename(executable)),['--background','--state-dir',untouched,'--port',String(await freePort())],{env,windowsHide:true}));await assert.rejects(fs.stat(untouched),{code:'ENOENT'});
 await fs.copyFile(path.join(path.dirname(executable),'chat2local-terminal-runner.exe'),path.join(packageDir,'chat2local-terminal-runner.exe'));const manifest=JSON.parse(await fs.readFile(path.join(packageDir,'manifest.json'),'utf8'));manifest.capabilities.version='0.1.0-alpha.27';await fs.writeFile(path.join(packageDir,'manifest.json'),JSON.stringify(manifest));await assert.rejects(exec(path.join(packageDir,path.basename(executable)),['--background','--state-dir',untouched,'--port',String(await freePort())],{env,windowsHide:true}));await assert.rejects(fs.stat(untouched),{code:'ENOENT'});
});

test('formal lifecycle upgrades and rolls back retained packages through a Unicode managed CMD without changing state',native,async t=>{
 const base=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-formal-lifecycle-')),parent=path.join(base,'\u4e2d\u6587 space & 100%'),directory=parent,installRoot=path.join(parent,'apps'),port=await freePort(),store=new Store(directory);let session,current;
 const args=['--state-dir',directory,'--port',String(port)],options={installRoot,store,port,noBrowser:true,nativeStartup:{available:()=>false}};
 const nativeExec=(file,args,extra={})=>exec(file,args,{env,windowsHide:true,...extra});
 t.after(async()=>{const saved=await store.readSession().catch(()=>null);if(saved?.ownerImage&&path.dirname(path.dirname(path.dirname(saved.ownerImage)))===installRoot){await nativeExec(saved.ownerImage,['--shutdown',...args]).catch(()=>{});await until(()=>{try{process.kill(saved.pid,0);return false;}catch{return true;}},15000);}await fs.rm(base,{recursive:true,force:true});});
 const first=JSON.parse((await nativeExec(executable,['--preflight',...args])).stdout);assert.equal(first.stopped,true);await assert.rejects(fs.stat(directory),{code:'ENOENT'});
 async function packageSource(label){
  const source=path.join(base,label);await fs.mkdir(source,{recursive:true});await fs.cp(path.dirname(executable),path.join(source,'native'),{recursive:true});
  const files={};for(const name of await fs.readdir(path.join(source,'native')))files['native/'+name]=createHash('sha256').update(await fs.readFile(path.join(source,'native',name))).digest('hex');
  for(const [name,bytes] of Object.entries({'scripts/launch.mjs':'// synthetic installer fixture - never executed','scripts/native-package.mjs':'// synthetic installer fixture - never executed','runtime/node.exe':'synthetic-bootstrap-not-executed','LICENSE':label})){await fs.mkdir(path.dirname(path.join(source,name)),{recursive:true});await fs.writeFile(path.join(source,name),bytes);files[name]=createHash('sha256').update(bytes).digest('hex');}
  await fs.writeFile(path.join(source,'BUILD-MANIFEST.json'),JSON.stringify({product:'Chat2Local',version:VERSION,platform:'win32-x64',runtimeKind:'rust-native',files}));return source;
 }
 const oldSource=await packageSource('retained-package'),newSource=await packageSource('new-package');
 const retained=await installPortable(oldSource,{...options,launch:false});
 await fs.mkdir(directory,{recursive:true});const config=(await store.load()).config;config.opaque={keep:['\u4e2d\u6587','\ud800']};await store.saveConfig(config);await store.saveSecrets({syntheticRetained:'do-not-reset'});
 const installed=await installPortable(newSource,options);current=path.join(installed.directory,'native/chat2local-native-agent.exe');session=await store.readSession();assert.equal(session.ownerImage,current);
 const savedSettings=await fs.readFile(path.join(directory,'settings.json')),savedVault=await fs.readFile(path.join(directory,'vault.json')),sessionBytes=await fs.readFile(path.join(directory,'session.json'));
 const entry=path.join(parent,'Chat2Local.cmd'),bytes=await fs.readFile(entry,'utf8');assert.equal(bytes,managementEntryContent(installed.directory,{platform:'win32',native:true,port}));assert.ok([...bytes].every(c=>c.charCodeAt(0)<128));
 const live=JSON.parse((await nativeExec(current,['--preflight',...args])).stdout);assert.equal(live.running,true);assert.equal(live.pid,session.pid);assert.deepEqual(await fs.readFile(path.join(directory,'session.json')),sessionBytes);
 const reused=await installPortable(newSource,options);assert.equal(reused.reused,true);assert.equal((await store.readSession()).pid,session.pid);assert.deepEqual(await fs.readFile(path.join(directory,'session.json')),sessionBytes);
 const foreign=path.join(retained.directory,'native/chat2local-native-agent.exe');await assert.rejects(nativeExec(foreign,['--shutdown',...args]));assert.equal((await fetch(session.origin+'/api/status',{headers:{'X-Chat2Local-Token':session.token}})).status,200);
 const stopped=await nativeExec(current,['--shutdown',...args]);assert.equal(JSON.parse(stopped.stdout).stopped,true);assert.equal(stopped.stdout.includes(session.token),false);
 const rollback=await installPortable(retained.directory,{...options,rollback:true});current=foreign;session=await store.readSession();assert.equal(session.ownerImage,current);assert.equal(rollback.directory,retained.directory);
 assert.deepEqual(await fs.readFile(path.join(directory,'settings.json')),savedSettings);assert.deepEqual(await fs.readFile(path.join(directory,'vault.json')),savedVault);
 assert.equal(await fs.readFile(entry,'utf8'),managementEntryContent(retained.directory,{platform:'win32',native:true,port}));const backup=(await fs.readdir(parent)).find(name=>name.startsWith('Chat2Local.cmd.previous-'));assert.equal(await fs.readFile(path.join(parent,backup),'utf8'),bytes);
 // Invoke the real generated ASCII CMD from a Unicode/space/ampersand/percent
 // parent. Environment and the embedded verified port keep it off real state.
 const launched=await exec(process.env.ComSpec||'C:\\Windows\\System32\\cmd.exe',['/d','/s','/c','Chat2Local.cmd'],{cwd:parent,env:{...env,LOCALAPPDATA:path.join(base,'unused-default-state'),CHAT2LOCAL_NO_BROWSER:'1'},windowsHide:true,timeout:20000});assert.equal(JSON.parse(launched.stdout).reused,true);assert.equal((await store.readSession()).pid,session.pid);
 await nativeExec(current,['--shutdown',...args]);assert.equal(JSON.parse((await nativeExec(current,['--preflight',...args])).stdout).stopped,true);await assert.rejects(nativeExec(current,['--shutdown',...args]));
});
