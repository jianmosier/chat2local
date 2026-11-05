import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import { Store } from '../src/agent/store.mjs';
import { freePort } from './controller-fixture.mjs';
import { until } from './native-bridge-fixture.mjs';
import { readNativeAgentArtifact } from '../scripts/native-agent-artifact.mjs';
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
