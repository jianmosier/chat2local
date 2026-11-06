import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import {readControllerArtifact} from '../scripts/controller-artifact.mjs';
import {fixture,relay,until} from './native-bridge-fixture.mjs';
const executable=process.env.CHAT2LOCAL_CONTROLLER_TEST_EXECUTABLE;
if(process.env.CHAT2LOCAL_CONTROLLER_TEST_REQUIRED==='1'&&!executable)throw Error('Required native controller fixture missing.');
if(executable)await readControllerArtifact(executable);
const native={skip:!executable,timeout:60000};
async function setup(t,platform={},options={}){const r=await relay(t);const f=await fixture(t,executable,r.origin,{externalRoot:true,platform,...options});return{r,f};}
async function temporary(t){const d=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-startup-fixture-'));await fs.writeFile(path.join(d,'.chat2local-startup-fixture'),'synthetic-startup-only\n');t.after(()=>fs.rm(d,{recursive:true,force:true}));return d;}
test('native startup refuses a synthetic legacy entry without preparing or replacing either shortcut',native,async t=>{
 const directory=await temporary(t);await fs.writeFile(path.join(directory,'Chat2Local.lnk'),'legacy-owned');const {f}=await setup(t,{startup:{directory}});const before=await fs.readFile(path.join(f.directory,'settings.json'));
 for(const enabled of [true,false])assert.equal((await f.api('/api/startup',{enabled})).status,409);
 assert.equal(await fs.readFile(path.join(directory,'Chat2Local.lnk'),'utf8'),'legacy-owned');await assert.rejects(fs.stat(path.join(directory,'Chat2Local Native Fixture.lnk')),{code:'ENOENT'});assert.deepEqual(await fs.readFile(path.join(f.directory,'settings.json')),before);assert.equal((await f.control({op:'inspect'})).helperStarts,0);
});
test('native names-only browse preserves grants, uses ordinal names and checks actual root identity',native,async t=>{
 const {f}=await setup(t);const initial=(await f.store.load()).config;
 for(const n of ['zeta','Alpha','中文','.hidden','node_modules'])await fs.mkdir(path.join(f.folder,n));
 const response=await f.api('/api/folder/browse',{path:f.folder.toLowerCase()});assert.equal(response.status,200,await response.clone().text());const body=await response.json();assert.deepEqual(body.entries.map(e=>e.name),['Alpha','zeta','中文']);assert.equal(body.selectable,true);assert.deepEqual(body.existingRoot,{id:f.root,label:'Synthetic',writeMode:'read-only'});
 assert.deepEqual((await f.store.load()).config,initial);
 for(const target of [f.directory,process.env.SystemRoot,process.env.ProgramFiles,'\\\\server\\share','\\\\?\\C:\\','C:\\bad\u0001'])assert.equal((await f.api('/api/folder/browse',{path:target})).status,400);
 for(const target of [os.homedir(),path.parse(f.folder).root]){const v=await(await f.api('/api/folder/browse',{path:target})).json();assert.equal(v.selectable,false);assert.equal(v.existingRoot,null);}
 for(const value of [{path:null},{path:4},{extra:1}])assert.equal((await f.api('/api/folder/browse',value)).status,400);
 const manager=await f.api('/api/management/session',{}),cookie=manager.headers.get('set-cookie').split(';')[0];const headers={'X-Chat2Local-Token':'','X-Chat2Local-Manager':'1',Cookie:cookie};
 assert.equal((await f.api('/api/folder/browse',{path:f.folder},headers)).status,200);for(const route of ['/api/pick-folder','/api/folder/cancel','/api/startup'])assert.equal((await f.api(route,{},headers)).status,401);
 assert.equal((await f.api('/api/management/startup',{enabled:true},headers)).status,400);assert.equal((await(await f.api('/api/status')).json()).startupAvailable,false);
 for(const route of ['/api/folder/select','/api/root/add'])assert.equal((await f.api(route,{})).status,400);assert.equal((await f.api('/api/browser/open',{})).status,501);
});
test('native browse holds directory identity, caps parallel enumeration and truncates first 300 eligible names',native,async t=>{
 const {f}=await setup(t);await Promise.all(Array.from({length:305},(_,i)=>fs.mkdir(path.join(f.folder,'entry'+String(i).padStart(3,'0')))));
 await f.control({op:'hold',point:'platform:browse'});const a=f.api('/api/folder/browse',{path:f.folder});const b=f.api('/api/folder/browse',{path:f.folder});await until(async()=>(await f.control({op:'inspect'})).entered['platform:browse']===2);
 assert.equal((await f.api('/api/folder/browse',{path:f.folder})).status,429);await assert.rejects(fs.rename(f.folder,f.folder+'-moved'));
 await f.control({op:'release',point:'platform:browse'});for(const response of await Promise.all([a,b])){const v=await response.json();assert.equal(v.entries.length,300);assert.equal(v.truncated,true);}assert.equal((await f.control({op:'inspect'})).browseActive,0);
});
test('native picker owns real helper, remains outside FIFO and retains singleflight until actual cancellation drain',native,async t=>{
 const {f}=await setup(t,{picker:{mode:'selected',path:'C:\\synthetic-candidate',delayMs:50}});const before=(await f.store.load()).config;
 assert.deepEqual(await(await f.api('/api/pick-folder',{})).json(),{path:'C:\\synthetic-candidate'});assert.deepEqual((await f.store.load()).config,before);
 await f.control({op:'platform-config',picker:{mode:'stall'}});await f.control({op:'hold',point:'platform:drain'});const pending=f.api('/api/pick-folder',{});await until(async()=>(await f.control({op:'inspect'})).helperActive===1);
 assert.equal((await f.api('/api/pick-folder',{})).status,409);assert.equal((await f.api('/api/status')).status,200);assert.equal((await f.api('/api/folder/cancel',{})).status,200);assert.deepEqual(await(await pending).json(),{path:null});await until(async()=>(await f.control({op:'inspect'})).entered['platform:drain']);
 assert.equal((await f.api('/api/pick-folder',{})).status,409);assert.equal((await f.control({op:'inspect'})).pickerActive,true);await f.control({op:'release',point:'platform:drain'});await until(async()=>(await f.control({op:'inspect'})).pickerActive===false);assert.deepEqual((await f.control({op:'inspect'})).helperPids,[]);
});
test('native picker cancellation before spawn, HTTP disconnect, pause and fault never publish a late selection',native,async t=>{
 for(const cause of ['disconnect','pause','fault'])await t.test(cause,async t=>{const {f}=await setup(t,{picker:{mode:'selected',path:'C:\\late'}});await f.control({op:'hold',point:'platform:spawn'});
 let request;const pending=cause==='disconnect'?new Promise(resolve=>{request=http.request(f.ready.origin+'/api/pick-folder',{method:'POST',headers:{Origin:f.ready.origin,'Content-Type':'application/json','X-Chat2Local-Token':f.session.token}},res=>{res.resume();resolve(res);});request.on('error',resolve);request.end('{}');}):f.api('/api/pick-folder',{});
 await until(async()=>(await f.control({op:'inspect'})).entered['platform:spawn']);if(cause==='disconnect'){request.destroy();await pending;await new Promise(r=>setTimeout(r,150));}else if(cause==='pause'){assert.equal((await f.api('/api/pause',{paused:true})).status,200);}else{await f.control({op:'arm',point:'core:snapshot',kind:'error'});await f.control({op:'trigger',point:'snapshot'});}
 if(cause!=='disconnect')assert.deepEqual(await(await pending).json(),{path:null});await f.control({op:'release',point:'platform:spawn'});await until(async()=>(await f.control({op:'inspect'})).pickerActive===false);assert.equal((await f.control({op:'inspect'})).helperStarts,0);
 });
});
test('native picker cancels admission when pause completes before registration',native,async t=>{
 const {f}=await setup(t,{picker:{mode:'selected',path:'C:\\late'}});await f.control({op:'hold',point:'platform:register'});const pending=f.api('/api/pick-folder',{});
 await until(async()=>(await f.control({op:'inspect'})).entered['platform:register']);assert.equal((await f.api('/api/pause',{paused:true})).status,200);
 await f.control({op:'release',point:'platform:register'});const response=await pending;assert.equal(response.status,200);assert.deepEqual(await response.json(),{path:null});
 const state=await f.control({op:'inspect'});assert.equal(state.helperStarts,0);assert.equal(state.pickerActive,false);assert.equal((await f.api('/api/pick-folder',{})).status,409);
});
test('native pause installation cancels a picker registered after early invalidation and retains real drain',native,async t=>{
 const {f}=await setup(t,{picker:{mode:'stall'}});await f.control({op:'hold',point:'platform:pause'});const pause=f.api('/api/pause',{paused:true});
 await until(async()=>(await f.control({op:'inspect'})).entered['platform:pause']);await f.control({op:'hold',point:'platform:drain'});const pending=f.api('/api/pick-folder',{});
 await until(async()=>(await f.control({op:'inspect'})).helperActive===1);await f.control({op:'release',point:'platform:pause'});assert.equal((await pause).status,200);
 assert.deepEqual(await(await pending).json(),{path:null});await until(async()=>(await f.control({op:'inspect'})).entered['platform:drain']);const held=await f.control({op:'inspect'});
 assert.equal(held.pickerActive,true);assert.equal(held.helperActive,1);for(const pid of held.helperPids)assert.doesNotThrow(()=>process.kill(pid,0));assert.equal((await f.api('/api/pick-folder',{})).status,409);
 await f.control({op:'release',point:'platform:drain'});await until(async()=>(await f.control({op:'inspect'})).pickerActive===false);assert.deepEqual((await f.control({op:'inspect'})).helperPids,[]);for(const pid of held.helperPids)assert.throws(()=>process.kill(pid,0));
});
test('native fixed picker helper validates output and reaps failure without poisoning host',native,async t=>{
 const {f}=await setup(t,{picker:{mode:'cancel'}});assert.deepEqual(await(await f.api('/api/pick-folder',{})).json(),{path:null});
 for(const mode of ['invalid','overflow','nonzero']){await f.control({op:'platform-config',picker:{mode}});assert.equal((await f.api('/api/pick-folder',{})).status,503);const i=await f.control({op:'inspect'});assert.equal(i.helperActive,0);assert.equal(i.pickerActive,false);assert.equal(i.fault,false);}
 await f.control({op:'platform-config',picker:{mode:'stall',timeoutMs:300}});assert.deepEqual(await(await f.api('/api/pick-folder',{})).json(),{path:null});assert.equal((await f.control({op:'inspect'})).helperActive,0);
});
test('native temporary managed startup uses actual COM create update delete and truthful save failure',native,async t=>{
 const directory=await temporary(t),{f}=await setup(t,{startup:{directory}});const link=path.join(directory,'Chat2Local Native Fixture.lnk'),before=(await f.store.load()).config;
 assert.equal((await(await f.api('/api/status')).json()).startupAvailable,false);for(const enabled of [true,true,false,true]){const response=await f.api('/api/startup',{enabled});assert.equal(response.status,200,await response.clone().text());assert.equal((await f.store.load()).config.startup,enabled);assert.equal(await fs.stat(link).then(()=>true,()=>false),enabled);}
 const manager=await f.api('/api/management/session',{}),cookie=manager.headers.get('set-cookie').split(';')[0];assert.equal((await f.api('/api/management/startup',{enabled:false},{'X-Chat2Local-Token':'','X-Chat2Local-Manager':'1',Cookie:cookie})).status,200);
 await f.control({op:'arm',point:'save',kind:'error'});const partial=await f.api('/api/startup',{enabled:true});assert.equal(partial.status,503);assert.match(await partial.text(),/OS action applied/);assert.ok((await fs.stat(link)).isFile());assert.equal((await f.store.load()).config.startup,false);
 const after=(await f.store.load()).config;for(const key of ['roots','accountRoots','terminalGrants','unknown','installationId'])assert.deepEqual(after[key],before[key]);
 await f.api('/api/startup',{enabled:false});await fs.writeFile(link,'foreign');const foreign=await fs.readFile(link);assert.equal((await f.api('/api/startup',{enabled:true})).status,503);assert.deepEqual(await fs.readFile(link),foreign);
 await assert.rejects(fs.stat(path.join(f.directory,'%SystemDrive%')), {code:'ENOENT'});
});
test('native startup checked existing shortcut is immutable and fault before actual commit refuses mutation',native,async t=>{
 const directory=await temporary(t),{f}=await setup(t,{startup:{directory}});assert.equal((await f.api('/api/startup',{enabled:true})).status,200);const link=path.join(directory,'Chat2Local Native Fixture.lnk'),before=await fs.readFile(link);
 await f.control({op:'hold',point:'platform:commit'});const pending=f.api('/api/startup',{enabled:true});await until(async()=>(await f.control({op:'inspect'})).entered['platform:commit']);await assert.rejects(fs.rename(link,link+'.other'));
 const produced=(await fs.readdir(directory)).find(n=>/^\.chat2local-[a-f0-9]{32}\.lnk$/.test(n));assert.ok(produced);await assert.rejects(fs.writeFile(path.join(directory,produced),'foreign'));await assert.rejects(fs.rename(path.join(directory,produced),path.join(directory,'replacement.lnk')));
 await f.control({op:'arm',point:'core:snapshot',kind:'error'});await f.control({op:'trigger',point:'snapshot'});await f.control({op:'release',point:'platform:commit'});assert.equal((await pending).status,409);assert.deepEqual(await fs.readFile(link),before);assert.equal((await f.store.load()).config.startup,true);
});
test('native internal browser capture validates exact issued local and relay target without public route',native,async t=>{
 const {f,r}=await setup(t,{browser:{mode:'capture'}});const target={kind:'local-panel',url:f.ready.origin+'/folders#'+f.session.token};assert.deepEqual(await f.control({op:'platform-browser',target}),{dispatched:true,captured:true});
 assert.deepEqual(await f.control({op:'platform-browser',target:{kind:'relay-handoff',url:r.origin+'/link#'+f.device+'.'+'a'.repeat(64)}}),{dispatched:true,captured:true});
 for(const url of ['file:///C:/Windows',f.ready.origin+'/#'+f.session.token,f.ready.origin+'/folders#wrong','http://foreign.invalid/folders#'+f.session.token])await assert.rejects(f.control({op:'platform-browser',target:{kind:'local-panel',url}}));
 await f.control({op:'platform-config',browser:{mode:'nonzero'}});await assert.rejects(f.control({op:'platform-browser',target}),/may have occurred/);await f.control({op:'platform-config',browser:{mode:'stall',timeoutMs:300}});await assert.rejects(f.control({op:'platform-browser',target}),/may have occurred/);await f.control({op:'platform-config',browser:{mode:'capture'}});
 await f.control({op:'hold',point:'platform:commit'});const pending=f.control({op:'platform-browser',target}).catch(e=>e);await until(async()=>(await f.control({op:'inspect'})).entered['platform:commit']);const starts=(await f.control({op:'inspect'})).helperStarts;await f.control({op:'trigger',point:'close'});await f.control({op:'release',point:'platform:commit'});assert.ok(await pending instanceof Error);await until(()=>f.child.exitCode!==null);assert.equal(f.child.exitCode,0);assert.equal(starts,4);
});
test('native close retains listener and real picker process until platform drainage completes',native,async t=>{
 const {f}=await setup(t,{picker:{mode:'stall'}});await f.control({op:'hold',point:'platform:drain'});const pending=f.api('/api/pick-folder',{});await until(async()=>(await f.control({op:'inspect'})).helperActive===1);assert.equal((await f.api('/api/shutdown',{})).status,200);await pending;await until(async()=>(await f.control({op:'inspect'})).entered['platform:drain']);const state=await f.control({op:'inspect'});assert.equal(state.helperActive,1);assert.equal(f.child.exitCode,null);for(const pid of state.helperPids)assert.doesNotThrow(()=>process.kill(pid,0));
 await new Promise(resolve=>{const server=net.createServer();server.once('error',error=>{assert.equal(error.code,'EADDRINUSE');resolve();});server.listen(f.ready.port,'127.0.0.1',()=>{server.close();assert.fail('Owned port was released early.');});});await f.control({op:'release',point:'platform:drain'});await until(()=>f.child.exitCode!==null);assert.equal(f.child.exitCode,0);for(const pid of state.helperPids)assert.throws(()=>process.kill(pid,0));
});
