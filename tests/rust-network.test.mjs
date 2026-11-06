import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {randomUUID} from 'node:crypto';
import {readControllerArtifact} from '../scripts/controller-artifact.mjs';
import {networkSettings} from '../src/agent/network.mjs';
import {fixture,relay,until} from './native-bridge-fixture.mjs';
const executable=process.env.CHAT2LOCAL_CONTROLLER_TEST_EXECUTABLE;
if(process.env.CHAT2LOCAL_CONTROLLER_TEST_REQUIRED==='1'&&!executable)throw Error('Required native controller fixture missing.');
if(executable)await readControllerArtifact(executable);
const native={skip:!executable,timeout:60000};
const remote='https://relay.example.invalid';
async function setup(t,options={}){const r=await relay(t,{health:{name:'chat2local-relay'}});const f=await fixture(t,executable,r.origin,{...options,before:async args=>{await args.store.saveSecrets({unknown:{keep:'\ud800'}});await options.before?.(args);}});return{r,f};}
test('native network settings match JS normalization and preserve grants without a relay',native,async t=>{
 const {f}=await setup(t);const initial=(await f.store.load()).config;
 for(const value of [{mode:'auto',proxy:{ignored:true}},{mode:'direct',proxy:42},{mode:'proxy',proxy:'HTTP://localhost:80/'},{mode:'auto'}]){const res=await f.api('/api/network/set',value);assert.equal(res.status,200,await res.clone().text());const body=await res.json();assert.deepEqual(body.settings,networkSettings(value));assert.equal(body.network.source,'not-checked');const config=(await f.store.load()).config;assert.deepEqual(config.network,networkSettings(value));for(const key of ['roots','accountRoots','terminalGrants','unknown','installationId'])assert.deepEqual(config[key],initial[key]);}
 for(const value of [{mode:'proxy',proxy:'http://u:p@localhost'},{mode:'proxy',proxy:'socks://localhost'},{mode:'invalid'},{mode:'auto',extra:1},null,[]])assert.equal((await f.api('/api/network/set',value)).status,400);
 const manager=await f.api('/api/management/session',{});const cookie=manager.headers.get('set-cookie').split(';')[0];for(const route of ['set','check'])assert.equal((await f.api('/api/network/'+route,{mode:'auto',origin:remote},{'X-Chat2Local-Token':'','X-Chat2Local-Manager':'1',Cookie:cookie})).status,401);
});
test('native force preparation shares current in-flight work and retires old cached eligibility',native,async t=>{
 const {f}=await setup(t,{transport:{env:{},systemQuery:{mode:'direct'}}});
 const a=await f.control({op:'network-prepare',origin:remote});const first=await f.control({op:'inspect'});assert.equal(first.queryStarts,1);
 const cached=await f.control({op:'network-prepare',origin:remote});assert.equal(cached.revision,a.revision);assert.equal((await f.control({op:'inspect'})).queryStarts,1);
 await f.control({op:'network-query',query:{mode:'direct',delayMs:700}});
 const forced=f.control({op:'network-prepare',origin:remote,force:true});await until(async()=>(await f.control({op:'inspect'})).queryActive===1);
 const shared=f.control({op:'network-prepare',origin:remote});const [b,c]=await Promise.all([forced,shared]);assert.equal(b.revision,c.revision);assert.ok(b.revision>a.revision);assert.equal((await f.control({op:'inspect'})).queryStarts,2);
});
test('native failed settings save keeps previous policy and fault restriction cannot be overwritten by its completion',native,async t=>{
 const {f}=await setup(t);const previous=(await f.store.load()).config;
 await f.control({op:'arm',point:'save',kind:'error'});assert.equal((await f.api('/api/network/set',{mode:'direct'})).status,503);
 assert.deepEqual((await f.store.load()).config,previous);assert.deepEqual((await(await f.api('/api/status')).json()).networkSettings,{mode:'auto'});
 await f.control({op:'hold',point:'save'});const setting=f.api('/api/network/set',{mode:'direct'});await until(async()=>(await f.control({op:'inspect'})).entered.save);
 await f.control({op:'arm',point:'core:snapshot',kind:'error'});await f.control({op:'trigger',point:'snapshot'});
 const restriction=await f.api('/api/pause',{paused:true});assert.equal(restriction.status,503);
 await f.control({op:'release',point:'save'});assert.equal((await setting).status,503);
 await until(async()=>(await f.control({op:'inspect'})).pendingPersistence===0);const saved=(await f.store.load()).config;
 assert.equal(saved.paused,true);assert.deepEqual(saved.network,{mode:'direct'});assert.deepEqual(saved.roots,previous.roots);
});
test('native health responses match JSON and redirect failure distinctions without following redirects',native,async t=>{
 let mode='healthy',redirected=0;
 const messages={healthy:'中继网络可达；这不代表已完成 ChatGPT 官网授权。',wrong:'入口响应不匹配，请核对中继地址。',bad:'无法连接中继，请检查直连／代理设置及代理是否运行。没有自动改用其他网络。'};
 const r=await relay(t,{health:(req,res)=>{if(req.url==='/other')redirected++;if(mode==='redirect'){res.writeHead(302,{location:'/other'});res.end();}else{res.writeHead(mode==='error'?500:200,{'content-type':'application/json'});res.end(mode==='bad'?'invalid':JSON.stringify({name:mode==='healthy'?'chat2local-relay':'different'}));}}});
 const f=await fixture(t,executable,r.origin);
 for(mode of ['healthy','wrong','bad','error','redirect']){const response=await f.api('/api/network/check',{});assert.equal(response.status,200);const value=await response.json();assert.equal(value.ok,mode==='healthy');assert.equal(value.websiteClientVerified,false);assert.equal(value.message,messages[mode==='healthy'?'healthy':['bad','redirect'].includes(mode)?'bad':'wrong']);}
 assert.equal(redirected,0);
});
test('native close retains a settings save until actual publication and never starts a replacement Bridge',native,async t=>{
 const {f,r}=await setup(t);await f.control({op:'hold',point:'save'});const pending=f.api('/api/network/set',{mode:'direct'});
 await until(async()=>(await f.control({op:'inspect'})).entered.save);await f.control({op:'trigger',point:'close'});
 assert.equal(f.child.exitCode,null);const held=await f.control({op:'inspect'});assert.equal(held.pendingPersistence,1);assert.equal(held.closing,true);
 await f.control({op:'release',point:'save'});assert.equal((await pending).status,503);await until(()=>f.child.exitCode!==null);assert.equal(f.child.exitCode,0);assert.equal(r.sockets.length,0);assert.deepEqual((await f.store.load()).config.network,{mode:'direct'});
});
test('native force settings and close retire actual pending TLS and CONNECT sockets before credential publication',native,async t=>{
 const {mint,proxy,clientHelloServer}=await import('./transport-fixture.mjs');
 const ca=await mint(),leaf=await mint({issuer_cert:ca.cert,issuer_key:ca.key,dns:['relay.example.test']});
 for(const stage of ['tls','connect'])for(const action of ['force','settings','close'])await t.test(stage+' '+action,async t=>{
  const r=await relay(t,{certificate:leaf});const stalled=await clientHelloServer({next:r,failure:'stall',failCount:1000});t.after(()=>stalled.close());
  const intermediary=stage==='connect'?await proxy({target:r,stall:true}):undefined;if(intermediary)t.after(()=>intermediary.close());
  const origin=`https://relay.example.test:${r.port}`,transport={env:{},ca:ca.cert,addresses:{'relay.example.test':`127.0.0.1:${stalled.port}`}};
  if(intermediary)transport.addresses['proxy.example.test']=`127.0.0.1:${intermediary.port}`;
  const f=await fixture(t,executable,origin,{transport,before:async({store,config})=>{config.network=intermediary?{mode:'proxy',proxy:`http://proxy.example.test:${intermediary.port}`}:{mode:'direct'};await store.saveConfig(config);}});
  const endpoint=intermediary??stalled;await until(()=>intermediary?intermediary.seen.tunnels===1:stalled.hellos.length===1);let result;
  if(action==='force')result=f.control({op:'network-prepare',origin,force:true}).catch(e=>e);
  else if(action==='settings')result=f.api('/api/network/set',{mode:'direct'});
  else await f.control({op:'trigger',point:'close'});
  await until(()=>endpoint.state.closed>=1);assert.equal(r.sockets.length,0);assert.equal(r.protocols.length,0);
  if(intermediary)assert.equal(intermediary.seen.isolated,true);
  if(action!=='close'){if(action==='settings')assert.equal((await result).status,200);assert.equal((await f.control({op:'inspect'})).fault,false);await f.control({op:'trigger',point:'close'});await result;}
  await until(()=>f.child.exitCode!==null);assert.equal(f.child.exitCode,0);assert.equal(r.sockets.length,0);
 });
});
test('native actual fixed query helper rejects malformed nonzero and oversized output without route fallback',native,async t=>{
 const {f}=await setup(t,{transport:{env:{},systemQuery:{mode:'direct'}}});await f.control({op:'network-prepare',origin:remote});
 for(const mode of ['invalid','nonzero','overflow']){await f.control({op:'network-query',query:{mode}});await assert.rejects(f.control({op:'network-prepare',origin:remote,force:true}),/系统代理/);const status=(await(await f.api('/api/status')).json()).network;assert.equal(status.source,'error');assert.equal('tlsProfile'in status,false);const inspect=await f.control({op:'inspect'});assert.equal(inspect.queryActive,0);assert.deepEqual(inspect.queryPids,[]);}
 await f.control({op:'network-query',query:{mode:'stall'}});const start=Date.now();await assert.rejects(f.control({op:'network-prepare',origin:remote,force:true}),/系统代理/);assert.ok(Date.now()-start>=7500);assert.equal((await f.control({op:'inspect'})).queryActive,0);
});
test('native network check verifies Business health without closing an established Bridge',native,async t=>{
 const r=await relay(t,{health:{name:'chat2local-relay'}}),f=await fixture(t,executable,r.origin);await until(()=>r.sockets.length===1);
 const before=(await f.control({op:'inspect'})).networkRevision;const checked=await(await f.api('/api/network/check',{origin:'https://ignored.invalid'})).json();assert.equal(checked.ok,true);assert.equal(checked.websiteClientVerified,false);assert.equal(checked.network.source,'loopback');assert.ok((await f.control({op:'inspect'})).networkRevision>before);
 assert.ok((await r.call('list_devices',{},f.access)).result);assert.equal(r.sockets.length,1);
 for(let i=0;i<5;i++){const response=await f.api('/api/network/set',{mode:'direct',proxy:{ignored:i}});assert.equal(response.status,200);await until(()=>r.sockets.length===i+2);assert.equal((await(await f.api('/api/status')).json()).nativeFault,false);}
});
test('native settings replace the Bridge while preserving an already running terminal and saved grants',native,async t=>{
 const r=await relay(t),f=await fixture(t,executable,r.origin,{externalRoot:true,before:async({store,config})=>{config.roots[0].writeMode='direct';config.roots[0].write=true;await store.saveConfig(config);}});
 const original=(await f.store.load()).config;f.access.roots[0].mode='direct';const requestId=randomUUID();
 const started=await r.call('terminal_execute',{rootId:f.root,requestId,command:"Start-Sleep -Milliseconds 6000; [Console]::Out.Write('survived-network-change')",timeoutMs:12000},f.access);assert.equal(started.error,undefined,JSON.stringify(started));assert.equal(started.result.status,'running');
 assert.equal((await f.api('/api/network/set',{mode:'direct'})).status,200);await until(()=>r.sockets.length===2);
 const done=await until(async()=>{const response=await r.call('terminal_status',{rootId:f.root,requestId},f.access);assert.equal(response.error,undefined,JSON.stringify(response));return response.result.outcomeKnown&&response.result;},15000);
 assert.equal(done.status,'succeeded');assert.equal(done.stdout,'survived-network-change');const saved=(await f.store.load()).config;for(const key of ['roots','accountRoots','terminalGrants','unknown'])assert.deepEqual(saved[key],original[key]);
});
test('native close cancels and reaps an actual pending system query before listener ownership releases',native,async t=>{
 const {f}=await setup(t,{transport:{env:{},systemQuery:{mode:'stall'}}});await f.control({op:'hold',point:'network:drain'});const pending=f.control({op:'network-prepare',origin:remote}).catch(e=>e);
 const active=await until(async()=>{const s=await f.control({op:'inspect'});return s.queryActive===1&&s;});assert.equal(active.queryPids.length,1);
 assert.equal((await f.api('/api/shutdown',{})).status,200);await until(async()=>(await f.control({op:'inspect'})).entered['network:drain']);
 assert.equal(f.child.exitCode,null);for(const pid of active.queryPids)process.kill(pid,0);
 const collision=net.createServer();await assert.rejects(new Promise((resolve,reject)=>{collision.once('error',reject);collision.listen(Number(new URL(f.ready.origin).port),'127.0.0.1',()=>{collision.close();resolve();});}),{code:'EADDRINUSE'});
 await f.control({op:'release',point:'network:drain'});await pending;await until(()=>f.child.exitCode!==null,15000);assert.equal(f.child.exitCode,0);
 for(const pid of active.queryPids)assert.throws(()=>process.kill(pid,0));
});
test('native current-user system query is query-only and returns no proxy secrets',native,async t=>{
 const {f}=await setup(t);const result=await f.control({op:'network-system-query',origin:remote});assert.equal(result.actualSystemQuery,true);assert.ok(['system-direct','system-proxy'].includes(result.source));assert.deepEqual(Object.keys(result).sort(),['actualSystemQuery','source']);assert.equal((await f.control({op:'inspect'})).queryActive,0);
});
