import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { getEventListeners } from 'node:events';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { AgentLifecycle, JsLifecycleCore, lifecycleError } from '../src/agent/runtime/lifecycle-core.mjs';
import { RustLifecycleCore, configuredLifecycle } from '../src/agent/runtime/rust-lifecycle.mjs';
import { SerialQueue } from '../src/agent/runtime/serial-queue.mjs';
import { AgentState } from '../src/agent/runtime/agent-state.mjs';
import { Bridge } from '../src/agent/bridge.mjs';
import { startController } from '../src/agent/main.mjs';
import { Store } from '../src/agent/store.mjs';
import { RustWriterBackend } from '../src/agent/files/rust-writer.mjs';
import { RustTerminalProcessRunner } from '../src/agent/terminal/rust-process-runner.mjs';
import { fakeWebSockets, fakeBridgeOptions, bridgeIdentity, deferred, until } from './lifecycle-fixtures.mjs';

const modulePath = process.env.CHAT2LOCAL_LIFECYCLE_TEST_MODULE ?? path.resolve('target/wasm32-unknown-unknown/release/chat2local_agent_lifecycle_wasm.wasm');
const terminalExecutable = process.env.CHAT2LOCAL_TERMINAL_TEST_EXECUTABLE ?? path.resolve('target/debug/chat2local-terminal-runner.exe');
const terminalStoreExecutable = process.env.CHAT2LOCAL_TERMINAL_STORE_TEST_EXECUTABLE ?? path.resolve('target/debug/chat2local-terminal-store.exe');
const writerExecutable = process.env.CHAT2LOCAL_WRITER_TEST_EXECUTABLE ?? path.resolve('target/debug/chat2local-writer.exe');
const available = existsSync(modulePath), nativeAvailable = available && process.platform === 'win32' && [terminalExecutable, terminalStoreExecutable, writerExecutable].every(existsSync);
if (process.env.CHAT2LOCAL_LIFECYCLE_TEST_REQUIRED === '1' && !nativeAvailable) throw Error('Strict lifecycle tests require actual WASM and Windows terminal/journal/writer helpers.');
const wasm = { skip: available ? false : 'Build lifecycle WASM' }, native = { skip: nativeAvailable ? false : 'Build lifecycle native fixtures' };
const core = () => new RustLifecycleCore({ modulePath });
const tick = () => new Promise(resolve => setImmediate(resolve));
function faultCore() {
  let armed;
  const state = new RustLifecycleCore({ modulePath, instantiate(module) {
    const real = new WebAssembly.Instance(module, {}).exports;
    return { exports: { ...real, command(length) {
      const command = JSON.parse(Buffer.from(real.memory.buffer, real.input_ptr(), length).toString()).command;
      if (armed?.op === command.op) {
        if (armed.mode === 'trap') throw new WebAssembly.RuntimeError('synthetic lifecycle trap');
        const code = real.command(length); const bytes = new Uint8Array(real.memory.buffer, real.output_ptr(), real.output_len()); bytes[0] = 255; return code;
      }
      return real.command(length);
    } } };
  } }); return { state, arm(op, mode = 'trap') { armed = { op, mode }; } };
}
class Clock {
  now = 0; timers = new Map(); serial = 0;
  set = (fn, delay) => { const key = ++this.serial; this.timers.set(key, { at: this.now + delay, fn }); return key; };
  clear = key => this.timers.delete(key);
  next() { const [key, timer] = [...this.timers].sort((a,b)=>a[1].at-b[1].at)[0]; this.timers.delete(key); this.now = timer.at; timer.fn(); }
}
async function fixture(t, { beforeStart, ...extra } = {}) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-lifecycle-')), project = path.join(base, 'project'); await fs.mkdir(project);
  const store = new Store(path.join(base, 'state')); if (beforeStart) await beforeStart(store);
  const app = await startController({ port: 0, store, lifecycleBackend: 'rust', lifecycleModulePath: modulePath, bridgeOptions: fakeBridgeOptions(), ...extra });
  const api = (route, value, auth = true) => fetch(`${app.origin}/api/${route}`, { method: value === undefined ? 'GET' : 'POST', headers: { Origin: app.origin, ...(auth ? { 'X-Chat2Local-Token': app.token } : {}), 'Content-Type': 'application/json' }, ...(value === undefined ? {} : { body: JSON.stringify(value) }), signal: AbortSignal.timeout(4000) });
  t.after(async () => { await app.close().catch(() => {}); await fs.rm(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); });
  const root = await (await api('root/add', { path: project, writeMode: 'direct', confirmDirect: true })).json();
  return { app, api, root, base, project, store };
}

test('explicit lifecycle selection has no missing/corrupt WASM fallback and default JS needs no artifact', async () => {
  assert.equal(configuredLifecycle({}, {}).snapshot().phase, 'starting');
  assert.throws(() => configuredLifecycle({ lifecycleBackend: 'rust', lifecycleModulePath: path.resolve('absent-lifecycle.wasm') }, {}), /lifecycle/);
  assert.throws(() => configuredLifecycle({ lifecycleBackend: 'wrong' }, {}), /Unsupported/);
  const stateDir = path.join(os.tmpdir(), 'c2l-no-lifecycle-' + randomUUID());
  await assert.rejects(startController({ stateDir, lifecycleBackend: 'rust', lifecycleModulePath: path.resolve('absent-lifecycle.wasm') }), /lifecycle/);
  assert.equal(existsSync(stateDir), false);
});

test('real WASM owns 24 FIFO tickets, order, once finish and healthy close drains accepted actions', wasm, async () => {
  const lifecycle = new AgentLifecycle(core()); lifecycle.run({ op: 'activate' }); const queue = new SerialQueue({ lifecycle });
  const held = deferred(), order = []; const jobs = Array.from({ length: 24 }, (_, n) => queue.run(async () => { if (!n) await held.promise; order.push(n); if (n === 8) throw Error('business'); return n; }));
  const settled = Promise.allSettled(jobs); await assert.rejects(queue.run(() => assert.fail('25th')), /busy/);
  lifecycle.beginClose(); await assert.rejects(queue.run(() => {}), /closing/); held.resolve(); await queue.drain();
  assert.deepEqual(order, Array.from({ length: 24 }, (_, n) => n)); assert.equal((await settled)[8].status, 'rejected'); assert.equal(queue.size, 0);
  lifecycle.run({ op: 'finishClose' }); assert.equal(lifecycle.snapshot().phase, 'closed'); assert.throws(() => lifecycle.run({ op: 'finish', ticket: '24' })); assert.equal(lifecycle.healthy, false);
});

test('JS and real WASM agree on generations, retry/jitter, deadlines, selection revision and dedup eviction', wasm, () => {
  const a = new JsLifecycleCore(), b = core(); const run = c => { const x = a.execute(c), y = b.execute(c); assert.deepEqual(y, x); return y; };
  run({ op: 'activate' }); run({ op: 'bridgeStart', hasIdentity: true, now: 0 }); let time = 0;
  const event = (event, now, jitter=499) => { const t = run({ op: 'snapshot' }).result.bridge; return run({ op:'bridgeEvent',generation:t.generation,attempt:t.attempt,event,now,jitter }); };
  for (const delay of [1000,2000,4000,8000,16000,30000,30000]) { const r = event('failed',time); const at = r.effects.find(e=>e.type==='armTimer').at; assert.equal(at-time,delay+499); time=at; event('retry',time); }
  event('prepared',time+1); event('open',time+2); event('heartbeat',time+25002); event('pong',time+25002); event('heartbeat',time+50002); event('heartbeat',time+90002); assert.equal(run({op:'snapshot'}).result.bridge.state,'connected');
  event('heartbeat',time+115002); assert.equal(run({op:'snapshot'}).result.bridge.state,'reconnecting');
  run({op:'bridgeStart',hasIdentity:true,now:200000});event('prepared',200001);event('open',200002);
  const t=run({op:'snapshot'}).result.bridge; const call=id=>run({op:'bridgeCall',generation:t.generation,attempt:t.attempt,id}).result;
  const ids=Array.from({length:1001},(_,n)=>`00000000-0000-0000-0000-${String(n).padStart(12,'0')}`);
  for(const id of ids) assert.equal(call(id),'execute'); assert.equal(call(ids[1]),'duplicate'); assert.equal(call(ids[0]),'execute');
  run({op:'bridgeStop'}); run({op:'bridgeStart',hasIdentity:true,now:300000}); event('prepared',300001);event('open',300002);
  const next=run({op:'snapshot'}).result.bridge;assert.equal(run({op:'bridgeCall',generation:next.generation,attempt:next.attempt,id:ids[0]}).result,'duplicate');
  run({op:'invalidateSelection'});run({op:'beginClose'});assert.equal(run({op:'permitEffect'}).result,false);
});

test('real Bridge cancels stalled network attempts, bounds retry resources/listeners and ignores old attempt callbacks', wasm, async () => {
  const lifecycle=new AgentLifecycle(core());lifecycle.run({op:'activate'});const clock=new Clock(), Socket=fakeWebSockets({autoOpen:false});
  let stall=true;const bridge=new Bridge(async()=>({}),{lifecycle,WebSocket:Socket,prepareNetwork:()=>stall?new Promise(()=>{}):Promise.resolve(),now:()=>clock.now,random:()=>0,setTimeout:clock.set,clearTimeout:clock.clear,fetch:async()=>Response.json({})});
  bridge.start(bridgeIdentity);
  for(let n=0;n<300;n++){clock.next();await tick();assert.ok(bridge.resourceCount<=1);assert.ok(getEventListeners(lifecycle.signal,'abort').length<=1);}
  stall=false;clock.next();await tick();clock.next();await tick();
  if(!Socket.instances.length){clock.next();await tick();}const old=Socket.instances.at(-1);assert.ok(old);clock.next();await tick();clock.next();await tick();
  const current=Socket.instances.at(-1);assert.notEqual(current,old);current.open();old.open();old.emit('error');old.emit('close');old.emit('message','pong');
  assert.equal(bridge.socket,current);assert.equal(bridge.state,'connected');bridge.stop();assert.equal(bridge.resourceCount,0);assert.equal(clock.timers.size,0);assert.equal(getEventListeners(lifecycle.signal,'abort').length,0);
});

test('Bridge result is sent only to original live attempt and old sockets cannot invoke work', wasm, async () => {
  const lifecycle=new AgentLifecycle(core());lifecycle.run({op:'activate'});const held=deferred();let calls=0;
  const options=fakeBridgeOptions();const bridge=new Bridge(async()=>{calls++;return held.promise;},{...options,lifecycle});bridge.start(bridgeIdentity);await until(()=>bridge.state==='connected');
  const old=bridge.socket,t=lifecycle.snapshot().bridge,raw=JSON.stringify({kind:'call',id:randomUUID(),tool:'read_file',args:{}});
  const pending=bridge.receive(raw,old,{generation:t.generation,attempt:t.attempt});bridge.start(bridgeIdentity);await until(()=>bridge.state==='connected');
  await bridge.receive(raw,old,{generation:t.generation,attempt:t.attempt});held.resolve({ok:true});await pending;assert.equal(calls,1);assert.equal(old.sent.length,0);assert.equal(bridge.socket.sent.length,0);bridge.stop();
});

test('malformed FIFO receipts and WASM traps freeze without losing confirmed action or pending resolvers', wasm, async () => {
  for(const mode of ['duplicate','drained','trap','malformed']) {
    const faulty=faultCore();let admitted=0;const lifecycle=new AgentLifecycle({execute(c){const r=faulty.state.execute(c);if(c.op==='admit'&&++admitted===2&&mode==='duplicate')return {result:{ticket:'1'},effects:[]};if(c.op==='finish'&&mode==='drained')return {result:null,effects:[{type:'drained'}]};return r;}});
    lifecycle.run({op:'activate'});const queue=new SerialQueue({lifecycle}),held=deferred();const first=queue.run(async()=>{await held.promise;return {written:true};});await tick();
    const second=queue.run(()=>assert.fail('frozen pending must not run'));const rejection=assert.rejects(second,/lifecycle/);
    if(['trap','malformed'].includes(mode))faulty.arm('finish',mode);held.resolve();assert.deepEqual(await first,{written:true});await rejection;await queue.drain();assert.equal(lifecycle.healthy,false);assert.equal(queue.size,0);await assert.rejects(queue.run(()=>{}),/lifecycle/);
  }
});

test('actual Rust controller close cancels ignored network/setup/enroll waits and late callbacks never restart', wasm, async t => {
  for(const route of ['network/set','enroll','setup/start'])await t.test(route,async t=>{
    const entered=deferred(),late=deferred();let sockets=0,browsers=0,requests=0;
    const Socket=class extends fakeWebSockets(){constructor(...args){super(...args);sockets++;}};
    const network={prepare(){entered.resolve();return late.promise;},status:()=>({}),close(){}};
    const f=await fixture(t,{beforeStart:async store=>{const saved=await store.load();await store.saveConfig({...saved.config,relay:bridgeIdentity.origin});},defaultRelay:bridgeIdentity.origin,network:route==='network/set'?undefined:network,
      networkOptions:{env:{},systemProxy:()=>{entered.resolve();return late.promise;},apply:()=>{requests++;},installTls:()=>{}},bridgeOptions:{WebSocket:Socket,fetch:async()=>{requests++;return Response.json({ok:true});}},openBrowser:async()=>{browsers++;},setupFetch:async()=>{requests++;return Response.json({name:'chat2local-relay',setupVersion:1,browserHandoff:true,selfService:true});}});
    const work=f.api(route,route==='network/set'?{mode:'auto'}:route==='enroll'?{origin:bridgeIdentity.origin,enrollmentToken:'a'.repeat(40)}:{});
    await entered.promise;const a=f.app.close(),b=f.app.close();assert.equal(a,b);await Promise.race([a,new Promise((_,reject)=>setTimeout(()=>reject(Error('close stalled')),1500))]);await work;
    late.resolve({proxy:''});await tick();assert.equal(sockets,0);assert.equal(browsers,0);assert.equal(requests,0);assert.equal((await f.store.load()).secrets.identity,undefined);
  });
});

test('authenticated fault restriction and shutdown remain available while ordinary writes stay frozen', wasm, async t => {
  const faulty=faultCore(),f=await fixture(t,{lifecycleCore:faulty.state});faulty.arm('admit');
  assert.equal((await f.api('root/add',{path:f.project,write:false})).status,503);assert.equal(f.app.lifecycle.healthy,false);
  assert.equal((await f.api('pause',{paused:true},false)).status,401);assert.equal((await f.api('pause',{paused:false})).status,503);
  assert.equal((await f.api('pause',{paused:true})).status,200);assert.equal((await f.store.load()).config.paused,true);
  assert.equal((await f.api('root/remove',{id:f.root.id})).status,200);assert.equal((await f.store.load()).config.roots.length,0);
  assert.equal((await f.api('disconnect',{})).status,200);assert.equal((await f.api('status')).status,200);
  assert.equal((await f.api('shutdown',{})).status,200);await until(()=>!f.app.server.listening);
});

test('fault restrictions serialize behind actual config I/O and cannot publish late permissive state', wasm, async t => {
  for (const failOld of [false, true]) await t.test(failOld ? 'old save rejects' : 'old save completes late', async t => {
    const f = await fixture(t), entered = deferred(), old = deferred(), restriction = deferred(), writes = [];
    const save = f.store.saveConfig.bind(f.store);
    f.store.saveConfig = async value => {
      writes.push(structuredClone(value));
      if (writes.length === 1) { entered.resolve(); await old.promise; }
      if (writes.length === 2) await restriction.promise;
      await save(value);
    };
    const ordinary = f.api('pause', { paused: false }); await entered.promise; f.app.lifecycle.poison();
    assert.equal((await ordinary).status, 503);
    let returned = false;
    const remove = f.api('root/remove', { id: f.root.id }).then(value => { returned = true; return value; });
    let restricted;
    for (let n = 0; n < 100; n++) { restricted = await (await f.api('status')).json(); if (!restricted.roots.length) break; await tick(); }
    assert.equal(restricted.roots.length, 0);
    const pause = f.api('pause', { paused: true }); await tick(); assert.equal(writes.length, 1); assert.equal(returned, false);
    if (failOld) old.reject(Error('old storage failure')); else old.resolve();
    await until(() => writes.length === 2); assert.equal(returned, false);
    const status = await (await f.api('status')).json(); assert.equal(status.paused, true); assert.equal(status.roots.length, 0);
    restriction.resolve(); assert.equal((await remove).status, 200); assert.equal((await pause).status, 200);
    assert.equal(writes.length, 3); assert.ok(writes.slice(1).every(value => value.paused && value.roots.length === 0));
    const saved = (await f.store.load()).config; assert.equal(saved.paused, true); assert.equal(saved.roots.length, 0);
  });
});

test('late vault completion cannot restore identity after disconnect and partial persistence never reports success', wasm, async t => {
  const f = await fixture(t), entered = deferred(), old = deferred(), snapshots = [];
  const save = f.store.saveSecrets.bind(f.store);
  f.store.saveSecrets = async value => { snapshots.push(structuredClone(value)); if (snapshots.length === 1) { entered.resolve(); await old.promise; } await save(value); };
  f.app.bridge.enroll = async () => bridgeIdentity;
  const enroll = f.api('enroll', { origin: bridgeIdentity.origin, enrollmentToken: 'a'.repeat(40) });
  await entered.promise; f.app.lifecycle.poison(); assert.equal((await enroll).status, 503);
  let returned = false; const disconnect = f.api('disconnect', {}).then(value => { returned = true; return value; });
  await tick(); assert.equal(returned, false); assert.equal(snapshots.length, 1); old.resolve();
  assert.equal((await disconnect).status, 200); assert.deepEqual(snapshots[1], {});
  assert.equal((await f.store.load()).secrets.identity, undefined); assert.equal((await (await f.api('status')).json()).mcpUrl, '');
  const configSave = f.store.saveConfig.bind(f.store); f.store.saveConfig = async () => { throw Error('second file failed'); };
  assert.equal((await f.api('disconnect', {})).status, 503); assert.equal((await (await f.api('status')).json()).paused, true);
  f.store.saveConfig = configSave; assert.equal((await f.api('pause', { paused: true })).status, 200);
});

test('pending storage reports bounded close uncertainty while ownership remains until actual completion', wasm, async t => {
  const f = await fixture(t), entered = deferred(), release = deferred(); let calls = 0;
  f.store.saveConfig = () => { calls++; entered.resolve(); return release.promise; };
  const ordinary = f.api('pause', { paused: false }); await entered.promise; f.app.lifecycle.poison();
  assert.equal((await ordinary).status, 503);
  const restricted = f.api('pause', { paused: true }).then(r => r.status, () => 'closed');
  const disconnect = f.api('disconnect', {}).then(r => r.status, () => 'closed');
  await tick(); assert.equal((await f.api('shutdown', {})).status, 200);
  const close = f.app.close(); assert.equal(close, f.app.close());
  await assert.rejects(close, error => error instanceof AggregateError && error.errors.some(e => e.code === 'EPERSISTENCE'));
  assert.ok([503, 'closed'].includes(await restricted)); assert.ok([503, 'closed'].includes(await disconnect)); assert.equal(calls, 1); assert.equal(f.app.server.listening, true); release.resolve(); await until(() => !f.app.server.listening);
});

test('fault persistence resources are bounded independently of disconnected callers and reject ordinary saves', wasm, async () => {
  const lifecycle = new AgentLifecycle(core()); lifecycle.run({ op: 'activate' });
  let calls = 0; const held = deferred(), config = { roots: [], accountRoots: [], paused: false };
  const state = new AgentState({ saveConfig: async () => { calls++; await held.promise; }, saveSecrets: async () => { calls++; } }, { config, secrets: {} }, lifecycle);
  lifecycle.poison(); await assert.rejects(state.saveConfig(config)); await assert.rejects(state.saveSecrets({ identity: bridgeIdentity })); assert.equal(calls, 0);
  const work = Array.from({ length: 24 }, () => state.restrictPolicy(config, { cancelPending() {} }).catch(error => error));
  assert.equal(state.pendingSaves, 24); assert.throws(() => state.restrictPolicy(config, { cancelPending() {} }), /busy/);
  await tick(); assert.equal(calls, 1); lifecycle.beginClose(); await Promise.all(work); assert.equal(state.pendingSaves, 24);
  assert.throws(() => state.persistDisconnect(), /closing/); held.resolve(); await until(() => state.pendingSaves === 0); assert.equal(calls, 24); assert.equal(state.config.paused, true);
});

test('close before late vault completion keeps ordered restrictions durable without reviving sockets or identity', wasm, async t => {
  const f = await fixture(t), entered = deferred(), old = deferred(); let writes = 0;
  const save = f.store.saveSecrets.bind(f.store);
  f.store.saveSecrets = async value => { writes++; if (writes === 1) { entered.resolve(); await old.promise; } await save(value); };
  f.app.bridge.enroll = async () => bridgeIdentity;
  const enrollment = f.api('enroll', { origin: bridgeIdentity.origin, enrollmentToken: 'a'.repeat(40) });
  await entered.promise; f.app.lifecycle.poison(); assert.equal((await enrollment).status, 503);
  const disconnect = f.api('disconnect', {}).then(r => r.status, () => 'closed');
  // Prove disconnect reached its local-first mutation and enqueued persistence before close.
  // A fixed20ms delay can close admission before fetch delivers the request under load.
  await until(() => f.app.files.getPolicy().remoteUseConfirmed === false);
  await assert.rejects(f.app.close(), /cleanup/); assert.ok([503, 'closed'].includes(await disconnect));
  old.resolve(); await until(() => writes === 2);
  await until(() => !f.app.server.listening);
  const saved = await f.store.load(); assert.equal(saved.secrets.identity, undefined); assert.equal(saved.config.paused, true);
  assert.equal(f.app.bridge.identity, undefined); assert.equal(f.app.bridge.resourceCount, 0); assert.equal(f.app.server.listening, false);
});

test('disconnect remote revocation that ignores cancellation cannot hold controller drain or start a late fetch', wasm, async t => {
  const f = await fixture(t, { beforeStart: store => store.saveSecrets({ identity: bridgeIdentity }) });
  const entered = deferred(), late = deferred(); let requests = 0;
  f.app.bridge.prepareNetwork = () => { entered.resolve(); return late.promise; };
  f.app.bridge.fetch = async () => { requests++; return Response.json({ ok: true }); };
  const disconnect = f.api('disconnect', {}); await entered.promise;
  const close = f.app.close(); await Promise.race([close, new Promise((_, reject) => setTimeout(() => reject(Error('Revocation blocked close')), 1500))]);
  const response = await (await disconnect).json(); assert.equal(response.ok, true); assert.equal(response.remoteRevoked, false);
  late.resolve(); await tick(); assert.equal(requests, 0); assert.equal((await f.store.load()).secrets.identity, undefined);
});

test('actual setup metadata, enrollment and browser-handoff callbacks cannot revive a closed controller', wasm, async t => {
  for(const stage of ['/setup-info','/enroll-device','/browser-handoff'])await t.test(stage,async t=>{
    const entered=deferred(),late=deferred();let browsers=0;const calls=[];
    const response=url=>url.endsWith('/setup-info')?Response.json({name:'chat2local-relay',setupVersion:1,browserHandoff:true,selfService:true,installUrl:'https://chatgpt.com/plugins/lifecycle-fixture'}):url.endsWith('/enroll-device')?Response.json({ok:true}):Response.json({secret:'d'.repeat(64),expiresAt:Date.now()+10000});
    const f=await fixture(t,{defaultRelay:bridgeIdentity.origin,network:{prepare:async()=>{},status:()=>({}),close(){}},openBrowser:async()=>{browsers++;},setupFetch:async url=>{calls.push(url);if(url.endsWith(stage)){entered.resolve();return late.promise;}return response(url);}});
    const pending=f.api('setup/start',{});await entered.promise;const count=calls.length;const a=f.app.close();assert.equal(a,f.app.close());await a;await pending;
    late.resolve(response(stage));await tick();assert.equal(browsers,0);assert.equal(calls.length,count);assert.equal(f.app.bridge.state,'disconnected');
    const saved=await f.store.load();if(stage!='/browser-handoff')assert.equal(saved.secrets.identity,undefined);if(stage==='/enroll-device')assert.ok(saved.secrets.enrollmentPending);
  });
});

test('actual HTTP admitted actions drain in order during close and cannot start later network effects', wasm, async t => {
  const f=await fixture(t),entered=deferred(),release=deferred(),audit=f.app.files.audit.bind(f.app.files);let starts=0;
  f.app.files.audit=async(action,details)=>{if(action==='written'){entered.resolve();await release.promise;}return audit(action,details);};
  const write=f.app.bridge.invoke('write_file',{rootId:f.root.id,path:'drain.txt',expectedHash:null,content:'one'});await entered.promise;
  const next=f.api('enroll',{origin:bridgeIdentity.origin,enrollmentToken:'a'.repeat(40)});await until(()=>f.app.lifecycle.snapshot().queueCount===2);
  f.app.bridge.enroll=async()=>{starts++;assert.fail('Closing forbids new enrollment effects');};
  let closed=false;const closing=f.app.close().then(()=>{closed=true;});await tick();assert.equal(closed,false);release.resolve();assert.equal((await write).status,'written');assert.equal((await next).status,503);await closing;assert.equal(starts,0);assert.equal(f.app.lifecycle.snapshot().queueCount,0);
});

test('bridgeEvent trap cleans resources and a late system-proxy result cannot apply after fault', wasm, async t => {
  const faulty=faultCore(),entered=deferred(),late=deferred();let applied=0;
  const f=await fixture(t,{lifecycleCore:faulty.state,beforeStart:async store=>{const saved=await store.load();await store.saveConfig({...saved.config,relay:bridgeIdentity.origin});},networkOptions:{env:{},systemProxy:()=>{entered.resolve();return late.promise;},apply:()=>{applied++;}}});
  const pending=f.api('network/set',{mode:'auto'});await entered.promise;faulty.arm('bridgeEvent');
  assert.throws(()=>f.app.lifecycle.run({op:'bridgeEvent',generation:'0',attempt:'0',event:'close',now:Date.now(),jitter:0}));
  assert.equal((await pending).status,503);late.resolve({proxy:''});await tick();assert.equal(applied,0);assert.equal(f.app.bridge.resourceCount,0);assert.equal((await f.api('pause',{paused:true})).status,200);
});

test('close shares cleanup completion and a failure does not skip later resources; failed startup leaves the port free', wasm, async t => {
  const f=await fixture(t,{network:{prepare:async()=>{},status:()=>({}),close(){throw Error('fixture network close');}}});
  const a=f.app.close(),b=f.app.close();assert.equal(a,b);await assert.rejects(a,/cleanup/);assert.equal(f.app.server.listening,false);assert.equal(f.app.lifecycle.snapshot().phase,'closed');
  const base=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-lifecycle-start-'));t.after(()=>fs.rm(base,{recursive:true,force:true}));const store=new Store(base);store.saveSession=async()=>{throw Error('session fault');};let cleaned=0;
  await assert.rejects(startController({port:0,store,lifecycleBackend:'rust',lifecycleModulePath:modulePath,network:{status:()=>({}),close(){cleaned++;}}}),/session fault/);assert.equal(cleaned,1);
  const faulty=faultCore();faulty.arm('activate');await assert.rejects(startController({port:0,store:new Store(path.join(base,'activate')),lifecycleCore:faulty.state,network:{status:()=>({}),close(){cleaned++;}}}),/lifecycle/);assert.ok(cleaned>=2);
});

test('two actual controllers own independent Rust state and a fault cannot freeze its peer', wasm, async t => {
  const a=await fixture(t),b=await fixture(t);a.app.lifecycle.poison();assert.equal((await a.api('status')).status,200);assert.equal((await b.api('pause',{paused:true})).status,200);assert.equal(b.app.lifecycle.healthy,true);assert.equal(b.app.lifecycle.snapshot().phase,'running');
});

async function nativeController(t, extra={}) {
  const f=await fixture(t,{terminalBackend:'rust',terminalExecutable,terminalStoreBackend:'rust',terminalStoreExecutable,...extra});
  // Use a synthetic authenticated relay identity and local terminal permission.
  const config=(await f.store.load()).config,access={version:1,connectionId:'a'.repeat(32),deviceId:bridgeIdentity.deviceId,resource:bridgeIdentity.origin+'/mcp',roots:[{rootId:f.root.id,mode:'direct'}],scopes:['files:read','files:write','terminal:execute']};
  await f.app.close();f.store=new Store(f.store.directory);await f.store.saveSecrets({identity:bridgeIdentity});await f.store.saveConfig({...config,remoteUseConfirmed:true,terminalGrants:[{connectionId:access.connectionId,resource:access.resource,rootId:f.root.id,enabled:true}]});
  const app=await startController({port:0,store:f.store,lifecycleBackend:'rust',lifecycleModulePath:modulePath,bridgeOptions:fakeBridgeOptions(),terminalBackend:'rust',terminalExecutable,terminalStoreBackend:'rust',terminalStoreExecutable,...extra});t.after(()=>app.close().catch(()=>{}));
  f.app=app;f.api=(route,value)=>fetch(`${app.origin}/api/${route}`,{method:value===undefined?'GET':'POST',headers:{Origin:app.origin,'X-Chat2Local-Token':app.token,'Content-Type':'application/json'},...(value===undefined?{}:{body:JSON.stringify(value)})});return {...f,access};
}

test('actual Rust controller composes native execution and journal; STARTED releases FIFO and pause/close supervise the tree', native, async t => {
  const f=await nativeController(t);const args={rootId:f.root.id,requestId:randomUUID(),command:"Write-Output 'lifecycle-native'; Start-Sleep -Seconds 20",timeoutMs:30000};
  const started=await f.app.bridge.invoke('terminal_execute',args,undefined,f.access);assert.equal(started.status,'running');
  assert.equal((await (await f.api('status')).json()).terminalJobsRunning,1);assert.equal((await f.api('pause',{paused:true})).status,200);
  await f.app.close();const envelope=JSON.parse(await fs.readFile(path.join(f.store.directory,'terminal','terminal-'+args.requestId+'.json'),'utf8'));assert.equal(envelope.format,'windows-dpapi-v1');
});

test('actual native READY sees lifecycle fault before RUN; an unconfirmed native helper remains busy in controller status', native, async t => {
  for(const stage of ['ready','started'])await t.test(stage,async t=>{
    let app, child, entered=deferred();
    const f=await nativeController(t,{terminalRunnerFactory:context=>new RustTerminalProcessRunner({...context,executable:terminalExecutable,spawnHelper:(...args)=>{
      child=spawn(...args);let received='';child.stdout.prependListener('data',chunk=>{received+=chunk.toString();if(stage==='ready'&&received.includes('"kind":"ready"')){app.lifecycle.poison();entered.resolve();}});return child;
    }})});app=f.app;
    const requestId=randomUUID(),args={rootId:f.root.id,requestId,command:"Add-Content -LiteralPath 'run-once.txt' -Value one; Start-Sleep -Seconds 20",timeoutMs:30000};
    const result=await app.bridge.invoke('terminal_execute',args,undefined,f.access);
    if(stage==='ready'){await entered.promise;assert.equal(existsSync(path.join(f.project,'run-once.txt')),false);assert.notEqual(result.status,'running');}
    else {assert.equal(result.status,'running');child.kill();await until(()=>child.exitCode!==null||child.signalCode!==null);await new Promise(resolve=>setTimeout(resolve,80));assert.equal((await (await f.api('status')).json()).terminalJobsRunning,1);}
    await app.close();
  });
});

test('finish trap after native STARTED preserves its confirmed receipt and closes native resources', native, async t => {
  let faulty;
  const f=await nativeController(t,{terminalRunnerFactory:context=>{const runner=new RustTerminalProcessRunner({...context,executable:terminalExecutable});const start=runner.start.bind(runner);runner.start=async args=>{const result=await start(args);faulty.arm('finish');return result;};return runner;}});
  // The real instance is wrapped only at the trusted composition boundary.
  await f.app.close();faulty=faultCore();
  const app=await startController({port:0,store:f.store,lifecycleCore:faulty.state,bridgeOptions:fakeBridgeOptions(),terminalStoreBackend:'rust',terminalStoreExecutable,
    terminalRunnerFactory:context=>{const runner=new RustTerminalProcessRunner({...context,executable:terminalExecutable});const start=runner.start.bind(runner);runner.start=async args=>{const result=await start(args);faulty.arm('finish');return result;};return runner;}});t.after(()=>app.close().catch(()=>{}));
  const result=await app.bridge.invoke('terminal_execute',{rootId:f.root.id,requestId:randomUUID(),command:'Start-Sleep -Seconds 20',timeoutMs:30000},undefined,f.access);
  assert.equal(result.status,'running');assert.equal(app.lifecycle.healthy,false);await app.close();
});

test('finish trap after actual write preserves its receipt; fault at actual native READY refuses commit', native, async t => {
  for(const stage of ['finish','ready'])await t.test(stage,async t=>{
    const faulty=faultCore(),f=await fixture(t,{lifecycleCore:faulty.state,writeBackend:'rust',writerExecutable});
    if(stage==='finish'){const audit=f.app.files.audit.bind(f.app.files);f.app.files.audit=async(action,details)=>{await audit(action,details);if(action==='written')faulty.arm('finish');};}
    else f.app.files.writer.writerBackend=new RustWriterBackend({executable:writerExecutable,spawnProcess:(...args)=>{const child=spawn(...args);let received='';child.stdout.prependListener('data',chunk=>{received+=chunk.toString();if(received.includes('"type":"ready"'))f.app.lifecycle.poison();});return child;}});
    const result=await f.app.bridge.invoke('write_file',{rootId:f.root.id,path:'native.txt',expectedHash:null,content:'confirmed'});
    if(stage==='finish'){assert.equal(result.status,'written');assert.equal(await fs.readFile(path.join(f.project,'native.txt'),'utf8'),'confirmed');}
    else {assert.equal(existsSync(path.join(f.project,'native.txt')),false);assert.notEqual(result.status,'written');}
    assert.equal(f.app.lifecycle.healthy,false);assert.equal((await f.api('pause',{paused:true})).status,200);
  });
});
