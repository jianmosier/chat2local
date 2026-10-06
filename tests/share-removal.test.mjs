import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { ShareRemoval, overlappingPaths } from '../src/agent/share-removal.mjs';
import { terminalPermission } from '../src/shared/terminal-permission.mjs';
import { annotateCoverage, directoryContains } from '../src/shared/share-tree.mjs';
import { PrivateInstance } from '../src/relay/private-instance.mjs';
import { AccountDirectory } from '../src/relay/account-directory.mjs';
import { FileService } from '../src/agent/files.mjs';

class Storage {
  constructor() { this.data = new Map(); this.tail = Promise.resolve(); }
  async get(k) { return structuredClone(this.data.get(k)); }
  async put(k,v) { return this.transaction(tx => tx.put(k,v)); }
  transaction(fn) { const work = this.tail.then(async () => {
    const data = structuredClone(this.data);
    const tx = { get: async k => structuredClone(data.get(k)), put: async (k,v) => data.set(k,structuredClone(v)), delete: async k => data.delete(k), list: async ({prefix,limit}) => new Map([...data].filter(([k]) => k.startsWith(prefix)).slice(0,limit)) };
    const result = await fn(tx); this.data = data; return structuredClone(result);
  }); this.tail = work.catch(()=>{}); return work; }
}
async function fixture(t) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-remove-')); t.after(()=>fs.rm(base,{recursive:true,force:true}));
  const project = path.join(base,'code'), child = path.join(project,'project'), sibling=path.join(base,'other');
  await fs.mkdir(child,{recursive:true}); await fs.mkdir(sibling); await fs.writeFile(path.join(child,'keep.txt'),'keep me');
  const rootIds = [randomUUID(),randomUUID(),randomUUID()];
  let config = { version:1, paused:false, roots: [project,child,sibling].map((p,i)=>({id:rootIds[i],path:p,label:path.basename(p),write:true,writeMode:'direct'})), terminalGrants:[], accountPolicyRevision:0 };
  const device = { deviceId:'a'.repeat(32),epoch:'b'.repeat(64),keyHash:'c'.repeat(64) }, other = {deviceId:'d'.repeat(32),epoch:'e'.repeat(64)};
  const connectionId='f'.repeat(32), origin='https://private.example.test', storage=new Storage(), instance=new PrivateInstance(storage,origin+'/mcp');
  const owner=await instance.owner(); const scopes=['files:read','files:write','terminal:execute'];
  const connection={id:connectionId,accountId:owner.accountId,clientId:'original',resource:origin+'/mcp',epoch:'9'.repeat(64),scopes,revision:1,revoked:false,policy:'explicit-shares',shares:[...rootIds.map(rootId=>({rootId,mode:'direct',deviceId:device.deviceId,deviceEpoch:device.epoch,intentId:'8'.repeat(32)})),{rootId:randomUUID(),mode:'direct',deviceId:other.deviceId,deviceEpoch:other.epoch,intentId:'7'.repeat(32)}]};
  await storage.put('device:'+device.deviceId,{kind:'private-instance',keyHash:device.keyHash});
  for(const d of [device,other])await storage.put('accounts:v3:device-owner:'+d.deviceId,{accountId:owner.accountId,epoch:d.epoch});
  await storage.put('accounts:v3:connection-index:'+owner.accountId,[connectionId]); await storage.put('accounts:v3:connection:'+connectionId,connection);
  await storage.put('instance:v1:client:'+connectionId,{clientName:'ChatGPT',redirectUri:'https://chatgpt.com/callback'});
  config.terminalGrants=rootIds.map(rootId=>({connectionId,rootId,resource:origin+'/mcp',enabled:true}));
  let network='ok', stops=[];
  const management={ connections:async()=>{
    const result=await instance.manage({action:'connections',device,input:{}});
    return {connections:result.connections.map(c=>({...c,roots:c.roots.map(r=>{const local=config.roots.find(l=>l.id===r.rootId);return {...r,path:local?.path,label:local?.label,locallyPresent:Boolean(local)};})}))};
  }, managementCall:async(action,input)=>{ if(network==='down')throw Error('offline');const result=await instance.manage({action,device,input});if(network==='lost'){network='ok';throw Error('response lost');}return result;} };
  let tail=Promise.resolve(); const serial=fn=>{const result=tail.then(fn);tail=result.catch(()=>{});return result;};
  const remove=new ShareRemoval({management,getConfig:()=>config,getIdentity:()=>({deviceId:device.deviceId,origin}),serial,changePolicy:async c=>{config={...c,accountPolicyRevision:config.accountPolicyRevision+1};},saveConfig:async c=>{config=c;},stopJobs:async(c,ids)=>{stops.push([c,ids]);}});
  return {base,child,rootIds,device,other,connectionId,storage,instance,remove,getConfig:()=>config,change:fn=>{config=fn(config);},network:value=>{network=value;},stops,grant:new AccountDirectory(storage).grant(connection),management};
}
const confirm = p=>({requestId:p.requestId,snapshotDigest:p.snapshotDigest,confirmation:'remove-shares-keep-files-v1'});
test('terminal status has identical meaning locally and remotely; missing OAuth does not erase local permission',()=>{
  const args={grants:[{connectionId:'c',rootId:'r',resource:'https://private.example.test/mcp',enabled:true}],connectionId:'c',rootId:'r',resource:'https://private.example.test/mcp',mode:'direct',scopes:['files:read','files:write']};
  const p=terminalPermission(args);assert.equal(p.terminalLocalEnabled,true);assert.equal(p.terminalAllowed,false);assert.equal(p.terminalScopeGranted,false);
  assert.equal(terminalPermission({...args,scopes:[...args.scopes,'terminal:execute']}).terminalAllowed,true);
});
test('removing a nested folder previews its covering parent and revokes files and terminal without deleting data',async t=>{
  const f=await fixture(t), before=JSON.stringify(f.getConfig());
  const p=await f.remove.preview({connectionId:f.connectionId,rootId:f.rootIds[1]});
  assert.equal(p.includesOverlaps,true);assert.deepEqual(p.folders.map(r=>r.rootId).sort(),f.rootIds.slice(0,2).sort());assert.equal(JSON.stringify(f.getConfig()),before);
  const result=await f.remove.execute('remove-confirm',confirm(p));assert.equal(result.cloudSynced,true);
  assert.deepEqual(f.getConfig().roots.map(r=>r.id),[f.rootIds[2]]);assert.deepEqual(f.getConfig().terminalGrants.map(g=>g.rootId),[f.rootIds[2]]);assert.equal(f.stops.length,1);
  const resolved=await new AccountDirectory(f.storage).execute({action:'resolve',grant:f.grant});
  assert.deepEqual(resolved.devices.find(d=>d.deviceId===f.device.deviceId).roots.map(r=>r.rootId),[f.rootIds[2]]);assert.ok(resolved.devices.some(d=>d.deviceId===f.other.deviceId));
  assert.equal(await fs.readFile(path.join(f.child,'keep.txt'),'utf8'),'keep me');
  const files=new FileService(f.getConfig,path.join(f.base,'state'),()=>({deviceId:f.device.deviceId}));
  await assert.rejects(()=>files.invoke('read_file',{rootId:f.rootIds[0],path:'project/keep.txt'}));
});
test('removing a parent keeps independently granted descendants with the same IDs and data', async t => {
  const f = await fixture(t);
  const p = await f.remove.preview({ connectionId: f.connectionId, rootId: f.rootIds[0] });
  assert.deepEqual(p.folders.map(r => r.rootId), [f.rootIds[0]]);
  assert.deepEqual(p.retainedChildren.map(r => r.rootId), [f.rootIds[1]]);
  assert.equal(p.includesOverlaps, false);
  assert.equal((await f.remove.execute('remove-confirm', confirm(p))).cloudSynced, true);
  assert.deepEqual(f.getConfig().roots.map(r => r.id), f.rootIds.slice(1));
  assert.deepEqual(f.getConfig().terminalGrants.map(r => r.rootId), f.rootIds.slice(1));
  const files = new FileService(f.getConfig, path.join(f.base,'state'), () => ({ deviceId:f.device.deviceId }));
  assert.equal((await files.invoke('read_file', { rootId:f.rootIds[1], path:'keep.txt' })).content, 'keep me');
  const resolved = await new AccountDirectory(f.storage).execute({ action:'resolve', grant:f.grant });
  assert.deepEqual(resolved.devices.find(d=>d.deviceId===f.device.deviceId).roots.map(r=>r.rootId), f.rootIds.slice(1));
});
test('coverage folds only dominated rights and retains every explicit grant; paths compare segments', () => {
  const base = { mode:'direct', locallyPresent:true, terminalLocalEnabled:false };
  const roots = [{...base,rootId:'parent',path:'E:\\Code'}, {...base,rootId:'child',path:'E:\\Code\\App'}, {...base,rootId:'other',path:'E:\\Code2'}];
  const folded = annotateCoverage(roots,'win32');
  assert.equal(folded.length,3); assert.equal(folded[1].coveredBy,'parent'); assert.equal(folded[2].coveredBy,null);
  assert.equal(annotateCoverage([{...roots[0],mode:'read-only'}, roots[1]],'win32')[1].coveredBy,null);
  assert.equal(annotateCoverage([roots[0], {...roots[1],terminalLocalEnabled:true}],'win32')[1].coveredBy,null);
  assert.equal(annotateCoverage([roots[1]],'win32')[0].coveredBy,null);
  assert.equal(directoryContains('E:\\CODE','e:\\code\\app','win32'),true);
  assert.equal(directoryContains('/Code','/code/app','darwin'),false);
  assert.equal(directoryContains('/code','/code2','linux'),false);
});
test('lost cloud response keeps local revocation and retries the SAME request without restoring permissions',async t=>{
  const f=await fixture(t);const p=await f.remove.preview({connectionId:f.connectionId,rootId:f.rootIds[1]});f.network('lost');
  const result=await f.remove.execute('remove-confirm',confirm(p));assert.equal(result.localRevoked,true);assert.equal(result.cloudSynced,false);assert.equal(f.getConfig().roots.length,1);
  await f.remove.flush();assert.equal(f.getConfig().shareRemovals.length,0);assert.equal(f.stops.length,1);
  assert.equal(await fs.readFile(path.join(f.child,'keep.txt'),'utf8'),'keep me');
});
test('offline revocation takes effect locally and synchronizes later; stale consent cannot remove changed scopes',async t=>{
  const f=await fixture(t);const p=await f.remove.preview({connectionId:f.connectionId,rootId:f.rootIds[1]});f.network('down');
  assert.equal((await f.remove.execute('remove-confirm',confirm(p))).cloudSynced,false);assert.equal(f.getConfig().roots.length,1);
  f.network('ok');assert.equal((await f.remove.flush()).pending.length,0);
  const q=await f.remove.preview({connectionId:f.connectionId,rootId:f.rootIds[2]});f.change(c=>({...c,accountPolicyRevision:c.accountPolicyRevision+1}));
  await assert.rejects(()=>f.remove.execute('remove-confirm',confirm(q)),/变化/);assert.equal(f.getConfig().roots.length,1);
});
test('forged native identity and changed removal request are rejected; the last root can be removed',async t=>{
  const f=await fixture(t);const input={requestId:'1'.repeat(32),connectionId:f.connectionId,rootIds:f.rootIds,expectedRevision:1};
  await assert.rejects(()=>f.instance.manage({action:'remove',device:{...f.device,keyHash:'0'.repeat(64)},input}),/registered/);
  assert.equal((await f.instance.manage({action:'remove',device:f.device,input})).removed,true);
  assert.equal((await f.instance.manage({action:'remove',device:f.device,input})).removed,true);
  const retained = await f.instance.manage({action:'connections',device:f.device,input:{}});
  assert.equal(retained.connections.length,1); assert.equal(retained.connections[0].roots.length,0);
  await assert.rejects(()=>f.instance.manage({action:'remove',device:f.device,input:{...input,rootIds:[f.rootIds[0]]}}),/changed/);
});
