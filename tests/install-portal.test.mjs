import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { InstallPortal } from '../src/relay/install-portal.mjs';
import { PrivateInstance } from '../src/relay/private-instance.mjs';
import { AccountDirectory } from '../src/relay/account-directory.mjs';
import { sha256 } from '../src/shared/protocol.mjs';
import { renderInstanceInstaller } from '../scripts/build-install-release.mjs';
import { VERSION } from '../src/shared/protocol.mjs';

const secret = () => randomBytes(32).toString('hex');
class Storage {
  constructor() { this.data = new Map(); this.tail = Promise.resolve(); }
  async get(k) { return structuredClone(this.data.get(k)); }
  async put(k,v) { return this.transaction(tx => tx.put(k,v)); }
  async delete(k) { return this.transaction(tx => tx.delete(k)); }
  transaction(fn) { const work = this.tail.then(async () => { const next = structuredClone(this.data); const tx = { get: async k => structuredClone(next.get(k)), put: async (k,v) => next.set(k,structuredClone(v)), delete: async k => next.delete(k), list: async ({prefix,limit}) => new Map([...next].filter(([k]) => k.startsWith(prefix)).slice(0,limit)) }; const result = await fn(tx); this.data = next; return result; }); this.tail = work.catch(() => {}); return work; }
}
async function fixture() {
  let now = Date.now(); const storage = new Storage(), resource = 'https://my-instance.example/mcp';
  const portal = new InstallPortal(storage, resource, secret(), () => now), instance = new PrivateInstance(storage, resource, () => now);
  const authRequest = { clientId: 'original', scope: ['files:read','files:write'], redirectUri: 'https://client.example/callback', state: secret() };
  const invite = await instance.createInvitation({ purpose: 'connect' }), flow = await instance.makeFlow({ authRequest, clientName: 'Original plugin' });
  const device = { deviceId: 'a'.repeat(32), epoch: secret(), keyHash: secret() }, deviceSession = secret();
  const native = (action,input={}) => instance.native({ action, flowId:flow.flowId, secret:action==='start'?flow.bootstrap:deviceSession, device,input, invitation:invite.invitation });
  await native('start',{sessionSecret:deviceSession}); const intent=await native('prepare',{roots:[{rootId:'kept-root',mode:'direct'}],policyDigest:secret()});
  await native('confirm',{snapshotDigest:intent.snapshotDigest}); const activated=await native('activate',{snapshotDigest:intent.snapshotDigest});
  const password='Correct private installer password 9437'; await portal.configure({password});
  const login=await portal.login({password,network:secret()});
  const id=randomBytes(16).toString('hex'), claim=secret(), browser=secret();
  await portal.start({id,claimHash:await sha256(claim),browserHash:await sha256(browser),name:'New Mac (fixture)'});
  return {storage,portal,instance,password,session:login.session,id,claim,browser,grant:activated.grant,tick:ms=>{now+=ms}};
}
test('installer password is owner-configured once, peppered, limited, and not a file-access credential', async()=>{
  const f=await fixture();
  assert.equal((await f.portal.configured()).configured,true);
  await assert.rejects(()=>f.portal.configure({password:f.password}),/already|已经/);
  assert.ok(!JSON.stringify([...f.storage.data]).includes(f.password));
  await assert.rejects(()=>f.portal.authorize({id:f.id,browser:f.browser,session:secret(),connectionId:null}),/登录|login/);
  for(let i=0;i<5;i++)await assert.rejects(()=>f.portal.login({password:'Wrong but long enough password',network:'f'.repeat(64)}));
  await assert.rejects(()=>f.portal.login({password:f.password,network:'f'.repeat(64)}),e=>e.status===429);
});
test('new-machine proof and browser proof are separate; no invitation/file/connection expansion before login',async()=>{
  const f=await fixture();
  assert.deepEqual(await f.portal.claim({id:f.id,secret:f.claim}),{waiting:true});
  const context=await f.portal.context({id:f.id,browser:f.browser,session:null}); assert.equal(context.authenticated,false); assert.deepEqual(context.connections,[]);
  await assert.rejects(()=>f.portal.claim({id:f.id,secret:f.browser}),/another computer/);
  await assert.rejects(()=>f.portal.context({id:f.id,browser:f.claim,session:f.session}),/another computer/);
  await assert.rejects(async()=>f.portal.start({id:f.id,claimHash:await sha256(secret()),browserHash:await sha256(f.browser),name:'New Mac (fixture)'}),/changed/);
});
test('authorized installer retries reuse one invitation; same old reference remains unchanged until folder consent',async()=>{
  const f=await fixture();
  await Promise.all([f.portal.authorize({id:f.id,browser:f.browser,session:f.session,connectionId:null}),f.portal.authorize({id:f.id,browser:f.browser,session:f.session,connectionId:null})]);
  const a=await f.portal.claim({id:f.id,secret:f.claim}), b=await f.portal.claim({id:f.id,secret:f.claim}); assert.equal(a.inviteUrl,b.inviteUrl); assert.equal(a.expiresAt,b.expiresAt);
  const resolved=await new AccountDirectory(f.storage).execute({action:'resolve',grant:f.grant}); assert.equal(resolved.devices.length,1); assert.deepEqual(resolved.devices[0].roots,[{rootId:'kept-root',mode:'direct'}]);
  assert.equal((await f.portal.context({id:f.id,browser:f.browser,session:f.session})).nextUrl,undefined);
  await f.portal.ready({id:f.id,secret:f.claim}); assert.equal((await f.portal.context({id:f.id,browser:f.browser,session:f.session})).nextUrl,a.inviteUrl);
  await f.portal.logout({session:f.session}); assert.equal((await f.portal.context({id:f.id,browser:f.browser,session:f.session})).nextUrl,undefined);
});
test('expired tickets and revoked invitations/connections cannot be recreated by installer retry',async()=>{
  const f=await fixture(); await f.portal.authorize({id:f.id,browser:f.browser,session:f.session,connectionId:null});
  await f.instance.revokeInvitation({invitationId:f.id}); await assert.rejects(()=>f.portal.claim({id:f.id,secret:f.claim}),/revoked/);
  const g=await fixture(); await g.portal.authorize({id:g.id,browser:g.browser,session:g.session,connectionId:null}); const owner=await g.instance.owner();
  await new AccountDirectory(g.storage).execute({action:'revoke-connection',actor:owner.actor,input:{connectionId:g.grant.connectionId}});
  await assert.rejects(()=>g.portal.claim({id:g.id,secret:g.claim}),/unavailable/);
  f.tick(601000); await assert.rejects(()=>f.portal.ready({id:f.id,secret:f.claim}),/expired/);
});
test('public installer has pinned per-chunk and whole-archive checks and no credentials or runtime downgrade',()=>{
  const records=['darwin-arm64','darwin-x64'].map(target=>({target,version:VERSION,packageName:'Chat2Local-macOS-'+target.split('-')[1],file:'Chat2Local-macOS-'+target.split('-')[1]+'.tar.gz',sha256:'a'.repeat(64),parts:[{path:'/releases/'+VERSION+'/'+target+'/'+'a'.repeat(64)+'.part00',sha256:'b'.repeat(64),bytes:1024}]}));
  const script=renderInstanceInstaller('https://my-instance.example',records);
  assert.match(script,/macOS 13.5/); assert.match(script,/hw.optional.arm64/); assert.match(script,/Release chunk verification failed/); assert.match(script,/SHA-256 mismatch/);
  assert.match(script,/install-from-instance\.mjs" --install 'https:\/\/my-instance\.example'/); assert.doesNotMatch(script,/ENROLLMENT_KEY|secret=|invitation=|sudo |curl .*http:\/\//);
  assert.throws(()=>renderInstanceInstaller('https://my-instance.example',records.map(r=>({...r,parts:[{...r.parts[0],path:'/../vault.json'}]}))));
});
