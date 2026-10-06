import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { deploymentPlan } from '../scripts/setup-selfhost.mjs';
import { inspectPublicText } from '../scripts/build-public.mjs';
import { checkSource } from '../scripts/check-source.mjs';
import { DEFAULT_RELAY } from '../src/shared/setup.mjs';
import { SetupManager } from '../src/agent/setup.mjs';
import { publicBootstrap } from '../src/shared/public-bootstrap.mjs';
import { assertUpgradeIdle, prepareUpgrade } from '../scripts/upgrade-session.mjs';
import { installManagementEntry } from '../scripts/install-portable.mjs';

test('unconfigured public client makes no request to an author instance', async () => {
  assert.equal(DEFAULT_RELAY, ''); let requests = 0;
  const setup = new SetupManager({ identity: () => null, fetch: () => { requests++; throw Error('unexpected network'); }, prepareNetwork: async () => {} });
  assert.equal((await setup.inspect()).code, 'INSTANCE_REQUIRED'); assert.equal(requests, 0);
});
test('self-host setup derives every deployment identifier from the new owner, with no personal defaults', () => {
  const config = deploymentPlan({ accountId: 'a'.repeat(32), namespaceId: 'b'.repeat(32), name: 'chat2local-123456789abc', subdomain: 'owner-fixture' });
  assert.equal(config.account_id, 'a'.repeat(32)); assert.equal(config.kv_namespaces[0].id, 'b'.repeat(32));
  assert.equal(config.vars.PUBLIC_ORIGIN, 'https://chat2local-123456789abc.owner-fixture.workers.dev');
  assert.equal(config.vars.PRIVATE_INSTANCE, 'true'); assert.equal(config.vars.ACCOUNT_CONNECTIONS, undefined);
  assert.equal(config.vars.ENROLLMENT_KEY, undefined);
  assert.throws(() => deploymentPlan({}), /Invalid/);
});
test('public export refuses known private settings and credential literals', () => {
  assert.throws(() => inspectPublicText('example.mjs', 'private-fixture-id', ['private-fixture-id']), /Private/);
  assert.throws(() => inspectPublicText('key.mjs', 'gh' + 'p_' + 'a'.repeat(40)), /Credential/);
  assert.throws(() => inspectPublicText('metadata', 'DESK' + 'TOP-1234567'), /Personal/);
  inspectPublicText('test.mjs', "const fakeKey = 'a'.repeat(64);");
});
test('public bootstraps parse and reject bad args before downloading or changing state', async () => {
  const script = await fs.readFile('install.sh', 'utf8');
  assert.equal(spawnSync('sh', ['-n'], { input: script }).status, 0);
  const help = spawnSync('sh', ['-s', '--', '--help'], { input: script, encoding: 'utf8' });
  assert.equal(help.status, 0); assert.match(help.stdout, /own private Cloudflare/);
  const bad = spawnSync('sh', ['-s', '--', '--bad-option'], { input: script, encoding: 'utf8' }); assert.equal(bad.status, 1);
  const cloud = publicBootstrap('https://owner.example.test', 'https://raw.githubusercontent.com/owner/project/v0.1.0-alpha.18/install.sh');
  assert.match(cloud, /--instance 'https:\/\/owner\.example\.test'/);
  assert.throws(() => publicBootstrap('https://owner.example.test', 'https://attacker.invalid/install.sh'));
});
test('source verification refuses altered source instead of overwriting retained configuration', async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-public-source-')); t.after(() => fs.rm(base, { recursive: true, force: true }));
  await fs.writeFile(path.join(base, 'sample.mjs'), 'original');
  const manifest = path.join(base, 'manifest.json'); await fs.writeFile(manifest, JSON.stringify({ product: 'chat2local-source', version: 'fixture', files: { 'sample.mjs': createHash('sha256').update('original').digest('hex') } }));
  assert.equal((await checkSource(base, manifest)).verified, true);
  await fs.writeFile(path.join(base, 'sample.mjs'), 'edited'); await assert.rejects(() => checkSource(base, manifest), /modified/);
});
test('management shortcuts reopen the installed app and never overwrite unrelated user files', async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-entry-')); t.after(() => fs.rm(base, { recursive: true, force: true }));
  const file = await installManagementEntry(path.join(base, "application's files"), { entryDirectory: base, platform: 'darwin' });
  const script = await fs.readFile(file, 'utf8'); assert.match(script, /--manage/); assert.equal(spawnSync('sh', ['-n'], { input: script }).status, 0);
  await fs.writeFile(file, 'unrelated user script');
  await assert.rejects(() => installManagementEntry(base, { entryDirectory: base, platform: 'darwin' }), /unrelated/);
});
test('lost shutdown reply needs a fresh refused connection, never a repeated shutdown or success on reset alone', async () => {
  const saved={config:{roots:[]},secrets:{}};
  const store={load:async()=>saved,readSession:async()=>({origin:'http://127.0.0.1:47631',token:'a'.repeat(64),instanceId:'known'})};
  const state={name:'chat2local',instanceId:'known',version:'old',pending:[],paused:false};
  let reads=0,posts=0;
  const call=async(_s,route)=>{
    if(route==='/api/shutdown'){posts++;throw Object.assign(Error('reply lost'),{code:'ECONNRESET'});}
    if(++reads===1)return state;
    throw Object.assign(Error('connection state'),{code:reads===2?'ECONNRESET':'ECONNREFUSED'});
  };
  const upgrade=await prepareUpgrade('new',{store,call,wait:async()=>{}});
  assert.equal(upgrade.stopped,true);assert.equal(posts,1);assert.equal(reads,3);
  reads=0;posts=0;
  await assert.rejects(()=>prepareUpgrade('new',{store,wait:async()=>{},call:async(_s,route)=>{
    if(route==='/api/shutdown'){posts++;return {ok:true};}
    if(++reads===1)return state;
    throw Object.assign(Error('reset is not proof'),{code:'ECONNRESET'});
  }}),/still present/);
  assert.equal(posts,1);
});

test('controlled upgrade rejects busy/untrusted apps and retains the exact settings', async () => {
  const idle = { name: 'chat2local', instanceId: 'known', version: 'old', paused: false, queuedOperations: 0, setupActive: false, folderPickerActive: false, pending: [] };
  for (const change of [{ pending: [{}] }, { paused: true }, { name: 'other' }, { instanceId: 'other' }, { queuedOperations: 1 }]) assert.throws(() => assertUpgradeIdle({ ...idle, ...change }, 'known'));
  let running = true, version = 'old', shutdowns = 0;
  const saved = { config: { roots: [{ id: 'keep', writeMode: 'direct' }] }, secrets: { identity: { deviceId: 'retained' } } };
  const store = { readSession: async () => ({ origin: 'http://127.0.0.1:47631', token: 'a'.repeat(64), instanceId: 'known' }), load: async () => saved };
  const call = async (_session, route) => {
    if (route === '/api/shutdown') { running = false; shutdowns++; return { ok: true }; }
    if (!running) throw Object.assign(Error('closed'), { code: 'ECONNREFUSED' });
    return { ...idle, version };
  };
  const result = await prepareUpgrade('new', { store, call, wait: async () => {} }); assert.equal(shutdowns, 1);
  running = true; version = 'new'; await result.verify();
  saved.config.roots = []; await assert.rejects(() => result.verify(), /retain/);
});
