import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { VERSION } from '../src/shared/protocol.mjs';
import { verifyNativePackage, runNative } from '../scripts/native-package.mjs';
import { installPortable, verifyPackage, managementEntryContent } from '../scripts/install-portable.mjs';
import { prepareNativeStartup } from '../scripts/native-startup.mjs';
import { buildPortable } from '../scripts/build-portable.mjs';
import { joinInvitation } from '../scripts/join-instance.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
async function fixture(t, version = VERSION) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-native-install-'));
  t.after(() => fs.rm(base, { recursive: true, force: true }));
  const source = path.join(base, 'package'), installRoot = path.join(base, 'apps'), state = base;
  await fs.mkdir(path.join(source, 'native'), { recursive: true });
  const cap = { name: 'chat2local-native-agent', fixtureOnly: false, fullAgent: false, upgradeReady: false, version, openssl: 'OpenSSL 3.5.8 fixture', localPanel: true, terminalAvailable: true, routes: ['/api/status', '/api/shutdown', '/api/instance/import-invitation'] };
  const inner = { v: 1, fixtureOnly: false, fullAgent: false, upgradeReady: false, platform: 'win32', architecture: 'x64', features: [], executable: 'chat2local-native-agent.exe', sha256: hash('synthetic-agent-not-executed'), terminalRunner: { fixtureOnly: false, executable: 'chat2local-terminal-runner.exe', sha256: hash('synthetic-runner-not-executed') }, opensslVersion: '3.5.8', capabilities: cap };
  const contents = { 'native/chat2local-native-agent.exe': 'synthetic-agent-not-executed', 'native/chat2local-terminal-runner.exe': 'synthetic-runner-not-executed', 'native/manifest.json': JSON.stringify(inner), 'runtime/node.exe': 'synthetic-node-not-executed', 'scripts/launch.mjs': '// not executed', 'scripts/native-package.mjs': '// not executed' };
  const manifest = { product: 'Chat2Local', version, platform: 'win32-x64', runtimeKind: 'rust-native', files: {} };
  for (const [name, bytes] of Object.entries(contents)) { await fs.mkdir(path.dirname(path.join(source, name)), { recursive: true }); await fs.writeFile(path.join(source, name), bytes); manifest.files[name] = hash(bytes); }
  await fs.writeFile(path.join(source, 'BUILD-MANIFEST.json'), JSON.stringify(manifest));
  const settings = '{"version":1,"roots":[{"id":"kept","writeMode":"review"}],"paused":false,"startup":false,"unknown":{"keep":"中文"}}';
  await fs.writeFile(path.join(state, 'settings.json'), settings);
  await fs.writeFile(path.join(state, 'vault.json'), 'synthetic-protected-identity-do-not-touch');
  const options = { target: 'win32-x64', installRoot, store: { directory: state }, nativeStartup: { available: () => false }, noBrowser: true };
  return { base, source, state, manifest, inner, settings, options };
}
async function retainedState(f) {
  assert.equal(await fs.readFile(path.join(f.state, 'settings.json'), 'utf8'), f.settings);
  assert.equal(await fs.readFile(path.join(f.state, 'vault.json'), 'utf8'), 'synthetic-protected-identity-do-not-touch');
}

test('Windows public packaging refuses missing native artifact before downloads', async () => {
  await assert.rejects(buildPortable(undefined, 'win32-x64'), /requires --native-agent/);
});
test('installed native verifier needs no source checkout and rejects inner fixture/platform/hash contracts', async t => {
  const f = await fixture(t);
  assert.equal((await verifyPackage(f.source, { target: 'win32-x64' })).manifest.runtimeKind, 'rust-native');
  for (const [key, value] of [['fixtureOnly', true], ['architecture', 'arm64'], ['fullAgent', true]]) {
    const altered = { ...f.inner, [key]: value };
    await fs.writeFile(path.join(f.source, 'native/manifest.json'), JSON.stringify(altered));
    await assert.rejects(verifyNativePackage(f.source, { target: 'win32-x64' }), /contract/);
  }
  await fs.writeFile(path.join(f.source, 'native/manifest.json'), JSON.stringify(f.inner));
  await fs.appendFile(path.join(f.source, 'native/chat2local-terminal-runner.exe'), 'changed');
  await assert.rejects(verifyNativePackage(f.source, { target: 'win32-x64' }), /integrity/);
});
test('native invocation sanitizes child diagnostics and does not replay an uncertain operation', async t => {
  const f = await fixture(t); let calls = 0;
  await assert.rejects(runNative(f.source, ['--shutdown'], { target: 'win32-x64', run: async () => { calls++; throw Error('PRIVATE-TOKEN-RESPONSE'); } }), error => !error.message.includes('PRIVATE') && /No automatic stop, fallback or retry/.test(error.message));
  assert.equal(calls, 1);
});
test('no-launch stages native files without changing the management entry or user state', async t => {
  const f = await fixture(t), entry = path.join(f.base, 'Chat2Local.cmd');
  await fs.writeFile(entry, 'previous-entry');
  const result = await installPortable(f.source, { ...f.options, launch: false, nativeRun: () => { throw Error('must not execute'); } });
  assert.equal(result.stagedOnly, true); assert.equal(result.managementEntry, undefined);
  assert.equal(await fs.readFile(entry, 'utf8'), 'previous-entry'); await retainedState(f);
});
test('old live or uncertain owner prevents launch and entry replacement; no shutdown is sent', async t => {
  const f = await fixture(t), entry = path.join(f.base, 'Chat2Local.cmd'), calls = [];
  await fs.writeFile(entry, 'previous-entry');
  await assert.rejects(installPortable(f.source, { ...f.options, nativeRun: async (_directory, args) => { calls.push(args[0]); throw Error('Quit normally'); } }), /Quit normally/);
  assert.deepEqual(calls, ['--preflight']); assert.equal(await fs.readFile(entry, 'utf8'), 'previous-entry'); await retainedState(f);
});
test('failed new launch retains old management entry and never starts a fallback', async t => {
  const f = await fixture(t), entry = path.join(f.base, 'Chat2Local.cmd'), calls = [];
  await fs.writeFile(entry, 'previous-entry');
  await assert.rejects(installPortable(f.source, { ...f.options, nativeRun: async (_directory, args) => { calls.push(args[0]); if (args[0] === '--preflight') return { stopped: true }; throw Error('synthetic launch failed'); } }), /launch failed/);
  assert.deepEqual(calls, ['--preflight', '--launch']); assert.equal(await fs.readFile(entry, 'utf8'), 'previous-entry'); await retainedState(f);
});

test('custom state cannot publish a daily entry bound to a different directory', async t => {
  const f = await fixture(t); let calls = 0;
  await assert.rejects(installPortable(f.source, { ...f.options, store: { directory: path.join(f.base, 'different-state') }, nativeRun: async () => { calls++; } }), /original state directory/);
  assert.equal(calls, 0); await retainedState(f);
});
test('same installed running package reuses only its exact entry and never republishes entries', async t => {
  const f = await fixture(t), staged = await installPortable(f.source, { ...f.options, launch: false });
  const entry = path.join(f.base, 'Chat2Local.cmd'), content = managementEntryContent(staged.directory, { platform: 'win32', native: true });
  await fs.writeFile(entry, content); const before = await fs.stat(entry), calls = [];
  const nativeRun = async (_directory, args) => { calls.push(args[0]); return args[0] === '--preflight' ? { running: true } : { reused: true }; };
  const result = await installPortable(f.source, { ...f.options, nativeRun });
  assert.equal(result.reused, true); assert.deepEqual(calls, ['--preflight', '--launch']); assert.equal((await fs.stat(entry)).mtimeMs, before.mtimeMs);
  assert.doesNotMatch(content, /node|launch\.mjs/);
  await fs.writeFile(entry, 'different-entry'); calls.length = 0;
  await assert.rejects(installPortable(f.source, { ...f.options, nativeRun }), /differs/);
  assert.deepEqual(calls, ['--preflight']); await retainedState(f);
});
test('activation is attempted only after launch and unresolved writes prevent all native invocation', async t => {
  const f = await fixture(t), calls = [];
  const result = await installPortable(f.source, { ...f.options, nativeRun: async (_directory, args) => { calls.push(args[0]); if (args[0] === '--preflight') return { stopped: true }; if (args[0] === '--activate-entry') return { entryActivated: true, managementEntry: path.join(f.base, 'Chat2Local.cmd') }; return { reused: false }; } });
  assert.equal(result.launched, true); assert.deepEqual(calls, ['--preflight', '--launch', '--activate-entry']);
  await fs.mkdir(path.join(f.state, 'write-gate')); calls.length = 0;
  await assert.rejects(installPortable(f.source, { ...f.options, nativeRun: async () => calls.push('unexpected') }), /unresolved write/);
  assert.deepEqual(calls, []); await retainedState(f);
});
test('explicit rollback requires a verified retained native directory and keeps current state', async t => {
  const f = await fixture(t, '0.1.0-alpha.1');
  await assert.rejects(installPortable(f.source, { ...f.options, rollback: true, launch: false }), /retained native installation/);
  await assert.rejects(fs.stat(path.join(f.options.installRoot, '.install-lock')), { code: 'ENOENT' });
  const verified = await verifyPackage(f.source, { target: 'win32-x64', allowOtherVersion: true });
  const installed = path.join(f.options.installRoot, `${f.manifest.version}-win32-x64-${verified.manifestHash.slice(0, 12)}`);
  await fs.cp(f.source, installed, { recursive: true });
  const result = await installPortable(installed, { ...f.options, rollback: true, launch: false });
  assert.equal(result.reused, true); assert.equal(result.directory, installed); await retainedState(f);
});
test('legacy and previous native startup block before switching and preserve preference bytes', async t => {
  const f = await fixture(t), store = { directory: f.state }, target = path.join(f.base, 'old/native/chat2local-native-agent.exe');
  await assert.rejects(prepareNativeStartup(f.source, { store, available: () => true, inspect: async () => ({ legacy: true }), verify: async () => {} }), /original panel/);
  const enabled = f.settings.replace('"startup":false', '"startup":true'); await fs.writeFile(path.join(f.state, 'settings.json'), enabled);
  const link = path.join(f.base, 'synthetic-startup.lnk'); await fs.writeFile(link, 'synthetic-only');
  await assert.rejects(prepareNativeStartup(f.source, { store, available: () => true, inspect: async () => ({ legacy: false, native: { path: link, target, arguments: '--background', working: path.dirname(target), description: 'Chat2Local managed startup' } }), verify: async () => {} }), /Disable login startup/);
  assert.equal(await fs.readFile(path.join(f.state, 'settings.json'), 'utf8'), enabled); assert.equal(await fs.readFile(link, 'utf8'), 'synthetic-only');
});
test('invitation import accepts the formal native profile and rejects fixture impersonation without submitting', async () => {
  const origin = 'http://127.0.0.1:47631', session = { origin, token: 'a'.repeat(64), instanceId: 'same', profile: 'chat2local-native-agent', fixtureOnly: false, fullAgent: false };
  const invitation = { purpose: 'connect', inviteUrl: 'https://owner.example.test/instance/invite#' + 'b'.repeat(32) + '.' + 'c'.repeat(64), expiresAt: Date.now() + 60000 };
  let posts = 0, fixtureOnly = false;
  const options = { store: { readSession: async () => session }, launch: async () => {}, request: async (_url, request) => { if (request.method === 'POST') { posts++; return Response.json({ imported: true, origin: 'https://owner.example.test' }); } return Response.json({ name: 'chat2local-native-agent', fixtureOnly, fullAgent: false, upgradeReady: false, instanceId: 'same' }); } };
  assert.equal((await joinInvitation(invitation, options)).imported, true); assert.equal(posts, 1);
  fixtureOnly = true; await assert.rejects(joinInvitation(invitation, options), /identity did not match/); assert.equal(posts, 1);
  await assert.rejects(joinInvitation(invitation, { ...options, store: { readSession: async () => { throw Error('PRIVATE-protected-json'); } } }), error => !error.message.includes('PRIVATE'));
});
