import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { existsSync, renameSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { FileService, approveRoot } from '../src/agent/files.mjs';
import { RustWriterBackend, configuredWriterBackend } from '../src/agent/files/rust-writer.mjs';
import { acquireWriteGate, assertWriteFenceClear } from '../src/agent/files/write-fence.mjs';

const executable = process.env.CHAT2LOCAL_WRITER_TEST_EXECUTABLE ?? path.resolve('target/debug/chat2local-writer.exe');
const unavailable = process.platform !== 'win32' ? 'Requires Windows NTFS' : !existsSync(executable) ? 'Build writer with npm run test:rust-writer' : false;
if (process.env.CHAT2LOCAL_WRITER_TEST_REQUIRED === '1' && unavailable) throw Error(unavailable);
const native = { skip: unavailable };
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
async function fixture(t, backend) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-writer-'));
  const directory = path.join(base, 'project'), state = path.join(base, 'state');
  await fs.mkdir(directory); await fs.mkdir(state);
  const root = { ...await approveRoot(directory, state, true), writeMode: 'direct' };
  const config = { paused: false, roots: [root], accountRoots: [] };
  const writerBackend = backend ?? new RustWriterBackend({ executable });
  const service = new FileService(() => config, state, () => undefined, { writerBackend });
  t.after(() => fs.rm(base, { recursive: true, force: true }));
  return { base, directory, state, root, config, service, writerBackend,
    write: (name, content, expectedHash = null) => service.invoke('write_file', { rootId: root.id, path: name, content, expectedHash }) };
}

test('write selection is independent, explicit, fixed local and defaults to JS', () => {
  assert.equal(configuredWriterBackend({}, {}), undefined);
  assert.equal(configuredWriterBackend({ writeBackend: 'js' }, { CHAT2LOCAL_WRITE_BACKEND: 'rust' }), undefined);
  assert.throws(() => configuredWriterBackend({}, { CHAT2LOCAL_WRITE_BACKEND: 'other' }), /must be js or rust/);
  if (process.platform === 'win32') assert.equal(configuredWriterBackend({}, { CHAT2LOCAL_WRITE_BACKEND: 'rust' }).executable, path.resolve('runtime/chat2local-writer.exe'));
});

test('real native create and replace preserve raw BOM and empty backups and byte hashes', native, async t => {
  const f = await fixture(t);
  for (const [name, before, after] of [['bom.txt', '\ufeff中文\r\n', 'new\r\n'], ['empty.txt', '', 'now'], ['limit.txt', 'x', 'a'.repeat(65536)]]) {
    await fs.writeFile(path.join(f.directory, name), before);
    const result = await f.write(name, after, digest(before));
    assert.equal(result.status, 'written', JSON.stringify(result)); assert.equal(result.sha256, digest(after)); assert.equal(result.backupSaved, true);
    assert.deepEqual(await fs.readFile(path.join(f.state, 'rust-writes', `${result.operationId}.before`)), Buffer.from(before));
    assert.equal(await fs.readFile(path.join(f.directory, name), 'utf8'), after);
  }
  const created = await f.write('created.txt', '\ud800');
  assert.equal(created.status, 'written', JSON.stringify(created));
  assert.equal(created.backupSaved, false); assert.equal(created.sha256, digest('\ufffd'));
  assert.equal(await fs.readFile(path.join(f.directory, 'created.txt'), 'utf8'), '\ufffd');
  await assertWriteFenceClear(f.state);
  assert.deepEqual((await fs.readdir(f.directory)).filter(n => n.startsWith('.chat2local-')), []);
});

test('hash conflicts, hardlinks, junctions, alternate streams, readonly and invalid UTF8 fail before commit', native, async t => {
  const f = await fixture(t); const file = path.join(f.directory, 'file.txt'); await fs.writeFile(file, 'old');
  assert.equal((await f.write('file.txt', 'new', digest('other'))).status, 'failed');
  await fs.link(file, path.join(f.directory, 'link.txt'));
  assert.equal((await f.write('file.txt', 'new', digest('old'))).status, 'failed'); await fs.unlink(path.join(f.directory, 'link.txt'));
  const outside = path.join(f.base, 'outside'); await fs.mkdir(outside); await fs.symlink(outside, path.join(f.directory, 'junction'), 'junction');
  assert.equal((await f.write('junction/no.txt', 'new')).status, 'failed');
  await fs.writeFile(file + ':extra', 'hidden');
  assert.equal((await f.write('file.txt', 'new', digest('old'))).status, 'failed'); await fs.unlink(file + ':extra');
  await fs.chmod(file, 0o444); assert.equal((await f.write('file.txt', 'new', digest('old'))).status, 'failed'); await fs.chmod(file, 0o666);
  await fs.writeFile(file, Buffer.from([0xff])); assert.equal((await f.write('file.txt', 'new', digest(Buffer.from([0xff])))).status, 'failed');
  await assertWriteFenceClear(f.state);
});

test('ready rechecks current authorization and cleans an aborted intent before releasing the gate', native, async t => {
  const f = await fixture(t);
  const original = f.service.writer.writeAuthority;
  let calls = 0;
  f.service.writer.writeAuthority = (...args) => { if (++calls === 2) f.config.paused = true; return original(...args); };
  const result = await f.write('cancelled.txt', 'new');
  assert.equal(result.status, 'unknown', JSON.stringify(result));
  assert.deepEqual(Object.keys(result).sort(), ['message', 'operationId', 'status']);
  assert.equal(existsSync(path.join(f.directory, 'cancelled.txt')), false);
  await assertWriteFenceClear(f.state);
  f.config.paused = false;
  const retained = f.service.status(result.operationId);
  assert.equal(retained.status, 'failed', JSON.stringify(retained));
  assert.match(retained.message, /EACCESS/);
});

test('JS writers and a restarted instance refuse pending or corrupt native intents', async t => {
  const f = await fixture(t);
  const dir = path.join(f.state, 'rust-writes'); await fs.mkdir(dir);
  const id = randomUUID(), file = path.join(dir, `${id}.json`);
  const js = () => new FileService(() => f.config, f.state);
  for (const data of ['broken', JSON.stringify({ v: 1, operationId: id, phase: 'committing', intent: 'a'.repeat(64), sha256: 'b'.repeat(64) })]) {
    await fs.writeFile(file, data);
    await assert.rejects(() => assertWriteFenceClear(f.state), /unresolved/);
    const result = await js().invoke('write_file', { rootId: f.root.id, path: 'blocked.txt', content: 'x', expectedHash: null });
    assert.equal(result.status, 'failed'); assert.match(result.message, /EFENCE/);
    assert.equal(existsSync(path.join(f.directory, 'blocked.txt')), false);
  }
});

test('shared cross-process gate refuses a second writer and a surviving gate blocks restart', async t => {
  const f = await fixture(t); const release = await acquireWriteGate(f.state);
  await assert.rejects(() => acquireWriteGate(f.state), /unresolved/);
  await assert.rejects(() => assertWriteFenceClear(f.state), /unresolved/);
  await release(); await assertWriteFenceClear(f.state);
});

function fakeChild(handle) {
  const child = new EventEmitter(); child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.unref = () => {};
  child.kill = () => { queueMicrotask(() => child.emit('close', null, 'SIGTERM')); return true; };
  let input = '';
  child.stdin.on('data', bytes => { input += bytes; while (input.includes('\n')) { const end = input.indexOf('\n'); const line = input.slice(0, end); input = input.slice(end + 1); handle(child, line); } });
  return child;
}

test('malformed child, timeout and unconfirmed termination stay unknown and retain the gate', async t => {
  for (const mode of ['malformed', 'timeout', 'unconfirmed']) {
    const backend = new RustWriterBackend({ executable: path.resolve('fixture.exe'), timeoutMs: 20, spawnProcess: () => {
      const child = fakeChild((c) => { if (mode === 'malformed') queueMicrotask(() => c.stdout.write('garbage\n')); });
      if (mode === 'unconfirmed') child.kill = () => false;
      return child;
    } });
    const f = await fixture(t, backend); const result = await f.write('unknown.txt', 'new');
    assert.equal(result.status, 'unknown'); await assert.rejects(() => assertWriteFenceClear(f.state));
    if (mode === 'unconfirmed') assert.equal(backend.unavailable, true);
  }
});

test('native postcommit audit failure remains successful with a warning', native, async t => {
  const f = await fixture(t), audit = f.service.audit.bind(f.service);
  f.service.audit = async (name, details) => { if (name === 'written') throw Error('audit full'); return audit(name, details); };
  const result = await f.write('ok.txt', 'new');
  assert.equal(result.status, 'written', JSON.stringify(result)); assert.match(result.message, /audit/);
  await assertWriteFenceClear(f.state);
});

function powershell(file, script) {
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `$ErrorActionPreference='Stop'; ${script}`], {
    env: { ...process.env, WRITER_TEST_FILE: file }, encoding: 'utf8', windowsHide: true,
  });
  assert.equal(result.status, 0, result.stderr); return result.stdout.trim();
}
const acl = file => JSON.parse(powershell(file, '$a=if([IO.Directory]::Exists($env:WRITER_TEST_FILE)){[IO.Directory]::GetAccessControl($env:WRITER_TEST_FILE)}else{[IO.File]::GetAccessControl($env:WRITER_TEST_FILE)}; @{sddl=$a.Sddl; protected=$a.AreAccessRulesProtected; owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value; rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object { @{sid=$_.IdentityReference.Value; rights=[int]$_.FileSystemRights; type=[int]$_.AccessControlType} })} | ConvertTo-Json -Depth 4 -Compress'));

test('actual Windows owner/DACL survives replacement and backup/intent ACL grants only user and System', native, async t => {
  const f = await fixture(t), file = path.join(f.directory, 'acl.txt'); await fs.writeFile(file, 'before');
  const original = acl(file), result = await f.write('acl.txt', 'after', digest('before'));
  assert.equal(result.status, 'written', JSON.stringify(result));
  assert.equal(acl(file).sddl, original.sddl);
  for (const privatePath of [path.join(f.state, 'rust-writes'), path.join(f.state, 'rust-writes', `${result.operationId}.before`), path.join(f.state, 'rust-writes', `${result.operationId}.json`)]) {
    const security = acl(privatePath); assert.equal(security.protected, true); assert.equal(security.rules.length, 2);
    assert.deepEqual(security.rules.map(r => r.sid).sort(), [security.owner, 'S-1-5-18'].sort());
    assert.ok(security.rules.every(r => r.type === 0 && r.rights === 2032127));
  }
});

test('a read-only DACL is not bypassed using writable parent-directory replacement permission', native, async t => {
  const f = await fixture(t), file = path.join(f.directory, 'readonly-acl.txt'); await fs.writeFile(file, 'before');
  const saved = acl(file).sddl;
  powershell(file, '$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User; $a=[IO.File]::GetAccessControl($env:WRITER_TEST_FILE); $a.SetSecurityDescriptorSddlForm("D:P(A;;FR;;;$($sid.Value))(A;;FA;;;SY)",[Security.AccessControl.AccessControlSections]::Access); [IO.File]::SetAccessControl($env:WRITER_TEST_FILE,$a)');
  try {
    const result = await f.write('readonly-acl.txt', 'after', digest('before')); assert.equal(result.status, 'failed', JSON.stringify(result));
    assert.equal(await fs.readFile(file, 'utf8'), 'before');
  } finally {
    powershell(file, `$a=[IO.File]::GetAccessControl($env:WRITER_TEST_FILE); $a.SetSecurityDescriptorSddlForm('${saved}',[Security.AccessControl.AccessControlSections]::Access); [IO.File]::SetAccessControl($env:WRITER_TEST_FILE,$a)`);
  }
});

test('ready holds root, target and private-state guards throughout the write', native, async t => {
  const f = await fixture(t), file = path.join(f.directory, 'guarded.txt'); await fs.writeFile(file, 'before');
  const original = f.service.writer.writeAuthority; let calls = 0;
  f.service.writer.writeAuthority = (...args) => {
    if (++calls === 2) {
      assert.throws(() => renameSync(f.directory, path.join(f.base, 'moved')));
      assert.throws(() => renameSync(f.state, path.join(f.base, 'moved-state')));
      assert.throws(() => writeFileSync(file, 'intruder'));
      const second = spawnSync(process.execPath, ['--input-type=module', '-e', `import { acquireWriteGate } from './src/agent/files/write-fence.mjs'; try { await acquireWriteGate(process.env.WRITER_STATE); process.exitCode=2; } catch(e) { process.stdout.write(e.code); }`], {
        cwd: path.resolve('.'), env: { ...process.env, WRITER_STATE: f.state }, encoding: 'utf8', windowsHide: true, timeout: 5000,
      });
      assert.equal(second.status, 0, second.stderr); assert.equal(second.stdout, 'EFENCE');
    }
    return original(...args);
  };
  const result = await f.write('guarded.txt', 'after', digest('before')); assert.equal(result.status, 'written', JSON.stringify(result));
});

test('an ADS introduced at ready is detected before the native rename', native, async t => {
  const f = await fixture(t), file = path.join(f.directory, 'late-stream.txt'); await fs.writeFile(file, 'before');
  const original = f.service.writer.writeAuthority; let calls = 0;
  f.service.writer.writeAuthority = (...args) => { if (++calls === 2) writeFileSync(file + ':late', 'must survive'); return original(...args); };
  const result = await f.write('late-stream.txt', 'after', digest('before'));
  assert.equal(result.status, 'unknown', JSON.stringify(result));
  assert.equal(await fs.readFile(file, 'utf8'), 'before'); assert.equal(await fs.readFile(file + ':late', 'utf8'), 'must survive');
});

test('an explicit integrity label that temp cannot preserve is refused', native, async t => {
  const f = await fixture(t), file = path.join(f.directory, 'label.txt'); await fs.writeFile(file, 'before');
  const label = spawnSync('icacls.exe', [file, '/setintegritylevel', 'L'], { encoding: 'utf8', windowsHide: true });
  assert.equal(label.status, 0, label.stdout + label.stderr);
  const result = await f.write('label.txt', 'after', digest('before')); assert.equal(result.status, 'failed', JSON.stringify(result));
  assert.equal(await fs.readFile(file, 'utf8'), 'before'); await assertWriteFenceClear(f.state);
});

test('staged ADS introduced at ready is refused before publication', native, async t => {
  const f = await fixture(t); const original = f.service.writer.writeAuthority; let calls = 0;
  f.service.writer.writeAuthority = (...args) => {
    if (++calls === 2) {
      const operation = [...f.service.operations.values()].find(v => v.status === 'applying');
      writeFileSync(path.join(f.directory, `.chat2local-${operation.operationId}.tmp`) + ':late', 'unsafe metadata');
    }
    return original(...args);
  };
  const result = await f.write('staged.txt', 'body'); assert.equal(result.status, 'unknown', JSON.stringify(result));
  assert.equal(existsSync(path.join(f.directory, 'staged.txt')), false);
});

test('existing loose private-state permissions and a state junction are refused', native, async t => {
  for (const junction of [false, true]) {
    const f = await fixture(t), privateDir = path.join(f.state, 'rust-writes');
    if (junction) { const outside = path.join(f.base, 'outside'); await fs.mkdir(outside); await fs.symlink(outside, privateDir, 'junction'); }
    else await fs.mkdir(privateDir);
    const result = await f.write('private.txt', 'body'); assert.notEqual(result.status, 'written');
    assert.equal(existsSync(path.join(f.directory, 'private.txt')), false);
  }
});

test('unconfirmed child after commit freezes the backend and fences both future backends', async t => {
  let spawns = 0;
  const backend = new RustWriterBackend({ executable: path.resolve('fixture.exe'), timeoutMs: 30, spawnProcess: () => {
    spawns++;
    const child = fakeChild((c, line) => {
      const v = JSON.parse(line); if (!v.request) return;
      queueMicrotask(() => c.stdout.write(JSON.stringify({ v: 1, type: 'ready', id: v.request.id, operationId: v.operationId, intent: digest(line) }) + '\n'));
    });
    child.kill = () => false; return child;
  } });
  const f = await fixture(t, backend), result = await f.write('after-commit.txt', 'new');
  assert.equal(result.status, 'unknown'); assert.equal(backend.unavailable, true);
  assert.equal((await f.write('again.txt', 'no')).status, 'failed'); assert.equal(spawns, 1);
  const js = new FileService(() => f.config, f.state);
  assert.equal((await js.invoke('write_file', { rootId: f.root.id, path: 'js.txt', content: 'no', expectedHash: null })).status, 'failed');
});

test('account local-review accepts direct write scope without propose and rejects changed grants at ready', native, async t => {
  const f = await fixture(t), deviceId = 'a'.repeat(32), connectionId = 'b'.repeat(32), resource = 'https://writer-fixture.example.test/mcp';
  f.root.connectionId = connectionId; f.config.accountRoots = [f.root]; f.config.roots = [];
  const access = { version: 1, deviceId, connectionId, resource, roots: [{ rootId: f.root.id, mode: 'direct' }], scopes: ['files:read', 'files:write'] };
  const service = new FileService(() => f.config, f.state, () => ({ deviceId }), { writerBackend: f.writerBackend, getResource: () => resource });
  const proposal = await service.invoke('propose_write', { rootId: f.root.id, path: 'reviewed.txt', content: 'reviewed', expectedHash: null }, access);
  assert.equal((await service.decide(proposal.operationId, true)).status, 'approved');
  const next = await service.invoke('propose_write', { rootId: f.root.id, path: 'denied.txt', content: 'x', expectedHash: null }, access);
  const original = service.writer.writeAuthority; let calls = 0;
  service.writer.writeAuthority = (...args) => { if (++calls === 2) { f.root.writeMode = 'read-only'; f.root.write = false; } return original(...args); };
  assert.equal((await service.decide(next.operationId, true)).status, 'failed');
  assert.equal(existsSync(path.join(f.directory, 'denied.txt')), false);
});

test('a real write followed by corrupted result remains unknown without rollback or automatic retry', native, async t => {
  const backend = new RustWriterBackend({ executable, spawnProcess: (...args) => {
    const actual = spawn(...args), child = new EventEmitter();
    child.stdin = actual.stdin; child.stdout = new PassThrough(); child.kill = () => actual.kill(); child.unref = () => actual.unref();
    let buffer = '';
    actual.stdout.on('data', chunk => { buffer += chunk; while (buffer.includes('\n')) { const end = buffer.indexOf('\n'), line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      child.stdout.write(line.includes('"type":"result"') ? 'corrupted\n' : line + '\n'); } });
    actual.on('error', error => child.emit('error', error)); actual.on('close', (code, signal) => child.emit('close', code, signal));
    return child;
  } });
  const f = await fixture(t, backend), result = await f.write('published.txt', 'published');
  assert.equal(result.status, 'unknown', JSON.stringify(result)); assert.match(result.message, /do not retry/);
  assert.equal(await fs.readFile(path.join(f.directory, 'published.txt'), 'utf8'), 'published');
  await assert.rejects(() => assertWriteFenceClear(f.state));
});
