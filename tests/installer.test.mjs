import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { gunzipSync } from 'node:zlib';
import { VERSION } from '../src/shared/protocol.mjs';
import { powershell } from '../src/agent/store.mjs';
import { releaseTarget, packageNameFor, RELEASE_TARGETS } from '../scripts/release-targets.mjs';
import { writeTarGz, tarHeader } from '../scripts/archive.mjs';
import { verifyPackage, installPortable, installationDirectory } from '../scripts/install-portable.mjs';
import { installerArtifacts, renderPosixInstaller, renderWindowsInstaller, buildInstallers } from '../scripts/build-installers.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const execute = promisify(execFile);
async function temp(t) { const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-install-')); t.after(() => fs.rm(base, { recursive: true, force: true })); return base; }
function record(target) { const value = releaseTarget(target); return { target, packageName: `${value.prefix}-test`, file: `${value.prefix}-test.${value.extension}`, version: VERSION, sha256: 'a'.repeat(64) }; }
async function fixture(t) {
  const base = await temp(t); const source = path.join(base, 'package');
  const executable = process.platform === 'win32' ? 'runtime/node.exe' : 'runtime/node';
  const contents = { [executable]: 'not-executed-test-runtime', 'scripts/launch.mjs': '// test fixture; never executed', 'LICENSE': 'fixture' };
  const manifest = { product: 'Chat2Local', version: VERSION, platform: `${process.platform}-${process.arch}`, files: {} };
  for (const [name, content] of Object.entries(contents)) { await fs.mkdir(path.dirname(path.join(source, name)), { recursive: true }); await fs.writeFile(path.join(source, name), content); manifest.files[name] = hash(content); }
  await fs.writeFile(path.join(source, 'BUILD-MANIFEST.json'), JSON.stringify(manifest));
  return { base, source, manifest, executable };
}

test('release target matrix covers both architectures on three systems without silent fallback', () => {
  assert.equal(Object.keys(RELEASE_TARGETS).length, 6);
  assert.equal(releaseTarget('darwin-arm64').archiveName, 'node-v24.21.0-darwin-arm64.tar.gz');
  assert.equal(releaseTarget('win32-arm64').executable, 'node.exe');
  assert.equal(releaseTarget('linux-x64').extension, 'tar.gz');
  assert.throws(() => releaseTarget('linux-ia32')); assert.throws(() => releaseTarget('linux-musl-x64'));
  assert.throws(() => packageNameFor('darwin-arm64', 'Chat2Local-Windows-x64'));
});
test('tar archive refuses traversal and retains POSIX executable modes on any build host', async t => {
  for (const name of ['/absolute', '../escape', 'safe/../escape', 'safe\\escape', 'safe\nname']) assert.throws(() => tarHeader(name, 1));
  const base = await temp(t); const source = path.join(base, 'Chat2Local-macOS-arm64-test');
  await fs.mkdir(path.join(source, 'runtime'), { recursive: true });
  await fs.writeFile(path.join(source, 'runtime', 'node'), 'fixture-node');
  await fs.writeFile(path.join(source, '开始使用.txt'), 'text');
  const archive = path.join(base, 'test.tar.gz'); await writeTarGz(source, archive);
  const raw = gunzipSync(await fs.readFile(archive));
  assert.equal(parseInt(raw.subarray(100, 108).toString().replace(/\0/g, '').trim(), 8), 0o755);
  const unpacked = path.join(base, 'unpacked'); await fs.mkdir(unpacked);
  const tar = process.platform === 'win32' ? path.join(process.env.SystemRoot, 'System32', 'tar.exe') : 'tar';
  await execute(tar, ['-xzf', archive, '-C', unpacked]);
  assert.equal(await fs.readFile(path.join(unpacked, path.basename(source), 'runtime', 'node'), 'utf8'), 'fixture-node');
  assert.equal(await fs.readFile(path.join(unpacked, path.basename(source), '开始使用.txt'), 'utf8'), 'text');
  if (process.platform !== 'win32') assert.equal((await fs.stat(path.join(unpacked, path.basename(source), 'runtime', 'node'))).mode & 0o111, 0o111);
});
test('installer verifies an exact manifest before installing and refuses a foreign architecture', async t => {
  const f = await fixture(t); assert.equal((await verifyPackage(f.source)).manifest.version, VERSION);
  await assert.rejects(() => verifyPackage(f.source, { target: 'unsupported-target' }), /architecture/);
  await fs.writeFile(path.join(f.source, 'unlisted-secret.txt'), 'not allowed');
  await assert.rejects(() => verifyPackage(f.source), /exactly match/);
});
test('modified package content and manifest traversal cannot be installed', async t => {
  const f = await fixture(t); await fs.writeFile(path.join(f.source, f.executable), 'tampered');
  await assert.rejects(() => verifyPackage(f.source), /integrity/);
  f.manifest.files['../outside'] = 'a'.repeat(64);
  await fs.writeFile(path.join(f.source, 'BUILD-MANIFEST.json'), JSON.stringify(f.manifest));
  await assert.rejects(() => verifyPackage(f.source), /Unsafe/);
});
test('repeated installation reuses verified program files and never resets user state', async t => {
  const f = await fixture(t); const installRoot = path.join(f.base, 'apps'); const settings = path.join(f.base, 'settings.json');
  await fs.writeFile(settings, '{"root":"keep","permission":"review","device":"keep"}');
  const before = await fs.readFile(settings, 'utf8');
  const first = await installPortable(f.source, { installRoot, launch: false });
  const second = await installPortable(f.source, { installRoot, launch: false });
  assert.equal(first.installed, true); assert.equal(first.reused, false); assert.equal(first.launched, false);
  assert.equal(second.reused, true); assert.equal(second.directory, first.directory);
  assert.equal(await fs.readFile(settings, 'utf8'), before);
  await fs.writeFile(path.join(first.directory, 'LICENSE'), 'locally modified');
  await assert.rejects(() => installPortable(f.source, { installRoot, launch: false }), /integrity/);
  assert.equal(await fs.readFile(path.join(first.directory, 'LICENSE'), 'utf8'), 'locally modified');
  assert.equal(await fs.readFile(settings, 'utf8'), before);
});
test('installer refuses an active lock instead of deleting it or killing processes', async t => {
  const f = await fixture(t); const installRoot = path.join(f.base, 'apps'); await fs.mkdir(path.join(installRoot, '.install-lock'), { recursive: true });
  await assert.rejects(() => installPortable(f.source, { installRoot, launch: false }), /Another installation/);
  assert.equal((await fs.stat(path.join(installRoot, '.install-lock'))).isDirectory(), true);
});
test('installation paths are separate from portable source and keep per-user permissions', () => {
  assert.equal(installationDirectory({ platform: 'darwin', home: '/Users/jack', env: {} }), '/Users/jack/Library/Application Support/Chat2Local/apps');
  assert.equal(installationDirectory({ platform: 'linux', home: '/home/jack', env: {} }), '/home/jack/.local/share/chat2local/apps');
  assert.throws(() => installationDirectory({ platform: 'unknown' }));
});
test('generated POSIX bootstrap is pinned, HTTPS-only, and needs no Node/npm/Git', () => {
  const script = renderPosixInstaller('https://releases.example.org/v1', [record('darwin-arm64'), record('linux-x64')]);
  assert.match(script, /hw.optional.arm64/); assert.match(script, /expected='a{64}'/);
  assert.match(script, /--proto-redir '=https'/); assert.match(script, /SHA-256 mismatch/);
  assert.ok(script.indexOf('SHA-256 mismatch') < script.indexOf('tar -xzf'));
  assert.doesNotMatch(script, /npm install|git clone|NODE_TLS_REJECT_UNAUTHORIZED|curl -k/);
  assert.throws(() => renderPosixInstaller('http://releases.example.org', [record('darwin-arm64')]));
  assert.throws(() => renderPosixInstaller('https://not-configured.invalid', [record('darwin-arm64')]));
});
test('bootstrap metadata cannot mix versions, duplicate targets, or embed unsafe filenames', () => {
  assert.throws(() => installerArtifacts([record('darwin-arm64'), record('darwin-arm64')]));
  assert.throws(() => installerArtifacts([{ ...record('darwin-arm64'), version: 'old' }]));
  assert.throws(() => installerArtifacts([{ ...record('darwin-arm64'), file: '../../escape' }]));
  assert.throws(() => renderWindowsInstaller('https://releases.example.org', [record('linux-x64')]));
});
test('generated installer scripts pass native syntax parsers without executing downloads', async () => {
  const shell = renderPosixInstaller('https://releases.example.org/v1', [record('darwin-arm64'), record('linux-x64')]);
  await new Promise((resolve, reject) => {
    const child = spawn('sh', ['-n'], { stdio: ['pipe', 'ignore', 'pipe'] }); let errors = '';
    child.stderr.on('data', bytes => { errors += bytes; }); child.once('error', reject);
    child.once('close', code => code === 0 ? resolve() : reject(new Error(errors))); child.stdin.end(shell);
  });
  const windows = renderWindowsInstaller('https://releases.example.org/v1', [record('win32-x64'), record('win32-arm64')]);
  if (process.platform === 'win32') {
    const result = await powershell("$s=[Console]::In.ReadToEnd(); $tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseInput($s,[ref]$tokens,[ref]$errors)|Out-Null; if($errors.Count){throw ($errors|Out-String)}; 'syntax-ok'", windows);
    assert.equal(result, 'syntax-ok');
  }
});
test('release generator verifies archive bytes and refuses to label a partial build complete', async t => {
  const base = await temp(t); const r = record('darwin-arm64'); r.sha256 = hash('archive-fixture');
  await fs.writeFile(path.join(base, r.file), 'archive-fixture');
  const metadata = path.join(base, 'package.release.json'); await fs.writeFile(metadata, JSON.stringify(r));
  await assert.rejects(() => buildInstallers('https://releases.example.org/v1', [metadata], { output: path.join(base, 'complete') }), /all six/);
  const output = path.join(base, 'preview'); const result = await buildInstallers('https://releases.example.org/v1', [metadata], { output, partial: true });
  assert.equal(result.preview, true); assert.equal(result.published, false); assert.equal(result.targets.length, 1);
  assert.match(await fs.readFile(path.join(output, 'install.sh'), 'utf8'), /runtime\/node/);
  await fs.writeFile(path.join(base, r.file), 'tampered');
  await assert.rejects(() => buildInstallers('https://releases.example.org/v1', [metadata], { output: path.join(base, 'bad'), partial: true }), /actual archive/);
});
