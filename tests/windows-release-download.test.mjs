import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { windowsReleaseIdentity, releaseChecksum, downloadWindowsRelease } from '../scripts/download-windows-release.mjs';
import { verifyPackage } from '../scripts/install-portable.mjs';
import { VERSION } from '../src/shared/protocol.mjs';
test('Windows bootstrap selects the exact native release and refuses architecture fallback', () => {
  const release = windowsReleaseIdentity('win32-x64');
  assert.ok(release.base.endsWith('/v' + VERSION));
  assert.equal(release.file, 'Chat2Local-Windows-x64-' + VERSION.replaceAll('.', '-') + '.zip');
  for (const target of ['win32-arm64', 'darwin-x64', 'linux-x64']) assert.throws(() => windowsReleaseIdentity(target), /no architecture fallback/);
});
test('downloaded release is extracted and independently verified without launching or changing user state', { skip: !process.env.CHAT2LOCAL_RELEASE_PACKAGE_TEST_ARCHIVE, timeout: 120000 }, async t => {
  const project = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-download-')); t.after(() => fs.rm(project, { recursive: true, force: true }));
  const release = windowsReleaseIdentity('win32-x64'), bytes = await fs.readFile(process.env.CHAT2LOCAL_RELEASE_PACKAGE_TEST_ARCHIVE), hash = createHash('sha256').update(bytes).digest('hex');
  const previous = globalThis.fetch; t.after(() => { globalThis.fetch = previous; });
  const calls = [];
  globalThis.fetch = async url => {
    calls.push(url);
    if (url === `${release.base}/${release.file}.sha256`) return new Response(hash + '  ' + release.file + '\n');
    if (url === `${release.base}/${release.file}`) return new Response(null, { status: 302, headers: { Location: 'https://release-assets.githubusercontent.com/test.zip' } });
    if (url === 'https://release-assets.githubusercontent.com/test.zip') return new Response(bytes);
    throw Error('Unexpected download target');
  };
  const directory = await downloadWindowsRelease(project), verified = await verifyPackage(directory, { target: 'win32-x64' });
  assert.equal(verified.manifest.runtimeKind, 'rust-native');
  assert.equal(await downloadWindowsRelease(project), directory);
  assert.equal(calls.length, 6);
  assert.deepEqual((await fs.readdir(project)).sort(), ['dist']);
  globalThis.fetch = async url => url.endsWith('.sha256') ? new Response(hash + '  ' + release.file + '\n') : new Response(null, { status: 302, headers: { Location: 'http://127.0.0.1/unsafe' } });
  await assert.rejects(downloadWindowsRelease(project), /Unsafe release/);
  globalThis.fetch = async url => url.endsWith('.sha256') ? new Response('0'.repeat(64) + '  ' + release.file + '\n') : new Response(bytes);
  await assert.rejects(downloadWindowsRelease(project), /checksum mismatch/);
});
test('download checksum must bind both bytes and exact asset name', () => {
  const release = windowsReleaseIdentity('win32-x64'), hash = 'a'.repeat(64);
  assert.equal(releaseChecksum(hash + '  ' + release.file + '\n', release.file), hash);
  for (const text of [hash + '  wrong.zip', 'bad  ' + release.file, hash + '  ' + release.file + '\n' + hash + '  other.zip']) assert.throws(() => releaseChecksum(text, release.file), /identity mismatch/);
});
