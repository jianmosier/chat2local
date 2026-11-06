import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';
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

// Deliberately inconsistent size declarations exercise hostile archive input.
// Payloads remain tiny: these tests never allocate the advertised large sizes.
function fixtureZip(entries) {
  const local = [], central = []; let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name), bytes = Buffer.from(entry.content || ''), compressed = deflateRawSync(bytes);
    let crc = 0xffffffff;
    for (const byte of bytes) { crc ^= byte; for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0); }
    crc = (crc ^ 0xffffffff) >>> 0;
    const length = entry.length ?? bytes.length, header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50); header.writeUInt16LE(20, 4); header.writeUInt16LE(8, 8);
    header.writeUInt32LE(crc, 14); header.writeUInt32LE(compressed.length, 18); header.writeUInt32LE(length, 22); header.writeUInt16LE(name.length, 26);
    local.push(header, name, compressed);
    const record = Buffer.alloc(46); record.writeUInt32LE(0x02014b50); record.writeUInt16LE(20, 4); record.writeUInt16LE(20, 6); record.writeUInt16LE(8, 10);
    record.writeUInt32LE(crc, 16); record.writeUInt32LE(compressed.length, 20); record.writeUInt32LE(length, 24); record.writeUInt16LE(name.length, 28);
    record.writeUInt32LE(entry.attributes || 0, 38); record.writeUInt32LE(offset, 42); central.push(record, name);
    offset += header.length + name.length + compressed.length;
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10); end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, directory, end]);
}

test('valid-checksum malformed ZIPs are refused before oversized or outside staging writes', { skip: process.platform !== 'win32', timeout: 90000 }, async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-zip-bounds-'));
  t.after(() => fs.rm(base, { recursive: true, force: true }));
  const originalFetch = globalThis.fetch; t.after(() => { globalThis.fetch = originalFetch; });
  const release = windowsReleaseIdentity('win32-x64'), prefix = release.folder + '/';
  const cases = [
    { name: 'per-entry declaration', entries: [{ name: prefix + 'large', length: 128 * 1024 * 1024 + 1 }], error: /expanded size exceeds limit/ },
    { name: 'aggregate declarations', entries: [1, 2, 3].map(i => ({ name: prefix + i, length: 100 * 1024 * 1024 })), error: /expanded size exceeds limit/ },
    { name: 'actual bytes exceed declaration', entries: [{ name: prefix + 'short', length: 1, content: 'x'.repeat(32768) }], error: /byte length mismatch/ },
    { name: 'path traversal', entries: [{ name: prefix + '../outside', content: 'refused' }], error: /Unsafe release entry/ },
    { name: 'symlink mode', entries: [{ name: prefix + 'link', attributes: (0xa1ff * 65536) >>> 0 }], error: /Unsafe release entry/ },
  ];
  for (const [i, fixture] of cases.entries()) await t.test(fixture.name, async () => {
    const project = path.join(base, 'case-' + i), bytes = fixtureZip(fixture.entries), hash = createHash('sha256').update(bytes).digest('hex');
    globalThis.fetch = async url => {
      if (url === `${release.base}/${release.file}.sha256`) return new Response(hash + '  ' + release.file + '\n');
      if (url === `${release.base}/${release.file}`) return new Response(bytes);
      throw Error('Unexpected fixture download');
    };
    await assert.rejects(downloadWindowsRelease(project), fixture.error);
    assert.deepEqual(await fs.readdir(path.join(project, 'dist')), [], 'Failed extraction must leave no promoted package or partial stage.');
    assert.deepEqual(await fs.readdir(project), ['dist']);
  });
});
