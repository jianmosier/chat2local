import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { refreshInstalledStartup } from '../scripts/install-portable.mjs';
import { managerRoute } from '../src/agent/management-session.mjs';
import { RELEASE_TARGETS, releasePackageName, releaseAssetFiles } from '../scripts/release-artifacts.mjs';
import { packageNameFor } from '../scripts/release-targets.mjs';

test('release package names satisfy the actual packager contract for Windows and both Mac chips', () => {
  for (const target of RELEASE_TARGETS) assert.equal(packageNameFor(target, releasePackageName(target)), releasePackageName(target));
  const report = { archive: 'source.tar.gz', installers: RELEASE_TARGETS.map(target => ({ archive: releasePackageName(target) + '.archive' })) };
  const files = releaseAssetFiles(report);
  assert.equal(files.length, 8); assert.equal(new Set(files).size, 8);
});
test('update retargets only an already-enabled login entry and never changes grants or the startup preference', async () => {
  const config = { startup: false, roots: [{ id: 'preserved', path: '/project' }] };
  const before = structuredClone(config), calls = [];
  const store = { directory: 'fixture-state', load: async () => ({ config }) };
  const options = { store, available: () => true, apply: async (...args) => calls.push(args), platform: 'darwin' };
  assert.deepEqual(await refreshInstalledStartup('/installed/new', options), { enabled: false, updated: false });
  assert.equal(calls.length, 0); assert.deepEqual(config, before);
  config.startup = true;
  assert.deepEqual(await refreshInstalledStartup('/installed/new', options), { enabled: true, updated: true });
  assert.equal(calls.length, 1); assert.equal(calls[0][0], true);
  assert.equal(calls[0][1], path.join('/installed/new', 'src', 'agent', 'main.mjs'));
  assert.equal(calls[0][3].node, path.join('/installed/new', 'runtime', 'node'));
  assert.deepEqual(config.roots, before.roots); assert.equal(config.startup, true);
  await assert.rejects(() => refreshInstalledStartup('/other', { ...options, available: () => false }), /could not be updated/);
});
test('a management browser can change only the explicit installed-app startup preference, not general control', () => {
  assert.equal(managerRoute('POST', '/api/management/startup'), true);
  for (const route of ['/api/startup','/api/shutdown','/api/network','/api/enroll','/api/write_file']) assert.equal(managerRoute('POST', route), false);
  assert.equal(managerRoute('GET', '/api/management/startup'), false);
});
