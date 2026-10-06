import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const project = fileURLToPath(new URL('..', import.meta.url));
async function run(args) {
  try { return { code: 0, ...await execute(process.execPath, args, { timeout: 10000, maxBuffer: 16384 }) }; }
  catch (error) {
    if (!Number.isInteger(error.code)) throw error;
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}
async function alias(t, target) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-main-alias-'));
  t.after(() => fs.rm(base, { recursive: true, force: true }));
  const link = path.join(base, 'directory-alias');
  await fs.symlink(target, link, process.platform === 'win32' ? 'junction' : 'dir');
  return { base, link };
}

test('reproduce the path-alias failure: argv spelling differs from the ESM entry realpath', async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-main-source-'));
  t.after(() => fs.rm(base, { recursive: true, force: true }));
  await fs.writeFile(path.join(base, 'entry.mjs'), "import path from 'node:path'; import {fileURLToPath} from 'node:url'; console.log(JSON.stringify({oldGuard:path.resolve(process.argv[1])===fileURLToPath(import.meta.url),nativeMain:import.meta.main}));\n");
  const { link } = await alias(t, base);
  const result = await run([path.join(link, 'entry.mjs')]);
  assert.equal(result.code, 0);
  assert.deepEqual(JSON.parse(result.stdout), { oldGuard: false, nativeMain: true });
});

test('real installer/agent CLIs cannot silently exit zero when started through a directory alias', async t => {
  const { link } = await alias(t, project);
  for (const script of ['scripts/install-from-instance.mjs', 'scripts/install-portable.mjs', 'scripts/join-instance.mjs', 'src/agent/main.mjs']) {
    // Invalid arguments must fail before creating state, starting a service or using the network.
    const direct = await run([path.join(project, script), '--invalid-entry-test']);
    const aliased = await run([path.join(link, script), '--invalid-entry-test']);
    assert.equal(direct.code, 1, script + ' direct entry');
    assert.equal(aliased.code, 1, script + ' aliased entry must run its argument validation');
    assert.ok(aliased.stderr.trim(), script + ' must explain the failure');
    assert.equal(aliased.stderr, direct.stderr, script + ' alias must preserve behavior');
  }
});

test('importing CLI modules stays side-effect free even when argv claims to name that module', async () => {
  for (const script of ['scripts/install-from-instance.mjs', 'scripts/install-portable.mjs', 'scripts/join-instance.mjs', 'src/agent/main.mjs']) {
    const full = path.join(project, script);
    const code = `process.argv=[process.execPath,${JSON.stringify(full)},'--invalid-entry-test'];await import(${JSON.stringify(pathToFileURL(full).href)});console.log('import-only');`;
    const result = await run(['--input-type=module', '-e', code]);
    assert.equal(result.code, 0, script + ' must not run when imported');
    assert.equal(result.stdout.trim(), 'import-only');
    assert.equal(result.stderr, '');
  }
});
