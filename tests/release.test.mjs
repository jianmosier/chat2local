import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { releaseOptions, validateRepository, syncSnapshot, publicationCloneArgs, verifyPublishedTree, inputFingerprint } from '../scripts/release.mjs';
import { rustSourceFiles, publicDocuments } from '../scripts/build-public.mjs';
import { checkSource } from '../scripts/check-source.mjs';
const execFileAsync = promisify(execFile);
const hash = text => createHash('sha256').update(text).digest('hex');

test('release is prepare-only by default and publication/creation are explicit', () => {
  assert.equal(releaseOptions([]).publish,false);
  assert.throws(()=>releaseOptions(['--create-repo']),/requires/);
  assert.throws(()=>releaseOptions(['--repo','../elsewhere']),/Invalid/);
  assert.throws(()=>releaseOptions(['--skip-tests']),/Usage/);
  assert.equal(releaseOptions(['--publish','--create-repo','--repo','owner/chat2local']).create,true);
});
test('release never guesses another account, changes repo visibility or writes an archived repository', () => {
  const owner={login:'owner'};
  assert.throws(()=>validateRepository('other/repo',owner,null,true),/authenticated owner/);
  assert.throws(()=>validateRepository('owner/chat2local',owner,null,false),/not found/);
  validateRepository('owner/chat2local',owner,null,true);
  for(const metadata of [{full_name:'owner/chat2local',visibility:'private',permissions:{push:true}},{full_name:'owner/chat2local',visibility:'public',archived:true,permissions:{push:true}}]) assert.throws(()=>validateRepository('owner/chat2local',owner,metadata,false));
});
test('snapshot update preserves unrelated files/history and removes only previously managed files', async t => {
  const base=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-release-'));t.after(()=>fs.rm(base,{recursive:true,force:true}));
  const source=path.join(base,'source'),target=path.join(base,'target');await fs.mkdir(source);await fs.mkdir(target);
  await fs.writeFile(path.join(source,'README.md'),'new');await fs.writeFile(path.join(source,'SOURCE-SHA256.json'),JSON.stringify({product:'chat2local-source',files:{'README.md':hash('new')}}));
  await fs.writeFile(path.join(target,'README.md'),'old');await fs.writeFile(path.join(target,'old.mjs'),'old-owned');await fs.writeFile(path.join(target,'unrelated.txt'),'preserve');
  await syncSnapshot(source,target,{files:{'README.md':hash('old'),'old.mjs':hash('old-owned')}});
  assert.equal(await fs.readFile(path.join(target,'README.md'),'utf8'),'new');assert.equal(await fs.readFile(path.join(target,'unrelated.txt'),'utf8'),'preserve');
  await assert.rejects(()=>fs.stat(path.join(target,'old.mjs')),{code:'ENOENT'});
  await assert.rejects(()=>syncSnapshot(source,target,null),/Unmanaged/);
});
test('publication clone preserves manifest bytes with inherited CRLF settings and still rejects edits', async t => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-release-eol-'));
  t.after(() => fs.rm(base, { recursive:true, force:true }));
  const source = path.join(base, 'source'), old = path.join(base, 'old-clone'), target = path.join(base, 'fixed-clone');
  const hooks = path.join(base, 'empty-hooks'), config = path.join(base, 'fixture.gitconfig');
  await fs.mkdir(hooks);
  const configBytes = '[core]\n\tautocrlf = true\n\teol = crlf\n';
  await fs.writeFile(config, configBytes);
  const env = { ...process.env, GIT_CONFIG_NOSYSTEM:'1', GIT_CONFIG_GLOBAL:config, GIT_CONFIG_COUNT:'0',
    GIT_AUTHOR_NAME:'Release fixture', GIT_COMMITTER_NAME:'Release fixture',
    GIT_AUTHOR_EMAIL:'fixture@example.invalid', GIT_COMMITTER_EMAIL:'fixture@example.invalid', GIT_TERMINAL_PROMPT:'0' };
  const git = (args, cwd=base) => execFileAsync('git', ['-c','core.hooksPath='+hooks,...args],
    { cwd, env, windowsHide:true, timeout:20000 });
  await git(['init','-b','main',source]);
  const files = { '.gitignore':'node_modules/\n.artifacts/\n', 'README.md':'# Fixture\nExact LF bytes.\n' };
  for (const [name, bytes] of Object.entries(files)) await fs.writeFile(path.join(source,name),bytes);
  await fs.writeFile(path.join(source,'SOURCE-SHA256.json'), JSON.stringify({ product:'chat2local-source', version:'fixture',
    files:Object.fromEntries(Object.entries(files).map(([name,bytes]) => [name,hash(bytes)])) })+'\n');
  await git(['-c','core.autocrlf=false','add','--all'], source);
  await git(['-c','commit.gpgsign=false','commit','-m','fixture'], source);

  // Reproduce the old failure without changing the user's real Git settings.
  await git(['clone','--single-branch','--branch','main',source,old]);
  assert.match(await fs.readFile(path.join(old,'.gitignore'),'utf8'), /\r\n/);
  await assert.rejects(() => checkSource(old,path.join(old,'SOURCE-SHA256.json')), /Existing source was modified/);

  await git(publicationCloneArgs('main',source,target));
  assert.equal((await checkSource(target,path.join(target,'SOURCE-SHA256.json'))).verified,true);
  for (const [name,bytes] of Object.entries(files)) assert.equal(await fs.readFile(path.join(target,name),'utf8'),bytes);
  assert.equal((await git(['config','--local','--get','core.autocrlf'],target)).stdout.trim(),'false');
  assert.equal((await git(['config','--local','--get','core.eol'],target)).stdout.trim(),'lf');
  assert.equal(await fs.readFile(config,'utf8'),configBytes);
  await fs.writeFile(path.join(target,'README.md'),'changed after clone\n');
  await assert.rejects(() => checkSource(target,path.join(target,'SOURCE-SHA256.json')), /Existing source was modified: README.md/);
});
async function releaseTaskFixture(t) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-prepare-task-'));
  // A terminal record is saved after the release child and log have closed;
  // its detached supervisor can briefly retain this owned directory as cwd.
  t.after(() => fs.rm(base, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }));
  await fs.mkdir(path.join(base, 'scripts'));
  await fs.mkdir(path.join(base, 'src/shared'), { recursive: true });
  await fs.mkdir(path.join(base, '.artifacts'));
  await fs.copyFile('scripts/release-task.mjs', path.join(base, 'scripts/release-task.mjs'));
  await fs.writeFile(path.join(base, 'src/shared/protocol.mjs'), "export const VERSION = 'fixture';\n");
  const entry = path.join(base, 'scripts/release-task.mjs');
  const taskFile = path.join(base, '.artifacts/release-task-fixture/task.json');
  const progress = path.join(base, '.artifacts/release-task-fixture/progress.log');
  const invoke = (mode, ...args) => execFileAsync(process.execPath, [entry, mode, 'fixture/chat2local', ...args], { cwd: base, windowsHide: true, timeout: 5000 });
  const finished = async () => {
    for (let i = 0; i < 150; i++) {
      const task = JSON.parse(await fs.readFile(taskFile, 'utf8'));
      if (['completed','failed'].includes(task.state)) return task;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw Error('Isolated task fixture did not complete.');
  };
  return { base, taskFile, progress, invoke, finished };
}

test('task preparation and retry never add publication arguments', { timeout: 30000 }, async t => {
  const { base, progress, invoke, finished } = await releaseTaskFixture(t);
  // The fixture executable only reports arguments; it cannot publish anything.
  await fs.writeFile(path.join(base, 'scripts/release.mjs'), 'console.log(JSON.stringify(process.argv.slice(2))); process.exitCode = 1;');
  await invoke('prepare');
  assert.equal((await finished()).state, 'failed');
  assert.equal((await fs.readFile(progress, 'utf8')).trim(), '[]');
  await fs.writeFile(path.join(base, 'scripts/release.mjs'), 'console.log(JSON.stringify(process.argv.slice(2)));');
  await invoke('retry');
  const task = await finished();
  assert.equal(task.state, 'completed'); assert.equal(task.action, 'prepare');
  assert.equal(task.exitCode, 0); assert.equal(task.timedOut, false);
  assert.equal((await fs.readFile(progress, 'utf8')).trim(), '[]');
});

test('background publication requires its recorded exact commit and never blindly retries a failure', { timeout: 30000 }, async t => {
  const { base, taskFile, progress, invoke, finished } = await releaseTaskFixture(t);
  for (const args of [[], ['--commit', 'not-a-sha'], ['--commit', 'A'.repeat(40)], ['--commit', 'a'.repeat(40), '--publish']]) {
    await assert.rejects(invoke('start', ...args), /EXACT_REVIEWED_SHA/);
    assert.deepEqual(await fs.readdir(path.join(base, '.artifacts')), [], 'Invalid input must not create a task or spawn a worker.');
  }
  await fs.writeFile(path.join(base, 'scripts/release.mjs'), 'console.log(JSON.stringify(process.argv.slice(2))); process.exitCode = 1;');
  const commit = 'a'.repeat(40);
  await invoke('start', '--commit', commit);
  const task = await finished(); assert.equal(task.state, 'failed'); assert.equal(task.action, 'publish'); assert.equal(task.commit, commit);
  assert.deepEqual(JSON.parse(await fs.readFile(progress, 'utf8')), ['--publish', '--repo', 'fixture/chat2local', '--commit', commit]);
  const before = await fs.readFile(taskFile, 'utf8'), log = await fs.readFile(progress, 'utf8');
  await assert.rejects(invoke('retry'), /Inspect GitHub.*no task was retried/);
  await assert.rejects(invoke('retry', '--commit', 'b'.repeat(40)), /EXACT_REVIEWED_SHA/);
  assert.equal(await fs.readFile(taskFile, 'utf8'), before); assert.equal(await fs.readFile(progress, 'utf8'), log);
  await fs.writeFile(taskFile, JSON.stringify({ ...task, commit: undefined }));
  const legacy = await fs.readFile(taskFile, 'utf8');
  await assert.rejects(invoke('retry'), /Legacy publication task/);
  await assert.rejects(invoke('worker'), /Task identity or action changed/);
  assert.equal(await fs.readFile(taskFile, 'utf8'), legacy);
  await fs.writeFile(taskFile, JSON.stringify({ ...task, state: 'starting', commit: undefined }));
  await assert.rejects(invoke('worker'), /lacks an exact reviewed commit/);
  assert.equal(await fs.readFile(progress, 'utf8'), log, 'Refused attempts must not invoke the publisher.');
});
test('release publication code pins commit, verifies downloaded assets and never force-pushes or clobbers', async () => {
  const source=await fs.readFile('scripts/release.mjs','utf8');
  assert.match(source,/'--target', options.commit/);assert.match(source,/--draft/);assert.match(source,/'release', 'download'/);
  assert.match(source,/verifyPublishedTree/);assert.match(source,/inputFingerprint/);
  assert.doesNotMatch(source,/'--force'|'--clobber'|'--mirror'/);
  assert.doesNotMatch(source.slice(source.indexOf('export async function publishRelease')), /git\(\['push'|git\(\['add'|core\.hooksPath|commit\.gpgsign/);
});

test('release targets an exact reviewed remote tree and rejects stale, missing and unsafe blobs', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-release-tree-')); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.writeFile(path.join(directory, 'README.md'), 'reviewed source');
  await fs.writeFile(path.join(directory, 'SOURCE-SHA256.json'), JSON.stringify({ files: { 'README.md': hash('reviewed source') } }));
  const tree = { truncated: false, tree: [] };
  for (const name of ['README.md', 'SOURCE-SHA256.json']) {
    const bytes = await fs.readFile(path.join(directory, name));
    tree.tree.push({ path: name, type: 'blob', mode: '100644', sha: createHash('sha1').update(Buffer.from('blob ' + bytes.length + '\0')).update(bytes).digest('hex') });
  }
  await verifyPublishedTree(tree, directory);
  await assert.rejects(verifyPublishedTree({ ...tree, truncated: true }, directory), /inventory/);
  await assert.rejects(verifyPublishedTree({ tree: tree.tree.slice(1) }, directory), /inventory/);
  await assert.rejects(verifyPublishedTree({ tree: [{ ...tree.tree[0], mode: '120000' }, tree.tree[1]] }, directory), /unsafe/);
  await assert.rejects(verifyPublishedTree({ tree: [...tree.tree, { type: 'commit', mode: '160000', path: 'extra', sha: 'a'.repeat(40) }] }, directory), /unsupported/);
  await assert.rejects(verifyPublishedTree({ tree: [...tree.tree, { type: 'tree', mode: '040000', path: 'extra', sha: 'a'.repeat(40) }] }, directory), /unexpected/);
  await fs.writeFile(path.join(directory, 'README.md'), 'changed');
  await assert.rejects(verifyPublishedTree(tree, directory), /differs/);
  assert.throws(() => releaseOptions(['--commit', 'main']), /exact reviewed/);
});

test('release freshness covers launchers and Rust inputs as well as application modules', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'c2l-release-input-')); t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const fixed = ['package.json', 'package-lock.json', 'install.sh', 'install.ps1', 'start-chat2local.cmd', 'start-chat2local.sh', 'LICENSE', 'tsconfig.json', 'wrangler.jsonc', '.gitignore', ...publicDocuments, ...rustSourceFiles];
  for (const name of new Set(fixed)) { await fs.mkdir(path.dirname(path.join(directory, name)), { recursive: true }); await fs.writeFile(path.join(directory, name), 'fixture'); }
  for (const name of ['src', 'scripts', 'tests']) await fs.mkdir(path.join(directory, name), { recursive: true });
  const original = await inputFingerprint(directory);
  for (const name of ['start-chat2local.cmd', 'start-chat2local.sh', 'LICENSE', 'tsconfig.json', 'Cargo.toml', 'crates/agent-controller/src/native.rs']) {
    await fs.writeFile(path.join(directory, name), 'changed');
    assert.notEqual(await inputFingerprint(directory), original, name);
    await fs.writeFile(path.join(directory, name), 'fixture');
  }
});
