import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { releaseOptions, validateRepository, syncSnapshot, publicationCloneArgs } from '../scripts/release.mjs';
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
test('release publication code pins commit, verifies downloaded assets and never force-pushes or clobbers', async () => {
  const source=await fs.readFile('scripts/release.mjs','utf8');
  assert.match(source,/--target',commit/);assert.match(source,/--draft/);assert.match(source,/release','download/);
  assert.match(source,/users\.noreply\.github\.com/);assert.match(source,/inputFingerprint/);
  assert.doesNotMatch(source,/'--force'|'--clobber'|'--mirror'/);
});
