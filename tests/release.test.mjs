import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { releaseOptions, validateRepository, syncSnapshot } from '../scripts/release.mjs';
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
test('release publication code pins commit, verifies downloaded assets and never force-pushes or clobbers', async () => {
  const source=await fs.readFile('scripts/release.mjs','utf8');
  assert.match(source,/--target',commit/);assert.match(source,/--draft/);assert.match(source,/release','download/);
  assert.match(source,/users\.noreply\.github\.com/);assert.match(source,/inputFingerprint/);
  assert.doesNotMatch(source,/'--force'|'--clobber'|'--mirror'/);
});
