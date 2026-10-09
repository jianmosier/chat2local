import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { VERSION } from '../src/shared/protocol.mjs';

// Tool-friendly wrapper for the NORMAL release command. No skipped tests or
// alternative publication path; only bounded progress logs outside the source.
const root = fileURLToPath(new URL('..', import.meta.url));
const directory = path.join(root, '.artifacts', 'release-task-' + VERSION);
const record = path.join(directory, 'task.json');
const [mode, repository] = process.argv.slice(2);
if (!['prepare','start','retry','status','worker'].includes(mode)) throw Error('Usage: release-task.mjs prepare|start OWNER/REPO | retry OWNER/REPO | status');
if (mode === 'status') {
  const result = JSON.parse(await fs.readFile(record, 'utf8'));
  let log = ''; try { log = await fs.readFile(path.join(directory,'progress.log'),'utf8'); } catch {}
  console.log(JSON.stringify({ ...result, tail: log.slice(-6500) }, null, 2));
} else if (mode === 'prepare' || mode === 'start' || mode === 'retry') {
  if (!/^[A-Za-z0-9-]+\/[A-Za-z0-9_.-]+$/.test(repository || '')) throw Error('Exact repository required.');
  let action = mode === 'prepare' ? 'prepare' : 'publish';
  if (mode === 'retry') {
    const previous = JSON.parse(await fs.readFile(record, 'utf8'));
    if (previous.state !== 'failed' || previous.repository !== repository || !['prepare','publish'].includes(previous.action)) throw Error('Only a confirmed failed task with the same explicit action may be retried.');
    action = previous.action;
    await fs.copyFile(record, path.join(directory, 'attempt-' + Date.now() + '.json'));
  } else await fs.mkdir(directory);
  await fs.writeFile(record, JSON.stringify({ version: VERSION, repository, action, state: 'starting', startedAt: new Date().toISOString() }), { flag:mode === 'retry' ? 'w' : 'wx' });
  const worker = spawn(process.execPath, ['--use-env-proxy', fileURLToPath(import.meta.url), 'worker', repository], { cwd:root, detached:true, windowsHide:true, stdio:'ignore' });
  worker.unref(); console.log(JSON.stringify({ started:true, version:VERSION, workerPid:worker.pid }));
} else {
  const task = JSON.parse(await fs.readFile(record,'utf8'));
  if (task.repository !== repository || task.state !== 'starting' || !['prepare','publish'].includes(task.action)) throw Error('Task identity or action changed.');
  let log = '', writing = Promise.resolve();
  const save = (state, result = {}) => fs.writeFile(record, JSON.stringify({ ...task, state, ...result }, null, 2));
  await save('running');
  // Preparation never invokes GitHub or deployment operations. Retrying it
  // preserves the same action rather than silently promoting it to publication.
  const args = ['--use-env-proxy','scripts/release.mjs', ...(task.action === 'publish' ? ['--publish','--repo',repository] : [])];
  const child = spawn(process.execPath, args, { cwd:root, windowsHide:true, stdio:['ignore','pipe','pipe'] });
  const collect = bytes => { log = (log + bytes.toString()).slice(-262144); const snapshot = log; writing = writing.then(() => fs.writeFile(path.join(directory,'progress.log'),snapshot)); };
  child.stdout.on('data',collect); child.stderr.on('data',collect);
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; child.kill(); }, 1500000);
  const result = await new Promise(resolve => { child.once('error',e => resolve({ exitCode:null,error:e.code || 'spawn-error' })); child.once('close',(code,signal) => resolve({ exitCode:code,signal })); });
  clearTimeout(timer); await writing;
  await save(result.exitCode === 0 && !timedOut ? 'completed' : 'failed', { ...result, timedOut, endedAt:new Date().toISOString() });
}
