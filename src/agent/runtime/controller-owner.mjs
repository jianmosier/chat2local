import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';

// Process-local evidence of an actually drained generation, never an own-PID bypass.
const completed = new Map();
const fail = () => Object.assign(new Error('Previous controller ownership is live, uncertain, or changed.'), { code: 'EOWNER' });
async function generation(directory) {
  try { return createHash('sha256').update(await fs.readFile(path.join(directory, 'session.json'))).digest('hex'); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
export async function claimControllerOwner(store, inspect = pid => process.kill(pid, 0)) {
  const selected = path.resolve(store.directory);
  const directory = await fs.realpath(selected).catch(error => { if (error.code === 'ENOENT') return selected; throw error; }), before = await generation(directory);
  if (before !== null) {
    const session = await store.readSession();
    if (!session || !Number.isSafeInteger(session.pid) || session.pid <= 0 || typeof session.instanceId !== 'string') throw fail();
    if (completed.get(directory) !== before) {
      let absent = false;
      try { inspect(session.pid); } catch (error) { if (error.code === 'ESRCH') absent = true; else throw fail(); }
      if (!absent) throw fail();
    }
  }
  if (await generation(directory) !== before) throw fail();
  let expected = before, released = false;
  completed.delete(directory);
  return {
    async guard() { if (released || await generation(directory) !== expected) throw fail(); },
    async published(instanceId) {
      const before = await generation(directory);
      const session = await store.readSession();
      if (before === null || session.instanceId !== instanceId || session.pid !== process.pid || await generation(directory) !== before) throw fail();
      expected = before;
    },
    async release() { if (released) return; if (await generation(directory) === expected && expected !== null) completed.set(directory, expected); released = true; },
  };
}
