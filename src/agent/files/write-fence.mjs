import fs from 'node:fs/promises';
import path from 'node:path';
import { relativeParts } from './path-policy.mjs';

const blocked = () => Object.assign(new Error('An unresolved write requires local inspection. Do not retry or use an older release.'), { code: 'EFENCE' });
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const digest = /^[a-f0-9]{64}$/;
function validBinding(value) {
  const fields = ['rootId', 'rootPath', 'path', 'beforeHash', 'deviceId', 'resource', 'connectionId', 'fileId'];
  const nullableHash = (s, n) => s === null || typeof s === 'string' && new RegExp(`^[a-f0-9]{${n}}$`).test(s);
  if (!value || typeof value !== 'object' || Object.keys(value).length !== fields.length || fields.some(k => !Object.hasOwn(value, k))) return false;
  try { relativeParts(value.path); } catch { return false; }
  return /^[a-zA-Z0-9_-]{1,80}$/.test(value.rootId) && typeof value.rootPath === 'string' && path.isAbsolute(value.rootPath)
    && nullableHash(value.beforeHash, 64) && nullableHash(value.deviceId, 32) && nullableHash(value.connectionId, 32)
    && (value.resource === null || typeof value.resource === 'string' && value.resource.length <= 2048)
    && (value.fileId === null || Array.isArray(value.fileId) && value.fileId.length === 3 && value.fileId.every(n => Number.isInteger(n) && n >= 0 && n <= 0xffffffff));
}
async function exists(file) {
  try { return await fs.lstat(file); } catch (error) { if (error.code === 'ENOENT') return null; throw blocked(); }
}

/** Both backends and startup refuse unresolved, malformed or unsafe Rust fences. */
export async function assertWriteFenceClear(stateDir, { ownGate = false } = {}) {
  if (!stateDir) return;
  if (!ownGate && await exists(path.join(stateDir, 'write-gate'))) throw blocked();
  const directory = path.join(stateDir, 'rust-writes');
  const stat = await exists(directory);
  if (!stat) return;
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw blocked();
  const entries = await fs.readdir(directory);
  for (const name of entries) {
    if (name === 'writer.lock' || (name.endsWith('.before') && uuid.test(name.slice(0, -7)))) continue;
    if (!name.endsWith('.json') || !uuid.test(name.slice(0, -5))) throw blocked();
    const file = path.join(directory, name), info = await exists(file);
    if (!info?.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 16384) throw blocked();
    let value;
    try { value = JSON.parse(await fs.readFile(file, 'utf8')); } catch { throw blocked(); }
    if (!value || Object.keys(value).length !== 6 || value.v !== 1 || `${value.operationId}.json` !== name
        || !digest.test(value.intent) || !digest.test(value.sha256) || !['complete', 'aborted'].includes(value.phase)
        || !validBinding(value.binding)) throw blocked();
  }
}

/** Content-free, cross-process gate shared by JS and Rust. A crash leaves it closed. */
export async function acquireWriteGate(stateDir) {
  if (!stateDir) return async () => {};
  await fs.mkdir(stateDir, { recursive: true });
  const gate = path.join(stateDir, 'write-gate');
  try { await fs.mkdir(gate); } catch { throw blocked(); }
  const identity = await fs.lstat(gate);
  try { await assertWriteFenceClear(stateDir, { ownGate: true }); }
  catch (error) { throw error; } // Keep evidence and block subsequent writers.
  return async () => {
    await assertWriteFenceClear(stateDir, { ownGate: true });
    const current = await fs.lstat(gate);
    if (current.isSymbolicLink() || !current.isDirectory() || current.dev !== identity.dev || current.ino !== identity.ino) throw blocked();
    await fs.rmdir(gate);
  };
}
