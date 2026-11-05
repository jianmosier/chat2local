import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { randomUUID, createHash } from 'node:crypto';

const MAX = 512 * 1024;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const failed = (code, unknown = false) => Object.assign(new Error(unknown
  ? 'Write outcome is unknown. Inspect local files and the write fence before proceeding.'
  : 'Rust write was refused.'), { code, unknown });
const codes = new Set(['EACCESS', 'EPATH', 'ELINK', 'EFILE', 'EACL', 'EILSEQ', 'ENOTSUP', 'EPROTOCOL', 'ENOENT', 'EACCES', 'EBUSY', 'ENOTDIR', 'EIO', 'EFENCE', 'ECONFLICT', 'EUNKNOWN']);

/** One bounded local child per write, with a fresh parent authorization at ready. */
export class RustWriterBackend {
  constructor({ executable, timeoutMs = 10000, spawnProcess = spawn } = {}) {
    if (typeof executable !== 'string' || !path.isAbsolute(executable)) throw new Error('A local absolute writer executable is required.');
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw new Error('Invalid writer timeout.');
    Object.assign(this, { executable, timeoutMs, spawnProcess });
  }

  invoke(operation, authority, stateDir, reauthorize) {
    if (this.unavailable) return Promise.reject(failed('ECHILD_UNCONFIRMED', true));
    if (!path.isAbsolute(stateDir ?? '')) return Promise.reject(failed('EPROTOCOL'));
    const id = randomUUID(), operationId = operation.operationId;
    // Match Buffer.from(content, 'utf8') including replacement of lone surrogates.
    const content = Buffer.from(operation.content, 'utf8').toString('utf8');
    const raw = Buffer.from(JSON.stringify({ request: { v: 1, id, op: 'read_file', args: { rootId: operation.rootId, path: operation.path }, authority },
      operationId, authorization: operation.authorization, expectedHash: operation.expectedHash, content, stateDir }));
    if (raw.length + 1 > MAX) return Promise.reject(failed('E2BIG'));
    const intent = createHash('sha256').update(raw).digest('hex');
    const expected = createHash('sha256').update(content).digest('hex');
    return new Promise((resolve, reject) => {
      let child;
      try { child = this.spawnProcess(this.executable, [], { shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'], env: { SystemRoot: process.env.SystemRoot || 'C:\\Windows' } }); }
      catch { reject(failed('ECHILD')); return; }
      let buffer = Buffer.alloc(0), size = 0, ready = false, commitSent = false, result, error, finished = false, stopRequested = false, cleanupTimer;
      const stop = reason => {
        if (finished) return;
        error ??= reason;
        cleanupTimer ??= setTimeout(() => {
          if (finished) return;
          finished = true; clearTimeout(timer); this.unavailable = true;
          child.stdin.destroy(); child.stdout.destroy(); child.unref();
          reject(failed('ECHILD_UNCONFIRMED', true));
        }, 1000);
        if (!stopRequested) { stopRequested = true; try { child.kill(); } catch { /* close is still required */ } }
      };
      const timer = setTimeout(() => stop(failed('ETIMEDOUT', true)), this.timeoutMs);
      child.on('error', () => stop(failed('ECHILD', true)));
      child.stdin.on('error', () => stop(failed('EPIPE', true)));
      child.stdout.on('error', () => stop(failed('EPIPE', true)));
      child.stdout.on('data', chunk => {
        if (finished || error) return;
        size += chunk.length;
        if (size > MAX) { stop(failed('E2BIG', true)); return; }
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.includes(10) && !error) {
          const end = buffer.indexOf(10), line = buffer.subarray(0, end); buffer = buffer.subarray(end + 1);
          try {
            const v = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line));
            const keys = ['v', 'type', 'id', 'operationId', 'intent'];
            if (v?.type === 'result') keys.push('result'); else if (v?.type === 'error') keys.push('code');
            if (!exact(v, keys) || v.v !== 1 || v.id !== id || v.operationId !== operationId || v.intent !== intent || result) throw failed('EPROTOCOL', true);
            if (v.type === 'ready' && !ready) {
              ready = true;
              // This callback is intentionally synchronous: check and send occupy
              // the same JS turn, without opening a post-check await window.
              try { if (reauthorize() !== true) throw failed('EACCESS'); }
              catch { error = failed('EACCESS'); child.stdin.end(); continue; }
              commitSent = true;
              child.stdin.end(JSON.stringify({ id, operationId, intent }) + '\n');
            } else if (v.type === 'result' && commitSent && exact(v.result, ['sha256', 'backupSaved'])
                && v.result.sha256 === expected && typeof v.result.backupSaved === 'boolean') {
              result = v.result;
            } else if (v.type === 'error' && codes.has(v.code)) {
              error = failed(v.code, commitSent || v.code === 'EUNKNOWN'); child.stdin.end();
            } else throw failed('EPROTOCOL', true);
          } catch (reason) { stop(reason?.code ? reason : failed('EPROTOCOL', true)); }
        }
      });
      child.once('close', (code, signal) => {
        if (finished) return;
        finished = true; clearTimeout(timer); clearTimeout(cleanupTimer);
        if (error) { reject(error); return; }
        if (code !== 0 || signal || buffer.length || !result) { reject(failed('EPROTOCOL', true)); return; }
        resolve(result);
      });
      child.stdin.write(raw); child.stdin.write('\n');
    });
  }
}

export function configuredWriterBackend(options = {}, environment = process.env) {
  const selected = options.writeBackend ?? environment.CHAT2LOCAL_WRITE_BACKEND ?? 'js';
  if (!['js', 'rust'].includes(selected)) throw new Error('CHAT2LOCAL_WRITE_BACKEND must be js or rust.');
  if (selected === 'js') return undefined;
  if (process.platform !== 'win32') throw new Error('Rust writing currently requires Windows NTFS.');
  return new RustWriterBackend({ executable: options.writerExecutable ?? fileURLToPath(new URL('../../../runtime/chat2local-writer.exe', import.meta.url)) });
}
