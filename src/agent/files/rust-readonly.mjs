import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { forbiddenName } from './path-policy.mjs';

const MAX_MESSAGE_BYTES = 512 * 1024;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const failed = code => Object.assign(new Error('Rust readonly operation failed.'), { code });
const messages = Object.freeze({
  EACCESS: 'Folder access is not authorized.',
  EPATH: 'Path traversal, reserved names, and sensitive files are blocked.',
  ELINK: 'Symbolic links and junctions are blocked.',
  EFILE: 'Only regular text files up to 64 KiB are supported.',
  EBINARY: 'Binary files are not supported.',
});
const codes = new Set(['ENOENT', 'EACCES', 'EBUSY', 'ENOTDIR', 'EIO', 'EILSEQ', 'ENOTSUP', 'EPROTOCOL', 'ERR_ENCODING_INVALID_ENCODED_DATA']);

function responseValue(bytes, id, op, args) {
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw failed('EPROTOCOL'); }
  if (!exact(value, ['v', 'id', 'ok', value?.ok === true ? 'result' : 'error'])
      || value.v !== 1 || value.id !== id || typeof value.ok !== 'boolean') throw failed('EPROTOCOL');
  if (!value.ok) {
    if (!exact(value.error, ['code', 'message']) || typeof value.error.message !== 'string') throw failed('EPROTOCOL');
    // Only local fixed text reaches the caller, never arbitrary child output.
    if (Object.hasOwn(messages, value.error.code)) throw new Error(messages[value.error.code]);
    if (!codes.has(value.error.code)) throw failed('EPROTOCOL');
    throw failed(value.error.code);
  }
  const result = value.result;
  if (op === 'read_file') {
    if (!exact(result, ['path', 'content', 'sha256']) || result.path !== args.path
        || typeof result.content !== 'string' || Buffer.byteLength(result.content) > 65536 || result.content.includes('\0')
        || typeof result.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(result.sha256)) throw failed('EPROTOCOL');
  } else if (!exact(result, ['entries', 'truncated']) || !Array.isArray(result.entries)
      || result.entries.length > 500 || typeof result.truncated !== 'boolean'
      || result.entries.some(entry => !exact(entry, ['name', 'type']) || typeof entry.name !== 'string'
        || !entry.name || entry.name === '.' || entry.name === '..' || /[\\/\0]/.test(entry.name)
        || forbiddenName(entry.name) || !['directory', 'file'].includes(entry.type))) throw failed('EPROTOCOL');
  return result;
}

/** Fixed local child, private pipes, one request, no retries or fallback. */
export class RustReadonlyBackend {
  constructor({ executable, timeoutMs = 10000, spawnProcess = spawn } = {}) {
    if (typeof executable !== 'string' || !path.isAbsolute(executable)) throw new Error('A local absolute readonly executable is required.');
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw new Error('Invalid readonly timeout.');
    Object.assign(this, { executable, timeoutMs, spawnProcess });
  }

  invoke(op, args, authority) {
    if (this.unavailable) return Promise.reject(failed('ECHILD_UNCONFIRMED'));
    if (!['read_file', 'list_directory'].includes(op)) return Promise.reject(failed('EPROTOCOL'));
    const id = randomUUID();
    const request = Buffer.from(JSON.stringify({ v: 1, id, op, args, authority }));
    if (request.length > MAX_MESSAGE_BYTES) return Promise.reject(failed('E2BIG'));
    return new Promise((resolve, reject) => {
      let child;
      try {
        child = this.spawnProcess(this.executable, [], {
          shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'],
          // Do not copy application credentials, proxy tokens or remote inputs.
          env: { SystemRoot: process.env.SystemRoot || 'C:\\Windows' },
        });
      } catch { reject(failed('ECHILD')); return; }
      const chunks = [];
      let size = 0, failure, cleanupTimer, finished = false, terminationRequested = false;
      const stop = code => {
        if (finished) return;
        failure ??= failed(code);
        cleanupTimer ??= setTimeout(() => {
          if (finished) return;
          finished = true; clearTimeout(timer);
          // A failed kill must not deadlock pause/revoke/shutdown behind the FIFO.
          // Disable this backend for the controller lifetime; termination remains
          // explicitly unconfirmed and the request is never retried or successful.
          this.unavailable = true;
          child.stdin.destroy(); child.stdout.destroy(); child.unref();
          reject(failed('ECHILD_UNCONFIRMED'));
        }, 1000);
        if (!terminationRequested) {
          terminationRequested = true;
          try { child.kill(); } catch { /* Termination still needs confirmation. */ }
        }
      };
      const timer = setTimeout(() => stop('ETIMEDOUT'), this.timeoutMs);
      child.on('error', () => stop('ECHILD'));
      child.stdin.once('error', () => stop('EPIPE'));
      child.stdout.once('error', () => stop('EPIPE'));
      child.stdout.on('data', chunk => {
        size += chunk.length;
        if (size > MAX_MESSAGE_BYTES) { stop('E2BIG'); return; }
        if (!failure) chunks.push(chunk);
      });
      child.once('close', (code, signal) => {
        if (finished) return;
        finished = true; clearTimeout(timer); clearTimeout(cleanupTimer);
        if (failure || code !== 0 || signal) { reject(failure ?? failed('ECHILD')); return; }
        try { resolve(responseValue(Buffer.concat(chunks), id, op, args)); } catch (error) { reject(error); }
      });
      child.stdin.end(request);
    });
  }
}

export function configuredReadonlyBackend(options = {}, environment = process.env) {
  const selected = options.readBackend ?? environment.CHAT2LOCAL_READ_BACKEND ?? 'js';
  if (!['js', 'rust'].includes(selected)) throw new Error('CHAT2LOCAL_READ_BACKEND must be js or rust.');
  if (selected === 'js') return undefined;
  if (process.platform !== 'win32') throw new Error('Rust readonly backend currently requires Windows.');
  // Development override is a trusted composition option, never a tool argument.
  const executable = options.readonlyExecutable ?? fileURLToPath(new URL('../../../runtime/chat2local-readonly.exe', import.meta.url));
  return new RustReadonlyBackend({ executable });
}
