import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const FRAME = 1024 * 1024 + 64 * 1024;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const uncertain = () => Object.assign(Error('Terminal journal outcome unknown. No new launch right was granted; inspect existing effects before any retry.'), { code: 'EUNKNOWN' });

/** A single-use receipt, never repaired by reading or retrying after IPC loss. */
export class RustTerminalRecords {
  constructor({ stateDir, executable, spawnHelper = spawn, timeoutMs = 15000, closeMs = 1000 }) {
    Object.assign(this, { stateDir: path.resolve(stateDir), executable, spawnHelper, timeoutMs, closeMs });
    this.frozen = false;
  }
  assertAvailable() { if (this.frozen) throw uncertain(); }
  read(id) { return this.call('read', id).then(result => result.kind === 'missing' ? null : JSON.parse(result.recordJson)); }
  reserve(record) { this.assertAvailable(); return this.call('reserve', record.requestId, record).then(result => ({ kind: result.kind, record: JSON.parse(result.recordJson) })); }
  save(record) { this.assertAvailable(); return this.call('save', record.requestId, record); }
  call(op, requestId, record) {
    if (!UUID.test(requestId)) return Promise.reject(Error('Invalid terminal request UUID.'));
    const nonce = randomUUID(), recordJson = record === undefined ? null : JSON.stringify(record);
    if (recordJson !== null && Buffer.byteLength(recordJson) > 512 * 1024) return Promise.reject(Error('Terminal record exceeds 512 KiB.'));
    const request = Buffer.from(JSON.stringify({ v: 1, nonce, stateDir: this.stateDir, op, requestId, recordJson }));
    if (request.length > FRAME) return Promise.reject(Error('Terminal journal frame exceeds its limit.'));
    return new Promise((resolve, reject) => {
      let child, chunks = [], size = 0, errors = 0, fault = false, settled = false, cleanup;
      const finish = (error, value) => {
        if (settled) return; settled = true; clearTimeout(deadline); clearTimeout(cleanup);
        if (error?.code === 'EUNKNOWN') this.frozen = true;
        error ? reject(error) : resolve(value);
      };
      const abort = () => {
        fault = true; try { child?.kill(); } catch {}
        cleanup ??= setTimeout(() => finish(uncertain()), this.closeMs);
      };
      const deadline = setTimeout(abort, this.timeoutMs);
      try {
        child = this.spawnHelper(this.executable, [], { windowsHide: true, shell: false, stdio: ['pipe','pipe','pipe'] });
        child.stdout.on('data', chunk => { size += chunk.length; if (size > FRAME) abort(); else chunks.push(chunk); });
        child.stderr.on('data', chunk => { errors += chunk.length; if (errors > 8192) abort(); });
        child.once('error', abort); child.stdin.on('error', abort);
        child.once('close', code => {
          if (fault || code !== 0) return finish(uncertain());
          try {
            const response = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
            if (response.v !== 1 || response.nonce !== nonce || typeof response.ok !== 'boolean') throw Error();
            if (!response.ok) {
              if (!exact(response, ['v','nonce','ok','code']) || !/^E[A-Z]+$/.test(response.code)) throw Error();
              return finish(response.code === 'EUNKNOWN' ? uncertain() : Object.assign(Error(`Native terminal journal rejected the operation (${response.code}); no new launch right was granted.`), { code: response.code }));
            }
            const result = response.result;
            if (!exact(response, ['v','nonce','ok','result']) || !exact(result, ['kind','recordJson'])) throw Error();
            if (op === 'read' && result.kind === 'missing' && result.recordJson === null) return finish(null, result);
            if (!(op === 'read' ? ['found'] : op === 'reserve' ? ['created','existing'] : ['saved']).includes(result.kind)
              || typeof result.recordJson !== 'string' || Buffer.byteLength(result.recordJson) > 512 * 1024) throw Error();
            const value = JSON.parse(result.recordJson);
            if (value?.requestId !== requestId || (['created','saved'].includes(result.kind) && result.recordJson !== recordJson)) throw Error();
            if (record && ['rootId','connectionId','resource','deviceId','inputHash'].some(key => record[key] !== value[key])) throw Error();
            finish(null, result);
          } catch { finish(uncertain()); }
        });
        child.stdin.end(request);
      } catch { abort(); }
    });
  }
}

export function configuredTerminalStore(options = {}, environment = process.env) {
  const backend = options.terminalStoreBackend ?? environment.CHAT2LOCAL_TERMINAL_STORE_BACKEND ?? 'js';
  if (backend === 'js') return undefined;
  if (backend !== 'rust' || process.platform !== 'win32') throw Error('Terminal store backend must be js or rust (Windows).');
  const executable = options.terminalStoreExecutable ?? fileURLToPath(new URL('../../../runtime/chat2local-terminal-store.exe', import.meta.url));
  return store => new RustTerminalRecords({ stateDir: store.directory, executable });
}
