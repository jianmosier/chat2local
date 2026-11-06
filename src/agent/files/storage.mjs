import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { MAX_FILE_BYTES } from '../../shared/protocol.mjs';
import { acquireWriteGate } from './write-fence.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');

/** Read bounded UTF-8 bytes from an already checked file-tool path. */
export async function readTextSnapshot(target, mayCreate = false) {
  let handle;
  try {
    handle = await fs.open(target, 'r');
  } catch (error) {
    if (mayCreate && error.code === 'ENOENT') return { target, bytes: null, sha256: null };
    throw error;
  }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_FILE_BYTES) {
      throw new Error('Only regular text files up to 64 KiB are supported.');
    }
    const buffer = Buffer.alloc(MAX_FILE_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length > MAX_FILE_BYTES) throw new Error('File grew beyond the size limit.');
    const bytes = buffer.subarray(0, length);
    if (bytes.includes(0)) throw new Error('Binary files are not supported.');
    const content = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return { target, bytes, content, sha256: hash(bytes) };
  } finally {
    await handle.close();
  }
}

/** File commit mechanics. The service owns serialization and authorization context. */
export class FileWriter {
  constructor({ safePath, readSnapshot, policyRoot, audit, stateDir, writerBackend, writeAuthority }) {
    Object.assign(this, { safePath, readSnapshot, policyRoot, audit, stateDir, writerBackend, writeAuthority });
  }

  async commit(operation) {
    const id = operation.operationId;
    const permission = operation.authorization === 'directory-direct' ? 'direct' : true;
    let temporary, releaseGate, preserveGate = false;
    try {
      releaseGate = await acquireWriteGate(this.stateDir);
      if (this.writerBackend) {
        const authority = JSON.stringify(this.writeAuthority(operation.rootId, permission));
        if (permission === 'direct') await this.audit('direct-write-requested', { operationId: id, rootId: operation.rootId, path: operation.path });
        const result = await this.writerBackend.invoke(operation, JSON.parse(authority), this.stateDir,
          () => JSON.stringify(this.writeAuthority(operation.rootId, permission)) === authority);
        operation.backupSaved = result.backupSaved;
        operation.sha256 = result.sha256;
        await this.completed(operation, permission);
        return;
      }
      const { target } = await this.safePath(operation.rootId, operation.path, { writing: permission, mayCreate: true });
      const snapshot = await this.readSnapshot(operation.rootId, operation.path, true);
      if (snapshot.sha256 !== operation.expectedHash) throw new Error('File changed after proposal; nothing was written.');
      if (permission === 'direct') {
        await this.audit('direct-write-requested', { operationId: id, rootId: operation.rootId, path: operation.path });
      }
      operation.backupSaved = false;
      if (snapshot.bytes && this.stateDir) {
        const directory = path.join(this.stateDir, 'backups');
        await fs.mkdir(directory, { recursive: true });
        await fs.writeFile(path.join(directory, `${id}.before`), snapshot.bytes, { flag: 'wx', mode: 0o600 });
        operation.backupSaved = true;
      }
      const bytes = Buffer.from(operation.content, 'utf8');
      temporary = path.join(path.dirname(target), `.chat2local-${id}.tmp`);
      await fs.writeFile(temporary, bytes, { flag: 'wx', mode: 0o600 });
      await this.safePath(operation.rootId, operation.path, { writing: permission, mayCreate: true });
      const current = await this.readSnapshot(operation.rootId, operation.path, true);
      if (current.sha256 !== operation.expectedHash) throw new Error('Concurrent file change detected; nothing was written.');
      this.policyRoot(operation.rootId, permission);
      // Exclusive creation cannot clobber a file created after the hash check.
      if (operation.expectedHash === null) {
        await fs.link(temporary, target);
      } else {
        await fs.chmod(temporary, (await fs.stat(target)).mode);
        this.policyRoot(operation.rootId, permission);
        await fs.rename(temporary, target);
        temporary = undefined;
      }
      operation.sha256 = hash(bytes);
      await this.completed(operation, permission);
    } catch (error) {
      preserveGate = error.unknown === true;
      operation.status = preserveGate ? 'unknown' : 'failed';
      operation.message = preserveGate ? `Write outcome is unknown (${error.code || 'EUNKNOWN'}). Inspect local files before proceeding; do not retry or use an older release.`
        : error.code ? `Filesystem operation failed (${error.code}).` : error.message;
    } finally {
      if (temporary) await fs.unlink(temporary).catch(() => {});
      if (releaseGate && !preserveGate) {
        try { await releaseGate(); }
        catch {
          if (!['written', 'approved'].includes(operation.status)) operation.status = 'unknown';
          operation.message = 'Write storage is fenced. Inspect local files before proceeding; do not retry or use an older release.';
        }
      }
      delete operation.content;
      delete operation.before;
    }
  }

  async completed(operation, permission) {
    operation.status = permission === 'direct' ? 'written' : 'approved';
    try {
      await this.audit('written', { operationId: operation.operationId, rootId: operation.rootId, path: operation.path,
        sha256: operation.sha256, authorization: operation.authorization });
    } catch {
      operation.message = 'File was written, but the audit log could not be saved. Check local storage.';
    }
  }
}
