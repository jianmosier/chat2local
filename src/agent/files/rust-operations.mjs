import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkedAccess } from '../../shared/connection-access.mjs';
import { FRAME_BYTES, exact, fail, messages, id, rootId, digest, text, eventDetails } from './operation-contract.mjs';

const MAX_MEMORY = 64 * 1024 * 1024;
const statuses = ['pending', 'applying', 'rejected', 'expired', 'written', 'approved', 'failed', 'unknown'];
function validView(value, local = false) {
  if (!exact(value, ['operationId', 'status'], ['path', 'message', 'sha256', 'authorization', 'backupSaved',
    ...(local ? ['rootId', 'expectedHash', 'createdAt', 'content', 'before'] : [])]) || !id(value.operationId) || !statuses.includes(value.status)
    || ('path' in value && !text(value.path, 4096)) || ('message' in value && !text(value.message, 4096))
    || ('sha256' in value && !digest(value.sha256)) || ('backupSaved' in value && typeof value.backupSaved !== 'boolean')
    || ('authorization' in value && !['directory-direct', 'local-review'].includes(value.authorization))) return false;
  if (local && (!rootId(value.rootId) || !(value.expectedHash === null || digest(value.expectedHash)) || !Number.isSafeInteger(value.createdAt)
    || ['content', 'before'].some(key => key in value && (!text(value[key], 65536) || Buffer.byteLength(value[key]) > 65536)))) return false;
  return true;
}
function validTicket(ticket, operationId) {
  if (!exact(ticket, ['attempt', 'operation', 'owner']) || typeof ticket.attempt !== 'string' || !/^[1-9][0-9]{0,19}$/.test(ticket.attempt)
    || !validView(ticket.operation, true) || ticket.operation.operationId !== operationId || ticket.operation.status !== 'applying'
    || typeof ticket.operation.content !== 'string') return false;
  if (ticket.owner !== null) checkedAccess(ticket.owner);
  return true;
}
function validEvent(event) {
  if (!event || typeof event !== 'object' || !text(event.at, 32) || !text(event.action, 32)) return false;
  const { at: _at, action, ...details } = event;
  eventDetails(action, details); return true;
}
function validResult(command, result) {
  switch (command.op) {
    case 'propose': return validView(result) && result.operationId === command.input.operationId && result.status === 'pending';
    case 'beginDirect': return validTicket(result, command.input.operationId) && result.operation.authorization === 'directory-direct';
    case 'decide': return command.approved ? exact(result, ['ticket']) && validTicket(result.ticket, command.id) && result.ticket.operation.authorization === 'local-review'
      : exact(result, ['status']) && validView(result.status) && result.status.operationId === command.id && result.status.status === 'rejected';
    case 'finish': return validView(result) && result.operationId === command.id && result.status === command.outcome.status;
    case 'status': return validView(result) && result.operationId === command.id;
    case 'pendingIds': case 'snapshotIds': return Array.isArray(result) && result.length <= (command.op === 'pendingIds' ? 20 : 200) && result.every(id) && new Set(result).size === result.length;
    case 'snapshot': case 'pendingView': return result === null || (validView(result, true) && result.operationId === command.id && (command.op !== 'pendingView' || result.status === 'pending'));
    case 'prune': case 'cancel': return result === null;
    case 'eventCount': return Number.isInteger(result) && result >= 0 && result <= 100;
    case 'event': return result === null || validEvent(result);
    case 'audit': return validEvent(result) && result.at === command.at && result.action === command.action
      && Object.entries(command.details).every(([key, value]) => result[key] === value);
    default: return false;
  }
}

// Inspect the declared memory limit, not merely today's allocation. WASM has no
// imports; a module without a hard maximum is rejected before instantiation.
function boundedMemory(bytes) {
  let offset = 8, found = false;
  const leb = end => {
    let value = 0, shift = 0;
    for (let count = 0; count < 5 && offset < end; count++) {
      const byte = bytes[offset++]; value += (byte & 127) * 2 ** shift;
      if (!(byte & 128)) return value; shift += 7;
    }
    throw fail('EOPERATIONS');
  };
  while (offset < bytes.length) {
    const section = bytes[offset++], size = leb(bytes.length), end = offset + size;
    if (end > bytes.length) throw fail('EOPERATIONS');
    if (section === 5) {
      if (found || leb(end) !== 1 || leb(end) !== 1) throw fail('EOPERATIONS');
      const initial = leb(end), maximum = leb(end);
      if (initial > maximum || maximum !== MAX_MEMORY / 65536 || offset !== end) throw fail('EOPERATIONS');
      found = true;
    }
    offset = end;
  }
  if (!found) throw fail('EOPERATIONS');
}

/** Trusted local composition only. Every service owns one non-recoverable instance. */
export class RustOperationCore {
  #exports;
  #healthy = true;
  #serial = 0;
  #input;
  #output;
  constructor({ modulePath, instantiate = module => new WebAssembly.Instance(module, {}) } = {}) {
    try {
      if (typeof modulePath !== 'string' || !path.isAbsolute(modulePath)) throw fail('EOPERATIONS');
      const bytes = fs.readFileSync(modulePath);
      if (bytes.length > 4 * 1024 * 1024) throw fail('EOPERATIONS');
      const module = new WebAssembly.Module(bytes);
      if (WebAssembly.Module.imports(module).length) throw fail('EOPERATIONS');
      boundedMemory(bytes);
      const exports = instantiate(module).exports;
      if (!(exports.memory instanceof WebAssembly.Memory) || ['abi_version', 'frame_capacity', 'input_ptr', 'output_ptr', 'output_len', 'command'].some(key => typeof exports[key] !== 'function')
        || exports.abi_version() !== 1 || exports.frame_capacity() !== FRAME_BYTES) throw fail('EOPERATIONS');
      this.#exports = exports; this.#input = exports.input_ptr(); this.#output = exports.output_ptr();
      this.#bounds();
    } catch { this.#healthy = false; throw fail('EOPERATIONS'); }
  }
  get healthy() { return this.#healthy; }
  freeze() { this.#healthy = false; }
  assertHealthy() { if (!this.#healthy) throw fail('EOPERATIONS'); }
  #bounds() {
    const size = this.#exports.memory.buffer.byteLength;
    if (size > MAX_MEMORY || !Number.isInteger(this.#input) || !Number.isInteger(this.#output) || this.#input < 0 || this.#output < 0
      || this.#input + FRAME_BYTES > size || this.#output + FRAME_BYTES > size
      || Math.abs(this.#input - this.#output) < FRAME_BYTES) throw fail('EOPERATIONS');
  }
  execute(command) {
    this.assertHealthy();
    const serial = this.#serial + 1;
    let bytes;
    try {
      bytes = Buffer.from(JSON.stringify({ v: 1, serial, command }, (_key, value) => {
        // Body text was normalized to the writer's UTF-8 bytes by the facade.
        // Invalid UTF-16 in identifiers/paths is input rejection, not an ABI fault.
        if (typeof value === 'string' && !value.isWellFormed()) throw fail('EINPUT');
        return value;
      }));
      if (bytes.length > FRAME_BYTES) throw fail('EINPUT');
    } catch { throw fail('EINPUT'); }
    let response;
    try {
      if (!Number.isSafeInteger(serial)) throw fail('EOPERATIONS');
      this.#serial = serial;
      this.#bounds(); new Uint8Array(this.#exports.memory.buffer, this.#input, bytes.length).set(bytes);
      if (this.#exports.command(bytes.length) !== 0) throw fail('EOPERATIONS');
      this.#bounds();
      const length = this.#exports.output_len();
      if (!Number.isInteger(length) || length < 1 || length > FRAME_BYTES) throw fail('EOPERATIONS');
      response = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(this.#exports.memory.buffer, this.#output, length)));
      if (!exact(response, ['v', 'serial', 'ok', response?.ok === true ? 'result' : 'error']) || response.v !== 1 || response.serial !== serial
        || typeof response.ok !== 'boolean' || (response.ok ? !validResult(command, response.result) : !Object.hasOwn(messages, response.error) || response.error === 'EOPERATIONS')) throw fail('EOPERATIONS');
    } catch { this.#healthy = false; throw fail('EOPERATIONS'); }
    if (!response.ok) throw fail(response.error);
    return response.result;
  }
}

export function configuredOperationsCore(options = {}, environment = process.env) {
  const backend = options.operationsBackend ?? environment.CHAT2LOCAL_OPERATIONS_BACKEND ?? 'js';
  if (backend === 'js') return undefined;
  if (backend !== 'rust') throw new Error('Unsupported operations backend.');
  return new RustOperationCore({ modulePath: options.operationsModulePath ?? fileURLToPath(new URL('../../../runtime/chat2local-operation.wasm', import.meta.url)) });
}
