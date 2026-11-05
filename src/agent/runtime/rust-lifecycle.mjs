import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AgentLifecycle, JsLifecycleCore, exact, validLifecycleValue, lifecycleError } from './lifecycle-core.mjs';
const FRAME = 65536, MAX = 16 * 1024 * 1024;
function bounded(bytes) {
  let offset = 8, found = false;
  const leb = end => { let n = 0, shift = 0; for (let i = 0; i < 5 && offset < end; i++) { const b = bytes[offset++]; n += (b & 127) * 2 ** shift; if (!(b & 128)) return n; shift += 7; } throw lifecycleError(); };
  while (offset < bytes.length) { const section = bytes[offset++], length = leb(bytes.length), end = offset + length; if (end > bytes.length) throw lifecycleError();
    if (section === 5) { if (found || leb(end) !== 1 || leb(end) !== 1) throw lifecycleError(); const initial = leb(end), max = leb(end); if (max !== MAX / 65536 || initial > max || offset !== end) throw lifecycleError(); found = true; } offset = end; }
  if (!found) throw lifecycleError();
}
export class RustLifecycleCore {
  #exports; #serial = 0; #healthy = true; #input; #output;
  constructor({ modulePath, instantiate = module => new WebAssembly.Instance(module, {}) } = {}) {
    try { if (!path.isAbsolute(modulePath)) throw lifecycleError(); const bytes = fs.readFileSync(modulePath); if (bytes.length > 4 * 1024 * 1024) throw lifecycleError();
      bounded(bytes); const module = new WebAssembly.Module(bytes); if (WebAssembly.Module.imports(module).length) throw lifecycleError(); this.#exports = instantiate(module).exports; const e = this.#exports;
      if (!(e.memory instanceof WebAssembly.Memory) || ['abi_version', 'frame_capacity', 'input_ptr', 'output_ptr', 'output_len', 'command'].some(k => typeof e[k] !== 'function') || e.abi_version() !== 1 || e.frame_capacity() !== FRAME) throw lifecycleError();
      this.#input = e.input_ptr(); this.#output = e.output_ptr(); this.#bounds();
    } catch { this.#healthy = false; throw lifecycleError(); }
  }
  #bounds() { const size = this.#exports.memory.buffer.byteLength; if (size > MAX || [this.#input, this.#output].some(p => !Number.isInteger(p) || p < 0 || p + FRAME > size) || Math.abs(this.#input - this.#output) < FRAME) throw lifecycleError(); }
  execute(command) {
    if (!this.#healthy) throw lifecycleError(); let r;
    try { const serial = ++this.#serial, bytes = Buffer.from(JSON.stringify({ v: 1, serial, command })); if (bytes.length > FRAME || !Number.isSafeInteger(serial)) throw lifecycleError(); this.#bounds(); new Uint8Array(this.#exports.memory.buffer, this.#input, bytes.length).set(bytes);
      if (this.#exports.command(bytes.length) !== 0) throw lifecycleError(); this.#bounds(); const length = this.#exports.output_len(); if (!Number.isInteger(length) || length < 1 || length > FRAME) throw lifecycleError();
      r = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(this.#exports.memory.buffer, this.#output, length)));
      if (!exact(r, ['v', 'serial', 'ok', r?.ok === true ? 'value' : 'error']) || r.v !== 1 || r.serial !== serial || typeof r.ok !== 'boolean' || (r.ok ? !validLifecycleValue(command, r.value) : !['EBUSY', 'ECLOSING', 'ESTATE', 'ETICKET', 'EINPUT'].includes(r.error))) throw lifecycleError();
    } catch { this.#healthy = false; throw lifecycleError(); }
    if (!r.ok) throw lifecycleError(r.error); return r.value;
  }
}
export function configuredLifecycle(options = {}, environment = process.env) {
  const backend = options.lifecycleBackend ?? environment.CHAT2LOCAL_LIFECYCLE_BACKEND ?? 'js'; if (!['js', 'rust'].includes(backend)) throw new Error('Unsupported lifecycle backend.');
  return new AgentLifecycle(options.lifecycleCore ?? (backend === 'js' ? new JsLifecycleCore() : new RustLifecycleCore({ modulePath: options.lifecycleModulePath ?? environment.CHAT2LOCAL_LIFECYCLE_MODULE ?? fileURLToPath(new URL('../../../runtime/chat2local-agent-lifecycle.wasm', import.meta.url)) })));
}
