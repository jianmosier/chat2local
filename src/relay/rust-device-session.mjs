import { DEVICE_FRAME_BYTES, exact, validResult } from './device-session-core.mjs';
const MAX_MEMORY = 16 * 1024 * 1024;

/** One non-recoverable instance per Device; no platform/credential imports. */
export class RustDeviceSessionCore {
  #exports; #input; #output; #serial = 0; #healthy = true;
  constructor(module, instantiate = value => new WebAssembly.Instance(value, {})) {
    try {
      if (!(module instanceof WebAssembly.Module) || WebAssembly.Module.imports(module).length) throw Error();
      const exports = instantiate(module).exports;
      if (!(exports.memory instanceof WebAssembly.Memory) || ['abi_version', 'frame_capacity', 'input_ptr', 'output_ptr', 'output_len', 'command'].some(key => typeof exports[key] !== 'function')
        || exports.abi_version() !== 1 || exports.frame_capacity() !== DEVICE_FRAME_BYTES) throw Error();
      this.#exports = exports; this.#input = exports.input_ptr(); this.#output = exports.output_ptr(); this.#bounds();
    } catch { this.#healthy = false; throw Error('Device session core unavailable.'); }
  }
  get healthy() { return this.#healthy; }
  freeze() { this.#healthy = false; }
  #bounds() {
    const size = this.#exports.memory.buffer.byteLength;
    if (size > MAX_MEMORY || !Number.isInteger(this.#input) || !Number.isInteger(this.#output) || this.#input < 0 || this.#output < 0
      || this.#input + DEVICE_FRAME_BYTES > size || this.#output + DEVICE_FRAME_BYTES > size || Math.abs(this.#input - this.#output) < DEVICE_FRAME_BYTES) throw Error();
  }
  execute(command) {
    if (!this.#healthy) throw Error('Device session core unavailable.');
    try {
      const serial = ++this.#serial;
      if (!Number.isSafeInteger(serial)) throw Error();
      const bytes = new TextEncoder().encode(JSON.stringify({ v: 1, serial, command }));
      if (bytes.length > DEVICE_FRAME_BYTES) throw Error();
      this.#bounds(); new Uint8Array(this.#exports.memory.buffer, this.#input, bytes.length).set(bytes);
      if (this.#exports.command(bytes.length) !== 0) throw Error();
      this.#bounds(); const length = this.#exports.output_len();
      if (!Number.isInteger(length) || length < 1 || length > DEVICE_FRAME_BYTES) throw Error();
      const response = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(this.#exports.memory.buffer, this.#output, length)));
      if (!exact(response, ['v', 'serial', 'result']) || response.v !== 1 || response.serial !== serial || !validResult(command, response.result)) throw Error();
      return response.result;
    } catch { this.#healthy = false; throw Error('Device session core unavailable.'); }
  }
}
