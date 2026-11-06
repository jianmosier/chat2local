const FRAME_BYTES = 65536, MAX_WIRE = 16 * 1024 * 1024, MAX_MEMORY = 256 * 1024 * 1024;
const unavailable = () => Object.assign(new Error('OIDC token core unavailable.'), { status: 503 });
const exact = (v, keys) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const safe = n => Number.isSafeInteger(n) && n >= 0;
const units = s => Array.from({ length: s.length }, (_, i) => s.charCodeAt(i));
const text = units => { let s = ''; for (let i = 0; i < units.length; i += 8192) s += String.fromCharCode(...units.slice(i, i + 8192)); return s; };
const bits = n => { const buffer = new ArrayBuffer(8), view = new DataView(buffer); view.setFloat64(0, n); return view.getBigUint64(0).toString(16).padStart(16, '0'); };
const scalar = value => {
  if (value === undefined) return { type: 'undefined' };
  if (value === null) return { type: 'null' };
  if (typeof value === 'boolean') return { type: 'bool', value };
  if (typeof value === 'number') return { type: 'number', bits: bits(value) };
  if (typeof value === 'string') return value.length > 32768 ? { type: 'long_string', length16: value.length } : { type: 'string', units: units(value) };
  if (typeof value === 'object') return { type: Array.isArray(value) ? 'array' : 'object' };
  throw unavailable();
};
const nowPacket = value => {
  if (typeof value === 'string') return { now: { type: 'string', units: units(value) }, now_graph: null };
  if (!value || typeof value !== 'object') return { now: scalar(value), now_graph: null };
  const queue = [value], seen = new Map([[value, 0]]), nodes = [];
  const ref = value => { if (value && typeof value === 'object' && seen.has(value)) return seen.get(value); const id = queue.length; queue.push(value); if (value && typeof value === 'object') seen.set(value, id); return id; };
  for (let i = 0; i < queue.length; i++) {
    if (queue.length > 2 * 1024 * 1024) throw unavailable();
    const item = queue[i];
    if (item && typeof item === 'object') {
      const blocked = Object.hasOwn(item, 'toString');
      nodes.push(Array.isArray(item) ? { tag: 'array', items: Array.from(item, ref), blocked } : { tag: 'object', blocked });
    } else nodes.push({ tag: 'scalar', value: typeof item === 'string' ? { type: 'string', units: units(item) } : scalar(item) });
  }
  return { now: scalar(value), now_graph: nodes };
};
const messages = new Set(['Invalid identity token.', 'Malformed identity token.', 'Unsupported identity signature.', 'Invalid identity key set.', 'Unknown or invalid identity signing key.', 'Identity token signature or claims did not verify.', 'Identity issuer or audience mismatch.', 'Identity token is expired or outside this login window.', 'Identity nonce or subject mismatch.', 'Invalid identity access-token binding.', 'Identity access-token binding mismatch.']);
const validUnits = v => Array.isArray(v) && v.every(c => Number.isInteger(c) && c >= 0 && c <= 65535);

/** Request-private, public-key-only verifier. Host supplies no crypto verdict. */
export class RustOidcTokenVerifier {
  #exports; #input; #output; #serial = 0; #healthy = true; #used = false;
  constructor(module, instantiate = module => new WebAssembly.Instance(module, {})) {
    try {
      if (!(module instanceof WebAssembly.Module) || WebAssembly.Module.imports(module).length) throw Error();
      const e = instantiate(module).exports;
      if (!(e.memory instanceof WebAssembly.Memory) || ['abi_version', 'frame_capacity', 'input_ptr', 'output_ptr', 'output_len', 'command'].some(k => typeof e[k] !== 'function') || e.abi_version() !== 1 || e.frame_capacity() !== FRAME_BYTES) throw Error();
      this.#exports = e; this.#input = e.input_ptr(); this.#output = e.output_ptr(); this.#bounds();
    } catch { this.#healthy = false; throw unavailable(); }
  }
  get healthy() { return this.#healthy; }
  #bounds() {
    const size = this.#exports.memory.buffer.byteLength;
    if (size > MAX_MEMORY || !safe(this.#input) || !safe(this.#output) || this.#input + FRAME_BYTES > size || this.#output + FRAME_BYTES > size || Math.abs(this.#input - this.#output) < FRAME_BYTES) throw Error();
  }
  execute(command) {
    if (!this.#healthy) throw unavailable();
    try {
      const serial = ++this.#serial; if (!safe(serial)) throw Error();
      const data = new TextEncoder().encode(JSON.stringify({ v: 1, serial, command })); if (data.length > FRAME_BYTES) throw Error();
      this.#bounds(); new Uint8Array(this.#exports.memory.buffer, this.#input, data.length).set(data);
      if (this.#exports.command(data.length) !== 0) throw Error();
      this.#bounds(); const length = this.#exports.output_len(); if (!safe(length) || length < 1 || length > FRAME_BYTES) throw Error();
      const response = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(this.#exports.memory.buffer, this.#output, length)));
      if (!exact(response, ['v', 'serial', 'result']) || response.v !== 1 || response.serial !== serial) throw Error();
      const r = response.result;
      const stage = { start: 'upload', chunk: 'upload', eof: 'url', skew: 'clock', claims: 'output', output: 'output_chunk' }[command.kind];
      if (!stage) throw Error();
      if (r?.kind === 'unavailable' && exact(r, ['kind'])) return r;
      if (r?.kind === 'error' && exact(r, ['kind', 'message', 'status']) && r.status === 401 && messages.has(r.message)) return r;
      if (r?.kind === 'native' && command.kind === 'eof' && exact(r, ['kind', 'property']) && ['kid', 'iss'].includes(r.property)) return r;
      if (r?.kind === 'native_coercion' && command.kind === 'skew' && exact(r, ['kind'])) return r;
      if (r?.kind !== stage) throw Error();
      if (stage === 'upload') { if (!exact(r, ['kind', 'offset']) || r.offset !== (command.kind === 'start' ? 0 : command.offset + command.bytes.length)) throw Error(); }
      else if (stage === 'output') { if (!exact(r, ['kind', 'length']) || !safe(r.length) || r.length < 1 || r.length > MAX_WIRE) throw Error(); }
      else if (stage === 'output_chunk') { if (!exact(r, ['kind', 'offset', 'bytes', 'eof']) || r.offset !== command.offset || typeof r.eof !== 'boolean' || !Array.isArray(r.bytes) || !r.bytes.length || r.bytes.length > 8192 || r.bytes.some(b => !Number.isInteger(b) || b < 0 || b > 255)) throw Error(); }
      else if (!exact(r, ['kind'])) throw Error();
      return r;
    } catch { this.#healthy = false; throw unavailable(); }
  }
  #result(command) {
    const result = this.execute(command);
    if (result.kind === 'unavailable') { this.#healthy = false; throw unavailable(); }
    if (result.kind === 'error') throw Object.assign(new Error(result.message), { status: result.status });
    if (result.kind === 'native') { const value = null; return value[result.property]; }
    return result;
  }
  async verify(token, jwksText, { issuer, clientId, nonce, now = Date.now(), accessToken } = {}) {
    if (this.#used) { this.#healthy = false; throw unavailable(); } this.#used = true;
    if (typeof jwksText !== 'string' || jwksText.length > 4 * 1024 * 1024) throw unavailable();
    const data = new TextEncoder().encode(JSON.stringify({ token: scalar(token), jwks: units(jwksText), issuer: scalar(issuer), client_id: scalar(clientId), nonce: scalar(nonce), ...nowPacket(now), access: scalar(accessToken) }));
    if (data.length > MAX_WIRE) throw unavailable();
    this.#result({ kind: 'start', length: data.length });
    for (let offset = 0; offset < data.length; offset += 8192) this.#result({ kind: 'chunk', offset, bytes: [...data.subarray(offset, offset + 8192)] });
    this.#result({ kind: 'eof' });
    // Original URL primitive occurs after wrapper/key prechecks and before skew.
    new URL('.well-known/jwks.json', issuer);
    const skew = this.#result({ kind: 'skew', bits: bits(Date.now()) });
    if (skew.kind === 'native_coercion') { Number(now); throw unavailable(); }
    // The SDK samples wall time again when its JWT claims phase is reached.
    await Promise.resolve();
    const ready = this.#result({ kind: 'claims', bits: bits(Date.now()) });
    let result;
    try {
      const bytes = new Uint8Array(ready.length); let offset = 0;
      while (offset < bytes.length) {
        const part = this.#result({ kind: 'output', offset });
        if (part.bytes.length !== Math.min(8192, bytes.length - offset) || part.eof !== (offset + part.bytes.length === bytes.length)) throw Error();
        bytes.set(part.bytes, offset); offset += part.bytes.length;
      }
      result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      if (!exact(result, ['kind', 'issuer', 'subject', 'displayName']) || result.kind !== 'identity' || ![result.issuer, result.subject, result.displayName].every(validUnits) || result.issuer.length > 32768 || result.subject.length > 255 || result.displayName.length > 120) throw Error();
    } catch { this.#healthy = false; throw unavailable(); }
    return { issuer: text(result.issuer), subject: text(result.subject), displayName: text(result.displayName) };
  }
}
