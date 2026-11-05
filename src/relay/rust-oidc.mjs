const FRAME_BYTES = 65536, MAX_MEMORY = 16 * 1024 * 1024;
const unavailable = () => Object.assign(new Error('OIDC decision core unavailable.'), { status: 503 });
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const safe = value => Number.isSafeInteger(value) && value >= 0;
const units = (value, start = 0, end = value.length) => Array.from({ length: end - start }, (_, i) => value.charCodeAt(start + i));
const text = value => String.fromCharCode(...value);
const rejected = new Map([
  ['Invalid sign-in continuation.', 400],
  ['Duplicate identity callback fields.', 401],
  ['Identity callback state is missing.', 401],
  ['This sign-in belongs to another browser or has expired.', 401],
  ['Identity provider did not complete this sign-in.', 401],
]);

/** Fresh instance per begin/callback invocation. No storage, fetch or crypto. */
export class RustOidcDecisionCore {
  #exports; #input; #output; #serial = 0; #healthy = true;
  constructor(module, instantiate = value => new WebAssembly.Instance(value, {})) {
    try {
      if (!(module instanceof WebAssembly.Module) || WebAssembly.Module.imports(module).length) throw Error();
      const exports = instantiate(module).exports;
      if (!(exports.memory instanceof WebAssembly.Memory) || ['abi_version', 'frame_capacity', 'input_ptr', 'output_ptr', 'output_len', 'command'].some(key => typeof exports[key] !== 'function')
        || exports.abi_version() !== 1 || exports.frame_capacity() !== FRAME_BYTES) throw Error();
      this.#exports = exports; this.#input = exports.input_ptr(); this.#output = exports.output_ptr(); this.#bounds();
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
      const serial = ++this.#serial;
      if (!safe(serial)) throw Error();
      const bytes = new TextEncoder().encode(JSON.stringify({ v: 1, serial, command }));
      if (bytes.length > FRAME_BYTES) throw Error();
      this.#bounds(); new Uint8Array(this.#exports.memory.buffer, this.#input, bytes.length).set(bytes);
      if (this.#exports.command(bytes.length) !== 0) throw Error();
      this.#bounds(); const length = this.#exports.output_len();
      if (!safe(length) || length < 1 || length > FRAME_BYTES) throw Error();
      const response = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(this.#exports.memory.buffer, this.#output, length)));
      if (!exact(response, ['v', 'serial', 'result']) || response.v !== 1 || response.serial !== serial) throw Error();
      const result = response.result;
      const simple = ['accepted', 'cookie', 'take'].includes(result?.kind) && exact(result, ['kind']);
      const comparison = result?.kind === 'comparing' && exact(result, ['kind', 'total', 'offset']) && safe(result.total) && safe(result.offset) && result.offset <= result.total;
      const code = result?.kind === 'code_accepted' && exact(result, ['kind', 'code']) && Array.isArray(result.code) && result.code.length > 0 && result.code.length <= 4096 && result.code.every(n => Number.isInteger(n) && n >= 0 && n <= 65535);
      const rejection = result?.kind === 'rejected' && exact(result, ['kind', 'status', 'message']) && rejected.get(result.message) === result.status;
      const expected = { begin: ['accepted'], callback_pre: ['cookie'], callback_cookie: ['take'], callback_after_take: ['code_accepted', 'comparing'], issuer_chunk: ['comparing'], issuer_finish: ['code_accepted'] }[command.kind];
      const reasons = { begin: ['Invalid sign-in continuation.'], callback_pre: ['Duplicate identity callback fields.', 'Identity callback state is missing.'], callback_cookie: ['This sign-in belongs to another browser or has expired.'], callback_after_take: ['Identity provider did not complete this sign-in.'], issuer_chunk: [], issuer_finish: ['Identity provider did not complete this sign-in.'] }[command.kind];
      if (!(simple || comparison || code || rejection) || !expected || (!rejection && !expected.includes(result.kind))) throw Error();
      if (rejection && !reasons.includes(result.message)) throw Error();
      if (comparison && command.kind === 'callback_after_take' && (result.total !== command.issuer_length16 || result.total !== command.expected_length16 || result.offset !== 0)) throw Error();
      return result;
    } catch { this.#healthy = false; throw unavailable(); }
  }
  #decision(command) {
    const result = this.execute(command);
    if (result.kind === 'rejected') throw Object.assign(new Error(result.message), { status: result.status });
    return result;
  }
  begin(returnPath, target, origin) {
    const isString = typeof returnPath === 'string', connection = target?.searchParams.get('connection') || '';
    return this.#decision({ kind: 'begin', is_string: isString, length16: isString ? returnPath.length : 0,
      prefix: isString ? units(returnPath, 0, Math.min(11, returnPath.length)) : [],
      target: target ? { same_origin: target.origin === origin, has_hash: !!target.hash,
        pathname_length16: target.pathname.length, pathname_prefix: units(target.pathname, 0, Math.min(12, target.pathname.length)),
        other_keys: [...target.searchParams.keys()].some(key => key !== 'connection'), connections: target.searchParams.getAll('connection').length,
        connection_length16: connection.length, connection: units(connection, 0, Math.min(33, connection.length)) } : null });
  }
  callbackPre(query) {
    const state = query.get('state');
    return this.#decision({ kind: 'callback_pre', counts: ['state', 'code', 'error', 'iss'].map(key => query.getAll(key).length), state: state?.length === 64 ? units(state) : null });
  }
  callbackCookie(cookie) { return this.#decision({ kind: 'callback_cookie', cookie: cookie === null ? null : units(cookie) }); }
  callbackAfterTake(query, issuer) {
    const code = query.get('code'), actual = query.get('iss');
    let result = this.#decision({ kind: 'callback_after_take', has_error: query.has('error'),
      code: { present: code !== null, length16: code?.length || 0, units: code === null ? [] : code.length <= 4096 ? units(code) : null },
      iss_present: query.has('iss'), issuer_length16: actual?.length || 0, expected_length16: issuer.length });
    if (result.kind === 'comparing') {
      let offset = 0;
      if (result.total !== actual.length || result.offset !== offset) { this.#healthy = false; throw unavailable(); }
      while (offset < actual.length) {
        const next = Math.min(offset + 512, actual.length);
        result = this.#decision({ kind: 'issuer_chunk', offset, actual: units(actual, offset, next), expected: units(issuer, offset, next) });
        if (result.total !== actual.length || result.offset !== next) { this.#healthy = false; throw unavailable(); }
        offset = next;
      }
      result = this.#decision({ kind: 'issuer_finish' });
    }
    return text(result.code);
  }
}
