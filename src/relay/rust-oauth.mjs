// Request-private primitive host. No provider/authorization callback or fallback.
const FRAME = 1_048_576, MEMORY = 256 * 1024 * 1024, MAX_WIRE = 160 * 1024 * 1024;
const unavailable = () => Object.assign(new Error('OAuth core unavailable.'), { code: 'EOAUTHCORE' });
const units = value => Array.from({ length: value.length }, (_, i) => value.charCodeAt(i));
const urlParts = value => { const url = new URL(value); return { origin: url.origin, pathname: url.pathname, search: url.search }; };
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === fields.split(' ').sort().join(',');
function bytes(value) { if (typeof value !== 'string' || value.length > 36 * 1024 * 1024) throw unavailable(); const decoded = atob(value); return Uint8Array.from(decoded, c => c.charCodeAt(0)); }
function base64(value) { let encoded = ''; const bytes = new Uint8Array(value); for (let i=0;i<bytes.length;i+=16384) encoded += String.fromCharCode(...bytes.subarray(i,i+16384)); return btoa(encoded); }
export class Wire {
  constructor(module, instantiate, version = 1) {
    if (!(module instanceof WebAssembly.Module) || WebAssembly.Module.imports(module).length) throw unavailable();
    this.e = instantiate(module).exports; this.serial = 0; this.version = version;
    if (!(this.e.memory instanceof WebAssembly.Memory) || ['abi_version','frame_capacity','input_ptr','output_ptr','input_begin','input_append','output_read','output_len','command'].some(k => typeof this.e[k] !== 'function') || this.e.abi_version() !== 1 || this.e.frame_capacity() !== FRAME) throw unavailable();
    if (version === 2 && (this.e.provider_abi_version?.() !== 2 || typeof this.e.provider_command !== 'function')) throw unavailable();
    this.input = this.e.input_ptr(); this.output = this.e.output_ptr(); this.bounds();
  }
  bounds() { const size = this.e.memory.buffer.byteLength; if (size > MEMORY || ![this.input,this.output].every(n => Number.isInteger(n) && n >= 0 && n + FRAME <= size) || Math.abs(this.input - this.output) < FRAME) throw unavailable(); }
  call(command) {
    const serial = ++this.serial, input = new TextEncoder().encode(JSON.stringify({ v:this.version, serial, command }));
    if (input.length > MAX_WIRE || this.e.input_begin(input.length) !== 0) throw unavailable();
    for (let offset=0;offset<input.length;offset+=FRAME) { const chunk = input.subarray(offset,offset+FRAME); this.bounds(); new Uint8Array(this.e.memory.buffer,this.input,chunk.length).set(chunk); if (this.e.input_append(chunk.length) !== 0) throw unavailable(); }
    if ((this.version === 2 ? this.e.provider_command(input.length) : this.e.command(input.length)) !== 0) throw unavailable();
    this.bounds(); const length = this.e.output_len();
    if (!Number.isInteger(length) || length < 1 || length > MAX_WIRE) throw unavailable();
    const output = new Uint8Array(length);
    for (let offset=0;offset<length;offset+=FRAME) { const count=this.e.output_read(offset); this.bounds(); if (count !== Math.min(FRAME,length-offset)) throw unavailable(); output.set(new Uint8Array(this.e.memory.buffer,this.output,count),offset); }
    const result = JSON.parse(new TextDecoder('utf-8', { fatal:true }).decode(output));
    if (!exact(result, 'v serial result') || result.v !== this.version || result.serial !== serial) throw unavailable();
    return result.result;
  }
  close() { try { new Uint8Array(this.e.memory.buffer).fill(0); } finally { this.e = null; } }
}
export class RustOAuthBearer {
  constructor(module, { instantiate = module => new WebAssembly.Instance(module, {}), now = () => Date.now() } = {}) { this.module = module; this.instantiate = instantiate; this.now = now; }
  async authenticate(request, env, { resource, scopes }) {
    let wire; const keys = new Map(); let sequence = 0;
    try {
      wire = new Wire(this.module, this.instantiate);
      let result = wire.call({ type:'start', header:request.headers.get('Authorization') === null ? null : units(request.headers.get('Authorization')), resource, scopes, url:urlParts(request.url) });
      const order = ['kv_get','clock','url_parse','import_key','unwrap_key','decrypt'];
      for (;;) {
        if (result?.kind === 'reject') {
          if (sequence > 3 || !exact(result, 'kind status headers body') || result.status !== 401 || !(result.body === null || typeof result.body === 'string') || !result.headers || typeof result.headers !== 'object' || Array.isArray(result.headers) || Object.values(result.headers).some(v => typeof v !== 'string')) throw unavailable();
          return { response:new Response(result.body, { status:result.status, headers:result.headers }) };
        }
        if (result?.kind === 'accept') {
          if (sequence !== order.length || !exact(result, 'kind propsJson') || typeof result.propsJson !== 'string') throw unavailable();
          return { props:JSON.parse(result.propsJson) };
        }
        if (!exact(result, 'kind sequence op') || result.kind !== 'effect' || result.sequence !== ++sequence || sequence > order.length || result.op?.type !== order[sequence - 1]) throw unavailable();
        const op = result.op; let value;
        switch (op.type) {
          case 'kv_get':
            if (!exact(op, 'type key') || typeof op.key !== 'string' || !op.key.startsWith('token:')) throw unavailable();
            // Only the single exact key emitted by this request's core can be read.
            { const text = await env.OAUTH_KV.get(op.key, { type:'text' }); if (text !== null && typeof text !== 'string') throw unavailable(); value = { type:'kv', text }; } break;
          case 'clock':
            if (!exact(op, 'type')) throw unavailable();
            value = { type:'clock', millis:this.now() }; break;
          case 'url_parse':
            if (!exact(op, 'type input') || typeof op.input !== 'string') throw unavailable();
            { let parsed = null; try { parsed = urlParts(op.input); } catch { /* WHATWG parse failure is data. */ } value = { type:'url', value:parsed }; } break;
          case 'import_key':
            if (!exact(op, 'type format bytes algorithm extractable usages') || op.format !== 'raw' || op.algorithm !== 'AES-KW' || op.extractable !== false || JSON.stringify(op.usages) !== '["wrapKey","unwrapKey"]') throw unavailable();
            keys.set(sequence, await crypto.subtle.importKey(op.format, bytes(op.bytes), { name:op.algorithm }, op.extractable, op.usages)); value = { type:'key', id:sequence }; break;
          case 'unwrap_key':
            if (!exact(op, 'type key format bytes algorithm unwrappedAlgorithm extractable usages') || op.key !== sequence - 1 || !keys.has(op.key) || op.format !== 'raw' || op.algorithm !== 'AES-KW' || op.unwrappedAlgorithm !== 'AES-GCM' || op.extractable !== true || JSON.stringify(op.usages) !== '["encrypt","decrypt"]') throw unavailable();
            keys.set(sequence, await crypto.subtle.unwrapKey(op.format, bytes(op.bytes), keys.get(op.key), { name:op.algorithm }, { name:op.unwrappedAlgorithm }, op.extractable, op.usages)); keys.delete(op.key); value = { type:'key', id:sequence }; break;
          case 'decrypt':
            if (!exact(op, 'type key algorithm iv bytes') || op.key !== sequence - 1 || !keys.has(op.key) || op.algorithm !== 'AES-GCM' || JSON.stringify(op.iv) !== '[0,0,0,0,0,0,0,0,0,0,0,0]') throw unavailable();
            value = { type:'bytes', base64:base64(await crypto.subtle.decrypt({ name:op.algorithm, iv:new Uint8Array(op.iv) }, keys.get(op.key), bytes(op.bytes))) }; keys.delete(op.key); break;
          default: throw unavailable();
        }
        result = wire.call({ type:'resume', sequence, value });
      }
    } catch { throw unavailable(); }
    finally { keys.clear(); if (wire) wire.close(); }
  }
}
