export const lifecycleError = (code = 'ELIFECYCLE') => Object.assign(new Error(['EBUSY', 'ECLOSING'].includes(code)
  ? 'Local controller is busy or closing.' : 'Agent lifecycle failed; new work is frozen. Confirm existing effects before retrying.'), { code, status: 503 });
export const exact = (v, keys) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const token = v => typeof v === 'string' && /^(0|[1-9][0-9]{0,15})$/.test(v);
const integer = v => Number.isSafeInteger(v) && v >= 0;
export function validLifecycleValue(c, v) {
  if (!exact(v, ['result', 'effects']) || !Array.isArray(v.effects) || v.effects.length > 8) return false;
  for (const e of v.effects) {
    if (['clearBridge', 'cancelSetup', 'cancelPicker', 'drained'].includes(e?.type)) { if (!exact(e, ['type'])) return false; }
    else if (e?.type === 'runTicket') { if (!exact(e, ['type', 'ticket']) || !token(e.ticket) || e.ticket === '0') return false; }
    else if (['retireAttempt', 'cancelTimers', 'prepareNetwork', 'openSocket', 'sendPing', 'publishMetadata', 'armTimer'].includes(e?.type)) {
      if (!exact(e, ['type', 'generation', 'attempt', ...(e.type === 'armTimer' ? ['timer', 'at'] : [])]) || !token(e.generation) || !token(e.attempt)) return false;
      if (e.type === 'armTimer' && (!['connect', 'heartbeat', 'retry'].includes(e.timer) || !integer(e.at))) return false;
    } else return false;
  }
  const r = v.result;
  if (c.op === 'snapshot') return !v.effects.length && exact(r, ['phase', 'queueCount', 'selectionRevision', 'bridge'])
    && ['starting', 'running', 'closing', 'closed'].includes(r.phase) && integer(r.queueCount) && r.queueCount <= 24 && integer(r.selectionRevision)
    && exact(r.bridge, ['state', 'generation', 'attempt']) && ['not-configured', 'disconnected', 'connecting', 'connected', 'reconnecting'].includes(r.bridge.state) && token(r.bridge.generation) && token(r.bridge.attempt);
  if (c.op === 'admit') return exact(r, ['ticket']) && token(r.ticket) && r.ticket !== '0' && v.effects.length <= 1 && v.effects.every(e => e.type === 'runTicket' && e.ticket === r.ticket);
  if (c.op === 'finish') return r === null && v.effects.length === 1 && ['runTicket', 'drained'].includes(v.effects[0].type) && v.effects[0].ticket !== c.ticket;
  if (c.op === 'invalidateSelection') return integer(r) && v.effects.length === 2 && v.effects[0].type === 'cancelSetup' && v.effects[1].type === 'cancelPicker';
  if (['permitEffect', 'replyPermit'].includes(c.op)) return typeof r === 'boolean' && !v.effects.length;
  if (c.op === 'bridgeCall') return ['drop', 'duplicate', 'execute'].includes(r) && !v.effects.length;
  const allowed = { activate: [], finishClose: [], beginClose: ['clearBridge', 'cancelSetup', 'cancelPicker'], bridgeStop: ['clearBridge'], bridgeStart: ['clearBridge', 'armTimer', 'prepareNetwork'], bridgeEvent: ['armTimer', 'retireAttempt', 'openSocket', 'cancelTimers', 'publishMetadata', 'sendPing', 'prepareNetwork'] }[c.op];
  return r === null && allowed && v.effects.every(e => allowed.includes(e.type));
}

/** Default implementation of the same contract. Never instantiated for Rust. */
export class JsLifecycleCore {
  #phase = 'starting'; #queue = []; #ticket = 0; #revision = 0; #generation = 0; #attempt = 0; #retries = 0;
  #bridge = 'not-configured'; #step = 'stopped'; #deadline = 0; #pong = 0; #seen = new Set();
  execute(c) {
    const effects = [], effect = type => ({ type, generation: String(this.#generation), attempt: String(this.#attempt) });
    const timer = timer => ({ ...effect('armTimer'), timer, at: this.#deadline });
    const current = () => c.generation === String(this.#generation) && c.attempt === String(this.#attempt);
    const stop = () => { this.#generation++; this.#step = 'stopped'; this.#bridge = 'disconnected'; this.#deadline = 0; effects.push({ type: 'clearBridge' }); };
    const connect = () => { this.#attempt++; this.#step = 'preparing'; this.#bridge = 'connecting'; this.#deadline = c.now + 15000; effects.push(timer('connect'), effect('prepareNetwork')); };
    const retry = () => { effects.push(effect('retireAttempt')); this.#step = 'retry'; this.#bridge = 'reconnecting'; this.#deadline = c.now + Math.min(30000, 1000 * 2 ** Math.min(this.#retries++, 5)) + c.jitter; effects.push(timer('retry')); };
    let result = null;
    switch (c.op) {
      case 'snapshot': result = { phase: this.#phase, queueCount: this.#queue.length, selectionRevision: this.#revision, bridge: { state: this.#bridge, generation: String(this.#generation), attempt: String(this.#attempt) } }; break;
      case 'activate': if (this.#phase !== 'starting') throw lifecycleError('ESTATE'); this.#phase = 'running'; break;
      case 'beginClose': if (!['closing', 'closed'].includes(this.#phase)) { this.#phase = 'closing'; this.#revision++; stop(); effects.push({ type: 'cancelSetup' }, { type: 'cancelPicker' }); } break;
      case 'finishClose': if (this.#phase !== 'closing' || this.#queue.length) throw lifecycleError('ESTATE'); this.#phase = 'closed'; break;
      case 'admit': if (!Number.isInteger(c.capacity) || c.capacity < 1 || c.capacity > 24) throw lifecycleError('EINPUT');
        if (['closing', 'closed'].includes(this.#phase) || this.#queue.length >= c.capacity) throw lifecycleError('EBUSY'); result = { ticket: String(++this.#ticket) }; this.#queue.push(result.ticket); if (this.#queue.length === 1) effects.push({ type: 'runTicket', ticket: result.ticket }); break;
      case 'finish': if (this.#queue[0] !== c.ticket) throw lifecycleError('ETICKET'); this.#queue.shift(); effects.push(this.#queue.length ? { type: 'runTicket', ticket: this.#queue[0] } : { type: 'drained' }); break;
      case 'invalidateSelection': result = ++this.#revision; effects.push({ type: 'cancelSetup' }, { type: 'cancelPicker' }); break;
      case 'permitEffect': result = this.#phase === 'running'; break;
      case 'bridgeStop': stop(); break;
      case 'bridgeStart': if (this.#phase !== 'running') throw lifecycleError('ECLOSING'); stop(); this.#retries = 0; if (c.hasIdentity) connect(); else this.#bridge = 'not-configured'; break;
      case 'bridgeEvent':
        if (this.#phase !== 'running' || !current() || this.#step === 'stopped') break;
        if (c.event === 'retry' && this.#step === 'retry' && c.now >= this.#deadline) { effects.push(effect('retireAttempt')); connect(); }
        else if (c.event === 'prepared' && this.#step === 'preparing') { if (c.now >= this.#deadline) retry(); else { this.#step = 'connecting'; effects.push(effect('openSocket')); } }
        else if (c.event === 'open' && this.#step === 'connecting') { if (c.now >= this.#deadline) retry(); else { effects.push(effect('cancelTimers')); this.#step = 'connected'; this.#bridge = 'connected'; this.#retries = 0; this.#pong = c.now; this.#deadline = c.now + 25000; effects.push(timer('heartbeat'), effect('publishMetadata')); } }
        else if (c.event === 'pong' && this.#step === 'connected') this.#pong = c.now;
        else if (c.event === 'heartbeat' && this.#step === 'connected' && c.now >= this.#deadline) { if (c.now - this.#pong > 65000) retry(); else { effects.push(effect('sendPing')); this.#deadline = c.now + 25000; effects.push(timer('heartbeat')); } }
        else if (c.event === 'connect' && ['preparing', 'connecting'].includes(this.#step) && c.now >= this.#deadline) retry();
        else if (['failed', 'close'].includes(c.event) && this.#step !== 'retry') retry(); break;
      case 'replyPermit': result = c.open && this.#phase === 'running' && this.#step === 'connected' && current(); break;
      case 'bridgeCall': result = this.#phase !== 'running' || this.#step !== 'connected' || !current() ? 'drop' : this.#seen.has(c.id) ? 'duplicate' : 'execute';
        if (result === 'execute') { this.#seen.add(c.id); if (this.#seen.size > 1000) this.#seen.delete(this.#seen.values().next().value); } break;
      default: throw lifecycleError('EINPUT');
    }
    return { result, effects };
  }
}

/** Host resources/fault latch only; the core owns healthy decisions. */
export class AgentLifecycle {
  #core; #handlers = new Set(); #faultHandlers = new Set(); #abort = new AbortController(); #closeAbort = new AbortController(); #fault = null;
  constructor(core = new JsLifecycleCore()) { this.#core = core; }
  get fault() { return this.#fault; }
  get healthy() { return this.fault === null; }
  get signal() { return this.#abort.signal; }
  get closeSignal() { return this.#closeAbort.signal; }
  onEffect(fn) { this.#handlers.add(fn); }
  onFault(fn) { this.#faultHandlers.add(fn); }
  poison(error = lifecycleError()) { if (this.#fault) return; this.#fault = error; this.#abort.abort(lifecycleError()); for (const fn of this.#faultHandlers) { try { fn(error); } catch {} } }
  call(command) { if (this.fault) throw lifecycleError(); try { const v = this.#core.execute(command); if (!validLifecycleValue(command, v)) throw lifecycleError(); return v; } catch (error) { if (!['EBUSY', 'ECLOSING'].includes(error.code)) this.poison(error); throw error; } }
  apply(v) { if (!this.healthy) return; try { for (const e of v.effects) for (const fn of this.#handlers) fn(e); } catch (error) { this.poison(error); throw error; } }
  run(c) { const v = this.call(c); this.apply(v); return v.result; }
  snapshot() { if (!this.fault) { try { return this.run({ op: 'snapshot' }); } catch {} } return { phase: 'faulted', queueCount: null, selectionRevision: null, bridge: { state: 'disconnected' } }; }
  permit() { if (!this.run({ op: 'permitEffect' })) throw lifecycleError('ECLOSING'); }
  beginClose() { try { if (this.healthy) this.run({ op: 'beginClose' }); } finally { this.#abort.abort(lifecycleError('ECLOSING')); this.#closeAbort.abort(lifecycleError('ECLOSING')); } }
  async wait(work, attemptSignal) {
    this.permit();
    return new Promise((resolve, reject) => {
      const signals = [this.signal, ...(attemptSignal ? [attemptSignal] : [])]; let settled = false;
      const finish = (error, value) => { if (settled) return; settled = true; for (const signal of signals) signal.removeEventListener('abort', abort); if (error) reject(error); else resolve(value); };
      const abort = () => finish(signals.find(signal => signal.aborted)?.reason ?? lifecycleError('ECLOSING'));
      for (const signal of signals) signal.addEventListener('abort', abort, { once: true });
      if (signals.some(signal => signal.aborted)) abort();
      Promise.resolve(work).then(value => { if (settled) return; try { this.permit(); finish(null, value); } catch (error) { finish(error); } }, error => finish(error));
    });
  }
}
