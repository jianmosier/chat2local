export function fakeWebSockets({ autoOpen = true } = {}) {
  return class FakeSocket extends EventTarget {
    static instances = [];
    constructor() { super(); this.readyState = 0; this.sent = []; this.constructor.instances.push(this); if (autoOpen) queueMicrotask(() => this.open()); }
    emit(type, data) { const event = new Event(type); if (data !== undefined) event.data = data; this.dispatchEvent(event); }
    open() { this.readyState = 1; this.emit('open'); }
    send(value) { this.sent.push(value); }
    close() { if (this.readyState === 3) return; this.readyState = 3; this.emit('close'); }
  };
}
export const bridgeIdentity = { origin: 'https://relay.example.test', deviceId: 'b'.repeat(32), deviceKey: 'c'.repeat(64) };
export const fakeBridgeOptions = () => ({ WebSocket: fakeWebSockets(), prepareNetwork: async () => {}, fetch: async () => Response.json({ ok: true }) });
export async function until(check, timeout = 3000) { const end = Date.now() + timeout; while (!check()) { if (Date.now() > end) throw Error('Fixture deadline'); await new Promise(resolve => setTimeout(resolve, 5)); } }
export function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
