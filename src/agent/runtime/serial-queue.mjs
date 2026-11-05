import { AgentLifecycle, lifecycleError } from './lifecycle-core.mjs';
/** Promise resources only; the core chooses admission, order and completion. */
export class SerialQueue {
  #jobs = new Map(); #drains = new Set();
  constructor({ capacity = 24, isClosing = () => false, lifecycle = new AgentLifecycle() } = {}) {
    Object.assign(this, { capacity, isClosing, lifecycle });
    lifecycle.onEffect(e => {
      if (e.type === 'runTicket') {
        const job = this.#jobs.get(e.ticket); if (!job || job.started || [...this.#jobs.values()].some(item => item.started)) throw lifecycleError(); job.started = true;
        queueMicrotask(async () => {
          let value, error;
          try { if (!lifecycle.healthy) throw lifecycleError(); value = await job.action(); } catch (caught) { error = caught; }
          this.#jobs.delete(e.ticket);
          try { lifecycle.run({ op: 'finish', ticket: e.ticket }); } catch (caught) { lifecycle.poison(caught); }
          // Confirmed business outcome survives a failed core completion.
          if (error) job.reject(error); else job.resolve(value);
          if (!lifecycle.healthy) this.#settleDrains();
        });
      } else if (e.type === 'drained') { if (this.#jobs.size) throw lifecycleError(); this.#settleDrains(); }
    });
    lifecycle.onFault(() => { for (const [ticket, job] of this.#jobs) if (!job.started) { this.#jobs.delete(ticket); job.reject(lifecycleError()); } this.#settleDrains(); });
  }
  get size() { return this.lifecycle.healthy ? this.lifecycle.snapshot().queueCount : this.#jobs.size; }
  run(action) {
    try {
      if (this.isClosing()) throw lifecycleError('ECLOSING'); const response = this.lifecycle.call({ op: 'admit', capacity: this.capacity });
      if (this.#jobs.has(response.result.ticket) || (!this.#jobs.size && response.effects.length !== 1)) { this.lifecycle.poison(); throw lifecycleError(); }
      const promise = new Promise((resolve, reject) => this.#jobs.set(response.result.ticket, { action, resolve, reject, started: false }));
      try { this.lifecycle.apply(response); } catch (error) { this.lifecycle.poison(error); } return promise;
    } catch (error) { return Promise.reject(error); }
  }
  #settleDrains() { if (this.#jobs.size) return; for (const resolve of this.#drains) resolve(); this.#drains.clear(); }
  drain() {
    if (this.lifecycle.healthy) {
      const count = this.lifecycle.snapshot().queueCount;
      if (count !== this.#jobs.size) this.lifecycle.poison();
      else if (count === 0) return Promise.resolve();
    }
    return this.#jobs.size ? new Promise(resolve => this.#drains.add(resolve)) : Promise.resolve();
  }
}
