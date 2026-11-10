export const SOCKET_LEASE_MS = 75_000;
export const DEVICE_FRAME_BYTES = 16 * 1024;
export const exact = (value, keys) => Boolean(value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)));
export const requestId = value => typeof value === 'string' && /^[a-f0-9-]{36}$/.test(value);
export const socketToken = value => typeof value === 'string' && /^[1-9][0-9]{0,15}$/.test(value);
export const epoch = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value) ? value : null;
const number = field => field?.kind === 'number' && Number.isFinite(field.value) ? field.value : null;
export function field(value, present = true) {
  if (!present) return { kind: 'missing' };
  if (value === null) return { kind: 'null' };
  if (typeof value === 'boolean') return { kind: 'boolean', value };
  if (typeof value === 'number' && Number.isFinite(value)) return { kind: 'number', value };
  return { kind: 'invalid' };
}
export function projectLease(value) {
  if (value === null) return { kind: 'null' };
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { kind: 'invalid' };
  return { kind: 'record', ...Object.fromEntries(['version', 'connectedAt', 'lastSeenAt', 'retired'].map(key => [key, field(value[key], Object.hasOwn(value, key))])) };
}
export function leaseDecision(command) {
  if (command.op === 'leaseRetire') return { patch: { version: 1, retired: true } };
  const now = number(command.now), lease = command.attachment;
  if (!command.open || now === null || now < 0) return { live: false, patch: null };
  if (lease.kind === 'null') return { live: true, patch: { version: 1, connectedAt: now, lastSeenAt: now, retired: false } };
  const connected = number(lease.connectedAt), seen = number(lease.lastSeenAt);
  const live = lease.kind === 'record' && number(lease.version) === 1 && lease.retired?.kind === 'boolean' && lease.retired.value === false
    && connected !== null && seen !== null && connected >= 0 && seen >= 0 && connected <= seen && seen <= now + 5000 && now - seen < SOCKET_LEASE_MS;
  return { live, patch: live && command.op === 'leaseTouch' ? { lastSeenAt: Math.max(now, seen) } : null };
}

/** Default backend; the Device adapter owns platform resources, never decisions. */
export class JsDeviceSessionCore {
  #pending = new Map();
  healthy = true;
  freeze() { this.healthy = false; }
  execute(command) {
    if (!this.healthy) throw Error('Device session core unavailable.');
    if (command.op.startsWith('lease')) return leaseDecision(command);
    if (command.op === 'admit') {
      const { identity, capability } = command;
      const reason = !identity.present || identity.revoked || !command.epoch || command.epoch !== identity.epoch ? 'revoked'
        : !command.live ? 'offline' : capability.required && !capability.supported ? 'capability'
        : this.#pending.has(command.id) ? 'duplicate' : this.#pending.size >= 12 ? 'busy' : null;
      if (!reason) this.#pending.set(command.id, command.socket);
      return { admitted: !reason, reason };
    }
    if (command.op === 'count') return { count: this.#pending.size };
    let ids;
    if (command.op === 'disconnect') ids = [...this.#pending].filter(([, token]) => command.socket === null || token === command.socket).map(([id]) => id);
    else if (['settle', 'timeout'].includes(command.op)) ids = command.id && this.#pending.get(command.id) === command.socket ? [command.id] : [];
    else throw Error('Invalid Device session command.');
    for (const id of ids) this.#pending.delete(id);
    return { consumed: ids };
  }
}

export function validResult(command, result) {
  if (command.op === 'leaseRetire') return exact(result, ['patch']) && exact(result.patch, ['version', 'retired']) && result.patch.version === 1 && result.patch.retired === true;
  if (['leaseObserve', 'leaseTouch'].includes(command.op)) {
    if (!exact(result, ['live', 'patch']) || typeof result.live !== 'boolean') return false;
    if (!result.live) return result.patch === null;
    if (command.attachment.kind === 'invalid') return false;
    if (command.attachment.kind === 'null') return command.open && number(command.now) !== null && number(command.now) >= 0
      && exact(result.patch, ['version', 'connectedAt', 'lastSeenAt', 'retired']) && result.patch.version === 1 && result.patch.retired === false
      && result.patch.connectedAt === number(command.now) && result.patch.connectedAt === result.patch.lastSeenAt;
    if (command.op === 'leaseObserve') return result.patch === null;
    return exact(result.patch, ['lastSeenAt']) && number(command.now) !== null && number(command.attachment.lastSeenAt) !== null
      && result.patch.lastSeenAt >= 0 && result.patch.lastSeenAt === Math.max(number(command.now), number(command.attachment.lastSeenAt));
  }
  if (command.op === 'admit') return exact(result, ['admitted', 'reason']) && typeof result.admitted === 'boolean'
    && (result.admitted ? result.reason === null : ['revoked', 'offline', 'capability', 'duplicate', 'busy'].includes(result.reason));
  if (command.op === 'count') return exact(result, ['count']) && Number.isInteger(result.count) && result.count >= 0 && result.count <= 12;
  return exact(result, ['consumed']) && Array.isArray(result.consumed) && result.consumed.length <= 12
    && result.consumed.every(requestId) && new Set(result.consumed).size === result.consumed.length;
}
