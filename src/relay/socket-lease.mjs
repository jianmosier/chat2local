// Relay-side heartbeat lease. The agent already sends ping every 25 seconds.
// Persist connection-only metadata in WebSocket attachments so hibernation and
// status polling cannot reset the timeout. No device keys or file data are stored.
import { field, projectLease, leaseDecision, validResult, SOCKET_LEASE_MS } from './device-session-core.mjs';
export { SOCKET_LEASE_MS };
const decide = (core, command) => {
  const result = core ? core.execute(command) : leaseDecision(command);
  if (!validResult(command, result)) throw Error('Invalid lease decision.');
  return result;
};

function validTime(value) { return Number.isFinite(value) && value >= 0; }
export function readLease(socket) {
  try { return socket.deserializeAttachment(); } catch { return undefined; }
}
export function startLease(socket, now = Date.now(), core) {
  if (!validTime(now)) throw new Error('Invalid connection timestamp.');
  const lease = decide(core, { op: 'leaseObserve', attachment: { kind: 'null' }, open: true, now: field(now) }).patch;
  socket.serializeAttachment(lease);
  return lease;
}
export function socketIsLive(socket, now = Date.now(), core) {
  const lease = readLease(socket);
  // Existing pre-lease connections get ONE grace interval on first observation.
  // Persist it immediately: repeated /describe or /connect calls cannot renew it.
  const result = decide(core, { op: 'leaseObserve', attachment: projectLease(lease), open: socket.readyState === 1, now: field(now) });
  if (result.patch) { try { socket.serializeAttachment(Object.assign(lease ?? {}, result.patch)); } catch { return false; } }
  return result.live;
}
export function touchLease(socket, now = Date.now(), core) {
  const lease = readLease(socket);
  const result = decide(core, { op: 'leaseTouch', attachment: projectLease(lease), open: socket.readyState === 1, now: field(now) });
  if (result.patch) socket.serializeAttachment(Object.assign(lease ?? {}, result.patch));
  return result.live;
}
export function retireSocket(socket, reason = 'Connection heartbeat expired', core) {
  // The marker also excludes a socket that remains CLOSING until a close reply.
  const lease = readLease(socket);
  const patch = decide(core, { op: 'leaseRetire' }).patch;
  try { socket.serializeAttachment(Object.assign(lease && typeof lease === 'object' ? lease : {}, patch)); } catch {}
  try { socket.close(1000, reason); } catch {}
}

/** Old-socket close/error must not fail new-socket requests. A timed-out or
 * disconnected operation has an unknown outcome; it is never queued for replay.
 */
export function failSocketPending(pending, socket, response) {
  for (const [id, operation] of pending) {
    if (socket && operation.socket !== socket) continue;
    clearTimeout(operation.timer);
    pending.delete(id);
    operation.resolve(response());
  }
}
