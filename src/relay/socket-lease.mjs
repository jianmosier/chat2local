// Relay-side heartbeat lease. The agent already sends ping every 25 seconds.
// Persist connection-only metadata in WebSocket attachments so hibernation and
// status polling cannot reset the timeout. No device keys or file data are stored.
export const SOCKET_LEASE_MS = 75_000;

function validTime(value) { return Number.isFinite(value) && value >= 0; }
export function readLease(socket) {
  try { return socket.deserializeAttachment(); } catch { return undefined; }
}
export function startLease(socket, now = Date.now()) {
  if (!validTime(now)) throw new Error('Invalid connection timestamp.');
  const lease = { version: 1, connectedAt: now, lastSeenAt: now, retired: false };
  socket.serializeAttachment(lease);
  return lease;
}
export function socketIsLive(socket, now = Date.now()) {
  if (socket.readyState !== 1 || !validTime(now)) return false;
  let lease = readLease(socket);
  // Existing pre-lease connections get ONE grace interval on first observation.
  // Persist it immediately: repeated /describe or /connect calls cannot renew it.
  if (lease === null) {
    try { lease = startLease(socket, now); } catch { return false; }
  }
  return Boolean(lease?.version === 1 && lease.retired === false
    && validTime(lease.connectedAt) && validTime(lease.lastSeenAt)
    && lease.connectedAt <= lease.lastSeenAt && lease.lastSeenAt <= now + 5000
    && now - lease.lastSeenAt < SOCKET_LEASE_MS);
}
export function touchLease(socket, now = Date.now()) {
  if (!socketIsLive(socket, now)) return false;
  const lease = readLease(socket);
  socket.serializeAttachment({ ...lease, lastSeenAt: Math.max(now, lease.lastSeenAt) });
  return true;
}
export function retireSocket(socket, reason = 'Connection heartbeat expired') {
  // The marker also excludes a socket that remains CLOSING until a close reply.
  const lease = readLease(socket);
  try { socket.serializeAttachment({ ...(lease || {}), version: 1, retired: true }); } catch {}
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
