import { json, sha256 } from '../shared/protocol.mjs';
import { checkedDevices, validEpoch, deviceDescription, MAX_GRANT_DEVICES } from '../shared/device-grants.mjs';

export const rosterCookieName = origin => origin.startsWith('https:') ? '__Host-c2l_devices' : 'c2l_devices';
export function exactCookie(request, name) {
  const values = (request.headers.get('Cookie') || '').split(';').map(item => item.trim()).filter(item => item.startsWith(`${name}=`));
  return values.length === 1 ? values[0].slice(name.length + 1) : null;
}
export async function rosterHash(request, origin) {
  const secret = exactCookie(request, rosterCookieName(origin));
  return validEpoch(secret) ? sha256(secret) : null;
}
const registry = env => env.REGISTRY.get(env.REGISTRY.idFromName('registry-v1'));
export async function rosterInternal(env, route, value) {
  return registry(env).fetch(new Request(`http://internal${route}`, { method: 'POST', body: JSON.stringify(value) }));
}

/** This is a short-lived browser proof collection, NOT a cloud account/login.
 * Cross-browser ownership must be established separately, never by name/IP.
 */
export async function browserRoster(request, env, origin) {
  if (env.MULTI_DEVICE !== 'true') return null;
  const sessionHash = await rosterHash(request, origin);
  if (!sessionHash) return null;
  const response = await rosterInternal(env, '/roster/read', { sessionHash });
  if (!response.ok) return null;
  const { devices } = await response.json();
  const checked = await Promise.all(checkedDevices(devices).map(async target => {
    const stub = env.DEVICES.get(env.DEVICES.idFromName(target.deviceId));
    const state = await stub.fetch(new Request('http://internal/describe', { method: 'POST', body: JSON.stringify({ epoch: target.epoch }) }));
    if (state.status === 401 || state.status === 403) return null;
    if (!state.ok) throw new Error('Device identity could not be verified.');
    const status = await state.json();
    return { ...target, description: { ...target.description, ...deviceDescription(status.description) }, online: status.online === true };
  }));
  return checked.filter(Boolean);
}
async function reserve(storage, prefix) {
  const rows = await storage.list({ prefix, limit: 257 });
  const expired = [...rows].filter(([, row]) => row.expiresAt <= Date.now()).map(([key]) => key);
  if (expired.length) await storage.delete(expired);
  if (rows.size - expired.length >= 200) throw Object.assign(new Error('Too many pending browser connections.'), { status: 429 });
}

/** Only the Worker can call these internal storage routes. File tools cannot
 * create, append, consume, or otherwise mutate browser/device authorization.
 */
export async function rosterStorageRoute(storage, route, value) {
  if (route === '/link-ticket/new') {
    if (!validEpoch(value.csrfHash) || !validEpoch(value.proofHash) || (value.previousHash !== null && !validEpoch(value.previousHash))) return json({ error: 'Invalid link ticket.' }, 400);
    return storage.transaction(async tx => {
      await reserve(tx, 'link-ticket:');
      await tx.put(`link-ticket:${value.csrfHash}`, { proofHash: value.proofHash, previousHash: value.previousHash, expiresAt: Date.now() + 300000 });
      return json({ ok: true });
    });
  }
  if (route === '/link-ticket/consume') {
    if (!validEpoch(value.csrfHash) || !validEpoch(value.proofHash)) return json({ error: 'Invalid browser confirmation.' }, 403);
    return storage.transaction(async tx => {
      const key = `link-ticket:${value.csrfHash}`; const ticket = await tx.get(key);
      if (!ticket || ticket.expiresAt <= Date.now() || ticket.proofHash !== value.proofHash || ticket.previousHash !== value.previousHash) return json({ error: 'Browser or target changed. Restart the connection.' }, 403);
      await tx.delete(key); return json({ ok: true });
    });
  }
  if (route === '/roster/read') {
    if (!validEpoch(value.sessionHash)) return json({ error: 'Invalid browser session.' }, 403);
    const record = await storage.get(`browser-roster:${value.sessionHash}`);
    return record && record.expiresAt > Date.now() ? json(record) : json({ error: 'Browser device session expired.' }, 403);
  }
  if (route === '/roster/append') {
    if (!validEpoch(value.sessionHash) || (value.previousHash !== null && !validEpoch(value.previousHash))) return json({ error: 'Invalid browser session.' }, 400);
    const target = checkedDevices([value.device])[0];
    return storage.transaction(async tx => {
      const key = value.previousHash ? `browser-roster:${value.previousHash}` : null;
      const previous = key ? await tx.get(key) : null;
      const devices = previous?.expiresAt > Date.now() ? checkedDevices(previous.devices) : [];
      const others = devices.filter(item => item.deviceId !== target.deviceId);
      if (others.length >= MAX_GRANT_DEVICES) return json({ error: 'Too many computers in this browser session.' }, 409);
      await reserve(tx, 'browser-roster:');
      await tx.put(`browser-roster:${value.sessionHash}`, { devices: [...others, target], expiresAt: Date.now() + 900000 });
      if (key && value.previousHash !== value.sessionHash) await tx.delete(key);
      return json({ ok: true, deviceCount: others.length + 1 });
    });
  }
  return json({ error: 'Unknown browser device route.' }, 404);
}
