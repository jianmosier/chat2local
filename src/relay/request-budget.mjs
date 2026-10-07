import { json } from '../shared/protocol.mjs';

// Distinguish this relay-only hotfix without requiring a client/package upgrade.
export const REQUEST_BUDGET_VERSION = 2;

// Private native requests still face an anonymous transport ceiling. Once the
// exact device credential is checked, read and mutation budgets are independent
// per device. None of these buckets can issue or expand an authorization grant.
const deviceRoute = /^\/instance\/(?:manage\/(?:connections|start|remove)|native\/(?:start|prepare|status|confirm|activate|cancel))$/;
const limits = Object.freeze({
  register: 100, authorize: 1000, token: 6000, enroll: 200, setup: 200,
  'device-transport': 24000, 'device-read': 3600, 'device-change': 200,
});
export function requestBudget(pathname, method) {
  if (method === 'POST' && deviceRoute.test(pathname)) return 'device-transport';
  if (pathname === '/oauth/register') return 'register';
  if (pathname === '/authorize' || (pathname === '/instance/finish' && method === 'GET')) return 'authorize';
  if (pathname === '/oauth/token') return 'token';
  if (pathname === '/enroll') return 'enroll';
  if (pathname === '/enroll-device' || pathname === '/install/start' || pathname.startsWith('/link/') || pathname.startsWith('/account/') || pathname.startsWith('/instance/')) return 'setup';
  return null;
}
export async function consumeBudget(storage, value, now = Date.now()) {
  if (!value || !Object.hasOwn(limits, value.bucket)) return json({ error: 'Invalid budget.' }, 400);
  const scoped = value.bucket === 'device-read' || value.bucket === 'device-change';
  if (scoped ? !/^[a-f0-9]{32}$/.test(value.deviceId || '') : value.deviceId !== undefined) return json({ error: 'Invalid budget scope.' }, 400);
  const key = `budget:${value.bucket}${scoped ? ':' + value.deviceId : ''}`;
  return storage.transaction(async tx => {
    let record = await tx.get(key);
    if (!record || record.until <= now) record = { count: 0, until: now + 3_600_000 };
    if (record.count >= limits[value.bucket]) {
      const retryAfterSeconds = Math.max(1, Math.ceil((record.until - now) / 1000));
      return json({ error: 'Relay request budget exceeded; retry later.', retryAfterSeconds }, 429, { 'Retry-After': String(retryAfterSeconds) });
    }
    record.count++;
    await tx.put(key, record);
    return json({ ok: true });
  });
}
// Internal-only helper. Call ONLY after the route has independently verified the
// device key/epoch; neither an OAuth file token nor a supplied deviceId suffices.
export async function deviceBudget(env, deviceId, readOnly) {
  const registry = env.REGISTRY.get(env.REGISTRY.idFromName('registry-v1'));
  const response = await registry.fetch(new Request('http://internal/budget', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ bucket: readOnly ? 'device-read' : 'device-change', deviceId }),
  }));
  if (!response.ok) {
    const value = await response.json();
    throw Object.assign(new Error(value.error || 'Device request budget exceeded.'), { status: response.status, retryAfterSeconds: value.retryAfterSeconds });
  }
}
