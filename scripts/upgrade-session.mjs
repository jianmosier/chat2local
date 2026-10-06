import http from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { createHash } from 'node:crypto';
import { Store } from '../src/agent/store.mjs';

const fingerprint = state => createHash('sha256').update(JSON.stringify({ config: state.config, secrets: state.secrets })).digest('hex');
export function assertUpgradeIdle(state, instanceId) {
  if (state?.name !== 'chat2local' || state.instanceId !== instanceId || typeof state.version !== 'string') throw Error('The local listener is not the expected chat2local instance.');
  if (state.paused || state.setupActive || state.folderPickerActive || state.queuedOperations || state.terminalJobsRunning || !Array.isArray(state.pending) || state.pending.length) throw Error('chat2local is paused or busy. Finish the current action before updating; nothing was stopped.');
  if (state.lastRemoteCallAt && Date.now() - Date.parse(state.lastRemoteCallAt) < 3000) throw Error('chat2local was used just now. Retry the update after current work finishes.');
}
function request(session, route, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = http.request(session.origin + route, { method, headers: { 'X-Chat2Local-Token': session.token, ...(method === 'POST' ? { Origin: session.origin, 'Content-Type': 'application/json', 'Content-Length': 2 } : {}) }, timeout: 3000 }, response => {
      let text = ''; response.setEncoding('utf8');
      response.on('data', chunk => { text += chunk; if (text.length > 131072) response.destroy(Error('Local status too large.')); });
      response.on('error', reject);
      response.on('end', () => { try { if (response.statusCode !== 200) throw Error('Local session was not authenticated.'); resolve(JSON.parse(text)); } catch (error) { reject(error); } });
    });
    req.once('error', reject); req.once('timeout', () => req.destroy(Error('Local update timed out.'))); req.end(method === 'POST' ? '{}' : undefined);
  });
}
/** Installer-only controlled update. No kill, new credentials, directory grant,
 * proxy change, or automatic restart preference. Only the exact idle local app
 * is asked to shut down through its existing authenticated endpoint.
 */
export async function prepareUpgrade(version, { store = new Store(), call = request, wait = delay } = {}) {
  let session;
  try { session = await store.readSession(); } catch { return { stopped: false, verify: async () => {} }; }
  if (session.origin !== 'http://127.0.0.1:47631' || !/^[a-f0-9]{64}$/.test(session.token || '')) throw Error('Saved local session is invalid; no process was stopped.');
  let state;
  try { state = await call(session, '/api/status'); } catch (error) { if (error.code === 'ECONNREFUSED') return { stopped: false, verify: async () => {} }; throw error; }
  if (state.version === version) return { stopped: false, verify: async () => {} };
  assertUpgradeIdle(state, session.instanceId);
  const before = fingerprint(await store.load());
  const result = await call(session, '/api/shutdown', 'POST');
  if (result.ok !== true) throw Error('Graceful update shutdown was not confirmed.');
  let closed = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    await wait(150);
    try { await call(session, '/api/status'); }
    catch (error) { if (error.code === 'ECONNREFUSED') { closed = true; break; } throw error; }
  }
  if (!closed) throw Error('Old controller is still present. No duplicate process was launched.');
  if (fingerprint(await store.load()) !== before) throw Error('Configuration changed while preparing update. Review before continuing.');
  return { stopped: true, from: state.version, verify: async () => {
    if (fingerprint(await store.load()) !== before) throw Error('Updated app did not retain the original configuration. No automatic re-enrollment was attempted.');
    const current = await store.readSession();
    if (current.origin !== session.origin) throw Error('Updated app is on an unexpected local endpoint.');
    const after = await call(current, '/api/status');
    if (after.name !== 'chat2local' || after.instanceId !== current.instanceId || after.version !== version) throw Error('Updated application was not verified.');
  } };
}
