import https from 'node:https';
import tls from 'node:tls';
import { syncBuiltinESMExports } from 'node:module';

export const COMPATIBLE_GROUPS = 'X25519:P-256';

/** Public, credential-free HEAD probe, through the already selected proxy.
 * Never retry enrollment, OAuth or file operations to test TLS compatibility. */
export function probeHandshake(origin, groups, timeoutMs = 3500) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      error ? reject(error) : resolve(result);
    };
    const request = https.request(new URL('/healthz', origin), {
      method: 'HEAD', headers: { Connection: 'close' },
      ...(groups ? { ecdhCurve: groups } : {}),
    }, response => {
      const socket = response.socket;
      const protocol = socket.getProtocol?.();
      if (!socket.authorized || !['TLSv1.2', 'TLSv1.3'].includes(protocol)) {
        finish(Object.assign(new Error('TLS verification failed.'), { code: 'TLS_VERIFICATION_FAILED' }));
      } else { finish(null, { protocol, verified: true }); }
      response.resume();
    });
    const timer = setTimeout(() => request.destroy(Object.assign(new Error('TLS probe timed out.'), { code: 'ETIMEDOUT' })), timeoutMs);
    request.once('error', error => finish(error));
    request.end();
  });
}

export async function selectProxyTlsProfile(origin, probe = probeHandshake) {
  try { await probe(origin); return 'default'; }
  catch (error) {
    // Certificate failures, DNS failures and proxy auth failures are not grounds
    // for a key-agreement fallback. The network route never changes here.
    if (error.code !== 'ECONNRESET') throw error;
    await probe(origin, COMPATIBLE_GROUPS);
    return 'proxy-compatible';
  }
}

/** Scope the compatibility option to the selected relay's SNI only. */
export function compatibleConnect(original, hostname) {
  return function connect(options, ...rest) {
    if (options && typeof options === 'object' && !Array.isArray(options) &&
        (options.servername || options.host) === hostname && options.ecdhCurve === undefined) {
      return original.call(this, { ...options, ecdhCurve: COMPATIBLE_GROUPS }, ...rest);
    }
    return original.call(this, options, ...rest);
  };
}
export function installRelayTlsProfile(origin, profile) {
  if (profile === 'default') return () => {};
  if (profile !== 'proxy-compatible') throw new Error('Unknown TLS compatibility profile.');
  const original = tls.connect;
  const wrapper = compatibleConnect(original, new URL(origin).hostname);
  tls.connect = wrapper; syncBuiltinESMExports();
  return () => {
    // Do not overwrite another component's later change.
    if (tls.connect === wrapper) { tls.connect = original; syncBuiltinESMExports(); }
  };
}
