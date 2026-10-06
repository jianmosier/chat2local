// Explicit, process-local maintenance compatibility profile for a verified proxy
// ClientHello interoperability failure. Load only with node --import when needed.
// Keeps certificate/hostname verification and TLS 1.3; never changes OS settings.
// Classical key agreement is used instead of the default hybrid/PQ group offer.
import tls from 'node:tls';
import { syncBuiltinESMExports } from 'node:module';
if (!['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY'].some(key => process.env[key])) {
  throw new Error('The maintainer compatibility profile requires an existing explicit HTTP(S) proxy.');
}
// DEFAULT_ECDH_CURVE alone is not consumed by all bundled HTTP clients.
// Supply the standard TLS option at connection construction, preserving every
// caller-supplied option (especially trust roots, SNI and verification settings).
const originalConnect = tls.connect;
tls.connect = function connect(options, ...rest) {
  if (options && typeof options === 'object' && !Array.isArray(options) && options.ecdhCurve === undefined) {
    return originalConnect.call(this, { ...options, ecdhCurve: 'X25519:P-256' }, ...rest);
  }
  return originalConnect.call(this, options, ...rest);
};
syncBuiltinESMExports();
