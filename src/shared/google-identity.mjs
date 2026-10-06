// Server-side Google login preset. All computers use this SAME backend client;
// desktop packages never contain its client secret. No account flag is enabled here.
// Primary metadata: https://accounts.google.com/.well-known/openid-configuration
export const GOOGLE_ISSUER = 'https://accounts.google.com';
export const GOOGLE_OIDC = Object.freeze({
  OIDC_ISSUER: GOOGLE_ISSUER,
  OIDC_AUTHORIZATION_ENDPOINT: 'https://accounts.google.com/o/oauth2/v2/auth',
  OIDC_TOKEN_ENDPOINT: 'https://oauth2.googleapis.com/token',
  OIDC_JWKS_URI: 'https://www.googleapis.com/oauth2/v3/certs',
});
const fail = message => Object.assign(new Error(message), { status: 503 });
export function googleClientId(value) {
  if (typeof value !== 'string' || value.length > 255 || !/^[0-9]+(?:-[A-Za-z0-9_-]+)?\.apps\.googleusercontent\.com$/.test(value)) throw fail('Create a Google Web application OAuth client; its client ID is missing or invalid.');
  return value;
}
export function googleClientSecret(value) {
  if (typeof value !== 'string' || !/^[\x21-\x7e]{8,512}$/.test(value)) throw fail('The Google web client secret is missing or invalid. Keep it in server-side secret storage, not in chat or desktop packages.');
  return value;
}
export function identityProviderEnvironment(env) {
  if (env.OIDC_PROVIDER === undefined || env.OIDC_PROVIDER === 'oidc') return env;
  if (env.OIDC_PROVIDER !== 'google') throw fail('Unsupported identity provider preset.');
  for (const [name, expected] of Object.entries(GOOGLE_OIDC)) {
    if (env[name] !== undefined && env[name] !== expected) throw fail('Google provider endpoints conflict with the pinned official configuration.');
  }
  googleClientId(env.OIDC_CLIENT_ID); googleClientSecret(env.OIDC_CLIENT_SECRET);
  return { ...env, ...GOOGLE_OIDC };
}
export function googleCallbackUri(origin) {
  let url; try { url = new URL(origin); } catch { throw fail('A canonical public HTTPS relay origin is required.'); }
  if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password || url.hostname === 'localhost' || url.hostname.endsWith('.localhost') || /^\[|^[0-9.]+$/.test(url.hostname)) throw fail('A canonical public HTTPS relay origin is required.');
  return origin + '/account/callback';
}

/** Google documents two issuer spellings. Only for the explicitly configured
 * Google issuer, validate the original signed JWT against that exact permitted
 * spelling; canonicalize the verified RESULT, never rewrite the JWT or trust
 * an arbitrary issuer alias. General OIDC issuer matching remains exact.
 */
export function expectedGoogleTokenIssuer(configuredIssuer, tokenIssuer) {
  return configuredIssuer === GOOGLE_ISSUER && tokenIssuer === 'accounts.google.com' ? 'accounts.google.com' : configuredIssuer;
}
