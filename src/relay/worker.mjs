import { WorkerEntrypoint } from 'cloudflare:workers';
import { OAuthProvider } from '@cloudflare/workers-oauth-provider';
import { Device, Registry, validDevice, validSecret, equalSecret } from './state.mjs';
import { handleMcp, json, readLimited, sha256, randomSecret, VERSION, requiredScopes } from '../shared/protocol.mjs';
import { installPage, oauthCallbackOrigin } from '../shared/setup.mjs';
import { linkRoute, browserIdentity } from './link.mjs';
import { authorizeStatusScript } from './authorize-status.mjs';
import { consentPage } from './consent-page.mjs';
import { browserRoster } from './device-roster.mjs';
import { grantDevices, bindingSignature, MAX_GRANT_DEVICES } from '../shared/device-grants.mjs';
import { routeDeviceTool } from './device-router.mjs';
import { checkedReferenceGrant } from '../shared/connection-access.mjs';
import { accountRoute, accountAuthorize } from './account-http.mjs';
import { oidcConfiguration } from './oidc-login.mjs';
import { instanceRoute, instanceAuthorize } from './instance-http.mjs';
import { publicBootstrap } from '../shared/public-bootstrap.mjs';
import { installRoute } from './install-http.mjs';
export { Device, Registry };

const DEFAULT_SCOPES = ['files:read', 'files:propose'];
const SCOPES = [...DEFAULT_SCOPES, 'files:write', 'terminal:execute'];
const AUTH_SCOPES = [...SCOPES, 'offline_access'];
const escapeHtml = text => String(text).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
function effectiveOrigin(request, env) {
  const url = new URL(request.url);
  if (env.PRIVATE_INSTANCE === 'true' && env.ACCOUNT_CONNECTIONS === 'true') throw new Error('Select one ownership mode, not both.');
  if (env.ALLOW_LOOPBACK === 'true' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) && url.protocol === 'http:') return url.origin;
  const origin = new URL(env.PUBLIC_ORIGIN);
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash || url.origin !== origin.origin) throw new Error('Relay PUBLIC_ORIGIN must match the canonical HTTPS origin.');
  return origin.origin;
}
const registry = env => env.REGISTRY.get(env.REGISTRY.idFromName('registry-v1'));
const device = (env, id) => env.DEVICES.get(env.DEVICES.idFromName(id));
const internal = (stub, route, value) => stub.fetch(new Request(`http://internal${route}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value) }));
async function unpack(response) {
  const value = await response.json();
  if (!response.ok) throw Object.assign(new Error(value.error || 'Relay operation failed.'), { status: response.status });
  return value;
}

class McpApi extends WorkerEntrypoint {
  async fetch(request) {
    if (new URL(request.url).pathname !== '/mcp') return json({ error: 'Not found.' }, 404);
    const props = this.ctx.props;
    try {
      if (props?.grantVersion === 3) {
        if (this.env.ACCOUNT_CONNECTIONS !== 'true' && this.env.PRIVATE_INSTANCE !== 'true') throw new Error('Scoped connections disabled.');
        checkedReferenceGrant(props);
      } else grantDevices(props);
    } catch { return json({ error: 'Invalid or disabled connection grant.' }, 403); }
    return handleMcp(request, (tool, args) => routeDeviceTool({
      props, tool, args, origin: new URL(request.url).origin,
      describe: async target => unpack(await internal(device(this.env, target.deviceId), '/describe', { epoch: target.epoch })),
      resolveConnection: (this.env.ACCOUNT_CONNECTIONS === 'true' || this.env.PRIVATE_INSTANCE === 'true') ? grant => internal(registry(this.env), '/accounts/resolve', grant).then(unpack) : undefined,
      invoke: async (target, localTool, localArgs, connectionDiagnostics, connectionAccess) => (await unpack(await internal(device(this.env, target.deviceId), '/invoke', { epoch: target.epoch, tool: localTool, args: localArgs, connectionDiagnostics, ...(connectionAccess === undefined ? {} : { connectionAccess }) }))).result,
    }));
  }
}

const authHandler = {
  async fetch(request, env) {
    const url = new URL(request.url); const origin = effectiveOrigin(request, env);
    if (url.pathname === '/healthz' && request.method === 'GET') return json({ ok: true, name: 'chat2local-relay', version: VERSION, deployment: 'self-hosted-preview' });
    if (url.pathname === '/setup-info' && request.method === 'GET') {
      let accountLoginConfigured = false;
      if (env.ACCOUNT_CONNECTIONS === 'true') { try { oidcConfiguration(env, origin); accountLoginConfigured = true; } catch { /* Report unavailable, never fall back to weaker identity. */ } }
      return json({ name: 'chat2local-relay', version: VERSION, setupVersion: 1, installUrl: installPage(env.CHATGPT_INSTALL_URL), selfService: env.SELF_SERVICE_ENROLLMENT === 'true', developerHandoff: env.DEVELOPER_HANDOFF === 'true', customConnector: env.CUSTOM_CONNECTOR_ENABLED === 'true', multiDevice: env.MULTI_DEVICE === 'true', browserHandoff: true,
        privateInstance: env.PRIVATE_INSTANCE === 'true',
        accountConnections: env.ACCOUNT_CONNECTIONS === 'true', accountLoginConfigured, accountEnrollment: env.ACCOUNT_ENROLLMENT === 'true' });
    }
    if (url.pathname === '/install.sh' && !env.ASSETS && env.PUBLIC_BOOTSTRAP_URL && env.PRIVATE_INSTANCE === 'true' && ['GET','HEAD'].includes(request.method) && !url.search) {
      const script = publicBootstrap(origin, env.PUBLIC_BOOTSTRAP_URL);
      return new Response(request.method === 'HEAD' ? null : script, { headers: { 'Content-Type': 'application/x-sh; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    if (url.pathname === '/install.sh' || /^\/releases\/0\.1\.0-alpha\.[0-9]+\/(darwin-arm64|darwin-x64)\/[a-f0-9]{64}\.part[0-9]{2}$/.test(url.pathname)) {
      if (env.PRIVATE_INSTANCE !== 'true' || !env.ASSETS || !['GET','HEAD'].includes(request.method) || url.search) return json({ error: 'Published installer is not available.' }, 404);
      return env.ASSETS.fetch(new Request(origin + url.pathname, { method: request.method }));
    }
    if (url.pathname === '/install' || url.pathname === '/install.js' || url.pathname.startsWith('/install/')) return installRoute(request, env, origin);
    if (url.pathname.startsWith('/instance/')) return instanceRoute(request, env, origin);
    if (url.pathname.startsWith('/account/')) return accountRoute(request, env, origin);
    if (url.pathname === '/authorize-status.js' && request.method === 'GET') return new Response(authorizeStatusScript, { headers: { 'Content-Type': 'text/javascript; charset=utf-8' } });
    if (url.pathname === '/authorize/device-status') {
      if (request.method !== 'GET' || request.headers.get('X-Chat2Local-Check') !== '1' || request.headers.get('Sec-Fetch-Site') === 'cross-site') return json({ error: 'Same-origin browser check required.' }, 403);
      return json({ linked: Boolean(await browserIdentity(request, env, origin)) });
    }
    if (url.pathname.startsWith('/link')) {
      const response = await linkRoute(request, env, origin);
      if (response) return response;
    }
    if (url.pathname === '/enroll-device' && request.method === 'POST') {
      if (env.SELF_SERVICE_ENROLLMENT !== 'true' || (!installPage(env.CHATGPT_INSTALL_URL) && env.CUSTOM_CONNECTOR_ENABLED !== 'true') || !validSecret(env.ENROLLMENT_KEY)) return json({ error: 'Self-service enrollment is not published or enabled.' }, 503);
      if (request.headers.get('Content-Type')?.split(';')[0] !== 'application/json') return json({ error: 'JSON required.' }, 415);
      const value = JSON.parse(await readLimited(request, 2048));
      if (!value || !validDevice(value.deviceId) || !validSecret(value.deviceKey) || Object.keys(value).some(key => !['deviceId', 'deviceKey'].includes(key))) return json({ error: 'Invalid device identity.' }, 400);
      const ip = request.headers.get('CF-Connecting-IP') || (env.ALLOW_LOOPBACK === 'true' ? 'synthetic-loopback' : '');
      if (!ip) return json({ error: 'Registration network identity unavailable.' }, 503);
      await unpack(await internal(registry(env), '/self-enroll', { deviceId: value.deviceId, keyHash: await sha256(value.deviceKey), ipHash: await sha256(`setup-ip:${env.ENROLLMENT_KEY}:${ip}`) }));
      return internal(device(env, value.deviceId), '/self-initialize', { deviceKey: value.deviceKey });
    }
    if (url.pathname === '/enroll' && request.method === 'POST') {
      const key = request.headers.get('Authorization')?.replace(/^Bearer /, '');
      if (!validSecret(env.ENROLLMENT_KEY) || !await equalSecret(key, await sha256(env.ENROLLMENT_KEY))) return json({ error: 'Operator enrollment authorization required.' }, 401);
      const value = JSON.parse(await readLimited(request, 2048));
      if (!value || !validDevice(value.deviceId) || !validSecret(value.deviceKey) || Object.keys(value).some(key => !['deviceId', 'deviceKey'].includes(key))) return json({ error: 'Invalid device identity.' }, 400);
      await unpack(await internal(registry(env), '/enroll', { deviceId: value.deviceId }));
      return device(env, value.deviceId).fetch(new Request('http://internal/initialize', { method: 'POST', body: JSON.stringify({ deviceKey: value.deviceKey }) }));
    }
    const deviceRoute = /^\/device\/([a-f0-9]{32})\/(connect|pair-code|revoke|browser-handoff|metadata)$/.exec(url.pathname);
    if (deviceRoute) {
      const [, id, action] = deviceRoute;
      if (request.method !== (action === 'connect' ? 'GET' : 'POST')) return json({ error: 'Wrong method.' }, 405);
      const response = await device(env, id).fetch(new Request(`http://internal/${action}`, request));
      if (action !== 'pair-code' || !response.ok) return response;
      const pair = await response.json(); return json({ code: `${id}.${pair.secret}`, expiresAt: pair.expiresAt });
    }
    if (url.pathname !== '/authorize') return json({ error: 'Not found.' }, 404);
    if (request.method === 'GET') {
      const authRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
      if (authRequest.codeChallengeMethod !== 'S256' || !authRequest.codeChallenge) return json({ error: 'S256 PKCE is required for every client.' }, 400);
      if (authRequest.scope.some(scope => !AUTH_SCOPES.includes(scope))) return json({ error: 'Unsupported requested scope.' }, 400);
      const client = await env.OAUTH_PROVIDER.lookupClient(authRequest.clientId);
      if (!client) return json({ error: 'Unknown client.' }, 400);
      if (env.PRIVATE_INSTANCE === 'true') return instanceAuthorize(request, env, origin, authRequest, client);
      if (env.ACCOUNT_CONNECTIONS === 'true') return accountAuthorize(request, env, origin, authRequest, client);
      const csrf = randomSecret();
      const currentDevice = await browserIdentity(request, env, origin);
      const verifiedRoster = await browserRoster(request, env, origin);
      const boundDevices = verifiedRoster?.length ? verifiedRoster : (currentDevice ? [currentDevice] : []);
      const boundDevice = boundDevices[0] || currentDevice;
      const { ticket } = await unpack(await internal(registry(env), '/ticket/new', { authRequest, csrfHash: await sha256(csrf), browserBinding: boundDevice, browserBindings: verifiedRoster?.length ? verifiedRoster : null }));
      return new Response(consentPage({ ticket, client, authRequest, origin, boundDevice, boundDevices, requestUrl: request.url, ...(env.ALLOW_LOOPBACK === 'true' && env.TEST_RECOVERY_ORIGIN ? { recoveryOrigin: env.TEST_RECOVERY_ORIGIN } : {}) }), { headers: {
        'Content-Type': 'text/html; charset=utf-8',
        // The validated OAuth callback must be allowed as a form redirect target.
        'Content-Security-Policy': `default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; form-action 'self' ${oauthCallbackOrigin(authRequest.redirectUri)}; frame-ancestors 'none'; base-uri 'none'`,
        'Set-Cookie': `c2l_csrf=${csrf}; HttpOnly; SameSite=Lax; Path=/authorize; Max-Age=300${origin.startsWith('https:') ? '; Secure' : ''}`,
      } });
    }
    if (env.ACCOUNT_CONNECTIONS === 'true' || env.PRIVATE_INSTANCE === 'true') return json({ error: 'Continue the scoped native confirmation; legacy consent is not accepted in this mode.' }, 409);
    if (request.method !== 'POST' || request.headers.get('Origin') !== origin) return json({ error: 'Local consent form origin required.' }, 403);
    if (request.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/x-www-form-urlencoded') return json({ error: 'Form required.' }, 415);
    const form = new URLSearchParams(await readLimited(request, 16 * 1024));
    if (['ticket', 'pair', 'propose', 'directWrite', 'source'].some(name => form.getAll(name).length > 1) || [...form.keys()].some(name => !['ticket', 'pair', 'propose', 'directWrite', 'source', 'device'].includes(name))) return json({ error: 'Invalid consent fields.' }, 400);
    const csrf = /(?:^|;\s*)c2l_csrf=([a-f0-9]{64})(?:;|$)/.exec(request.headers.get('Cookie') || '')?.[1];
    const proof = { ticket: form.get('ticket'), csrf };
    const checked = await unpack(await internal(registry(env), '/ticket/peek', proof));
    const pairing = /^([a-f0-9]{32})\.([a-f0-9]{64})$/.exec(form.get('pair') || '');
    let linked; let selectedDevices;
    const selections = form.getAll('device');
    if (selections.length > MAX_GRANT_DEVICES || new Set(selections).size !== selections.length) return json({ error: 'Invalid selected devices.' }, 400);
    if (checked.browserBindings) {
      if (form.get('source') !== 'browser' || form.has('pair') || (!selections.length && checked.browserBindings.length > 1)) return json({ error: 'Select at least one verified computer.' }, 403);
      const current = await browserRoster(request, env, origin);
      if (!current?.length || bindingSignature(current) !== bindingSignature(checked.browserBindings)) return json({ error: 'Verified computers changed. Reopen this authorization page.' }, 403);
      selectedDevices = (selections.length ? selections : [checked.browserBindings[0].deviceId]).map(id => checked.browserBindings.find(item => item.deviceId === id));
      if (selectedDevices.some(item => !item)) return json({ error: 'An unverified computer was selected.' }, 403);
      linked = selectedDevices[0];
    } else if (selections.length) return json({ error: 'Device selection was not offered by this consent request.' }, 400);
    else if (form.get('source') === 'browser') {
      if (form.has('pair')) return json({ error: 'Ambiguous authorization proof.' }, 403);
      linked = await browserIdentity(request, env, origin);
      if (!linked || !checked.browserBinding || linked.deviceId !== checked.browserBinding.deviceId || linked.epoch !== checked.browserBinding.epoch) return json({ error: 'Browser device changed or expired. Restart connection locally.' }, 403);
    } else if (form.has('source') || checked.browserBinding || !pairing) return json({ error: 'Invalid pairing proof.' }, 403);
    const requested = checked.authRequest.scope.length ? checked.authRequest.scope : DEFAULT_SCOPES;
    if (!requested.includes('files:read')) return json({ error: 'Read permission is required for this preview.' }, 400);
    if (form.has('propose') && (form.get('propose') !== 'yes' || !requested.includes('files:propose'))) return json({ error: 'Unrequested permission.' }, 400);
    if (form.has('directWrite') && (form.get('directWrite') !== 'yes' || !requested.includes('files:write'))) return json({ error: 'Unrequested direct-write permission.' }, 400);
    const scope = ['files:read', ...(form.get('propose') === 'yes' ? ['files:propose'] : []), ...(form.get('directWrite') === 'yes' ? ['files:write'] : []), ...(requested.includes('offline_access') ? ['offline_access'] : [])];
    const deviceId = linked?.deviceId ?? pairing[1];
    const { epoch } = linked ?? await unpack(await internal(device(env, deviceId), '/consume-pair', { secret: pairing[2] }));
    const accepted = await unpack(await internal(registry(env), '/ticket/consume', proof));
    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
      request: accepted.authRequest, userId: deviceId, metadata: {}, scope,
      props: selectedDevices ? { grantVersion: 2, devices: selectedDevices.map(({ deviceId, epoch, description }) => ({ deviceId, epoch, description })), scopes: scope } : { deviceId, epoch, scopes: scope },
    });
    return new Response(null, { status: 303, headers: { Location: redirectTo, 'Set-Cookie': 'c2l_csrf=; HttpOnly; SameSite=Lax; Path=/authorize; Max-Age=0' } });
  },
};

function providerFor(origin) {
  return new OAuthProvider({
    apiRoute: '/mcp', apiHandler: McpApi, defaultHandler: authHandler,
    authorizeEndpoint: '/authorize', tokenEndpoint: '/oauth/token', clientRegistrationEndpoint: '/oauth/register',
    scopesSupported: AUTH_SCOPES, accessTokenTTL: 3600, refreshTokenTTL: 7 * 86400, clientRegistrationTTL: 90 * 86400,
    allowPlainPKCE: false, allowImplicitFlow: false, clientIdMetadataDocumentEnabled: false,
    // Public deployments require an explicit HTTPS issuer. Loopback tests use the provider's request-derived issuer.
    resourceMetadata: { resource: `${origin}/mcp`, ...(origin.startsWith('https:') ? { authorization_servers: [origin] } : {}), scopes_supported: AUTH_SCOPES, resource_name: 'Chat2Local', bearer_methods_supported: ['header'] },
    // The provider validates token scope, but application props must also reflect scope narrowing.
    tokenExchangeCallback: options => ({ accessTokenProps: { ...options.props, scopes: options.requestedScope.filter(scope => SCOPES.includes(scope)) } }),
  });
}
export default {
  async fetch(request, env, ctx) {
    let response;
    try {
      const origin = effectiveOrigin(request, env);
      const sentOrigin = request.headers.get('Origin');
      if (sentOrigin && sentOrigin !== origin) return json({ error: 'Untrusted Origin.' }, 403);
      if (request.headers.get('Sec-Fetch-Site') === 'cross-site' && request.method !== 'GET') return json({ error: 'Cross-site mutation refused.' }, 403);
      const url = new URL(request.url);
      const bucket = url.pathname === '/oauth/register' ? 'register' : url.pathname === '/authorize' ? 'authorize' : url.pathname === '/oauth/token' ? 'token' : url.pathname === '/enroll' ? 'enroll' : (url.pathname === '/enroll-device' || url.pathname === '/install/start' || url.pathname.startsWith('/link/') || url.pathname.startsWith('/account/') || url.pathname.startsWith('/instance/')) ? 'setup' : null;
      if (bucket) await unpack(await internal(registry(env), '/budget', { bucket }));
      if (request.method === 'POST') {
        const body = await readLimited(request, url.pathname === '/mcp' ? undefined : 16 * 1024);
        request = new Request(request, { body });
      }
      response = await providerFor(origin).fetch(request, env, ctx);
    } catch (error) {
      // Detailed diagnostics are restricted to synthetic loopback tests, never deployment.
      if (env.TEST_DIAGNOSTICS === 'true' && env.ALLOW_LOOPBACK === 'true' && ['127.0.0.1', 'localhost'].includes(new URL(request.url).hostname)) console.error(error.stack);
      // Normal deployments never log tokens, pair codes, bodies, or auth URLs.
      response = json({ error: error.status ? error.message : 'Request rejected. Verify relay configuration and authorization parameters.' }, error.status ?? 400);
    }
    if (response.status === 101) return response;
    const headers = new Headers(response.headers);
    headers.set('Cache-Control', 'no-store'); headers.set('X-Content-Type-Options', 'nosniff'); if (!headers.has('Referrer-Policy')) headers.set('Referrer-Policy', 'same-origin'); // Preserve same-origin form Origin; never send auth-page URLs to other origins.
    if (!headers.has('Content-Security-Policy')) headers.set('Content-Security-Policy', "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    return new Response(response.body, { status: response.status, headers });
  },
};
