import { json, readLimited, randomSecret, sha256 } from '../shared/protocol.mjs';
import { exactFields, isDigest } from '../shared/connection-access.mjs';
import { installerPage, installerScript } from './install-page.mjs';

const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const sessionName = origin => origin.startsWith('https:') ? '__Host-c2l_installer' : 'c2l_installer';
const sessionCookie = (origin, value, age) =>
  `${sessionName(origin)}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${origin.startsWith('https:') ? '; Secure' : ''}`;

function cookieValue(request, name) {
  const values = (request.headers.get('Cookie') || '').split(';')
    .map(value => value.trim()).filter(value => value.startsWith(name + '='));
  const value = values.length === 1 ? values[0].slice(name.length + 1) : null;
  return isDigest(value) ? value : null;
}

export async function installCall(env, origin, action, input = {}) {
  const stub = env.REGISTRY.get(env.REGISTRY.idFromName('registry-v1'));
  const response = await stub.fetch(new Request('http://internal/install/' + action, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ resource: origin + '/mcp', input }),
  }));
  const value = await response.json();
  if (!response.ok) throw fail(value.error || 'Installer request failed.', response.status);
  return value;
}

// Installation presentation lives in install-page.mjs. Authentication and
// authorization stay here; downloading an installer does not grant file access.
export async function installRoute(request, env, origin) {
  if (env.PRIVATE_INSTANCE !== 'true' || env.ACCOUNT_CONNECTIONS === 'true') {
    return json({ error: 'Private installation unavailable.' }, 404);
  }
  const url = new URL(request.url);
  const route = url.pathname;
  if (url.search) throw fail('Installer URLs do not accept credentials in query parameters.');

  if (route === '/install' && request.method === 'GET') {
    const nonce = randomSecret();
    return new Response(installerPage(nonce, origin), {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Referrer-Policy': 'no-referrer',
        'Set-Cookie': `c2l_install_csrf=${nonce}; HttpOnly; SameSite=Strict; Path=/install; Max-Age=3600${origin.startsWith('https:') ? '; Secure' : ''}`,
      },
    });
  }
  if (route === '/install.js' && request.method === 'GET') {
    return new Response(installerScript, { headers: { 'Content-Type': 'text/javascript; charset=utf-8' } });
  }
  if (request.method !== 'POST' || request.headers.get('Content-Type')?.split(';')[0] !== 'application/json') {
    return json({ error: 'JSON POST required.' }, 405);
  }
  const input = JSON.parse(await readLimited(request, 2048));

  // Operator endpoints never accept the public install-page cookie as proof.
  if (route.startsWith('/install/owner/')) {
    const auth = request.headers.get('Authorization');
    if (!isDigest(env.ENROLLMENT_KEY) || !/^Bearer [a-f0-9]{64}$/.test(auth || '')
        || await sha256(auth.slice(7)) !== await sha256(env.ENROLLMENT_KEY)) {
      throw fail('Instance operator authentication required.', 401);
    }
    if (route === '/install/owner/status') {
      exactFields(input, []);
      return json(await installCall(env, origin, 'configured'));
    }
    if (route === '/install/owner/configure') return json(await installCall(env, origin, 'configure', input));
    return json({ error: 'Not found.' }, 404);
  }

  // Native installer exchange is separate from same-browser confirmation.
  if (['/install/start', '/install/claim', '/install/ready'].includes(route)) {
    if (request.headers.has('Origin') || request.headers.get('X-Chat2Local-Installer') !== '1') {
      throw fail('Native installer request required.', 403);
    }
    const action = route.slice('/install/'.length);
    if (action !== 'start') exactFields(input, ['id', 'secret']);
    return json(await installCall(env, origin, action, input));
  }

  const csrf = cookieValue(request, 'c2l_install_csrf');
  if (request.headers.get('Origin') !== origin || !csrf || request.headers.get('X-Chat2Local-CSRF') !== csrf) {
    throw fail('Same-browser installer confirmation required.', 403);
  }
  const session = cookieValue(request, sessionName(origin));
  if (route === '/install/login') {
    exactFields(input, ['password']);
    const ip = request.headers.get('CF-Connecting-IP') || (env.ALLOW_LOOPBACK === 'true' ? 'loopback' : null);
    if (!ip) throw fail('Login network identity unavailable.', 503);
    const result = await installCall(env, origin, 'login', {
      password: input.password,
      network: await sha256(env.ENROLLMENT_KEY + ':install-ip:' + ip),
    });
    return json({ authenticated: true }, 200, { 'Set-Cookie': sessionCookie(origin, result.session, 1800) });
  }
  if (route === '/install/logout') {
    exactFields(input, []);
    await installCall(env, origin, 'logout', { session });
    return json({ loggedOut: true }, 200, { 'Set-Cookie': sessionCookie(origin, '', 0) });
  }
  if (route === '/install/context') {
    exactFields(input, ['id', 'browser']);
    return json(await installCall(env, origin, 'context', { ...input, session }));
  }
  if (route === '/install/authorize') {
    exactFields(input, ['id', 'browser', 'connectionId']);
    return json(await installCall(env, origin, 'authorize', { ...input, session }));
  }
  return json({ error: 'Not found.' }, 404);
}
