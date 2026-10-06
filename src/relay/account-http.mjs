import { json, readLimited, sha256 } from '../shared/protocol.mjs';
import { AccountIdentity, accountPrincipal } from './account-identity.mjs';
import { OidcLogin, identityCookie, cookieHeader, sessionCookieName } from './oidc-login.mjs';
import { exactFields, isAccountId, isDigest } from '../shared/connection-access.mjs';

const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const registry = env => env.REGISTRY.get(env.REGISTRY.idFromName('registry-v1'));
async function privateCall(env, action, input) {
  const response = await registry(env).fetch(new Request('http://internal/onboarding/' + action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) }));
  const result = await response.json(); if (!response.ok) throw fail(result.error || 'Account operation failed.', response.status); return result;
}
function services(env, origin) {
  const login = new OidcLogin({ env, origin, records: (action, kind, secret, value, ttl) => privateCall(env, 'records', { action, kind, secret, value, ttl }),
    ...(env.ALLOW_LOOPBACK === 'true' && /^http:\/\/(127\.0\.0\.1|localhost|\[::1\]):\d+$/.test(origin) && env.TEST_IDENTITY_HTTP ? { request: (url, options) => env.TEST_IDENTITY_HTTP.fetch(new Request(url, options)) } : {}) });
  return { login, identity: new AccountIdentity({ verifySession: request => login.verifySession(request) }) };
}
function nativeNavigation(env, origin, flow) {
  const localOrigin = env.ALLOW_LOOPBACK === 'true' && env.TEST_RECOVERY_ORIGIN ? env.TEST_RECOVERY_ORIGIN : 'http://127.0.0.1:47631';
  const local = new URL(localOrigin);
  if (local.protocol !== 'http:' || !['127.0.0.1','localhost','[::1]'].includes(local.hostname) || local.pathname !== '/' || local.search || local.hash) throw fail('Invalid local onboarding target.', 503);
  return new Response(null, { status: 303, headers: { Location: `${local.origin}/account-connect#${new URLSearchParams({ origin, flow: flow.flowId + '.' + flow.bootstrap })}`, 'Set-Cookie': cookieHeader('c2l_finish_' + flow.flowId, flow.browser, origin, 86400) } });
}
const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]);
function accountPage(title, body, status = 200) {
  return new Response(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>chat2local</title><style>body{font:16px/1.7 system-ui;background:#f5f6f8;color:#1b2434;padding:32px 18px}main{max-width:540px;margin:5vh auto;background:white;padding:26px;border-radius:16px}a{display:block;padding:12px;margin:12px 0;border:1px solid #d4deeb;border-radius:8px;color:#2155be}h1{font-size:25px}small{overflow-wrap:anywhere}</style><main><h1>${escape(title)}</h1>${body}</main></html>`, { status, headers: { 'Content-Type':'text/html; charset=utf-8' } });
}
export async function accountAuthorize(request, env, origin, authRequest, client) {
  const resources = new URL(request.url).searchParams.getAll('resource');
  if (resources.length > 1 || resources.some(resource => resource !== origin + '/mcp')) throw fail('Authorization resource does not match this service.');
  const { login, identity } = services(env, origin);
  let principal;
  try { principal = await identity.authenticate(request); } catch (error) { if (error.code !== 'ACCOUNT_LOGIN_REQUIRED') throw error; return login.begin(new URL(request.url).pathname + new URL(request.url).search); }
  const actor = accountPrincipal(principal), resource = origin + '/mcp';
  const prior = await privateCall(env, 'reuse', { actor, authRequest, resource });
  if (prior.reusable === true) {
    // Reuse a recorded consent for this EXACT stable account/client/resource and
    // a subset of its scope ceiling. No new device/root or permission is added.
    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({ request: authRequest, userId: prior.accountId, metadata: {}, scope: [...prior.grant.scopes, ...(authRequest.scope.includes('offline_access') ? ['offline_access'] : [])], props: prior.grant });
    return new Response(null, { status: 303, headers: { Location: redirectTo } });
  }
  const flow = await privateCall(env, 'start', { actor, displayName: principal.displayName, clientName: client.clientName || '未命名应用', authRequest, resource });
  return nativeNavigation(env, origin, flow);
}
export async function accountRoute(request, env, origin) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith('/account/')) return null;
  if (env.ACCOUNT_CONNECTIONS !== 'true') return json({ error: 'Account onboarding is not enabled.' }, 404);
  if (url.pathname === '/account/callback' && request.method === 'GET') return services(env, origin).login.callback(request);
  if (url.pathname === '/account/add' && request.method === 'GET') {
    if (url.searchParams.getAll('connection').length > 1 || [...url.searchParams.keys()].some(k => k !== 'connection')) throw fail('Invalid connection selection.');
    const selected = url.searchParams.get('connection');
    if (selected !== null && !isAccountId(selected)) throw fail('Invalid connection selection.');
    const { identity, login } = services(env, origin);
    let principal;
    try { principal = await identity.authenticate(request); } catch (error) { if (error.code !== 'ACCOUNT_LOGIN_REQUIRED') throw error; return login.begin(url.pathname + url.search); }
    const actor = accountPrincipal(principal), resource = origin + '/mcp';
    const { connections } = await privateCall(env, 'connections', { actor, resource });
    const connection = selected ? connections.find(c => c.connectionId === selected) : connections.length === 1 ? connections[0] : null;
    if (selected && !connection) throw fail('This connection does not belong to the signed-in account.', 403);
    if (!connections.length) return accountPage('先连接原来的 chat2local', '<p>此账号还没有账号型插件连接。请在原 chat2local 中完成首次账号授权，不要创建第二个插件。</p>', 409);
    if (!connection) {
      const choices = await Promise.all(connections.map(async item => {
        const client = await env.OAUTH_PROVIDER.lookupClient(item.clientId);
        return client ? `<a href="/account/add?connection=${item.connectionId}">${escape(client.clientName || '已连接的应用')}<br><small>${escape(item.clientId)}</small></a>` : '';
      }));
      return accountPage('选择要加入的已有连接', '<p>选择目标不会开放文件。下一页选择文件夹后只确认一次。</p>' + choices.join(''));
    }
    const client = await env.OAUTH_PROVIDER.lookupClient(connection.clientId);
    if (!client) throw fail('The original OAuth client is no longer registered.', 409);
    // A join updates explicitly selected shares under the existing reference.
    // It neither fabricates a new OAuth request nor reissues the client's token.
    const flow = await privateCall(env, 'start', { actor, displayName: principal.displayName, clientName: client.clientName || '已连接的应用',
      authRequest: { clientId: connection.clientId, scope: connection.scopes, redirectUri: origin + '/account/add' },
      resource, mode: 'join', connectionId: connection.connectionId });
    return nativeNavigation(env, origin, flow);
  }
  if (url.pathname === '/account/finish' && request.method === 'GET') {
    if (url.searchParams.getAll('flow').length !== 1 || [...url.searchParams.keys()].some(k => k !== 'flow')) throw fail('Invalid account continuation.');
    const flowId = url.searchParams.get('flow'), browser = identityCookie(request, 'c2l_finish_' + flowId);
    if (!isAccountId(flowId) || !browser) throw fail('Return in the original browser to finish connecting.', 401);
    const principal = await services(env, origin).identity.authenticate(request);
    const value = await privateCall(env, 'finish', { flowId, browser, actor: accountPrincipal(principal) });
    if (value.joined === true) return accountPage('已加入原来的 chat2local', '<p>这台电脑的所选文件夹已共享。直接回原 ChatGPT 对话使用，无需新增插件、重新授权或复制测试指令。</p><p><a href="https://chatgpt.com/">回到 ChatGPT</a></p>');
    // Reuse the SAME OAuth provider, registered callback and original state/PKCE.
    // The user's single native confirmation is the consent source; no auto-click
    // of legacy pages or new plugin is involved.
    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({ request: value.authRequest, userId: value.accountId, metadata: {}, scope: [...value.grant.scopes, ...(value.authRequest.scope.includes('offline_access') ? ['offline_access'] : [])], props: value.grant });
    return new Response(null, { status: 303, headers: { Location: redirectTo, 'Set-Cookie': cookieHeader('c2l_finish_' + flowId, '', origin, 0) } });
  }
  if (url.pathname === '/account/logout' && request.method === 'POST') {
    if (request.headers.get('Origin') !== origin || request.headers.get('X-Chat2Local-Logout') !== '1') throw fail('Same-origin logout required.', 403);
    const secret = identityCookie(request, sessionCookieName(origin));
    if (secret) await privateCall(env, 'records', { action: 'delete', kind: 'session', secret });
    return json({ loggedOut: true, existingFileGrantsChanged: false }, 200, { 'Set-Cookie': cookieHeader(sessionCookieName(origin), '', origin, 0) });
  }
  const match = /^\/account\/native\/(enroll|start|prepare|status|confirm|activate|cancel)$/.exec(url.pathname);
  if (!match || request.method !== 'POST') return json({ error: 'Not found.' }, 404);
  if (request.headers.get('Content-Type')?.split(';')[0] !== 'application/json') throw fail('JSON required.', 415);
  const input = JSON.parse(await readLimited(request, 16 * 1024));
  exactFields(input, ['flowId','secret','deviceId','input']);
  if (!isAccountId(input.deviceId) || !isAccountId(input.flowId) || !isDigest(input.secret)) throw fail('Invalid native flow.');
  const auth = request.headers.get('Authorization');
  if (!/^Bearer [a-f0-9]{64}$/.test(auth || '')) throw fail('Native device authentication required.', 401);
  const stub = env.DEVICES.get(env.DEVICES.idFromName(input.deviceId));
  if (match[1] === 'enroll') {
    if (env.ACCOUNT_ENROLLMENT !== 'true') throw fail('Authenticated new-computer enrollment is not enabled by the service owner.', 503);
    exactFields(input.input, ['sessionSecret']);
    if (!isDigest(input.input.sessionSecret)) throw fail('Native session proof required.');
    const deviceKey = auth.slice(7);
    await privateCall(env, 'provision', { flowId: input.flowId, bootstrap: input.secret, deviceId: input.deviceId, keyHash: await sha256(deviceKey), sessionHash: await sha256(input.input.sessionSecret) });
    const initialized = await stub.fetch(new Request('http://internal/self-initialize', { method: 'POST', body: JSON.stringify({ deviceKey }) }));
    if (!initialized.ok) throw fail('The reserved device could not be initialized. Existing identities were not replaced.', initialized.status);
    return json({ enrolled: true, deviceId: input.deviceId });
  }
  const verified = await stub.fetch(new Request('http://internal/account-auth', { method: 'POST', headers: { Authorization: auth } }));
  const device = await verified.json(); if (!verified.ok) throw fail('Native device authentication failed.', verified.status);
  return json(await privateCall(env, 'native', { action: match[1], flowId: input.flowId, secret: input.secret, input: input.input, device: { deviceId: input.deviceId, epoch: device.epoch } }));
}
