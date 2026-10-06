import { json, readLimited, sha256 } from '../shared/protocol.mjs';
import { exactFields, isAccountId, isDigest } from '../shared/connection-access.mjs';
import { connectionResultPage } from './connection-result.mjs';

const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const enabled = env => env.PRIVATE_INSTANCE === 'true' && env.ACCOUNT_CONNECTIONS !== 'true';
async function internal(env, origin, action, input) {
  const stub = env.REGISTRY.get(env.REGISTRY.idFromName('registry-v1'));
  const response = await stub.fetch(new Request('http://internal/instance/' + action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ resource: origin + '/mcp', input }) }));
  const result = await response.json(); if (!response.ok) throw fail(result.error || 'Private pairing failed.', response.status); return result;
}
const rememberName = origin => origin.startsWith('https:') ? '__Host-c2l_private_connection' : 'c2l_private_connection';
function secretCookie(request, name) {
  const entries = (request.headers.get('Cookie') || '').split(';').map(s => s.trim()).filter(s => s.startsWith(name + '='));
  const value = entries.length === 1 ? entries[0].slice(name.length + 1) : null;
  return isDigest(value) ? value : null;
}
const cookieName = id => 'c2l_instance_finish_' + id;
const cookie = (origin, id, browser, age = 86400) => `${cookieName(id)}=${browser}; Path=/instance/finish; HttpOnly; SameSite=Lax; Max-Age=${age}${origin.startsWith('https:') ? '; Secure' : ''}`;
function browserCookie(request, id) {
  const entries = (request.headers.get('Cookie') || '').split(';').map(s => s.trim()).filter(s => s.startsWith(cookieName(id) + '='));
  const value = entries.length === 1 ? entries[0].slice(cookieName(id).length + 1) : null;
  return isDigest(value) ? value : null;
}
function localUrl(env, origin, flow) {
  const target = new URL(env.ALLOW_LOOPBACK === 'true' && env.TEST_RECOVERY_ORIGIN ? env.TEST_RECOVERY_ORIGIN : 'http://127.0.0.1:47631');
  if (target.protocol !== 'http:' || !['127.0.0.1','localhost','[::1]'].includes(target.hostname) || target.pathname !== '/' || target.search || target.hash) throw fail('Invalid private local entry.', 503);
  return target.origin + '/instance-connect#' + new URLSearchParams({ origin, flow: flow.flowId + '.' + flow.bootstrap });
}
const page = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>chat2local · 私人实例</title><script defer src="/instance/invite.js"></script><style>body{font:17px/1.7 system-ui;background:#f5f6f8;color:#182334;margin:0;padding:30px}main{max-width:560px;margin:10vh auto;background:white;border-radius:16px;padding:28px}p{overflow-wrap:anywhere}</style><main><h1>连接自己的电脑</h1><p id="message">正在准备你的私人实例邀请…</p><p>接下来选择文件夹，并确认一次。无需 Google 登录或填写配对码。</p></main></html>`;
const script = `(() => {const invitation=location.hash.slice(1);history.replaceState(null,'',location.pathname);const message=document.getElementById('message');if(!/^[a-f0-9]{32}\\.[a-f0-9]{64}$/.test(invitation)){message.textContent='邀请无效。请使用自己的实例生成的安装邀请。';return}fetch('/instance/join/start',{method:'POST',headers:{'Content-Type':'application/json','X-Chat2Local-Invite':'1'},credentials:'same-origin',body:JSON.stringify({invitation}),redirect:'error',signal:AbortSignal.timeout(12000)}).then(async response=>{const value=await response.json();if(!response.ok)throw Error(value.error||'邀请尚未就绪');const target=new URL(value.localUrl);if(target.protocol!=='http:'||!['127.0.0.1','localhost','[::1]'].includes(target.hostname)||target.pathname!=='/instance-connect'||target.username||target.password||target.search)throw Error('本机地址不匹配');location.assign(target.href)}).catch(()=>{message.textContent='此邀请暂不能继续。请检查它是否过期、是否已使用，以及本机客户端是否已经安装；不要重复授权或公开发送邀请。'});})();`;

export async function instanceAuthorize(request, env, origin, authRequest, client) {
  if (!enabled(env)) throw fail('Private instance mode is not enabled.', 503);
  const resource = new URL(request.url).searchParams.getAll('resource');
  if (resource.length > 1 || resource.some(r => r !== origin + '/mcp')) throw fail('OAuth resource does not match this private instance.');
  const remembered = await internal(env, origin, 'remembered', { secret: secretCookie(request, rememberName(origin)), authRequest });
  if (remembered) {
    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({ request: authRequest, userId: remembered.accountId, metadata: {}, scope: [...remembered.grant.scopes, ...(authRequest.scope.includes('offline_access') ? ['offline_access'] : [])], props: remembered.grant });
    return new Response(null, { status: 303, headers: { Location: redirectTo } });
  }
  const flow = await internal(env, origin, 'makeFlow', { authRequest, clientName: client.clientName || '请求应用' });
  return new Response(null, { status: 303, headers: { Location: localUrl(env, origin, flow), 'Set-Cookie': cookie(origin, flow.flowId, flow.browser) } });
}
export async function instanceRoute(request, env, origin) {
  if (!enabled(env)) return json({ error: 'Private instance pairing is not enabled.' }, 404);
  const url = new URL(request.url), route = url.pathname;
  if (route === '/instance/invite' && request.method === 'GET') return new Response(page, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  if (route === '/instance/invite.js' && request.method === 'GET') return new Response(script, { headers: { 'Content-Type': 'text/javascript; charset=utf-8' } });
  if (route === '/instance/finish' && request.method === 'GET') {
    const flowId = url.searchParams.get('flow');
    if (!isAccountId(flowId) || url.searchParams.getAll('flow').length !== 1 || [...url.searchParams.keys()].some(k => k !== 'flow')) throw fail('Invalid private continuation.');
    const value = await internal(env, origin, 'finish', { flowId, browser: browserCookie(request, flowId) });
    if (value.joined) return new Response(connectionResultPage(value), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({ request: value.authRequest, userId: value.accountId, metadata: {}, scope: [...value.grant.scopes, ...(value.authRequest.scope.includes('offline_access') ? ['offline_access'] : [])], props: value.grant });
    const headers = new Headers({ Location: redirectTo, 'Set-Cookie': cookie(origin, flowId, '', 0) });
    if (isDigest(value.remember)) headers.append('Set-Cookie', `${rememberName(origin)}=${value.remember}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000${origin.startsWith('https:') ? '; Secure' : ''}`);
    return new Response(null, { status: 303, headers });
  }
  if (request.method !== 'POST') return json({ error: 'Not found.' }, 404);
  if (request.headers.get('Content-Type')?.split(';')[0] !== 'application/json') throw fail('JSON required.', 415);
  const input = JSON.parse(await readLimited(request, 16384));
  const owner = /^\/instance\/owner\/(invitations|connections|revoke-invitation)$/.exec(route);
  if (owner) {
    const auth = request.headers.get('Authorization');
    if (!isDigest(env.ENROLLMENT_KEY) || !/^Bearer [a-f0-9]{64}$/.test(auth || '') || await sha256(auth.slice(7)) !== await sha256(env.ENROLLMENT_KEY)) throw fail('Instance operator authentication required.', 401);
    if (owner[1] === 'connections') { exactFields(input, []); return json(await internal(env, origin, 'connections', {})); }
    if (owner[1] === 'revoke-invitation') { exactFields(input, ['invitationId']); return json(await internal(env, origin, 'revokeInvitation', input)); }
    const value = await internal(env, origin, 'createInvitation', input);
    return json({ ...value, inviteUrl: origin + '/instance/invite#' + value.invitation }, 201);
  }
  if (route === '/instance/join/start') {
    if (request.headers.get('Origin') !== origin || request.headers.get('X-Chat2Local-Invite') !== '1') throw fail('Same-origin invitation entry required.', 403);
    exactFields(input, ['invitation']);
    const flow = await internal(env, origin, 'makeFlow', input);
    return json({ localUrl: localUrl(env, origin, flow) }, 200, { 'Set-Cookie': cookie(origin, flow.flowId, flow.browser) });
  }
  const management = /^\/instance\/manage\/(connections|start)$/.exec(route);
  if (management) {
    exactFields(input, ['deviceId', 'input']);
    const auth = request.headers.get('Authorization');
    if (!isAccountId(input.deviceId) || !/^Bearer [a-f0-9]{64}$/.test(auth || '')) throw fail('Independent device authentication required.', 401);
    const stub = env.DEVICES.get(env.DEVICES.idFromName(input.deviceId));
    const verified = await stub.fetch(new Request('http://internal/account-auth', { method: 'POST', headers: { Authorization: auth } }));
    const identity = await verified.json();
    if (!verified.ok) throw fail('Device authentication failed.', verified.status);
    return json(await internal(env, origin, 'manage', { action: management[1], device: { deviceId: input.deviceId, epoch: identity.epoch, keyHash: await sha256(auth.slice(7)) }, input: input.input }));
  }
  const native = /^\/instance\/native\/(enroll|start|prepare|status|confirm|activate|cancel)$/.exec(route);
  if (!native) return json({ error: 'Not found.' }, 404);
  exactFields(input, ['flowId','deviceId','secret','input','invitation']);
  if (!isAccountId(input.flowId) || !isAccountId(input.deviceId) || !isDigest(input.secret)) throw fail('Invalid private native flow.');
  const auth = request.headers.get('Authorization');
  if (!/^Bearer [a-f0-9]{64}$/.test(auth || '')) throw fail('Independent device credential required.', 401);
  const stub = env.DEVICES.get(env.DEVICES.idFromName(input.deviceId));
  const action = native[1], keyHash = await sha256(auth.slice(7));
  if (action === 'enroll') {
    exactFields(input.input, ['sessionSecret']); if (!isDigest(input.input.sessionSecret)) throw fail('Invalid native session.');
    await internal(env, origin, 'claim', { flowId: input.flowId, bootstrap: input.secret, invitation: input.invitation, deviceId: input.deviceId, keyHash, sessionHash: await sha256(input.input.sessionSecret), registering: true });
    const response = await stub.fetch(new Request('http://internal/self-initialize', { method: 'POST', body: JSON.stringify({ deviceKey: auth.slice(7) }) }));
    if (!response.ok) throw fail('Device initialization did not complete; previous identity retained.', response.status);
    return json({ enrolled: true, deviceId: input.deviceId });
  }
  const verified = await stub.fetch(new Request('http://internal/account-auth', { method: 'POST', headers: { Authorization: auth } }));
  const identity = await verified.json(); if (!verified.ok) throw fail('Device authentication failed.', verified.status);
  return json(await internal(env, origin, 'native', { action, flowId: input.flowId, secret: input.secret, invitation: input.invitation, input: input.input, device: { deviceId: input.deviceId, epoch: identity.epoch, keyHash } }));
}
