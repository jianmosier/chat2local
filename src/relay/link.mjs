import { json, readLimited, sha256, randomSecret } from '../shared/protocol.mjs';
import { installPage } from '../shared/setup.mjs';
import { authorizationReturn } from '../shared/authorization-navigation.mjs';
import { browserRoster, rosterHash, rosterCookieName, rosterInternal } from './device-roster.mjs';
const validProof = value => typeof value === 'string' && /^[a-f0-9]{32}\.[a-f0-9]{64}$/.test(value);
const stub = (env, id) => env.DEVICES.get(env.DEVICES.idFromName(id));
const internal = (device, route, value) => device.fetch(new Request(`http://internal${route}`, { method: 'POST', body: JSON.stringify(value) }));
const cookieName = origin => origin.startsWith('https:') ? '__Host-c2l_browser' : 'c2l_browser';
function cookie(request, name) {
  const parts = (request.headers.get('Cookie') || '').split(';').map(item => item.trim()).filter(item => item.startsWith(`${name}=`));
  return parts.length === 1 ? parts[0].slice(name.length + 1) : null;
}
export async function browserIdentity(request, env, origin) {
  const proof = cookie(request, cookieName(origin));
  if (!validProof(proof)) return null;
  const [deviceId, secret] = proof.split('.');
  const response = await internal(stub(env, deviceId), '/browser/verify', { secret });
  if (!response.ok) return null;
  const { epoch, description } = await response.json();
  return { deviceId, epoch, description };
}
const page = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>连接这台电脑 · Chat2Local</title><script defer src="/link.js"></script><style>body{font:16px/1.7 system-ui;background:#f3f6f8;color:#173332;margin:0;padding:32px}main{max-width:560px;margin:8vh auto;background:white;border-radius:16px;padding:32px}button{font:inherit;background:#176d59;color:white;border:0;padding:14px 20px;border-radius:9px;cursor:pointer}button:disabled{opacity:.5}small{color:#566;overflow-wrap:anywhere}</style></head><body><main><h1>把这台电脑连接到 ChatGPT</h1><p id="message">正在验证刚才由本机程序发起的连接…</p><p>确认这台电脑后继续原连接，不重新选择文件夹，也不更改已有权限。</p><button id="continue" disabled>确认这台电脑，继续</button><div id="custom-connection" hidden><p>在 ChatGPT 的自定义连接中填写：</p><p>名称：Chat2Local · 认证：OAuth</p><input id="mcp-url" readonly aria-label="MCP 连接地址" style="width:100%;box-sizing:border-box"><button id="copy-mcp" type="button">复制连接地址</button></div><p><small>只确认你刚才主动发起的连接，不要打开其他人发来的绑定链接。</small></p></main></body></html>`;
const script = `const pieces=location.hash.slice(1).split('&');let proof=pieces.shift();let returnUrl=null;const validateReturn=${authorizationReturn.toString()};try{const params=new URLSearchParams(pieces.join('&'));if([...params.keys()].some(key=>key!=='return')||params.getAll('return').length>1)throw Error('Invalid continuation');if(params.has('return'))returnUrl=validateReturn(params.get('return'),location.origin)}catch{proof=''}history.replaceState(null,'',location.pathname);let csrf='';const message=document.getElementById('message'),button=document.getElementById('continue');async function api(route,body){const response=await fetch(route,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),cache:'no-store'});const value=await response.json();if(!response.ok)throw Error(value.error||'连接失败，请从本机程序重新开始。');return value}if(!/^[a-f0-9]{32}\\.[a-f0-9]{64}$/.test(proof)){message.textContent='连接链接无效。请从本机 Chat2Local 点击连接，不要手工填写参数。'}else{api('/link/inspect',{proof}).then(value=>{csrf=value.csrf;message.textContent='电脑：'+(value.device?.description?.name||'已验证的本机')+'。确认后继续，不更改已有目录权限。';button.disabled=false}).catch(error=>{message.textContent=error.message})}button.addEventListener('click',async()=>{button.disabled=true;try{const value=await api('/link/confirm',{proof,csrf});proof='';csrf='';if(value.linked===true&&returnUrl){location.assign(returnUrl)}else if(value.installUrl){location.assign(value.installUrl)}else if(value.linked===true){message.textContent='本机已配对。请回到刚才的 ChatGPT 授权页，它会自动识别这台电脑。若原请求已过期，请从 ChatGPT 重新发起连接。无需输入配对码。';button.hidden=true;if(value.customConnection){document.getElementById('custom-connection').hidden=false;document.getElementById('mcp-url').value=value.customConnection.mcpUrl;document.getElementById('copy-mcp').onclick=async()=>{try{await navigator.clipboard.writeText(value.customConnection.mcpUrl);message.textContent='连接地址已复制。请在 ChatGPT 完成首次添加和授权。'}catch{document.getElementById('mcp-url').select();message.textContent='请复制已选中的连接地址。'}}}}else{throw Error('配对响应不完整，请重新从本机发起。')}}catch(error){message.textContent=error.message}});`;
export async function linkRoute(request, env, origin) {
  const route = new URL(request.url).pathname;
  if (request.method === 'GET' && route === '/link') return new Response(page, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  if (request.method === 'GET' && route === '/link.js') return new Response(script, { headers: { 'Content-Type': 'text/javascript; charset=utf-8' } });
  if (!['/link/inspect', '/link/confirm'].includes(route)) return null;
  if (request.method !== 'POST' || request.headers.get('Origin') !== origin) return json({ error: 'Same-origin browser confirmation required.' }, 403);
  if (request.headers.get('Content-Type')?.split(';')[0] !== 'application/json') return json({ error: 'JSON required.' }, 415);
  const value = JSON.parse(await readLimited(request, 2048));
  if (!value || !validProof(value.proof) || Object.keys(value).some(key => !['proof', 'csrf'].includes(key))) return json({ error: 'Invalid browser handoff.' }, 400);
  const installUrl = installPage(env.CHATGPT_INSTALL_URL);
  // Owner-operated development may bind an already enrolled device without a
  // public listing. Both paths still require the authenticated one-use handoff.
  if (!installUrl && env.DEVELOPER_HANDOFF !== 'true' && env.CUSTOM_CONNECTOR_ENABLED !== 'true') return json({ error: '本机配对流程尚未由维护者启用；无需填写连接参数。' }, 503);
  const [deviceId, secret] = value.proof.split('.');
  if (route === '/link/inspect') {
    const checked = await internal(stub(env, deviceId), '/browser/inspect', { secret });
    if (!checked.ok) return json({ error: '连接已失效，请从本机程序重新发起。' }, 403);
    const target = await checked.json();
    const csrf = randomSecret();
    const registered = await rosterInternal(env, '/link-ticket/new', { csrfHash: await sha256(csrf), proofHash: await sha256(value.proof), previousHash: await rosterHash(request, origin) });
    if (!registered.ok) return registered;
    return json({ csrf, device: { deviceId, description: target.description }, verifiedDeviceCount: (await browserRoster(request, env, origin))?.length || 0 }, 200, { 'Set-Cookie': `c2l_link_csrf=${csrf}; HttpOnly; SameSite=Strict; Path=/link; Max-Age=300${origin.startsWith('https:') ? '; Secure' : ''}` });
  }
  const csrfCookie = cookie(request, 'c2l_link_csrf');
  if (!/^[a-f0-9]{64}$/.test(value.csrf || '') || csrfCookie !== value.csrf) return json({ error: 'Browser confirmation expired.' }, 403);
  const previousHash = await rosterHash(request, origin);
  const ticket = await rosterInternal(env, '/link-ticket/consume', { csrfHash: await sha256(value.csrf), proofHash: await sha256(value.proof), previousHash });
  if (!ticket.ok) return ticket;
  const browserSecret = randomSecret();
  const consumed = await internal(stub(env, deviceId), '/browser/consume', { secret, browserHash: await sha256(browserSecret) });
  if (!consumed.ok) return json({ error: '连接已使用或失效，请从本机程序重新发起。' }, 403);
  const response = json({ installUrl, linked: true, mode: installUrl ? 'published' : env.CUSTOM_CONNECTOR_ENABLED === 'true' ? 'custom' : 'developer', ...(env.CUSTOM_CONNECTOR_ENABLED === 'true' && !installUrl ? { customConnection: { name: 'Chat2Local', mcpUrl: `${origin}/mcp`, authentication: 'OAuth' } } : {}) }, 200, { 'Set-Cookie': `${cookieName(origin)}=${deviceId}.${browserSecret}; HttpOnly; SameSite=Lax; Path=/; Max-Age=900${origin.startsWith('https:') ? '; Secure' : ''}` });
  if (env.MULTI_DEVICE === 'true') {
    const target = await consumed.json(); const sessionSecret = randomSecret();
    const appended = await rosterInternal(env, '/roster/append', { previousHash, sessionHash: await sha256(sessionSecret), device: { deviceId, epoch: target.epoch, description: target.description } });
    if (!appended.ok) return appended;
    response.headers.append('Set-Cookie', `${rosterCookieName(origin)}=${sessionSecret}; HttpOnly; SameSite=Lax; Path=/; Max-Age=900${origin.startsWith('https:') ? '; Secure' : ''}`);
  }
  return response;
}
