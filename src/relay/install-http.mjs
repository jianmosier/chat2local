import { json, readLimited, randomSecret, sha256 } from '../shared/protocol.mjs';
import { exactFields, isDigest } from '../shared/connection-access.mjs';

const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const cookieValue = (request, name) => {
  const values = (request.headers.get('Cookie') || '').split(';').map(s => s.trim()).filter(s => s.startsWith(name + '='));
  const value = values.length === 1 ? values[0].slice(name.length + 1) : null;
  return isDigest(value) ? value : null;
};
const sessionName = origin => origin.startsWith('https:') ? '__Host-c2l_installer' : 'c2l_installer';
const sessionCookie = (origin, value, age) => `${sessionName(origin)}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${origin.startsWith('https:') ? '; Secure' : ''}`;
export async function installCall(env, origin, action, input = {}) {
  const stub = env.REGISTRY.get(env.REGISTRY.idFromName('registry-v1'));
  const response = await stub.fetch(new Request('http://internal/install/' + action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ resource: origin + '/mcp', input }) }));
  const value = await response.json(); if (!response.ok) throw fail(value.error || 'Installer request failed.', response.status); return value;
}
const page = nonce => `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>安装到这台电脑 · chat2local</title><script defer src="/install.js"></script><style>body{font:16px/1.65 system-ui;background:#f4f6f8;color:#182334;margin:0;padding:24px}main{max-width:560px;margin:5vh auto;background:white;padding:28px;border:1px solid #dce3eb;border-radius:16px}h1{font-size:28px;line-height:1.25}input,select,button{font:inherit;box-sizing:border-box;max-width:100%;padding:12px;border:1px solid #ccd4df;border-radius:8px}input,select{width:100%;margin:8px 0 16px}button{background:#254fc0;color:white;cursor:pointer}button:disabled{opacity:.5}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f8;padding:12px;font-size:13px}small{color:#596777} [hidden]{display:none!important}</style></head><body><main><strong>chat2local · 你的私人实例</strong><h1>安装到这台电脑</h1><p id="message" role="status">正在检查安装入口…</p><input type="hidden" id="csrf" value="${nonce}"><section id="download" hidden><p>在新 Mac 的终端运行下面一条命令。安装器会识别芯片并校验程序，随后在这台 Mac 上继续。旧电脑无需在线。</p><pre id="command"></pre><button id="copy" type="button">复制安装命令</button><p><small>Mac 试用版。不需要 Node、Git、Codex 或 Google 登录。</small></p></section><section id="runner" hidden><p id="machine"></p><form id="login-form" hidden><label for="password">实例安装密码</label><input id="password" type="password" autocomplete="current-password" minlength="16" maxlength="256" required><button id="login" type="submit">登录并继续</button><p><small>这是你自己的实例安装密码，不是电脑开机密码或 ChatGPT 密码。仅用于加入新电脑，不提供现有文件访问权。</small></p></form><div id="selection" hidden><label for="connection">加入哪个现有连接</label><select id="connection"></select><button id="continue" type="button">继续</button></div><p id="after" hidden>安装器正在自动处理配对。接下来选择本机文件夹，并确认一次。</p></section></main></body></html>`;
const script = `const $=id=>document.getElementById(id);let ticket=null,busy=false,stopped=false;const csrf=$('csrf').value;
async function api(action,body={}){const response=await fetch('/install/'+action,{method:'POST',headers:{'Content-Type':'application/json','X-Chat2Local-CSRF':csrf},body:JSON.stringify(body),credentials:'same-origin',redirect:'error',signal:AbortSignal.timeout(15000)});const result=await response.json();if(!response.ok)throw Error(result.error||'安装暂未完成');return result}
function note(text){$('message').textContent=text}
async function choose(connectionId=null){if(busy||stopped)return;busy=true;try{await api('authorize',{...ticket,connectionId});$('selection').hidden=true;$('after').hidden=false;note('配对已交给这台电脑的安装器，无需操作旧电脑。')}catch(e){note(e.message)}finally{busy=false}}
async function refresh(){if(stopped||busy||!ticket)return;try{const s=await api('context',ticket);$('machine').textContent='当前安装器：'+s.name;$('login-form').hidden=s.authenticated||!s.configured;if(!s.configured){note('此实例尚未设置安装密码。请实例维护者完成一次设置；不用配置 Google。');stopped=true;return}if(!s.authenticated){note('请输入自己实例的安装密码。');return}if(s.nextUrl){const next=new URL(s.nextUrl);if(next.origin!==location.origin||next.pathname!=='/instance/invite'||next.search||!/^#[a-f0-9]{32}\\.[a-f0-9]{64}$/.test(next.hash))throw Error('安装返回地址不匹配');stopped=true;location.assign(next.href);return}if(s.phase!=='pending'){note('正在等待本机安装器接收配对信息…');$('after').hidden=false;return}if(s.connections.length===1){await choose(s.connections[0].connectionId)}else if(s.connections.length===0){note('此实例还没有可加入的插件连接。请先完成首次连接；不会替你创建第二个插件。')}else{const select=$('connection');if(!select.options.length){select.add(new Option('请选择',''));for(const c of s.connections)select.add(new Option(c.name+' · '+c.callbackOrigin,c.connectionId))}$('selection').hidden=false;note('请选择要加入的原连接。')}}catch(e){note(e.message)}}
$('login-form').onsubmit=async e=>{e.preventDefault();if(busy)return;busy=true;$('login').disabled=true;const password=$('password').value;try{await api('login',{password});$('password').value='';$('login-form').hidden=true}catch(e){$('password').value='';note(e.message)}finally{busy=false;$('login').disabled=false;await refresh()}};
$('continue').onclick=()=>{if($('connection').value)void choose($('connection').value)};
(async()=>{try{if(location.hash){const proof=location.hash.slice(1);history.replaceState(null,'',location.pathname);if(!/^[a-f0-9]{32}\\.[a-f0-9]{64}$/.test(proof))throw Error('安装请求格式不正确');const [id,browser]=proof.split('.');ticket={id,browser};sessionStorage.setItem('c2l-installer-ticket',JSON.stringify(ticket))}else ticket=JSON.parse(sessionStorage.getItem('c2l-installer-ticket')||'null');if(!ticket){$('download').hidden=false;$('command').textContent='curl -fsS --proto "=https" '+location.origin+'/install.sh | sh';$('copy').onclick=async()=>{try{await navigator.clipboard.writeText($('command').textContent);note('命令已复制，请在新 Mac 运行。')}catch{note('请复制上方命令。')}};note('在要连接的新电脑上安装，不需要旧电脑邀请。');return}$('runner').hidden=false;await refresh();const timer=setInterval(()=>{if(stopped)clearInterval(timer);else void refresh()},2000)}catch(e){note(e.message)}})();`;

export async function installRoute(request, env, origin) {
  if (env.PRIVATE_INSTANCE !== 'true' || env.ACCOUNT_CONNECTIONS === 'true') return json({ error: 'Private installation unavailable.' }, 404);
  const url = new URL(request.url), route = url.pathname;
  if (url.search) throw fail('Installer URLs do not accept credentials in query parameters.');
  if (route === '/install' && request.method === 'GET') {
    const nonce = randomSecret();
    return new Response(page(nonce), { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Referrer-Policy': 'no-referrer', 'Set-Cookie': `c2l_install_csrf=${nonce}; HttpOnly; SameSite=Strict; Path=/install; Max-Age=3600${origin.startsWith('https:') ? '; Secure' : ''}` } });
  }
  if (route === '/install.js' && request.method === 'GET') return new Response(script, { headers: { 'Content-Type': 'text/javascript; charset=utf-8' } });
  if (request.method !== 'POST' || request.headers.get('Content-Type')?.split(';')[0] !== 'application/json') return json({ error: 'JSON POST required.' }, 405);
  const input = JSON.parse(await readLimited(request, 2048));
  if (route.startsWith('/install/owner/')) {
    const auth = request.headers.get('Authorization');
    if (!isDigest(env.ENROLLMENT_KEY) || !/^Bearer [a-f0-9]{64}$/.test(auth || '') || await sha256(auth.slice(7)) !== await sha256(env.ENROLLMENT_KEY)) throw fail('Instance operator authentication required.', 401);
    if (route === '/install/owner/status') { exactFields(input, []); return json(await installCall(env, origin, 'configured')); }
    if (route === '/install/owner/configure') return json(await installCall(env, origin, 'configure', input));
    return json({ error: 'Not found.' }, 404);
  }
  if (['/install/start','/install/claim','/install/ready'].includes(route)) {
    if (request.headers.has('Origin') || request.headers.get('X-Chat2Local-Installer') !== '1') throw fail('Native installer request required.', 403);
    const action = route.slice('/install/'.length);
    if (action !== 'start') exactFields(input, ['id','secret']);
    return json(await installCall(env, origin, action, input));
  }
  const csrf = cookieValue(request, 'c2l_install_csrf');
  if (request.headers.get('Origin') !== origin || !csrf || request.headers.get('X-Chat2Local-CSRF') !== csrf) throw fail('Same-browser installer confirmation required.', 403);
  const session = cookieValue(request, sessionName(origin));
  if (route === '/install/login') {
    exactFields(input, ['password']);
    const ip = request.headers.get('CF-Connecting-IP') || (env.ALLOW_LOOPBACK === 'true' ? 'loopback' : null);
    if (!ip) throw fail('Login network identity unavailable.', 503);
    const result = await installCall(env, origin, 'login', { password: input.password, network: await sha256(env.ENROLLMENT_KEY + ':install-ip:' + ip) });
    return json({ authenticated: true }, 200, { 'Set-Cookie': sessionCookie(origin, result.session, 1800) });
  }
  if (route === '/install/logout') { exactFields(input, []); await installCall(env, origin, 'logout', { session }); return json({ loggedOut: true }, 200, { 'Set-Cookie': sessionCookie(origin, '', 0) }); }
  if (route === '/install/context') { exactFields(input, ['id','browser']); return json(await installCall(env, origin, 'context', { ...input, session })); }
  if (route === '/install/authorize') { exactFields(input, ['id','browser','connectionId']); return json(await installCall(env, origin, 'authorize', { ...input, session })); }
  return json({ error: 'Not found.' }, 404);
}
