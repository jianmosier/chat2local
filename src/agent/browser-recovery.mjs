import { randomBytes, timingSafeEqual } from 'node:crypto';
import { authorizationReturn } from '../shared/authorization-navigation.mjs';

const html = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const fail = (status, message) => Object.assign(new Error(message), { status });
const valid = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export function recoveryNavigation(request) {
  return request.method === 'GET' && request.url === '/connect' && request.headers['sec-fetch-mode'] === 'navigate' && request.headers['sec-fetch-dest'] === 'document';
}

/** Limited local-browser confirmation. This is NOT the control token and cannot
 * grant roots, execute tools, enroll devices, or change any stored permission.
 * GET only displays a page. A same-origin, one-use, browser-bound POST confirms
 * an already enrolled device and obtains its existing browser handoff.
 */
export class BrowserRecovery {
  constructor({ now = Date.now } = {}) { this.now = now; this.tickets = new Map(); }
  issue(binding) {
    for (const [key, value] of this.tickets) if (value.until <= this.now()) this.tickets.delete(key);
    if (this.tickets.size >= 32) throw fail(429, '连接页面过多，请稍后重试。');
    const token = randomBytes(32).toString('hex');
    this.tickets.set(token, { binding, until: this.now() + 300000 });
    return token;
  }
  consume(value, cookie, binding) {
    const parts = String(cookie || '').split(';').map(s => s.trim()).filter(s => s.startsWith('c2l_recovery='));
    const browser = parts.length === 1 ? parts[0].slice('c2l_recovery='.length) : null;
    if (!valid(value) || !valid(browser) || !timingSafeEqual(Buffer.from(value), Buffer.from(browser))) throw fail(403, '请从本机页面确认连接，不要复制其他窗口的请求。');
    const ticket = this.tickets.get(value);
    this.tickets.delete(value);
    if (!ticket || ticket.until <= this.now() || ticket.binding !== binding) throw fail(409, '本次连接已过期或本机权限已变化。请重新打开连接页。');
  }
}
export function recoveryPage({ token, name, available, reason, relay }) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>chat2local · 继续连接</title><link rel="stylesheet" href="/connect.css"><script defer src="/recovery.js"></script></head><body><main><header><strong>chat2local</strong><span>本机确认</span></header><section><h1>继续连接这台电脑</h1><p>${html(name)}</p><p id="recovery-message" role="status">${html(available ? '沿用已选文件夹，不重新设置目录权限。确认后自动返回原授权流程，无需配对码。' : reason)}</p><input type="hidden" id="recovery-token" value="${html(token)}"><input type="hidden" id="recovery-relay" value="${html(relay)}"><button id="recovery-continue" ${available ? '' : 'disabled'}>确认这台电脑并继续</button><p class="footnote">只确认你刚才主动发起的连接。此页不能新增目录权限、执行文件操作或替你批准 ChatGPT 的权限。</p></section></main></body></html>`;
}
export const recoveryScript = `(() => {
  const message=document.getElementById('recovery-message'),button=document.getElementById('recovery-continue');
  const raw=location.hash.slice(1); history.replaceState(null,'',location.pathname);
  let returnUrl; const authorizationReturn=${authorizationReturn.toString()};
  try { const params=new URLSearchParams(raw); if(params.getAll('return').length!==1 || [...params.keys()].some(k=>k!=='return')) throw Error('Invalid continuation'); returnUrl=authorizationReturn(params.get('return'),document.getElementById('recovery-relay').value); }
  catch { button.disabled=true; message.textContent='请从刚才的 chat2local 授权页点击“连接这台电脑”，不要手工填写地址。'; }
  button.addEventListener('click',async()=>{
    button.disabled=true; message.textContent='正在继续原连接…';
    try {
      const response=await fetch('/connect/continue',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({nonce:document.getElementById('recovery-token').value,confirm:true,returnUrl}),redirect:'error',signal:AbortSignal.timeout(70000)});
      const value=await response.json(); if(!response.ok || !value.ok) throw Error(value.error || value.message || '连接尚未完成');
      const link=new URL(value.url); if(link.origin!==new URL(returnUrl).origin || link.pathname!=='/link' || link.search || link.username || link.password || !/^[a-f0-9]{32}\\.[a-f0-9]{64}$/.test(link.hash.slice(1))) throw Error('连接响应不匹配');
      link.hash=link.hash.slice(1)+'&return='+encodeURIComponent(returnUrl); location.assign(link.href);
    } catch(error) { message.textContent=error.name==='TimeoutError'?'连接等待超时，没有自动重新提交。请返回授权页重试。':error.message; }
  });
})();`;
