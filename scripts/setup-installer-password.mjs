import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { ownerClient } from './private-instance-owner.mjs';
import { openBrowser } from '../src/agent/store.mjs';

/** One-time operator setup. The existing operator key is used internally only;
 * the browser receives a temporary loopback-only form token, never that key.
 * Password submission is a real human action; this helper does not set a default
 * password, reset a prior one, issue an invitation or authorize any folder.
 */
export async function passwordSetup({ call, browser = openBrowser } = {}) {
  call ||= await ownerClient();
  if ((await call('installer-status')).configured) return { alreadyConfigured: true };
  const token = randomBytes(32).toString('hex'), scriptNonce = randomBytes(16).toString('hex');
  let origin, busy = false, completed = false;
  const page = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>设置实例安装密码 · chat2local</title><style>body{font:17px/1.7 system-ui;background:#f4f6f8;color:#182334;margin:0;padding:24px}main{max-width:520px;background:white;border-radius:16px;padding:28px;margin:6vh auto}h1{font-size:27px}input,button{font:inherit;padding:12px;box-sizing:border-box;border-radius:8px;border:1px solid #ccd4df}input{width:100%;margin:8px 0 16px}button{background:#254fc0;color:white;cursor:pointer}small{color:#596777}</style><main><strong>chat2local · 仅需设置一次</strong><h1>设置你的实例安装密码</h1><p>以后在任何新 Mac 上直接使用这个密码安装、配对。旧 Windows 无需在线，不再传递邀请文件。</p><form id="form"><label>安装密码（至少 16 个字符）<input id="password" type="password" minlength="16" maxlength="128" autocomplete="new-password" required></label><label>再输入一次<input id="again" type="password" minlength="16" maxlength="128" autocomplete="new-password" required></label><button id="submit">保存到我的私人实例</button></form><p id="message" role="status"></p><p><small>请保存在自己的密码管理器中，不要发到聊天里。它只用于加入新电脑，不会更改现有文件权限。不是 Google、ChatGPT 或 Windows 的密码。</small></p></main><script nonce="${scriptNonce}">const proof=location.hash.slice(1);history.replaceState(null,'',location.pathname);const f=document.getElementById('form'),m=document.getElementById('message'),b=document.getElementById('submit');f.onsubmit=async e=>{e.preventDefault();if(b.disabled)return;const p=document.getElementById('password'),a=document.getElementById('again');if(p.value!==a.value){m.textContent='两次输入不一致。';return}b.disabled=true;try{const r=await fetch('/save',{method:'POST',headers:{'Content-Type':'application/json','X-Chat2Local-Setup':proof},body:JSON.stringify({password:p.value})});const v=await r.json();p.value='';a.value='';if(!r.ok)throw Error(v.error||'未保存');f.hidden=true;m.textContent='已保存。以后新 Mac 直接连接云端，不需要这台电脑在线。此窗口可以关闭。'}catch(e){m.textContent=e.message;b.disabled=false}};</script></html>`;
  const server = http.createServer((request,response) => {
    const send = (code,value,type='application/json') => { response.writeHead(code, { 'Content-Type': type+'; charset=utf-8', 'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':`default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${scriptNonce}'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'` }); response.end(type==='application/json'?JSON.stringify(value):value); };
    void(async()=>{
      if(request.headers.host!==new URL(origin).host || (request.headers.origin && request.headers.origin!==origin)) return send(403,{error:'Untrusted local request.'});
      if(request.url==='/'&&request.method==='GET') return send(200,page,'text/html');
      const candidate=request.headers['x-chat2local-setup'];
      if(request.url!=='/save'||request.method!=='POST'||request.headers.origin!==origin||request.headers['content-type']!=='application/json'||typeof candidate!=='string'||!/^[a-f0-9]{64}$/.test(candidate)||!timingSafeEqual(Buffer.from(candidate),Buffer.from(token))) return send(403,{error:'请使用刚打开的设置窗口。'});
      if(busy||completed)return send(409,{error:'设置已经提交，未重复执行。'});
      let raw='';for await(const part of request){raw+=part;if(Buffer.byteLength(raw)>2048)return send(413,{error:'Input too large.'});}
      let value;try{value=JSON.parse(raw)}catch{return send(400,{error:'Invalid input.'});}
      if(!value||Object.keys(value).some(k=>k!=='password')||typeof value.password!=='string'||value.password.length<16||Buffer.byteLength(value.password)>256)return send(400,{error:'密码至少 16 个字符，最多 256 字节。'});
      busy=true;
      try{const result=await call('configure-installer',{password:value.password});value.password='';completed=result.configured===true;if(!completed)throw Error('Not saved');send(200,{configured:true});console.log('Instance installation password configured. No password or operator credential was printed.');setTimeout(()=>server.close(),500).unref();}
      catch{value.password='';send(502,{error:'未能确认保存结果。请稍后核对实例状态，不要重复提交。'});}
      finally{busy=false;}
    })().catch(()=>send(500,{error:'Local setup did not complete.'}));
  });
  for(let attempt=0;attempt<8;attempt++){
    try{await new Promise((resolve,reject)=>{const failed=e=>{server.off('listening',ready);reject(e)},ready=()=>{server.off('error',failed);resolve()};server.once('error',failed);server.once('listening',ready);server.listen(randomInt(49152,65535),'127.0.0.1')});break;}
    catch(error){if(error.code!=='EADDRINUSE'||attempt===7)throw error;}
  }
  origin='http://127.0.0.1:'+server.address().port;
  const timer=setTimeout(()=>server.close(),900000);timer.unref();server.once('close',()=>clearTimeout(timer));
  await browser(origin+'/#'+token);
  return {opened:true,expiresInMinutes:15,close:()=>new Promise(resolve=>{server.close(resolve);server.closeIdleConnections()})};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))passwordSetup().then(v=>console.log(v.alreadyConfigured?'Installation password already configured; nothing changed.':'Opened the one-time installer-password form.')).catch(e=>{console.error(e.message);process.exitCode=1});
