import { relayEntry, relayRuntime } from './relay-runtime.mjs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { randomUUID, randomBytes, createHash, generateKeyPairSync, sign } from 'node:crypto';
import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { Store } from '../src/agent/store.mjs';
import { freePort } from './controller-fixture.mjs';
import { until } from './native-bridge-fixture.mjs';
export { until };
export const secret = () => randomBytes(32).toString('hex');
export const post = (url, body, headers={}) => fetch(url,{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify(body),redirect:'manual',signal:AbortSignal.timeout(25000)});
export async function data(response,status=200){assert.equal(response.status,status,await response.clone().text());return response.json();}
export async function cloud(t,{account=false,developer=false}={}){
 // Default remains ordinary JS; strict selected runs compose the exact cloud artifact.
 const bundle=await build({entryPoints:[await relayEntry()],bundle:true,write:false,format:'esm',platform:'neutral',mainFields:['module','main'],external:['cloudflare:workers','*.wasm']});
 const ownerKey=secret(),issuer='https://native-identity.example.test',clientId='native-signed-identity',codes=new Map(),keys=account?generateKeyPairSync('rsa',{modulusLength:2048}):null;
 const jwk=keys?{...keys.publicKey.export({format:'jwk'}),kid:'native-test-idp',alg:'RS256',use:'sig'}:null;let exchanges=0;
 const mf=new Miniflare(convertV4MiniflareOptions({...await relayRuntime(bundle),host:'127.0.0.1',port:0,compatibilityDate:'2026-09-20',compatibilityFlags:['nodejs_compat','global_fetch_strictly_public'],kvNamespaces:['OAUTH_KV'],durableObjects:{DEVICES:{className:'Device',useSQLite:true},REGISTRY:{className:'Registry',useSQLite:true}},bindings:{ALLOW_LOOPBACK:'true',ENROLLMENT_KEY:ownerKey,...(developer?{DEVELOPER_HANDOFF:'true'}:{}),...(account?{ACCOUNT_CONNECTIONS:'true',ACCOUNT_ENROLLMENT:'true',OIDC_ISSUER:issuer,OIDC_CLIENT_ID:clientId,OIDC_AUTHORIZATION_ENDPOINT:issuer+'/authorize',OIDC_TOKEN_ENDPOINT:issuer+'/token',OIDC_JWKS_URI:issuer+'/keys'}:{PRIVATE_INSTANCE:'true'})},...(account?{serviceBindings:{TEST_IDENTITY_HTTP:async request=>{
   if(request.url===issuer+'/keys')return Response.json({keys:[jwk]});assert.equal(request.url,issuer+'/token');assert.equal(request.method,'POST');const form=new URLSearchParams(await request.text()),record=codes.get(form.get('code'));assert.ok(record);codes.delete(form.get('code'));assert.equal(form.get('client_id'),clientId);assert.equal(form.get('redirect_uri'),record.redirect);assert.equal(createHash('sha256').update(form.get('code_verifier')).digest('base64url'),record.challenge);exchanges++;
   const now=Math.floor(Date.now()/1000),h=Buffer.from(JSON.stringify({alg:'RS256',kid:jwk.kid})).toString('base64url'),p=Buffer.from(JSON.stringify({iss:issuer,sub:'native-real-owner',aud:clientId,nonce:record.nonce,iat:now,exp:now+300,name:'Native signed identity'})).toString('base64url');return Response.json({id_token:h+'.'+p+'.'+sign('RSA-SHA256',Buffer.from(h+'.'+p),keys.privateKey).toString('base64url'),token_type:'Bearer',access_token:'idp-access-not-a-device-key'});
 }}}:{})}));
 t.after(()=>mf.dispose());const origin=(await mf.ready).origin;
 const owner=(action,input={})=>post(origin+'/instance/owner/'+action,input,{Authorization:'Bearer '+ownerKey});
 const login=async beginning=>{assert.equal(beginning.status,303);const q=new URL(beginning.headers.get('location')).searchParams,code=secret();assert.equal(q.get('client_id'),clientId);assert.equal(q.get('code_challenge_method'),'S256');codes.set(code,{redirect:q.get('redirect_uri'),challenge:q.get('code_challenge'),nonce:q.get('nonce')});const returned=await fetch(q.get('redirect_uri')+'?'+new URLSearchParams({code,state:q.get('state'),iss:issuer}),{headers:{Cookie:beginning.headers.get('set-cookie').split(';')[0]},redirect:'manual'});assert.equal(returned.status,303,await returned.clone().text());const cookie=returned.headers.getSetCookie().find(v=>v.startsWith('c2l_account=')).split(';')[0];const navigation=await fetch(returned.headers.get('location'),{headers:{Cookie:cookie},redirect:'manual'});return {navigation,cookie};};
 return {origin,owner,ownerKey,account,login,exchanges:()=>exchanges};
}
export async function agent(t,executable,origin,{directory,folder,before}={}){
 directory||=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-native-account-'));folder||=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-native-account-files-'));
 const store=new Store(directory),port=await freePort();
 if(!(await fs.stat(path.join(directory,'settings.json')).catch(()=>null))){await store.saveConfig({version:1,roots:[],paused:false,relay:origin,installationId:randomUUID(),unknown:{keep:['中文','\ud800'],round:9007199254740993}});await store.saveSecrets({unknown:{keep:'\ud800'}});}
 await before?.(store);await fs.writeFile(path.join(directory,'.chat2local-synthetic-fixture'),'synthetic-only\n');
 const transport=path.join(directory,'transport.json'),platform=path.join(directory,'platform.json');await fs.writeFile(transport,JSON.stringify({env:{}}));await fs.writeFile(platform,JSON.stringify({picker:{mode:'selected',path:folder},browser:{mode:'capture'}}));
 const child=spawn(executable,['--synthetic-state',directory,'--port',String(port),'--fixture-only','--fixture-transport',transport,'--fixture-platform',platform,'--control-stdin'],{env:{SystemRoot:process.env.SystemRoot,PATH:path.join(process.env.SystemRoot,'System32')},windowsHide:true,stdio:['pipe','pipe','pipe']});
 let stderr='',buffer='';const lines=[],pending=new Map();child.stderr.on('data',b=>stderr=(stderr+b).slice(-65536));child.stdout.on('data',b=>{buffer+=b;for(;;){const at=buffer.indexOf('\n');if(at<0)break;const line=JSON.parse(buffer.slice(0,at));buffer=buffer.slice(at+1);lines.push(line);if(line.control&&pending.has(line.control)){pending.get(line.control)(line);pending.delete(line.control);}}});const exited=once(child,'exit'),closed=once(child,'close');let api;
 const close=async()=>{if(child.exitCode===null)child.stdin.write(JSON.stringify({op:"trigger",point:"close"})+"\n");try{await until(()=>child.exitCode!==null,18000);await closed;}catch(error){child.kill();await closed;throw Error(error.message+': '+stderr);}};
 t.after(close);
 const ready=await until(()=>{if(child.exitCode!==null)throw Error('Native startup failed: '+stderr);return lines.find(r=>r.fixtureOnly);},15000),session=await store.readSession();
 api=(route,body,headers={})=>fetch(ready.origin+route,{method:body===undefined?'GET':'POST',headers:{Origin:ready.origin,'Content-Type':'application/json','X-Chat2Local-Token':session.token,...headers},...(body===undefined?{}:{body:JSON.stringify(body)}),redirect:'manual'});
 const control=async command=>{const id=randomUUID();const response=new Promise(resolve=>pending.set(id,resolve));child.stdin.write(JSON.stringify({id,...command})+'\n');const result=await Promise.race([response,new Promise((_,reject)=>{const timer=setTimeout(()=>reject(Error('Control timeout: '+stderr)),6000);timer.unref();})]);assert.equal(result.ok,true,result.error);return result.result;};
 return {directory,folder,store,port,ready,session,api,control,child,close,exited};
}
export async function page(f,profile='instance'){
 const response=await fetch(f.ready.origin+'/'+profile+'-connect',{headers:{'Sec-Fetch-Mode':'navigate','Sec-Fetch-Dest':'document'},redirect:'manual'});assert.equal(response.status,200);const html=await response.text(),nonce=/id="account-nonce"[^>]*value="([a-f0-9]{64})"/.exec(html)?.[1];assert.ok(nonce);const cookie=response.headers.get('set-cookie').split(';')[0];
 return {nonce,cookie,call:(action,input={})=>post(f.ready.origin+'/'+profile+'-connect/'+action,{nonce,...input},{Origin:f.ready.origin,Cookie:cookie})};
}
export async function firstFlow(f,r,{scope='files:read files:write offline_access'}={}){
 const callback='http://127.0.0.1:39999/callback',verifier=secret(),client=await data(await post(r.origin+'/oauth/register',{client_name:'Native account regression',redirect_uris:[callback],token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code']}),201);
 if(!r.account){const invite=await data(await r.owner('invitations',{purpose:'connect',clientId:client.client_id,scopes:scope.split(' ').filter(v=>['files:read','files:write','files:propose','terminal:execute'].includes(v))}),201);await data(await f.api('/api/instance/import-invitation',{url:invite.inviteUrl}));}
 const query=new URLSearchParams({client_id:client.client_id,redirect_uri:callback,response_type:'code',scope,state:secret(),code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',resource:r.origin+'/mcp'});
 let auth=await fetch(r.origin+'/authorize?'+query,{redirect:'manual'}),sessionCookie='';if(r.account){const signed=await r.login(auth);auth=signed.navigation;sessionCookie=signed.cookie+'; ';}assert.equal(auth.status,303,await auth.clone().text());const local=new URL(auth.headers.get('location')),bootstrap=Object.fromEntries(new URLSearchParams(local.hash.slice(1))),cookie=sessionCookie+auth.headers.get('set-cookie').split(';')[0];const localPage=await page(f,r.account?'account':'instance');
 const finish=async view=>{const response=await fetch(view.finishUrl,{headers:{Cookie:cookie},redirect:'manual'});assert.equal(response.status,303,await response.clone().text());const code=new URL(response.headers.get('location')).searchParams.get('code');return data(await fetch(r.origin+'/oauth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:client.client_id,redirect_uri:callback,code,code_verifier:verifier,resource:r.origin+'/mcp'})}));};
 return {...localPage,bootstrap,flowId:bootstrap.flow.split('.')[0],finish};
}

export async function joinFlow(f,r,connectionId){
 const invite=await data(await r.owner('invitations',{purpose:'join',connectionId}),201);await data(await f.api('/api/instance/import-invitation',{url:invite.inviteUrl}));const invitation=new URL(invite.inviteUrl).hash.slice(1);const response=await post(r.origin+'/instance/join/start',{invitation},{Origin:r.origin,'X-Chat2Local-Invite':'1'}),join=await data(response);const bootstrap=Object.fromEntries(new URLSearchParams(new URL(join.localUrl).hash.slice(1))),cookie=response.headers.get('set-cookie').split(';')[0];return {...await page(f),bootstrap,flowId:bootstrap.flow.split('.')[0],finish:async view=>{const finish=await fetch(view.finishUrl,{headers:{Cookie:cookie},redirect:'manual'});assert.equal(finish.status,200,await finish.clone().text());}};
}
export const mcp=(r,token)=>async(name,args={})=>(await data(await post(r.origin+'/mcp',{jsonrpc:'2.0',id:secret(),method:'tools/call',params:{name,arguments:args}},{Authorization:'Bearer '+token}))).result;
export async function okCall(call,name,args={}){const result=await call(name,args);assert.equal(result.isError,false,result.content[0].text);return JSON.parse(result.content[0].text);}
export async function restart(t,f,executable,origin){await f.close();assert.equal(f.child.exitCode,0);return agent(t,executable,origin,{directory:f.directory,folder:f.folder});}
export async function resumePage(f,bootstrap,profile='instance'){const p=await page(f,profile);await data(await p.call('start',bootstrap));return {...p,flowId:bootstrap.flow.split('.')[0]};}
