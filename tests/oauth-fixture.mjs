import fs from 'node:fs/promises';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { providerPath, providerSha256, hash } from '../scripts/oauth-artifact.mjs';
// Original, hash-checked provider logic; only its platform entrypoint base is
// supplied in Node. HTTP suites also run the unchanged provider in workerd.
let original;
export async function originalProvider() {
  if (!original) {
    const source = await fs.readFile(providerPath,'utf8');
    if (hash(source) !== providerSha256) throw Error('Wrong provider oracle.');
    const needle = 'import { WorkerEntrypoint } from "cloudflare:workers";';
    if (source.split(needle).length !== 2) throw Error('Oracle platform shim mismatch.');
    original = import('data:text/javascript;base64,'+Buffer.from(source.replace(needle,'class WorkerEntrypoint { constructor(ctx, env) { this.ctx=ctx; this.env=env; } }')).toString('base64'));
  }
  return original;
}
export const resource = 'https://relay.example.test/mcp';
export const scopes = ['files:read','files:propose','files:write','terminal:execute','offline_access'];
export const keyFor = token => 'token:'+token.split(':').slice(0,2).join(':')+':'+createHash('sha256').update(token).digest('hex');
const hmacKey = Buffer.from([34,126,38,134,141,241,225,109,128,112,234,23,151,91,71,166,130,24,250,135,40,174,222,133,181,29,74,217,150,202,202,67]);
export async function tokenRow({ token='user:grant:synthetic-secret', props={scopes:['files:read']}, plaintext, row={} } = {}) {
  const key = await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
  const wrapping = await crypto.subtle.importKey('raw',createHmac('sha256',hmacKey).update(token).digest(),{name:'AES-KW'},false,['wrapKey']);
  const wrappedEncryptionKey = Buffer.from(await crypto.subtle.wrapKey('raw',key,wrapping,{name:'AES-KW'})).toString('base64');
  const encryptedProps = Buffer.from(await crypto.subtle.encrypt({name:'AES-GCM',iv:new Uint8Array(12)},key,plaintext??Buffer.from(JSON.stringify(props)))).toString('base64');
  return { token, key:keyFor(token), text:JSON.stringify({audience:resource,expiresAt:Math.floor(Date.now()/1000)+3600,wrappedEncryptionKey,grant:{encryptedProps},...row}) };
}
export function memoryKV(entries=[]) {
  const data=new Map(entries), reads=[], writes=[];
  return {data,reads,writes,async get(key,options){reads.push(key);const text=data.get(key)??null;return options?.type==='json'&&text!==null?JSON.parse(text):text;},async put(key,value){writes.push(['put',key]);data.set(key,value);},async delete(key){writes.push(['delete',key]);data.delete(key);},async list({prefix=''}){return{keys:[...data.keys()].filter(k=>k.startsWith(prefix)).map(name=>({name})),list_complete:true,cursor:''};}};
}
export function request(header, url=resource) { return {url,method:'GET',headers:new Headers(header===undefined?{}:{Authorization:header})}; }
export async function oracle(req,kv) {
  const {OAuthProvider}=await originalProvider();
  let props;
  const provider=new OAuthProvider({apiRoute:'/mcp',apiHandler:{fetch(_request,_env,ctx){props=ctx.props;return new Response(null);}},defaultHandler:{fetch(){return new Response('not found',{status:404});}},authorizeEndpoint:'/authorize',tokenEndpoint:'/oauth/token',resourceMetadata:{resource,scopes_supported:scopes}});
  try { const response=await provider.fetch(req,{OAUTH_KV:kv},{});return response.status===200?{props}:{status:response.status,headers:Object.fromEntries(response.headers),body:await response.text()}; } catch { return {fault:true}; }
}
export async function rustResult(runner,req,kv) {
  try {const result=await runner.authenticate(req,{OAUTH_KV:kv},{resource,scopes});return result.response?{status:result.response.status,headers:Object.fromEntries(result.response.headers),body:await result.response.text()}:{props:result.props};}catch{return{fault:true};}
}
export const secret = () => randomBytes(32).toString('hex');
