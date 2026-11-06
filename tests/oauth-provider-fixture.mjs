import { createHash, webcrypto } from 'node:crypto';
import { originalProvider, resource, scopes } from './oauth-fixture.mjs';
export { resource, scopes };
export const origin=new URL(resource).origin;
export function clockCrypto() {
  let now=1_800_000_000_000,randomCounter=0,keyCounter=0;
  const random=bytes=>{for(let i=0;i<bytes.length;i++)bytes[i]=(randomCounter++*29+7)%256;return bytes;};
  const subtle=new Proxy(webcrypto.subtle,{get(target,name){if(name==='generateKey')return async(algorithm,extractable,usages)=>{const bytes=createHash('sha256').update('oauth-fixture-'+keyCounter++).digest();return target.importKey('raw',bytes,algorithm,extractable,usages);};const v=Reflect.get(target,name,target);return typeof v==='function'?v.bind(target):v;}});
  return {now:()=>now,advance:ms=>now+=ms,random,subtle,install(){const date=Date.now,descriptor=Object.getOwnPropertyDescriptor(globalThis,'crypto');Date.now=()=>now;Object.defineProperty(globalThis,'crypto',{configurable:true,value:{subtle,getRandomValues:random}});return()=>{Date.now=date;Object.defineProperty(globalThis,'crypto',descriptor);};}};
}
export function kvFixture(clock,{pageSize=2}={}) {
  const rows=new Map(),effects=[],pending=new Set();let hook=async()=>{};
  const execute=(op,key,action,details={})=>{const event={op,key,...details};effects.push(event);const result=(async()=>{await hook('before',event);const value=action();await hook('after',event);return value;})();pending.add(result);result.then(()=>pending.delete(result),()=>pending.delete(result));return result;};
  const live=key=>{const row=rows.get(key);if(row?.expires!==undefined&&row.expires<=clock.now()/1000){rows.delete(key);return null;}return row??null;};
  return {rows,effects,setHook(fn){hook=fn;},async drain(){while(pending.size)await Promise.allSettled([...pending]);},
    get(key,options){return execute('get',key,()=>{const text=live(key)?.text??null;return options?.type==='json'&&text!==null?JSON.parse(text):text;});},
    put(key,text,options={}){return execute('put',key,()=>{rows.set(key,{text,expires:options.expiration??(options.expirationTtl===undefined?undefined:Math.floor(clock.now()/1000)+options.expirationTtl)});},{text,options:{...options}});},
    delete(key){return execute('delete',key,()=>{rows.delete(key);});},
    list(options={}){return execute('list',options.prefix,()=>{const keys=[...rows.keys()].sort().filter(k=>k.startsWith(options.prefix??'')&&live(k)&&(!options.cursor||k>options.cursor)),size=Math.min(options.limit??pageSize,pageSize),selected=keys.slice(0,size);return{keys:selected.map(name=>({name})),list_complete:keys.length<=size,cursor:keys.length<=size?'':selected.at(-1)};},{options:{...options}});},
    snapshot(){return [...rows].sort(([a],[b])=>a.localeCompare(b));}
  };
}
export async function originalDriver() {
  const {OAuthProvider,getOAuthApi}=await originalProvider();
  const options={apiRoute:'/mcp',apiHandler:{fetch(_r,_e,ctx){return Response.json(ctx.props);}},defaultHandler:{fetch(){return new Response('default');}},authorizeEndpoint:'/authorize',tokenEndpoint:'/oauth/token',clientRegistrationEndpoint:'/oauth/register',scopesSupported:scopes,accessTokenTTL:3600,refreshTokenTTL:604800,clientRegistrationTTL:90*86400,allowPlainPKCE:false,allowImplicitFlow:false,clientIdMetadataDocumentEnabled:false,resourceMetadata:{resource,authorization_servers:[origin],scopes_supported:scopes,resource_name:'Chat2Local',bearer_methods_supported:['header']},tokenExchangeCallback:o=>({accessTokenProps:{...o.props,scopes:o.requestedScope.filter(s=>scopes.slice(0,4).includes(s))}})};
  const provider=new OAuthProvider(options);return {fetch:(r,e)=>provider.fetch(r,e,{}),parseAuthRequest:(r,e)=>getOAuthApi(options,e).parseAuthRequest(r),lookupClient:(id,e)=>getOAuthApi(options,e).lookupClient(id),completeAuthorization:(o,e)=>getOAuthApi(options,e).completeAuthorization(o)};
}
export const registration=(extra={})=>new Request(origin+'/oauth/register',{method:'POST',body:JSON.stringify({redirect_uris:['https://client.example.test/callback'],token_endpoint_auth_method:'none',...extra})});
export const form=body=>new Request(origin+'/oauth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(body)});
export async function flow(driver,env,client,{props={deviceId:'a'.repeat(32),epoch:'b'.repeat(64),scopes:['files:read','files:write','terminal:execute'],unknown:'\ud800'},revokeExistingGrants=false}={}) {
  const verifier='synthetic-pkce-verifier',challenge=createHash('sha256').update(verifier).digest('base64url');
  const url=origin+'/authorize?'+new URLSearchParams({client_id:client.client_id,response_type:'code',redirect_uri:client.redirect_uris[0],scope:'files:read files:write terminal:execute offline_access',code_challenge:challenge,code_challenge_method:'S256',resource,state:'synthetic-state'});
  const request=await driver.parseAuthRequest(new Request(url),env),completed=await driver.completeAuthorization({request,userId:'synthetic-user',scope:request.scope,metadata:{future:'\udfff'},props,revokeExistingGrants},env);
  return {request,completed,exchange:{grant_type:'authorization_code',client_id:client.client_id,code:new URL(completed.redirectTo).searchParams.get('code'),code_verifier:verifier,resource}};
}
