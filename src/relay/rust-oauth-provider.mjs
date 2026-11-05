import { Wire, RustOAuthBearer } from './rust-oauth.mjs';
import { encodeValue, decodeValue } from './rust-oauth-values.mjs';
const fault=()=>Object.assign(new Error('OAuth core unavailable.'),{code:'EOAUTHCORE'});
const exact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join(',')===keys.split(' ').filter(Boolean).sort().join(',');
const fromUnits=units=>decodeValue({root:0,nodes:[['s',units]]});
const bytes=s=>{if(typeof s!=='string')throw fault();return Uint8Array.from(atob(s),c=>c.charCodeAt(0));};
const base64=b=>{b=new Uint8Array(b);let s='';for(let i=0;i<b.length;i+=16384)s+=String.fromCharCode(...b.subarray(i,i+16384));return btoa(s);};
const keyFields={kv_get:'key',kv_put:'key text options',kv_delete:'key',kv_list:'options',clock:'',random:'length',url:'input',url_set:'input sets',decode_component:'input',request_text:'',request_form:'',digest:'algorithm bytes',import_key:'format bytes algorithm extractable usages',generate_key:'algorithm extractable usages',sign:'algorithm key bytes',encrypt:'algorithm key bytes',decrypt:'algorithm key bytes',wrap_key:'format key wrappingKey algorithm',unwrap_key:'format bytes key algorithm unwrappedAlgorithm extractable usages'};
class AuthorizationError extends Error { constructor(code,options){super(options.description);this.name='AuthorizationError';this.code=code;this.description=options.description;this.redirectUri=options.redirectUri;this.state=options.state;this.issuer=options.issuer;} }

// Each invocation owns its instance, capabilities, pending effects and keys.
// A public outcome and the eventual drain are deliberately separate promises.
export class RustOAuthProvider {
  constructor(module,{instantiate=m=>new WebAssembly.Instance(m,{}),now=()=>Date.now(),random=b=>crypto.getRandomValues(b),subtle=crypto.subtle,authorizationErrorClass=AuthorizationError}={}){this.module=module;this.instantiate=instantiate;this.now=now;this.random=random;this.subtle=subtle;this.authorizationErrorClass=authorizationErrorClass;this.drains=new Set();this.bearer=new RustOAuthBearer(module,{instantiate,now});}
  helpers(env,{origin}) {return Object.freeze({parseAuthRequest:r=>this.parseAuthRequest(r,env,{origin}),lookupClient:id=>this.lookupClient(id,env,{origin}),completeAuthorization:o=>this.completeAuthorization(o,env,{origin}),listUserGrants:(user,options)=>this.listUserGrants(user,options,env,{origin}),revokeGrant:(grant,user)=>this.revokeGrant(grant,user,env,{origin})});}
  async parseAuthRequest(request,env,{origin}){return this.run('parseAuthRequest',{url:request.url,origin},env,request);}
  lookupClient(clientId,env,{origin}){return this.run('lookupClient',{clientId,origin},env);}
  completeAuthorization(options,env,{origin}){return this.run('completeAuthorization',{options,origin},env);}
  listUserGrants(userId,options,env,{origin}){return this.run('listUserGrants',{userId,options,origin},env);}
  revokeGrant(grantId,userId,env,{origin}){return this.run('revokeGrant',{grantId,userId,origin},env);}
  async fetch(request,env,ctx,{origin,defaultHandler,apiHandler}) {
    const local=Object.create(env);Object.defineProperty(local,'OAUTH_PROVIDER',{value:this.helpers(local,{origin}),enumerable:true});
    const result=await this.run('fetch',{origin,url:request.url,method:request.method,contentType:request.headers.get('Content-Type')||'',contentLength:request.headers.get('Content-Length')||'0',authorization:request.headers.get('Authorization')},local,request,ctx);
    let response;
    if(result.kind==='response')response=new Response(result.body,{status:result.status,headers:result.headers});
    else if(result.kind==='default')return defaultHandler.fetch(request,local,ctx);
    else if(result.kind==='api'){const auth=await this.bearer.authenticate(request,local,{resource:result.resource,scopes:result.scopes});if(auth.response)response=auth.response;else{ctx.props=auth.props;response=await apiHandler.fetch(request,local,ctx);}}
    else throw fault();
    if(result.cors&&request.headers.get('Origin')){
      const patch=await this.run('cors',{origin:request.headers.get('Origin'),headers:[...response.headers]},local);
      response=new Response(response.body,response);for(const[k,v]of patch)response.headers.set(k,v);
    }return response;
  }
  run(operation,args,env,request,ctx) {
    let resolve,reject;const publicResult=new Promise((a,b)=>{resolve=a;reject=b});let wire;
    try{wire=new Wire(this.module,this.instantiate,2);}catch{reject(fault());return publicResult;}
    const keys=new Map(),errors=new Map(),pending=new Map();let effectId=0,errorId=0,terminal=false,broken=false,closed=false;
    let drainResolve;const drain=new Promise(r=>{drainResolve=r});this.drains.add(drain);drain.then(()=>this.drains.delete(drain));if(ctx?.waitUntil)ctx.waitUntil(drain);
    const close=()=>{if(closed)return;closed=true;keys.clear();errors.clear();wire.close();drainResolve();};
    const fail=()=>{broken=true;if(!terminal){terminal=true;reject(fault());}if(!pending.size)close();};
    const key=(id,name)=>{const k=keys.get(id);if(!Number.isInteger(id)||!k||k.algorithm.name!==name)throw fault();return k;};
    const primitive=async(kind,a,id)=>{
      if(!Object.hasOwn(keyFields,kind)||!exact(a,keyFields[kind]))throw fault();
      if(kind.startsWith('kv_')&&kind!=='kv_list')a={...a,key:decodeValue(a.key)};
      if(kind.startsWith('kv_')&&kind!=='kv_list'&&(typeof a.key!=='string'||!['client:','grant:','token:'].some(p=>a.key.startsWith(p))))throw fault();
      switch(kind){
        case'kv_get':{const text=await env.OAUTH_KV.get(a.key,{type:'text'});if(text!==null&&typeof text!=='string')throw fault();return text;}
        case'kv_put':if(typeof a.text!=='string')throw fault();await env.OAUTH_KV.put(a.key,a.text,decodeValue(a.options));return undefined;
        case'kv_delete':await env.OAUTH_KV.delete(a.key);return undefined;
        case'kv_list':{const options=decodeValue(a.options);if(!options||typeof options.prefix!=='string'||!['grant:','token:'].some(p=>options.prefix.startsWith(p))||Object.keys(options).some(k=>!['prefix','limit','cursor'].includes(k)))throw fault();return env.OAUTH_KV.list(options);}
        case'clock':return this.now();
        case'random':if(![16,32].includes(a.length))throw fault();{const b=new Uint8Array(a.length);this.random(b);return [...b];}
        case'url':{try{const u=new URL(decodeValue(a.input));return {href:u.href,origin:u.origin,protocol:u.protocol,hostname:u.hostname,pathname:u.pathname,search:u.search,hash:u.hash,params:[...u.searchParams]};}catch{return null;}}
        case'url_set':{const u=new URL(decodeValue(a.input));for(const[k,v]of decodeValue(a.sets))u.searchParams.set(k,v);return u.href;}
        case'decode_component':return decodeURIComponent(decodeValue(a.input));
        case'request_text':if(!request)throw fault();return request.text();
        case'request_form':if(!request)throw fault();return [...(await request.formData()).entries()];
        case'digest':if(a.algorithm!=='SHA-256')throw fault();return base64(await this.subtle.digest(a.algorithm,bytes(a.bytes)));
        case'import_key':{
          if(a.format!=='raw'||a.extractable!==false||!((JSON.stringify(a.algorithm)==='{"hash":"SHA-256","name":"HMAC"}'||JSON.stringify(a.algorithm)==='{"name":"HMAC","hash":"SHA-256"}')&&JSON.stringify(a.usages)==='["sign"]'||a.algorithm?.name==='AES-KW'&&exact(a.algorithm,'name')&&JSON.stringify(a.usages)==='["wrapKey","unwrapKey"]'))throw fault();
          keys.set(id,await this.subtle.importKey(a.format,bytes(a.bytes),a.algorithm,a.extractable,a.usages));return id;}
        case'generate_key':if(a.algorithm?.name!=='AES-GCM'||a.algorithm.length!==256||!exact(a.algorithm,'name length')||a.extractable!==true||JSON.stringify(a.usages)!=='["encrypt","decrypt"]')throw fault();keys.set(id,await this.subtle.generateKey(a.algorithm,a.extractable,a.usages));return id;
        case'sign':if(a.algorithm!=='HMAC')throw fault();return base64(await this.subtle.sign(a.algorithm,key(a.key,'HMAC'),bytes(a.bytes)));
        case'encrypt':case'decrypt':if(a.algorithm?.name!=='AES-GCM'||!exact(a.algorithm,'name iv')||JSON.stringify(a.algorithm.iv)!=='[0,0,0,0,0,0,0,0,0,0,0,0]')throw fault();return base64(await this.subtle[kind]({...a.algorithm,iv:new Uint8Array(a.algorithm.iv)},key(a.key,'AES-GCM'),bytes(a.bytes)));
        case'wrap_key':if(a.format!=='raw'||a.algorithm?.name!=='AES-KW'||!exact(a.algorithm,'name'))throw fault();return base64(await this.subtle.wrapKey(a.format,key(a.key,'AES-GCM'),key(a.wrappingKey,'AES-KW'),a.algorithm));
        case'unwrap_key':if(a.format!=='raw'||a.algorithm?.name!=='AES-KW'||!exact(a.algorithm,'name')||a.unwrappedAlgorithm?.name!=='AES-GCM'||!exact(a.unwrappedAlgorithm,'name')||a.extractable!==true||JSON.stringify(a.usages)!=='["encrypt","decrypt"]')throw fault();keys.set(id,await this.subtle.unwrapKey(a.format,bytes(a.bytes),key(a.key,'AES-KW'),a.algorithm,a.unwrappedAlgorithm,a.extractable,a.usages));return id;
        default:throw fault();
      }
    };
    const error=e=>{if(!e||typeof e!=='object')throw fault();if(e.kind==='host'){if(!errors.has(e.handle))throw fault();return errors.get(e.handle);}if(e.kind==='error'){const C=e.name==='TypeError'?TypeError:e.name==='SyntaxError'?SyntaxError:Error;const result=new C(fromUnits(e.message));if(!['Error','TypeError','SyntaxError'].includes(e.name))result.name=e.name;return result;}if(e.kind==='syntax_json'){try{JSON.parse(fromUnits(e.input));}catch(err){if(err instanceof SyntaxError)return err;throw fault();}throw fault();}if(e.kind==='cycle_json'){try{JSON.stringify(decodeValue(e.input));}catch(err){if(err instanceof TypeError)return err;throw fault();}throw fault();}if(e.kind==='authorization'){const description=fromUnits(e.description);return new this.authorizationErrorClass(e.code,{description,...(e.redirect?decodeValue(e.redirect):{})});}throw fault();};
    const pump=result=>{
      if(!exact(result,'effects outcome drained')||!Array.isArray(result.effects)||typeof result.drained!=='boolean')throw fault();
      for(const effect of result.effects){if(!exact(effect,'id operation child kind args')||effect.id!==++effectId||effect.operation!==operation||!Number.isSafeInteger(effect.child)||effect.child<0||pending.has(effect.id))throw fault();const id=effect.id;
        const confirmation=wire.call({type:'confirm',effect});if(!exact(confirmation,'confirmed')||confirmation.confirmed!==id)throw fault();
        const task=primitive(effect.kind,effect.args,id);pending.set(id,task);
        task.then(value=>{pending.delete(id);if(broken){if(!pending.size)close();return;}try{pump(wire.call({type:'resume',id,result:{ok:true,value:encodeValue(value)}}));}catch{fail();}},e=>{pending.delete(id);if(broken){if(!pending.size)close();return;}if(e?.code==='EOAUTHCORE'){fail();return;}const handle=++errorId;errors.set(handle,e);try{pump(wire.call({type:'resume',id,result:{ok:false,handle,name:e instanceof Error?e.name:'NonError',message:encodeValue(e instanceof Error?e.message:'')}}));}catch{fail();}});
      }
      if(result.outcome!==null){if(terminal||!exact(result.outcome,result.outcome.ok?'ok value':'ok error')||typeof result.outcome.ok!=='boolean')throw fault();const value=result.outcome.ok?decodeValue(result.outcome.value):error(result.outcome.error);terminal=true;if(result.outcome.ok)resolve(value);else reject(value);}
      if(result.drained){if(pending.size||!terminal)throw fault();close();}
    };
    try{pump(wire.call({type:'start',operation,args:encodeValue(args)}));}catch{fail();}return publicResult;
  }
}
