import { randomSecret, sha256 } from '../shared/protocol.mjs';
import { registryHttp } from './registry-transaction.mjs';
const FRAME = 1_048_576, MEMORY = 64 * 1024 * 1024, NEW = 1_000_000, MAX_REFS = 32768, MAX_STEPS = 16384;
const fields = new Set(`value limit now key consume csrf target deviceId keyHash ipHash kind count until expiresAt proofHash previousHash csrfHash sessionHash devices epoch description name platform arch system httpStatus body headers ok error retryAfterSeconds deviceCount
command action actor input native guard resource identityKey sessionBinding accountId account connectionId clientId scopes id createdAt revoked revision policy shares roots rootId mode deviceEpoch intentId connectionEpoch snapshotDigest policyDigest requestDigest requestHash phase expiresAt resumeUntil consentedAt allowScopeUpgrade connectionRevision grantVersion grant connections version
flowId flow expected current session browserHash bindingId issuer subject sessionId expiresAt ttl kind action secret value binding authRequest displayName clientName scope redirectUri bootstrapHash nativeHash provision owned registering device input until finishTaken accountId registered mode scopeUpgrade connectionId credentialHash
owner invitationId invitationHash purpose descriptor claim secretHash stable supplied bootstrapHash keyHash sessionHash registering flowId deviceId device manageExisting reuseExisting recoveryEpoch recoveryRevision recoveryRoots allowScopeUpgrade cancelled fingerprint result requestId rootIds expectedRevision removed filesDeleted
salt digest config sessionHash id claimHash browserHash name bucket limit windowMs proof type secret selectedConnectionId grant redirectUri rememberHash
hostname protocol username password search hash pathname href origin host inputKeys Retry-After deleted saved reserved activeSharesChanged management callbackOrigin recoveryRoots remember configured fileAccessGranted ready foldersGranted`.split(/\s+/));
const domains = {
  'registry.selfEnroll': ['device:', 'deviceCount', 'selfDeviceCount', 'selfRates'], 'registry.enroll': ['device:', 'deviceCount'], 'registry.ticket.inspect': ['ticket:'],
  'budget.consume': ['budget:'], 'roster.linkTicket.create': ['link-ticket:'], 'roster.linkTicket.consume': ['link-ticket:'], 'roster.append': ['browser-roster:'],
  'account.execute': ['accounts:v3:', 'onboarding:v1:session-binding:', 'instance:v1:flow:', 'instance:v1:invite:', 'device:'], 'account.resolve': ['accounts:v3:'],
  'onboarding.records': ['onboarding:v1:login:','onboarding:v1:session:','onboarding:v1:session-binding:'],
  'onboarding.flow.create': ['onboarding:v1:flow:','onboarding:v1:session-binding:'],
  'onboarding.device.provision': ['onboarding:v1:flow:','onboarding:v1:session-binding:','onboarding:v1:registered:','device:','deviceCount'],
  'onboarding.native.start': ['onboarding:v1:flow:','onboarding:v1:session-binding:'],
  'onboarding.finish.take': ['onboarding:v1:flow:','onboarding:v1:session-binding:'],
  ...Object.fromEntries(['owner.ensure','manage','shares.remove','invitation.create','invitation.revoke','invitation.pin','flow.create','invitation.claim','recovery.claim','native.bindEpoch','finish.take','remember.store'].map(name=>['instance.'+name,['instance:v1:','accounts:v3:','device:','deviceCount']])),
  'install.password.configure':['install:v1:password'],'install.rate.consume':['install:v1:rate:'], 'install.session.create':['install:v1:password','install:v1:session:'],
  ...Object.fromEntries(['ticket.create','context.ticket','claim.ticket','ticket.ready'].map(name=>['install.'+name,['install:v1:ticket:']])),
  'install.context.session':['install:v1:session:','install:v1:password'],
  ...Object.fromEntries(['authorize.check','authorize.pin','authorize.advance'].map(name=>['install.'+name,['install:v1:session:','install:v1:password','install:v1:ticket:']])),
};
const writes={
  'registry.selfEnroll':['selfRates','deviceCount','selfDeviceCount','device:'],'registry.enroll':['deviceCount','device:'],'registry.ticket.inspect':['ticket:'],
  'budget.consume':['budget:'],'roster.linkTicket.create':['link-ticket:'],'roster.linkTicket.consume':['link-ticket:'],'roster.append':['browser-roster:'],
  'account.resolve':[],
  'onboarding.records':['onboarding:v1:login:','onboarding:v1:session:','onboarding:v1:session-binding:'],'onboarding.flow.create':['onboarding:v1:flow:'],
  'onboarding.device.provision':['onboarding:v1:flow:','onboarding:v1:registered:','device:','deviceCount'],'onboarding.native.start':['onboarding:v1:flow:'],'onboarding.finish.take':['onboarding:v1:flow:'],
  'instance.owner.ensure':['instance:v1:owner:'],'instance.manage':['instance:v1:flow:'],'instance.shares.remove':['accounts:v3:connection:','instance:v1:device-link:','instance:v1:removal:'],
  'instance.invitation.create':['instance:v1:invite:'],'instance.invitation.revoke':['instance:v1:invite:'],'instance.invitation.pin':[],
  'instance.flow.create':['instance:v1:flow:'],'instance.invitation.claim':['instance:v1:invite:','instance:v1:flow:','device:','deviceCount'],
  'instance.recovery.claim':['instance:v1:flow:'],'instance.native.bindEpoch':['instance:v1:flow:'],'instance.finish.take':['instance:v1:flow:'],'instance.remember.store':['instance:v1:remember:'],
  'install.password.configure':['install:v1:password'],'install.rate.consume':['install:v1:rate:'],'install.session.create':['install:v1:session:'],
  'install.ticket.create':['install:v1:ticket:'],'install.context.ticket':[],'install.context.session':[],'install.authorize.check':[],
  'install.authorize.pin':['install:v1:ticket:'],'install.authorize.advance':['install:v1:ticket:'],'install.claim.ticket':[],'install.ticket.ready':['install:v1:ticket:'],
};
const accountWrites={account:['identity'],connections:[],prepare:['intent','intent-index','cleanup-index'],status:[],cancel:['intent'],confirm:['intent'],activate:['device-owner','connection','connection-index','intent'],'revoke-share':['connection'],'revoke-connection':['connection']};
const matches=(key,prefix)=>prefix.endsWith(':')?key.startsWith(prefix):key===prefix;
const effectCapabilities={
  'registry.selfEnroll':'get now put','registry.enroll':'get put','registry.ticket.inspect':'get now compute delete',
  'budget.consume':'get put','roster.linkTicket.create':'list now deleteMany put','roster.linkTicket.consume':'get now delete','roster.append':'get now list deleteMany put delete',
  'account.resolve':'get','onboarding.flow.create':'get now list delete put','onboarding.device.provision':'get now put','onboarding.native.start':'get now put','onboarding.finish.take':'get now put',
  'instance.owner.ensure':'get random put','instance.manage':'get compute list now delete put','instance.shares.remove':'get list put','instance.invitation.create':'get now compute list delete put','instance.invitation.revoke':'get put','instance.invitation.pin':'get now','instance.flow.create':'list now delete put','instance.invitation.claim':'get now compute put','instance.recovery.claim':'get now put','instance.native.bindEpoch':'get put compute','instance.finish.take':'get now put','instance.remember.store':'list now delete compute put',
  'install.password.configure':'get random put','install.rate.consume':'get list now delete put','install.session.create':'get list now delete put','install.ticket.create':'get list now delete put',
  'install.context.ticket':'get now compute','install.context.session':'get now compute','install.authorize.check':'get now compute','install.authorize.pin':'get now compute put','install.authorize.advance':'get now compute put','install.claim.ticket':'get now compute','install.ticket.ready':'get now compute put',
};
function allowedEffects(op,input){
  if(op==='account.execute')return ({account:'get random now put',connections:'get compute now',prepare:'compute get now random put delete',status:'get now',cancel:'get now put',confirm:'get now put compute',activate:'get now compute put','revoke-share':'get now compute put','revoke-connection':'get now random put'}[input.command?.action]||'').split(' ');
  if(op==='onboarding.records')return ({get:'get now',take:'get now delete',delete:'get delete',put:'get compute list now delete put'}[input.action]||'').split(' ');
  if(op==='instance.manage'&&input.action==='connections')return ['get','compute'];
  const types=(effectCapabilities[op]||'').split(' ');return op==='registry.ticket.inspect'&&input.consume!==true?types.filter(type=>type!=='delete'):types;
}
const patchFields = { 'registry.selfEnroll': ['count'], 'budget.consume': ['count'], 'account.execute': ['phase','consentedAt','resumeUntil','scopes','shares','revision','revoked','epoch'], 'onboarding.device.provision':['provision'], 'onboarding.native.start':['device','nativeHash'], 'onboarding.finish.take':['finishTaken'] };
const accountBranches=['account','connections','prepare','status','cancel','confirm','activate','revoke-share','revoke-connection','status-active','status-revoked','status-expired','active-idempotent-confirm','active-idempotent-activate','confirm-prepared','prepare-idempotent'];
const instancePatches={
  'instance.shares.remove':{'accounts:v3:connection:':['shares','revision']},
  'instance.invitation.revoke':{'instance:v1:invite:':['revoked']},
  'instance.invitation.claim':{'instance:v1:invite:':['claim','resumeUntil'],'instance:v1:flow:':['invitationId','invitationHash','connectionId','device']},
  'instance.recovery.claim':{'instance:v1:flow:':['allowScopeUpgrade','reuseExisting','connectionId','recoveryEpoch','recoveryRevision','recoveryRoots','device']},
  'instance.native.bindEpoch':{'instance:v1:flow:':['epoch']},
  'instance.finish.take':{'instance:v1:flow:':['finishTaken']},
  'install.rate.consume':{'install:v1:rate:':['count']}, 'install.authorize.pin':{'install:v1:ticket:':['connectionId']}, 'install.authorize.advance':{'install:v1:ticket:':['phase']},'install.ticket.ready':{'install:v1:ticket:':['phase']},
};
for(const [op,rules]of Object.entries(instancePatches))patchFields[op]=[...new Set(Object.values(rules).flat())];
function permittedPatch(op,origin,field){
  if(origin.kind!=='get')return false;
  if(op==='budget.consume')return origin.key.startsWith('budget:')&&origin.path.length===0;
  if(op==='registry.selfEnroll')return origin.key==='selfRates'&&origin.path.length===1&&Number.isInteger(origin.path[0]);
  if(op==='account.execute')return origin.path.length===0&&(origin.key.startsWith('accounts:v3:intent:')?['phase','consentedAt','resumeUntil'].includes(field):origin.key.startsWith('accounts:v3:connection:')&&['scopes','shares','revision','revoked','epoch'].includes(field));
  if(op.startsWith('onboarding.'))return origin.path.length===0&&origin.key.startsWith('onboarding:v1:flow:');
  return Object.entries(instancePatches[op]||{}).some(([prefix,allowed])=>origin.key.startsWith(prefix)&&allowed.includes(field)&&(op==='instance.native.bindEpoch'?origin.path.length===1&&origin.path[0]==='device':origin.path.length===0));
}
const branches={
  'registry.selfEnroll':{normal:['existing','quota','rate-capacity','rate-denied','created']},'registry.enroll':{normal:['denied','created']},
  'registry.ticket.inspect':{normal:['invalid','consumed','peek']},'budget.consume':{normal:['denied','allowed']},
  'roster.linkTicket.create':{normal:['created'],abort:['capacity']},'roster.linkTicket.consume':{normal:['invalid','consumed']},'roster.append':{normal:['device-limit','appended'],abort:['capacity','invalid']},
  'account.execute':{normal:accountBranches,abort:accountBranches},'account.resolve':{normal:['resolved'],abort:['resolved']},
  'onboarding.records':{normal:['records-get','records-take','records-delete','records-put'],abort:['records-get','records-take','records-delete','records-put']},
  ...Object.fromEntries(['flow.create','device.provision','native.start','finish.take'].map(name=>['onboarding.'+name,{normal:[name],abort:[name]}])),
  ...Object.fromEntries(['owner.ensure','manage','shares.remove','invitation.create','invitation.revoke','invitation.pin','flow.create','invitation.claim','recovery.claim','native.bindEpoch','finish.take','remember.store'].map(name=>['instance.'+name,{normal:[name,...(name==='invitation.create'?['invitation-idempotent']:name==='remember.store'?['remember-full']:[])],abort:[name]}])),
  ...Object.fromEntries(['password.configure','rate.consume','session.create','ticket.create','context.ticket','context.session','authorize.check','authorize.pin','authorize.advance','claim.ticket','ticket.ready'].map(name=>['install.'+name,{normal:[name,...(name==='ticket.create'?['ticket-idempotent']:[])],abort:[name]}])),
};
const exact = (v, names) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === names.length && names.every(k => Object.hasOwn(v, k));
const unavailable = () => Object.assign(Error('Registry transaction core unavailable; no fallback or replay.'), { code: 'EREGISTRY' });
const decision = (value,op,outcome) => exact(value,['op','branch','outcome'])&&value.op===op&&value.outcome===outcome&&branches[op]?.[outcome]?.includes(value.branch);
function validateResult(op,input,value){
  if(op.startsWith('registry.')||op.startsWith('roster.')||op==='budget.consume'){registryHttp(value);return;}
  if(op==='onboarding.records'&&['get','take'].includes(input.action))return;
  if(['onboarding.flow.create','onboarding.finish.take','instance.flow.create','instance.finish.take','instance.remember.store','install.rate.consume','install.session.create','install.authorize.pin','install.authorize.advance'].includes(op)){if(value!==undefined)throw unavailable();return;}
  if(op==='instance.recovery.claim'){if(typeof value!=='boolean')throw unavailable();return;}
  if(!value||typeof value!=='object'||Array.isArray(value))throw unavailable();
  const require=(field,type)=>{if(!Object.hasOwn(value,field)||(type==='array'?!Array.isArray(value[field]):typeof value[field]!==type))throw unavailable();};
  if(op==='account.execute'){
    const action=input.command.action;
    if(action==='account')require('accountId','string');
    else if(action==='connections'){require('accountId','string');require('connections','array');}
    else if(action.startsWith('revoke-')){require('revoked','boolean');require('revision','number');}
    else {for(const key of ['intentId','accountId','connectionId','deviceId','deviceEpoch','snapshotDigest','phase'])require(key,'string');require('roots','array');require('scopes','array');}
    return;
  }
  const contracts={
    'account.resolve':{accountId:'string',connectionId:'string',devices:'array',scopes:'array'},
    'onboarding.records':{[input.action==='put'?'saved':'deleted']:'boolean'},'onboarding.device.provision':{reserved:'boolean'},'onboarding.native.start':{id:'string'},
    'instance.owner.ensure':{resource:'string',identityKey:'string',sessionBinding:'string'},'instance.invitation.create':{id:'string',secretHash:'string'},'instance.invitation.pin':{id:'string',secretHash:'string'},
    'instance.invitation.revoke':{revoked:'boolean',activeSharesChanged:'boolean'},'instance.invitation.claim':{reserved:'boolean'},'instance.shares.remove':{removed:'boolean',rootIds:'array',revision:'number'},
    'instance.manage':input.action==='connections'?{connections:'array'}:{flowId:'string',requestDigest:'string'},'instance.native.bindEpoch':{flowId:'string',requestDigest:'string'},
    'install.password.configure':{configured:'boolean',fileAccessGranted:'boolean'},'install.ticket.create':{id:'string',until:'number'},'install.context.ticket':{id:'string',until:'number',phase:'string'},
    'install.context.session':{epoch:'string',until:'number'},'install.authorize.check':{id:'string',until:'number',phase:'string'},'install.claim.ticket':{id:'string',until:'number',phase:'string'},'install.ticket.ready':{ready:'boolean',foldersGranted:'boolean'},
  };
  if(!contracts[op])throw unavailable();for(const [field,type]of Object.entries(contracts[op]))require(field,type);
}
const units = value => Array.from({ length: value.length }, (_, i) => value.charCodeAt(i));
const string = value => { if (!Array.isArray(value) || value.length > 524288 || value.some(n => !Number.isInteger(n) || n < 0 || n > 65535)) throw unavailable(); let out = ''; for (let n=0;n<value.length;n+=4096) out += String.fromCharCode(...value.slice(n,n+4096)); return out; };

// Required projections describe protocol fields, not whole stored records.
// Unknown fields (including names used by another aggregate) remain host-owned.
const shape=(names='',children={})=>({...Object.fromEntries(names.split(' ').filter(Boolean).map(k=>[k,null])),...children});
const shapes={
  actor:shape('identityKey sessionBinding'), root:shape('rootId mode deviceId deviceEpoch intentId'),
  device:shape('deviceId epoch keyHash sessionHash'), auth:shape('clientId redirectUri',{scope:[null]}),
  grant:shape('grantVersion accountId connectionId connectionEpoch clientId resource',{scopes:[null]}),
  owner:shape('resource identityKey sessionBinding accountId',{actor:'actor'}),
  registration:shape('kind keyHash accountId invitationId'), rate:shape('key ipHash count until'),
  identity:shape('id createdAt'), index:shape('id until'), binding:shape('id identityKey until'),
  identityValue:shape('browserHash expiresAt'), identityRecord:shape('until bindingId',{value:'identityValue'}),
  descriptor:shape('clientName redirectUri'), proof:shape('intentId deviceId deviceEpoch snapshotDigest phase'),
  accountInput:shape('intentId connectionId clientId resource deviceId deviceEpoch policyDigest requestDigest allowScopeUpgrade snapshotDigest rootId',{roots:['root'],scopes:[null]}),
  connection:shape('id accountId clientId resource epoch revision revoked policy',{shares:['root'],scopes:[null]}),
  intent:shape('id accountId sessionBinding requestHash connectionId connectionEpoch connectionRevision phase expiresAt resumeUntil consentedAt intentId clientId resource deviceId deviceEpoch policyDigest requestDigest snapshotDigest allowScopeUpgrade',{roots:['root'],scopes:[null]}),
  flow:shape('id mode scopeUpgrade accountId displayName clientName resource connectionId bootstrapHash browserHash nativeHash createdAt until finishTaken invitationId invitationHash reuseExisting manageExisting recoveryEpoch recoveryRevision allowScopeUpgrade cancelled',{actor:'actor',authRequest:'auth',scopes:[null],device:'device',provision:'device',recoveryRoots:['root']}),
  invite:shape('id secretHash purpose resource accountId connectionId connectionEpoch clientId expiresAt revoked resumeUntil',{descriptor:'descriptor',scopes:[null],claim:shape('flowId deviceId keyHash sessionHash')}),
  manageInput:shape('flowId connectionId requestId expectedRevision',{rootIds:[null]}),
  rosterDevice:shape('deviceId epoch',{description:shape('name platform arch system')}),
  ticket:shape('csrfHash expiresAt',{authRequest:'opaque'}),
  linkTicket:shape('csrfHash proofHash previousHash expiresAt'),
  installTicket:shape('id claimHash browserHash name until phase connectionId'),
};
function storedShape(key,op,input){
  if(key==='install:v1:password')return shape('epoch');if(key.startsWith('install:v1:session:'))return shape('epoch until');if(key.startsWith('install:v1:ticket:'))return 'installTicket';if(key.startsWith('install:v1:rate:'))return 'rate';
  if(op==='onboarding.records'&&(key.startsWith('onboarding:v1:login:')||key.startsWith('onboarding:v1:session:')))return shape('until bindingId',{value:input.action==='take'?shape('browserHash'):'opaque'});
  if(op==='account.execute'&&input.command?.action==='connections'&&key.startsWith('accounts:v3:connection:'))return shape('id clientId accountId resource revoked',{scopes:[null]});
  if(key==='selfRates')return['rate'];if(key.startsWith('budget:'))return 'rate';if(key.startsWith('device:'))return 'registration';
  if(key.startsWith('ticket:'))return 'ticket';if(key.startsWith('link-ticket:'))return 'linkTicket';if(key.startsWith('browser-roster:'))return shape('expiresAt',{devices:['rosterDevice']});
  for(const [prefix,s]of [['accounts:v3:identity:','identity'],['accounts:v3:connection-index:',[null]],['accounts:v3:intent-index:',['index']],['accounts:v3:cleanup-index:',['index']],['accounts:v3:connection:','connection'],['accounts:v3:intent:','intent'],['accounts:v3:device-owner:',shape('accountId epoch')],['onboarding:v1:session-binding:','binding'],['onboarding:v1:session:','identityRecord'],['onboarding:v1:login:','identityRecord'],['onboarding:v1:registered:',[null]],['onboarding:v1:flow:','flow'],['instance:v1:flow:','flow'],['instance:v1:invite:','invite'],['instance:v1:owner:','owner'],['instance:v1:client:','descriptor'],['instance:v1:device-link:',shape('deviceEpoch connectionEpoch')],['instance:v1:removal:',shape('fingerprint',{result:'opaque'})],['instance:v1:remember:',shape('until redirectUri',{grant:'grant'})]])if(key.startsWith(prefix))return s;
  return null;
}
function inputShape(op){
  if(op==='install.password.configure')return shape('salt digest');
  if(op==='install.rate.consume')return shape('bucket limit windowMs');
  if(op==='install.session.create')return shape('sessionHash',{config:shape('epoch')});
  if(op==='install.ticket.create')return shape('',{input:'installTicket'});
  if(op.startsWith('install.'))return shape('id browser session secret selectedConnectionId');
  if(op==='account.execute')return shape('',{command:shape('action',{actor:'actor',input:'accountInput'}),native:'proof',guard:shape('kind resource',{flow:'flow'})});
  if(op==='account.resolve')return shape('',{grant:'grant'});
  if(op==='onboarding.records')return shape('action kind key ttl',{value:'identityValue',binding:'binding'});
  if(op==='onboarding.flow.create')return shape('id',{actor:'actor',value:'flow'});
  if(op==='onboarding.device.provision')return shape('flowId proofHash deviceId keyHash sessionHash');
  if(op==='onboarding.native.start')return shape('flowId credentialHash nativeHash',{device:'device'});
  if(op==='onboarding.finish.take')return shape('flowId browserHash',{actor:'actor'});
  if(op.startsWith('instance.'))return shape('resource action sessionHash fingerprint invitationId digest flowId bootstrapHash deviceId keyHash registering',{device:'device',input:'manageInput',owner:'owner',stable:shape('invitationId'),value:'invite',flow:'flow',supplied:shape('id hash'),remember:'opaque',grant:'grant',redirectUri:null});
  if(op==='registry.selfEnroll')return shape('limit',{value:shape('deviceId keyHash ipHash')});
  if(op==='registry.enroll')return shape('',{value:shape('deviceId')});
  if(op==='registry.ticket.inspect')return shape('key consume csrf');
  if(op==='budget.consume')return shape('now key limit');
  return shape('',{value:shape('csrfHash proofHash previousHash sessionHash',{device:'rosterDevice'}),target:'rosterDevice'});
}

class Wire {
  constructor(module, instantiate) {
    if (!(module instanceof WebAssembly.Module) || WebAssembly.Module.imports(module).length) throw unavailable();
    this.e = instantiate(module).exports; this.serial = 0;
    if (!(this.e.memory instanceof WebAssembly.Memory) || ['abi_version','frame_capacity','input_ptr','output_ptr','output_len','command'].some(k => typeof this.e[k] !== 'function') || this.e.abi_version() !== 1 || this.e.frame_capacity() !== FRAME) throw unavailable();
    this.input = this.e.input_ptr(); this.output = this.e.output_ptr(); this.bounds();
  }
  bounds() { const size=this.e.memory.buffer.byteLength; if(size>MEMORY||![this.input,this.output].every(n=>Number.isInteger(n)&&n>=0&&n+FRAME<=size)||Math.abs(this.input-this.output)<FRAME)throw unavailable(); }
  call(command) {
    const serial=++this.serial,bytes=new TextEncoder().encode(JSON.stringify({v:1,serial,command})); if(bytes.length>FRAME)throw unavailable();
    this.bounds();new Uint8Array(this.e.memory.buffer,this.input,bytes.length).set(bytes);if(this.e.command(bytes.length)!==0)throw unavailable();this.bounds();
    const length=this.e.output_len();if(!Number.isInteger(length)||length<1||length>FRAME)throw unavailable();
    const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(new Uint8Array(this.e.memory.buffer,this.output,length)));
    if(!exact(value,['v','serial','result'])||value.v!==1||value.serial!==serial)throw unavailable();return value.result;
  }
}
class References {
  constructor(op) { this.op=op;this.refs=new Map();this.ids=new WeakMap();this.origins=new Map();this.nodes=[];this.projections=new Map();this.measured=new WeakSet();this.cost=0; }
  measure(value) {
    const pending=[value];while(pending.length){const v=pending.pop();if(typeof v==='string')this.cost+=v.length*2;
      else if(typeof v==='bigint'){const magnitude=v<0n?-v:v;if(magnitude>>BigInt(8*FRAME))throw unavailable();this.cost+=16+Math.ceil(magnitude.toString(16).length/2)*2;}
      else if(v&&typeof v==='object'&&!this.measured.has(v)){
      this.measured.add(v);this.cost+=64;if(ArrayBuffer.isView(v))this.cost+=v.byteLength;else if(v instanceof ArrayBuffer)this.cost+=v.byteLength;
      else if(v instanceof Map){for(const [k,x]of v)pending.push(k,x);}else if(v instanceof Set)pending.push(...v);
      else if(v instanceof Date)this.cost+=16;
      else if(v instanceof RegExp)this.cost+=(v.source.length+v.flags.length)*2;
      else if(v instanceof Error){pending.push(v.message,v.stack,v.cause);}
      else if(typeof Blob!=='undefined'&&v instanceof Blob)this.cost+=v.size;
      else if(!Array.isArray(v)&&Object.getPrototypeOf(v)!==Object.prototype&&Object.getPrototypeOf(v)!==null)throw unavailable();
      for(const k of Object.keys(v)){this.cost+=k.length*2;pending.push(v[k]);}
    }if(this.cost>16*FRAME||pending.length>65536)throw unavailable();}
  }
  pack(value, origin = { kind: 'input', path: [] }) {
    let schema=origin.schema;while(typeof schema==='string'&&schema!=='opaque')schema=shapes[schema];
    if(schema==='opaque'&&value!==undefined){const id=this.refs.size+1;if(id>MAX_REFS)throw unavailable();this.refs.set(id,value);this.origins.set(id,[origin]);this.nodes.push({id,kind:'opaque',keys:[],props:[],items:[],base:null});return{t:'r',v:id};}
    if(value===undefined)return{t:'u'};if(value===null)return{t:'null'};if(typeof value==='boolean')return{t:'b',v:value};if(typeof value==='number')return{t:'n',v:Object.is(value,-0)?'-0':String(value)};if(typeof value==='string')return{t:'s',v:units(value)};
    if(typeof value==='bigint')return{t:'big'};if(!value||typeof value!=='object')throw unavailable();
    let id=this.ids.get(value);if(id){const origins=this.origins.get(id);if(origins.length<64)origins.push(origin);}else{if(this.refs.size>=MAX_REFS)throw unavailable();id=this.refs.size+1;this.refs.set(id,value);this.ids.set(value,id);this.origins.set(id,[origin]);}
    const plain=Object.getPrototypeOf(value)===Object.prototype||Object.getPrototypeOf(value)===null;
    let projection=this.projections.get(id);if(!projection){const node={id,kind:Array.isArray(value)?'array':plain?'object':'opaque',keys:[],props:[],items:[],base:null};projection={node,seen:new Set(),sent:false};this.projections.set(id,projection);this.nodes.push(node);if(plain){const keys=Object.keys(value);if(keys.length>4096)throw unavailable();node.keys=keys.map(units);}}
    const {node,seen}=projection;
    if(Array.isArray(value)&&Array.isArray(schema)&&!seen.has('*')){if(value.length>65536||projection.sent)throw unavailable();seen.add('*');node.items=Array.from({length:value.length},(_,i)=>Object.hasOwn(value,i)?this.pack(value[i],{...origin,path:[...origin.path,i],schema:schema[0]}):{t:'h'});}
    else if(plain&&schema&&typeof schema==='object'&&!Array.isArray(schema)){for(const k of Object.keys(value)){if(!Object.hasOwn(schema,k)||seen.has(k))continue;if(projection.sent)throw unavailable();seen.add(k);node.props.push([k,this.pack(value[k],{...origin,path:[...origin.path,k],schema:schema[k]})]);}}
    return{t:'r',v:id};
  }
  observe(value,wire,origin) {
    origin??={kind:'input',path:[]};if(origin.kind==='input')this.input=value;const schema=origin.kind==='input'?inputShape(this.op):origin.kind==='get'?storedShape(origin.key,this.op,this.input):origin.kind==='list'?[shape('key',{value:storedShape(origin.key,this.op,this.input)})]:origin.kind==='compute'?Array.isArray(value)?[null]:value&&typeof value==='object'?shape('href protocol hostname host username password search hash pathname origin'):null:null;
    this.measure(value);const result=this.pack(value,{...origin,schema});let chunk=[],size=0;
    for(const node of this.nodes.splice(0)){const n=JSON.stringify(node).length;if(n>FRAME-1024)throw unavailable();if(size+n>FRAME/2&&chunk.length){this.send(chunk,wire);chunk=[];size=0;}chunk.push(node);size+=n;const projection=this.projections.get(node.id);if(projection)projection.sent=true;}
    if(chunk.length)this.send(chunk,wire);return result;
  }
  send(nodes,wire){const r=wire.call({type:'graph',nodes});if(!exact(r,['kind'])||r.kind!=='ack')throw unavailable();}
  materialize(graph,op,value) {
    if(!exact(graph,['nodes','patches'])||!Array.isArray(graph.nodes)||graph.nodes.length>MAX_REFS||!Array.isArray(graph.patches)||graph.patches.length>MAX_STEPS)throw unavailable();
    const newNodes=new Map(),all={has:id=>this.refs.has(id)||newNodes.has(id)};
    for(const n of graph.nodes){if(!exact(n,['id','kind','keys','props','items','base'])||!Number.isInteger(n.id)||n.id<=NEW||n.id>NEW+MAX_REFS||all.has(n.id)||!['object','array'].includes(n.kind)||!Array.isArray(n.props)||!Array.isArray(n.items)||!Array.isArray(n.keys))throw unavailable();newNodes.set(n.id,n);}
    const check=v=>{if(!v||typeof v!=='object'||!['u','h','null','b','n','s','r'].includes(v.t))throw unavailable();if(['u','h','null'].includes(v.t)){if(!exact(v,['t']))throw unavailable();}else if(!exact(v,['t','v']))throw unavailable();else if(v.t==='r'&&!all.has(v.v))throw unavailable();else if(v.t==='s')string(v.v);else if(v.t==='b'&&typeof v.v!=='boolean')throw unavailable();else if(v.t==='n'&&(typeof v.v!=='string'||!/^(-?\d+(\.\d+)?([eE][+-]?\d+)?|NaN|inf|-inf|Infinity|-Infinity)$/.test(v.v)))throw unavailable();};
    check(value);
    for(const n of newNodes.values()){if(n.base!==null&&(!all.has(n.base)||n.base===n.id))throw unavailable();if(n.keys.length>4096||n.items.length>65536||n.props.length>4096)throw unavailable();const names=new Set();for(const k of n.keys){const s=string(k);if(names.has(s))throw unavailable();names.add(s);}for(const p of n.props){if(!Array.isArray(p)||p.length!==2||typeof p[0]!=='string'||!fields.has(p[0]))throw unavailable();check(p[1]);}for(const item of n.items)check(item);}
    for(const p of graph.patches){if(!exact(p,['target','field','value'])||!this.refs.has(p.target)||!patchFields[op]?.includes(p.field))throw unavailable();check(p.value);const target=this.refs.get(p.target);if(!target||typeof target!=='object'||Array.isArray(target))throw unavailable();
      if(!this.origins.get(p.target).some(o=>permittedPatch(op,o,p.field)))throw unavailable();}
    if(value.t==='u')return undefined;
    const selected=new Set(),required=new Set();
    const select=v=>{if(v.t!=='r'||selected.has(v.v))return;selected.add(v.v);if(this.refs.has(v.v)){required.add(v.v);return;}const n=newNodes.get(v.v);if(n.base!==null)select({t:'r',v:n.base});for(const [,item]of n.props)select(item);for(const item of n.items)select(item);};
    select(value);for(const p of graph.patches){required.add(p.target);select(p.value);}
    // One bundle clone preserves all unknown cycles, aliases and shared buffers.
    const originals=[...required].map(id=>[id,this.refs.get(id)]);const clones=structuredClone(originals.map(([,v])=>v));const objects=new Map(originals.map(([id],i)=>[id,clones[i]]));
    for(const n of newNodes.values())if(selected.has(n.id))objects.set(n.id,n.kind==='array'?[]:{});
    const decode=v=>v.t==='r'?objects.get(v.v):v.t==='s'?string(v.v):v.t==='n'?Number(v.v.replace('inf','Infinity')):v.t==='b'?v.v:v.t==='null'?null:undefined;
    const define=(obj,key,v)=>Object.defineProperty(obj,key,{value:v,enumerable:true,writable:true,configurable:true});
    for(const p of graph.patches)define(objects.get(p.target),p.field,decode(p.value));
    const done=new Set(),active=new Set();
    const fill=id=>{if(done.has(id)||!newNodes.has(id))return;if(active.has(id))throw unavailable();active.add(id);const n=newNodes.get(id),out=objects.get(id);if(n.base!==null)fill(n.base);
      if(n.kind==='array'){out.length=n.items.length;n.items.forEach((v,i)=>{if(v.t!=='h')out[i]=decode(v);});}
      else{const props=new Map(n.props);for(const key of n.keys.map(string)){if(props.has(key))define(out,key,decode(props.get(key)));else if(n.base!==null)define(out,key,objects.get(n.base)[key]);else throw unavailable();}}
      active.delete(id);done.add(id);};for(const id of selected)fill(id);
    return decode(value);
  }
}
/** Each real storage callback creates a fresh WASM instance and reference table. */
export class RustRegistryRunner {
  constructor(module,{instantiate=value=>new WebAssembly.Instance(value,{}),trace}={}){this.module=module;this.instantiate=instantiate;this.trace=trace;this.nextTransaction=0;}
  emit(event) { try { this.trace?.(event); } catch { /* Diagnostics cannot change commit, rollback or the caller's result. */ } }
  async transaction(storage,op,input,{now=Date.now}={}) {
    if(!domains[op])throw unavailable();let ordinal=0;const transaction=++this.nextTransaction,emit=event=>this.emit({transaction,...event});
    const writable=op==='account.execute'?(accountWrites[input.command?.action]||[]).map(kind=>'accounts:v3:'+kind+':'):writes[op],capabilities=allowedEffects(op,input);
    try {const result=await storage.transaction(async tx=>{
      const attempt=++ordinal,wire=new Wire(this.module,this.instantiate),refs=new References(op);let seq=0,readId=0;
      // Graph chunks precede init; references belong only to this callback.
      const root=refs.observe(input,wire);const init=wire.call({type:'init',op,input:root});if(!exact(init,['kind'])||init.kind!=='ack')throw unavailable();
      let step=wire.call({type:'run'});
      while(true){
        if(step.kind==='abort'){if(!exact(step,['kind','message','status','decision'])||typeof step.message!=='string'||step.message.length>1024||!Number.isInteger(step.status)||step.status<400||step.status>599||!decision(step.decision,op,'abort'))throw unavailable();emit({kind:'rust-decided',op,branch:step.decision.branch,outcome:'abort',attempt});throw Object.assign(Error(step.message),{status:step.status});}
        if(step.kind==='complete'){if(!exact(step,['kind','value','graph','decision'])||!decision(step.decision,op,'normal'))throw unavailable();const value=refs.materialize(step.graph,op,step.value);validateResult(op,input,value);emit({kind:'rust-decided',op,branch:step.decision.branch,outcome:'normal',attempt});return value;}
        if(!exact(step,['kind','seq','effect','graph'])||step.kind!=='need'||step.seq!==++seq||seq>MAX_STEPS)throw unavailable();
        const e=step.effect,allowed={get:['type','key','readId'],list:['type','prefix','limit','readId'],put:['type','key','value'],delete:['type','key'],deleteMany:['type','keys'],now:['type'],random:['type','kind'],compute:['type','kind','value']}[e?.type];
        if(!allowed||!exact(e,allowed)||!capabilities.includes(e.type))throw unavailable();
        const key=e.key??e.prefix;if(key!==undefined&&(typeof key!=='string'||key.length>512||!domains[op].some(p=>p.endsWith(':')?key.startsWith(p):key===p)))throw unavailable();
        if(e.type==='deleteMany'&&(!Array.isArray(e.keys)||!e.keys.length||e.keys.length>128||e.keys.some(key=>typeof key!=='string'||key.length>512||!domains[op].some(p=>p.endsWith(':')?key.startsWith(p):key===p))))throw unavailable();
        if(['put','delete','deleteMany'].includes(e.type)&&(e.keys||[e.key]).some(key=>!writable?.some(prefix=>matches(key,prefix))))throw unavailable();
        if(['get','list'].includes(e.type)&&e.readId!==++readId)throw unavailable();if(e.type==='list'&&(!Number.isInteger(e.limit)||e.limit<1||e.limit>1025))throw unavailable();
        if(e.type==='random'&&!['id','secret'].includes(e.kind))throw unavailable();if(e.type==='compute'&&!['sha256','jsonSha256','jsonText','jsonLength','parseUrl','sort','localeSort'].includes(e.kind))throw unavailable();
        const operand=refs.materialize(step.graph,op,e.value??{t:'u'});let answer;
        if(e.type==='get')answer=await tx.get(e.key);
        else if(e.type==='list')answer=[...await tx.list({prefix:e.prefix,limit:e.limit})].map(([key,value])=>({key,value}));
        else if(e.type==='put')await tx.put(e.key,operand);
        else if(e.type==='delete')await tx.delete(e.key);
        else if(e.type==='deleteMany')await tx.delete(e.keys);
        else if(e.type==='now')answer=now();
        else if(e.type==='random')answer=e.kind==='id'?crypto.randomUUID().replaceAll('-',''):randomSecret();
        else if(e.kind==='sha256')answer=await sha256(operand);
        else if(e.kind==='jsonSha256'||e.kind==='jsonText'||e.kind==='jsonLength'){const text=JSON.stringify(operand);if(typeof text!=='string'||text.length>524288)throw unavailable();answer=e.kind==='jsonSha256'?await sha256(text):e.kind==='jsonText'?text:text.length;}
        else if(e.kind==='parseUrl'){const u=new URL(operand);answer=Object.fromEntries(['href','protocol','hostname','host','username','password','search','hash','pathname','origin'].map(k=>[k,u[k]]));}
        else{if(!Array.isArray(operand)||operand.length>1025||operand.some(v=>typeof v!=='string'))throw unavailable();answer=operand.map((v,i)=>({v,i})).sort(e.kind==='localeSort'?(a,b)=>a.v.localeCompare(b.v):(a,b)=>a.v<b.v?-1:a.v>b.v?1:0).map(x=>x.i);}
        emit({kind:'host-effect',op,type:e.type,attempt});const value=refs.observe(answer,wire,{kind:e.type,key:e.key??e.prefix,path:[]});step=wire.call({type:'resume',seq,value});
      }
    });emit({kind:'tx-completed',op,outcome:'commit',attempt:ordinal});return result;
    }catch(error){emit({kind:'tx-completed',op,outcome:'abort',attempt:ordinal});throw error;}
  }
}
