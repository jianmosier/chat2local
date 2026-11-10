import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import https from 'node:https';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { WebSocketServer } from 'ws';
import { Store } from '../src/agent/store.mjs';
import { freePort } from './controller-fixture.mjs';
export const until = async (check, timeout = 10000) => { const end=Date.now()+timeout; while(Date.now()<end){const result=await check();if(result)return result;await new Promise(r=>setTimeout(r,20));}throw Error('Condition timed out.'); };
export async function relay(t,{pong=true,certificate,health}={}){
  const handler=(req,res)=>{if(typeof health==='function')return health(req,res);res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(health??{}));};
  const server=certificate?https.createServer(certificate,handler):http.createServer(handler);
  const wss=new WebSocketServer({server,handleProtocols: protocols=>protocols.has('chat2local-v1')?'chat2local-v1':false});
  const sockets=[], messages=[], protocols=[],pings=[];
  wss.on('connection',(ws,req)=>{sockets.push(ws);protocols.push(req.headers['sec-websocket-protocol']);ws.on('message',raw=>{if(raw.toString()==='ping'){pings.push(Date.now());if(pong)ws.send('pong');return;}messages.push({socket:ws,...JSON.parse(raw)});});});
  server.listen(0,'127.0.0.1');await once(server,'listening');
  t.after(async()=>{for(const s of wss.clients)s.terminate();await new Promise(r=>wss.close(r));await new Promise(r=>server.close(r));});
  const origin=`http://127.0.0.1:${server.address().port}`;
  return {origin,port:server.address().port,sockets,messages,protocols,pings,call:async(tool,args={},connectionAccess,extra={})=>{const socket=await until(()=>sockets.at(-1)?.readyState===1&&sockets.at(-1));const id=randomUUID();socket.send(JSON.stringify({kind:'call',id,tool,args,...(connectionAccess===undefined?{}:{connectionAccess}),...extra}));return until(()=>messages.find(m=>m.id===id));}};
}
export async function fixture(t,executable,origin,{before,externalRoot=false,transport={env:{}},platform}={}){
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'c2l-native-bridge-'));const port=await freePort();const store=new Store(directory);
  const root=randomUUID(),account=randomUUID(),device='a'.repeat(32),connection='b'.repeat(32),key='c'.repeat(64);
  const folder=externalRoot?await fs.mkdtemp(path.join(os.tmpdir(),'c2l-native-command-root-')):path.join(directory,'shared');if(!externalRoot)await fs.mkdir(folder);await fs.writeFile(path.join(folder,'hello.txt'),'native read\n');
  const config={version:1,roots:[{id:root,label:'Synthetic',path:folder,write:false}],accountRoots:[{id:account,label:'Scoped',path:folder,write:false,connectionId:connection}],paused:false,installationId:randomUUID(),unknown:{z:'\ud800',n:9007199254740993},terminalGrants:[{connectionId:connection,rootId:root,resource:origin+'/mcp',enabled:true}]};
  await store.saveConfig(config);await store.saveSecrets({identity:{origin,deviceId:device,deviceKey:key},unknown:{a:1}});await before?.({store,config,root,account,folder,device,connection,key});
  await fs.writeFile(path.join(directory,'.chat2local-synthetic-fixture'),'synthetic-only\n');const input=path.join(directory,'transport.json');await fs.writeFile(input,JSON.stringify(transport));
  const platformInput=path.join(directory,'platform.json');if(platform)await fs.writeFile(platformInput,JSON.stringify(platform));
  const child=spawn(executable,['--synthetic-state',directory,'--port',String(port),'--fixture-only','--fixture-transport',input,...(platform?['--fixture-platform',platformInput]:[]),'--control-stdin'],{windowsHide:true,env:{SystemRoot:process.env.SystemRoot,PATH:path.join(process.env.SystemRoot,'System32')},stdio:['pipe','pipe','pipe']});
  const lines=[],pending=new Map();let stderr='',buffer='';child.stderr.on('data',d=>stderr+=d);child.stdout.on('data',d=>{buffer+=d;for(;;){const at=buffer.indexOf('\n');if(at<0)break;const line=JSON.parse(buffer.slice(0,at));buffer=buffer.slice(at+1);lines.push(line);if(line.control&&pending.has(line.control)){pending.get(line.control)(line);pending.delete(line.control);}}});
  const exited=once(child,'exit');let api;
  t.after(async()=>{if(child.exitCode===null){for(const point of ['consent:checked','consent:publish','platform:register','platform:pause','platform:spawn','platform:commit','platform:drain','platform:browse','network:drain','read','reply','save','write:ready','write:committed','journal','journal:reserve','journal:reserved','journal:save','terminal:ready','terminal:spawn'])child.stdin.write(JSON.stringify({id:randomUUID(),op:'release',point})+'\n');await api?.('/api/shutdown',{}).catch(()=>{});try{await until(()=>child.exitCode!==null,10000);}catch{child.kill();await exited;}}await fs.rm(directory,{recursive:true,force:true});if(externalRoot)await fs.rm(folder,{recursive:true,force:true});});
  const ready=await until(()=>{if(child.exitCode!==null)throw Error(stderr);return lines.find(v=>v.fixtureOnly);});const session=await store.readSession();
  api=(route,body,headers={})=>fetch(ready.origin+route,{method:body===undefined?'GET':'POST',headers:{Origin:ready.origin,'Content-Type':'application/json','X-Chat2Local-Token':session.token,...headers},...(body===undefined?{}:{body:JSON.stringify(body)})});
  const control=async(command)=>{const id=randomUUID();const response=new Promise(resolve=>pending.set(id,resolve));child.stdin.write(JSON.stringify({id,...command})+'\n');const result=await Promise.race([response,new Promise((_,reject)=>{const timer=setTimeout(()=>reject(Error('Control timed out: '+stderr)),command.op?.startsWith('network-')||command.op?.startsWith('platform-')?45000:5000);timer.unref();})]);if(!result.ok)throw Error(result.error);return result.result;};
  return {directory,store,root,account,device,connection,key,folder,config,api,control,child,exited,ready,session,access:{version:1,connectionId:connection,deviceId:device,resource:origin+'/mcp',roots:[{rootId:root,mode:'read-only'},{rootId:account,mode:'read-only'}],scopes:['files:read','terminal:execute']}};
}

