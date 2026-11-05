import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { passwordSetup } from '../scripts/setup-installer-password.mjs';
import { renderInstanceInstaller } from '../scripts/build-install-release.mjs';
import { VERSION } from '../src/shared/protocol.mjs';

const records=['darwin-arm64','darwin-x64'].map(target=>({target,version:VERSION,packageName:'Chat2Local-macOS-'+target.split('-')[1]+'-fixture',file:'Chat2Local-macOS-'+target.split('-')[1]+'-fixture.tar.gz',sha256:'a'.repeat(64),parts:[{path:'/releases/'+VERSION+'/'+target+'/'+'a'.repeat(64)+'.part00',sha256:'b'.repeat(64),bytes:1024}]}));
function shell(script, args, phase) {
 return new Promise((resolve, reject) => {
  const started = performance.now(), events = [], limit = 32768;
  const p = spawn('sh', args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', output = '', failure, cleanupTimer, closed = false;
  let stdoutBytes = 0, stderrBytes = 0;
  const note = (event, details = {}) => { if (events.length < 16) events.push({ event, elapsedMs: Math.round(performance.now() - started), ...details }); };
  const rejectWithEvidence = () => reject(new Error(`${failure}; ${JSON.stringify({ phase, args, pid: p.pid, elapsedMs: Math.round(performance.now() - started), closed, stdoutBytes, stderrBytes, stdout, stderr, events })}`));
  const fail = message => {
   if (failure) return;
   failure = message;
   clearTimeout(timer);
   note('failure', { message });
   note('kill', { requested: p.kill() });
   // A failed deadline stays failed even if the child later exits with the expected code.
   // Wait only briefly to record close; lack of close is reported as unconfirmed cleanup.
   cleanupTimer = setTimeout(rejectWithEvidence, 1000);
  };
  const timer = setTimeout(() => fail('Shell fixture timed out after 10000ms'), 10000);
  p.on('spawn', () => note('spawn'));
  p.on('exit', (code, signal) => note('exit', { code, signal }));
  for (const stream of ['stdout', 'stderr']) p[stream].on('data', bytes => {
   if (stream === 'stdout') { stdoutBytes += bytes.length; stdout = (stdout + bytes).slice(0, limit); }
   else { stderrBytes += bytes.length; stderr = (stderr + bytes).slice(0, limit); }
   if (stdoutBytes > limit || stderrBytes > limit) { fail('Shell fixture output exceeded its diagnostic bound'); return; }
   output += bytes;
  });
  p.on('error', error => fail(`Shell fixture process error: ${error.code || ''} ${error.message}`));
  p.stdin.on('error', error => fail(`Shell fixture stdin error: ${error.code || ''} ${error.message}`));
  p.on('close', (code, signal) => {
   closed = true; note('close', { code, signal }); clearTimeout(timer); clearTimeout(cleanupTimer);
   if (failure) rejectWithEvidence(); else resolve({ code, output });
  });
  p.stdin.end(script, () => note('stdin-complete'));
 });
}
test('generated public installer parses and chooses ARM64 without downloading or executing another platform runtime',async()=>{
 const script=renderInstanceInstaller('https://instance.example',records);
 assert.equal((await shell(script,['-n'],'syntax')).code,0);
 assert.match(script,/stage=\$\(CDPATH= cd -P "\$stage" && pwd -P\)/);
 assert.match(script,/Downloading package chunk/);
 assert.match(script,/Checking complete package SHA-256/);
 assert.match(script,/Extracting verified package and starting installer/);
 const prefix=`id(){ echo 501; }; uname(){ case "$1" in -s) echo Darwin;; -m) echo x86_64;; esac; }; sysctl(){ echo 1; }; sw_vers(){ echo 27.0; }; curl(){ echo "fixture-download:$*"; exit 77; };\n`;
 const result=await shell(prefix+script,['-x','-s'],'arm64-selection');assert.equal(result.code,77);assert.match(result.output,/darwin-arm64/);assert.doesNotMatch(result.output,/darwin-x64|sudo/);
});
test('one-time local password setup requires its exact browser token and Origin; no default password or operator key is displayed',async t=>{
 let opened,configured=false,submissions=0;
 const setup=await passwordSetup({browser:async url=>{opened=new URL(url)},call:async(action,input)=>{if(action==='installer-status')return{configured};assert.equal(action,'configure-installer');assert.equal(input.password,'My private installation password 981');submissions++;configured=true;return{configured:true}}});
 t.after(()=>setup.close());
 const origin=opened.origin,page=await(await fetch(origin)).text();
 assert.doesNotMatch(page,new RegExp(opened.hash.slice(1)));assert.doesNotMatch(page,/ENROLLMENT_KEY|deviceKey/);assert.equal(submissions,0);
 const send=(headers)=>fetch(origin+'/save',{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify({password:'My private installation password 981'})});
 assert.equal((await send({Origin:origin})).status,403);
 assert.equal((await send({Origin:'https://attacker.invalid','X-Chat2Local-Setup':opened.hash.slice(1)})).status,403);
 assert.equal(submissions,0);
 assert.equal((await send({Origin:origin,'X-Chat2Local-Setup':opened.hash.slice(1)})).status,200);assert.equal(submissions,1);
 assert.equal((await send({Origin:origin,'X-Chat2Local-Setup':opened.hash.slice(1)})).status,409);
});
