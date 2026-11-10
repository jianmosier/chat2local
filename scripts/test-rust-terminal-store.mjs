import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('..',import.meta.url)),args=process.argv.slice(2);
if(process.platform!=='win32'||(args.length&&(args.length!==2||args[0]!=='--target-dir'))) throw Error('Usage (Windows): test-rust-terminal-store.mjs [--target-dir DIRECTORY]');
const target=args.length?path.resolve(args[1]):path.join(root,'target');
function run(file,args,env=process.env){const result=spawnSync(file,args,{cwd:root,env,stdio:'inherit',windowsHide:true,shell:false});if(result.error||result.status!==0)throw Error('Required native terminal journal validation failed.');}
run('cargo',['test','--locked','-p','chat2local-agent-platform','-p','chat2local-terminal-store','--target-dir',target]);
run('cargo',['build','--locked','-p','chat2local-terminal-store','-p','chat2local-terminal-runner','--target-dir',target]);
const artifacts=spawnSync('cargo',['test','--locked','-p','chat2local-agent-platform','--lib','--no-run','--message-format=json','--target-dir',target],{cwd:root,encoding:'utf8',windowsHide:true,shell:false});
if(artifacts.error||artifacts.status!==0)throw Error('Required native journal test harness was not built.');
const harness=artifacts.stdout.split(/\r?\n/).filter(Boolean).map(line=>JSON.parse(line)).find(item=>item.reason==='compiler-artifact'&&item.profile.test&&item.executable)?.executable;
if(!harness)throw Error('Missing test-only native journal harness.');
console.log(`Test-only native harness: ${harness}`);
run(process.execPath,['--test','--test-concurrency=1','tests/rust-terminal-store.test.mjs','tests/rust-terminal.test.mjs','tests/terminal.test.mjs','tests/agent-modules.test.mjs'],{...process.env,
CHAT2LOCAL_TERMINAL_STORE_TEST_REQUIRED:'1',CHAT2LOCAL_TERMINAL_STORE_TEST_EXECUTABLE:path.join(target,'debug/chat2local-terminal-store.exe'),CHAT2LOCAL_TERMINAL_STORE_TEST_HARNESS:harness,
CHAT2LOCAL_TERMINAL_TEST_REQUIRED:'1',CHAT2LOCAL_TERMINAL_TEST_EXECUTABLE:path.join(target,'debug/chat2local-terminal-runner.exe')});
