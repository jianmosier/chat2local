import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('..',import.meta.url)),args=process.argv.slice(2);
if(process.platform!=='win32'||(args.length&&(args.length!==2||args[0]!=='--target-dir')))throw Error('Usage (Windows): test-rust-lifecycle.mjs [--target-dir DIRECTORY]');
const target=args.length?path.resolve(args[1]):path.join(root,'target');
function run(command,args,env=process.env){const r=spawnSync(command,args,{cwd:root,env,stdio:'inherit',windowsHide:true,shell:false});if(r.error||r.status!==0)throw Error('Required lifecycle validation failed.');}
run('cargo',['test','--locked','-p','chat2local-agent-lifecycle-core','--target-dir',target]);
run(process.execPath,['scripts/build-rust-lifecycle.mjs','--target-dir',target]);
run('cargo',['build','--locked','-p','chat2local-terminal-runner','-p','chat2local-terminal-store','-p','chat2local-writer','--target-dir',target]);
const regression=['tests/agent-modules.test.mjs','tests/controller.test.mjs','tests/setup-concurrency.test.mjs','tests/network-settings.test.mjs','tests/folder-picker.test.mjs','tests/folder-browser.test.mjs','tests/share-removal.test.mjs','tests/management-session.test.mjs','tests/core.test.mjs'];
const baseline={...process.env};delete baseline.CHAT2LOCAL_LIFECYCLE_BACKEND;delete baseline.CHAT2LOCAL_LIFECYCLE_MODULE;
console.log('DEFAULT JS LIFECYCLE REGRESSION (no generated lifecycle artifact dependency)');
run(process.execPath,['--test','--test-concurrency=1',...regression],baseline);
const modulePath=path.join(target,'wasm32-unknown-unknown/release/chat2local_agent_lifecycle_wasm.wasm');
console.log('REQUIRED REAL RUST LIFECYCLE + WINDOWS EXECUTION/JOURNAL REGRESSION');
run(process.execPath,['--test','--test-concurrency=1','tests/rust-lifecycle.test.mjs','tests/terminal.test.mjs','tests/rust-terminal.test.mjs','tests/relay.test.mjs','tests/account-transport.test.mjs',...regression],{...process.env,
  CHAT2LOCAL_LIFECYCLE_BACKEND:'rust',CHAT2LOCAL_LIFECYCLE_MODULE:modulePath,CHAT2LOCAL_LIFECYCLE_TEST_REQUIRED:'1',CHAT2LOCAL_LIFECYCLE_TEST_MODULE:modulePath,
  CHAT2LOCAL_TERMINAL_TEST_REQUIRED:'1',CHAT2LOCAL_TERMINAL_TEST_EXECUTABLE:path.join(target,'debug/chat2local-terminal-runner.exe'),
  CHAT2LOCAL_TERMINAL_STORE_TEST_EXECUTABLE:path.join(target,'debug/chat2local-terminal-store.exe'),CHAT2LOCAL_WRITER_TEST_EXECUTABLE:path.join(target,'debug/chat2local-writer.exe')});
