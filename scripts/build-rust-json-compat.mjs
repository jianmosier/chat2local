import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { root, sourceFiles, hash, readJsonCompatArtifact } from './json-compat-artifact.mjs';
export { root } from './json-compat-artifact.mjs';
export function optionsFor(args) {
  const options={target:path.join(root,'target'),output:path.join(root,'.artifacts/rust-json-compat')},seen=new Set();
  for(let i=0;i<args.length;i+=2){const name=args[i];if(!['--target-dir','--out-dir'].includes(name)||seen.has(name)||!args[i+1])throw Error('Usage: [--target-dir DIRECTORY] [--out-dir DIRECTORY]');seen.add(name);options[name==='--target-dir'?'target':'output']=path.resolve(args[i+1]);}
  if(!options.output.split(path.sep).includes('.artifacts'))throw Error('JSON test fixtures must remain under .artifacts.');
  return options;
}
export function run(file,args,env=process.env){const result=spawnSync(file,args,{cwd:root,env,stdio:'inherit',shell:false,windowsHide:true});if(result.error||result.status!==0)throw Error('Required JSON compatibility command failed.');}
export async function buildJsonCompat(options) {
  const digest=async file=>hash(await fs.readFile(file));
  const sources={};for(const file of sourceFiles)sources[file]=await digest(path.join(root,file));
  run('cargo',['build','--locked','--release','-p','chat2local-js-value-compat-fixture','--bin','chat2local-js-value-compat-fixture','--target-dir',options.target]);
  run('cargo',['rustc','--locked','--release','-p','chat2local-js-value-compat-fixture','--lib','--target','wasm32-unknown-unknown','--target-dir',options.target,'--crate-type','cdylib','--','-C','link-arg=--max-memory=67108864']);
  for(const file of sourceFiles)if(await digest(path.join(root,file))!==sources[file])throw Error('JSON compatibility source changed during build: '+file);
  await fs.mkdir(options.output,{recursive:true});
  const name='chat2local-js-value-compat-fixture'+(process.platform==='win32'?'.exe':'');
  const executable=path.join(options.output,name),wasm=path.join(options.output,'json-compat.wasm');
  await fs.copyFile(path.join(options.target,'release',name),executable);
  await fs.copyFile(path.join(options.target,'wasm32-unknown-unknown/release/chat2local_js_value_compat_fixture.wasm'),wasm);
  const manifest={v:2,fixtureOnly:true,executable:name,wasm:'json-compat.wasm',hashes:{executable:await digest(executable),wasm:await digest(wasm)},sources};
  await fs.writeFile(path.join(options.output,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');
  await readJsonCompatArtifact({executable,wasm});
  console.log('JSON compatibility fixtures: '+options.output);return{executable,wasm};
}
if(import.meta.main)await buildJsonCompat(optionsFor(process.argv.slice(2)));
