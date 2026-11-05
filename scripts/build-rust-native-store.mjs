import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { root,sourceFiles,hash,readNativeStoreArtifact } from './native-store-artifact.mjs';
export function optionsFor(args){const options={target:path.join(root,'target'),output:path.join(root,'.artifacts/rust-native-store')},seen=new Set();for(let i=0;i<args.length;i+=2){const name=args[i];if(!['--target-dir','--out-dir'].includes(name)||seen.has(name)||!args[i+1])throw Error('Usage: [--target-dir DIRECTORY] [--out-dir DIRECTORY]');seen.add(name);options[name==='--target-dir'?'target':'output']=path.resolve(args[i+1]);}if(!options.output.split(path.sep).includes('.artifacts'))throw Error('Native Store fixture must remain under .artifacts.');return options;}
export function run(file,args,env=process.env){const result=spawnSync(file,args,{cwd:root,env,stdio:'inherit',windowsHide:true,shell:false});if(result.error||result.status!==0)throw Error('Required native Store command failed.');}
export async function buildNativeStore(options){
  const sources={};for(const file of await sourceFiles())sources[file]=hash(await fs.readFile(path.join(root,file)));
  run('cargo',['build','--locked','-p','chat2local-native-store-fixture','--target-dir',options.target]);
  for(const [file,digest] of Object.entries(sources))if(hash(await fs.readFile(path.join(root,file)))!==digest)throw Error('Native Store source changed during build.');
  await fs.mkdir(options.output,{recursive:true});const name='chat2local-native-store-fixture'+(process.platform==='win32'?'.exe':'');const executable=path.join(options.output,name);
  await fs.copyFile(path.join(options.target,'debug',name),executable);
  await fs.writeFile(path.join(options.output,'manifest.json'),JSON.stringify({v:1,fixtureOnly:true,executable:name,sha256:hash(await fs.readFile(executable)),sources},null,2)+'\n');
  await readNativeStoreArtifact(executable);return{executable};
}
if(import.meta.main)console.log(await buildNativeStore(optionsFor(process.argv.slice(2))));
