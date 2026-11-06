import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('..',import.meta.url)),args=process.argv.slice(2);
if(process.platform!=='win32'||(args.length&&(args.length!==2||args[0]!=='--target-dir'))) throw Error('Usage (Windows): build-rust-terminal-store.mjs [--target-dir DIRECTORY]');
const target=args.length?path.resolve(args[1]):path.join(root,'target');
const result=spawnSync('cargo',['build','--locked','--release','-p','chat2local-terminal-store','--target-dir',target],{cwd:root,stdio:'inherit',windowsHide:true,shell:false});
if(result.error||result.status!==0) throw Error('Required terminal journal build failed.');
const executable=path.join(target,'release/chat2local-terminal-store.exe');
if(!args.length){await fs.mkdir(path.join(root,'runtime'),{recursive:true});await fs.copyFile(executable,path.join(root,'runtime/chat2local-terminal-store.exe'));}
console.log(`Development terminal journal helper built: ${executable}`);
