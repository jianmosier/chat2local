import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
export const root=fileURLToPath(new URL('..',import.meta.url));
export const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
export async function sourceFiles(sourceRoot=root){
  const files=['Cargo.toml','Cargo.lock','scripts/build-rust-native-store.mjs','scripts/test-rust-native-store.mjs','scripts/native-store-artifact.mjs','tests/rust-native-store.test.mjs'];
  for(const crate of ['native-store','native-store-fixture','agent-platform','protocol','policy','js-value-compat']){
    files.push(`crates/${crate}/Cargo.toml`);
    for(const entry of await fs.readdir(path.join(sourceRoot,`crates/${crate}/src`),{recursive:true,withFileTypes:true}))if(entry.isFile()&&entry.name.endsWith('.rs'))files.push(path.relative(sourceRoot,path.join(entry.parentPath,entry.name)).split(path.sep).join('/'));
  }return files.sort();
}
export async function readNativeStoreArtifact(executable,{sourceRoot=root}={}){
  const manifest=JSON.parse(await fs.readFile(path.join(path.dirname(executable),'manifest.json'),'utf8'));
  const files=await sourceFiles(sourceRoot);
  if(manifest.v!==1||manifest.fixtureOnly!==true||manifest.executable!==path.basename(executable)||Object.keys(manifest.sources??{}).sort().join('\n')!==files.join('\n'))throw Error('Native Store fixture manifest mismatch.');
  for(const file of files)if(hash(await fs.readFile(path.join(sourceRoot,file)))!==manifest.sources[file])throw Error('Stale native Store fixture source: '+file);
  if(hash(await fs.readFile(executable))!==manifest.sha256)throw Error('Native Store fixture binary mismatch.');
  return manifest;
}
