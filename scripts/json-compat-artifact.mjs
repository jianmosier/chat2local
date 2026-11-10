import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
export const root=fileURLToPath(new URL('..',import.meta.url));
export const sourceFiles=Object.freeze(['Cargo.toml','Cargo.lock',
  ...['js-value-compat','js-value-compat-fixture'].flatMap(crate=>['Cargo.toml',...(crate==='js-value-compat'?['src/lib.rs','src/parse.rs','src/stringify.rs']:['src/lib.rs','src/main.rs'])].map(file=>'crates/'+crate+'/'+file)),
  'scripts/build-rust-json-compat.mjs','scripts/json-compat-artifact.mjs','scripts/test-rust-json-compat.mjs','tests/rust-json-compat.test.mjs']);
export const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const digest=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const same=(a,b)=>process.platform==='win32'?a.toLowerCase()===b.toLowerCase():a===b;
const refused=reason=>Object.assign(Error('JSON fixture artifact '+reason),{code:'EJSONARTIFACT'});
/** Test/build resource only. Direct strict tests always use the actual source root.
 * sourceRoot is explicit solely so negative tests can mutate isolated copies. */
export async function readJsonCompatArtifact({executable,wasm,sourceRoot=root}) {
  const directory=path.dirname(path.resolve(executable));
  if(!same(directory,path.dirname(path.resolve(wasm))))throw refused('paths must share one manifest directory.');
  const manifestPath=path.join(directory,'manifest.json'),raw=await fs.readFile(manifestPath);
  if(raw.length>65536)throw refused('manifest is too large.');
  let manifest;try{manifest=JSON.parse(raw.toString('utf8'));}catch{throw refused('manifest is invalid JSON.');}
  if(!exact(manifest,['v','fixtureOnly','executable','wasm','hashes','sources'])||manifest.v!==2||manifest.fixtureOnly!==true
    ||manifest.executable!==path.basename(executable)||manifest.wasm!==path.basename(wasm)
    ||!exact(manifest.hashes,['executable','wasm'])||!Object.values(manifest.hashes).every(digest)
    ||!exact(manifest.sources,sourceFiles)||!Object.values(manifest.sources).every(digest))throw refused('manifest has an unsupported shape.');
  for(const file of sourceFiles)if(hash(await fs.readFile(path.join(sourceRoot,file)))!==manifest.sources[file])throw refused('has stale source: '+file);
  const executableBytes=await fs.readFile(executable),wasmBytes=await fs.readFile(wasm);
  if(hash(executableBytes)!==manifest.hashes.executable||hash(wasmBytes)!==manifest.hashes.wasm)throw refused('binary hash mismatch.');
  return{manifest,executable,wasm,wasmBytes};
}
