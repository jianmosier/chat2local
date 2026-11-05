import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
export const projectRoot = fileURLToPath(new URL('..', import.meta.url));
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export function argumentsFor(args) {
  const result = { target: path.join(projectRoot, 'target'), output: path.join(projectRoot, '.artifacts/rust-relay') }, seen = new Set();
  for (let n = 0; n < args.length; n += 2) {
    const key = args[n];
    if (!['--target-dir', '--out-dir'].includes(key) || seen.has(key) || !args[n + 1]) throw Error('Usage: [--target-dir DIRECTORY] [--out-dir ARTIFACT_DIRECTORY]');
    seen.add(key); result[key === '--target-dir' ? 'target' : 'output'] = path.resolve(args[n + 1]);
  }
  if (!result.output.split(path.sep).includes('.artifacts')) throw Error('Generated relay entry must remain under an .artifacts directory.');
  return result;
}
export function validateModule(bytes, pages = 256) {
  if (bytes.length > 8 * 1024 * 1024 || WebAssembly.Module.imports(new WebAssembly.Module(bytes)).length) throw Error('Invalid relay WASM imports or size.');
  let offset = 8, found = false;
  const leb = end => {
    let value = 0, shift = 0;
    for (let count = 0; count < 5 && offset < end; count++) { const byte = bytes[offset++]; value += (byte & 127) * 2 ** shift; if (!(byte & 128)) return value; shift += 7; }
    throw Error('Invalid WASM memory declaration.');
  };
  while (offset < bytes.length) {
    const section = bytes[offset++], size = leb(bytes.length), end = offset + size;
    if (end > bytes.length) throw Error('Invalid WASM section.');
    if (section === 5) {
      if (found || leb(end) !== 1 || leb(end) !== 1) throw Error('Device WASM requires one bounded memory.');
      const initial = leb(end), maximum = leb(end);
      if (initial > maximum || maximum !== pages || offset !== end) throw Error('Relay WASM memory has an invalid bound.');
      found = true;
    }
    offset = end;
  }
  if (!found) throw Error('Device WASM has no memory.');
}
export async function readArtifact(directory) {
  const manifest = JSON.parse(await fs.readFile(path.join(directory, 'manifest.json'), 'utf8'));
  if (manifest.v !== 2 || manifest.entry !== 'worker.mjs' || !/^device-core-[a-f0-9]{64}\.wasm$/.test(manifest.wasm) || !/^registry-core-[a-f0-9]{64}\.wasm$/.test(manifest.registryWasm)) throw Error('Invalid combined relay artifact manifest.');
  for (const file of [manifest.entry, manifest.wasm, manifest.registryWasm]) {
    if (hash(await fs.readFile(path.join(directory, file))) !== manifest.artifacts?.[file]) throw Error('Missing or stale relay artifact: ' + file);
  }
  for (const [file, expected] of Object.entries(manifest.sources || {})) {
    if (file.includes('..') || !/^(src\/|crates\/|scripts\/|Cargo\.(toml|lock)$|package(?:-lock)?\.json$)/.test(file)) throw Error('Invalid artifact source binding.');
    if (hash(await fs.readFile(path.join(projectRoot, file))) !== expected) throw Error('Stale relay source; rebuild artifact: ' + file);
  }
  if (Object.keys(manifest.sources || {}).length < 6) throw Error('Incomplete relay source binding.');
  for (const crate of ['relay-device-core','relay-device-wasm','relay-registry-core','relay-registry-wasm']) {
    const required=[`crates/${crate}/Cargo.toml`,...(await fs.readdir(path.join(projectRoot,'crates',crate,'src'),{recursive:true})).filter(file=>file.endsWith('.rs')).map(file=>`crates/${crate}/src/${file.replaceAll('\\','/')}`)];
    if(required.some(file=>!Object.hasOwn(manifest.sources,file)))throw Error('Incomplete relay crate source binding.');
  }
  const wasmPath = path.join(directory, manifest.wasm), bytes = await fs.readFile(wasmPath); validateModule(bytes);
  if (manifest.wasm !== `device-core-${hash(bytes)}.wasm`) throw Error('Device WASM filename does not match its hash.');
  const registryWasmPath = path.join(directory, manifest.registryWasm), registryBytes = await fs.readFile(registryWasmPath); validateModule(registryBytes, 1024);
  if (manifest.registryWasm !== `registry-core-${hash(registryBytes)}.wasm`) throw Error('Registry WASM filename does not match its hash.');
  return { manifest, entry: path.join(directory, manifest.entry), wasmPath, bytes, registryWasmPath, registryBytes };
}
