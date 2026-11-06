import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { build } from 'esbuild';
import { argumentsFor, projectRoot, hash, validateModule } from './rust-relay-artifact.mjs';
const { target, output } = argumentsFor(process.argv.slice(2));
const result = spawnSync('cargo', ['rustc', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '--target-dir', target,
  '-p', 'chat2local-relay-device-wasm', '--', '-C', 'link-arg=--max-memory=16777216'], { cwd: projectRoot, stdio: 'inherit', shell: false, windowsHide: true });
if (result.error || result.status !== 0) throw Error('Required Device WASM build failed.');
const bytes = await fs.readFile(path.join(target, 'wasm32-unknown-unknown/release/chat2local_relay_device_wasm.wasm')); validateModule(bytes);
const wasm = `device-core-${hash(bytes)}.wasm`;
const registryBuild = spawnSync('cargo', ['rustc', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '--target-dir', target,
  '-p', 'chat2local-relay-registry-wasm', '--', '-C', 'link-arg=--max-memory=67108864'], { cwd: projectRoot, stdio: 'inherit', shell: false, windowsHide: true });
if (registryBuild.error || registryBuild.status !== 0) throw Error('Required Registry WASM build failed.');
const registryBytes = await fs.readFile(path.join(target, 'wasm32-unknown-unknown/release/chat2local_relay_registry_wasm.wasm')); validateModule(registryBytes, 1024);
const registryWasm = `registry-core-${hash(registryBytes)}.wasm`;
// Explicit development entry only. Production worker.mjs never imports this.
const bundle = await build({ absWorkingDir: projectRoot, stdin: { resolveDir: projectRoot, sourcefile: 'rust-device-entry.mjs', contents: `
import module from './${wasm}';
import registryModule from './${registryWasm}';
import { Device as OriginalDevice, Registry as OriginalRegistry } from './src/relay/state.mjs';
import { RustDeviceSessionCore } from './src/relay/rust-device-session.mjs';
import { RustRegistryRunner } from './src/relay/rust-registry.mjs';
export { default } from './src/relay/worker.mjs';
export class Device extends OriginalDevice { constructor(ctx, env) { super(ctx, env, () => new RustDeviceSessionCore(module)); } }
export class Registry extends OriginalRegistry { constructor(ctx, env) { super(ctx, env, () => new RustRegistryRunner(registryModule)); } }
` }, bundle: true, write: false, metafile: true, format: 'esm', platform: 'neutral', mainFields: ['module', 'main'], external: ['cloudflare:workers', '*.wasm'] });
const entry = bundle.outputFiles[0].contents, sources = {};
const localInputs = Object.keys(bundle.metafile.inputs).filter(file => file !== 'rust-device-entry.mjs' && !file.startsWith('..') && !file.includes('node_modules/'));
const inputs = new Set([...localInputs, 'Cargo.toml', 'Cargo.lock', 'package.json', 'package-lock.json',
  'scripts/build-rust-relay.mjs', 'scripts/rust-relay-artifact.mjs']);
// Bind every Rust source in the four explicitly selected crates, including new aggregate modules.
for (const crate of ['relay-device-core','relay-device-wasm','relay-registry-core','relay-registry-wasm']) {
  inputs.add(`crates/${crate}/Cargo.toml`);
  for (const file of await fs.readdir(path.join(projectRoot, 'crates', crate, 'src'), { recursive: true })) {
    if (file.endsWith('.rs')) inputs.add(`crates/${crate}/src/${file.replaceAll('\\', '/')}`);
  }
}
for (const file of [...inputs].sort()) sources[file] = hash(await fs.readFile(path.join(projectRoot, file)));
await fs.mkdir(output, { recursive: true });
await fs.writeFile(path.join(output, wasm), bytes); await fs.writeFile(path.join(output, 'worker.mjs'), entry);
await fs.writeFile(path.join(output, registryWasm), registryBytes);
await fs.writeFile(path.join(output, 'manifest.json'), JSON.stringify({ v: 2, entry: 'worker.mjs', wasm, registryWasm,
  artifacts: { 'worker.mjs': hash(entry), [wasm]: hash(bytes), [registryWasm]: hash(registryBytes) }, sources }, null, 2) + '\n');
console.log(`Local Device + Registry entry built: ${output}`);
